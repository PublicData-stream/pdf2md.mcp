//! Transport-independent OAuth access-token validation.
//!
//! These types validate access tokens only. Token acquisition for the optional
//! registered client lives in [`crate::oauth`]; this module never issues tokens.
use crate::{
    client_auth::{ClientAssertionConfig, ClientAuth},
    error::{LoadError, Result},
};
use futures_util::StreamExt;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use std::{
    fmt,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use url::Url;

pub(crate) const MAX_RESPONSE: usize = 256 * 1024;
pub(crate) const MAX_TOKEN: usize = 64 * 1024;
const MAX_ADDITIONAL_AUDIENCES: usize = 16;
/// Casdoor's signed access-token class claim and value.
const CASDOOR_TOKEN_TYPE: &str = "access-token";
const METADATA_TTL: Duration = Duration::from_secs(300);
const KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// Tolerated clock difference, in seconds, for the not-yet-valid checks
/// (`nbf` and `iat`). Providers issue whole-second timestamps, so a freshly
/// issued token can appear to come from the future when clocks differ
/// slightly. Expiry is never extended.
const CLOCK_SKEW_SECS: i64 = 30;

fn invalid() -> LoadError {
    LoadError::new(
        "auth_invalid",
        "valid access-token credentials are required",
    )
}
fn forbidden() -> LoadError {
    LoadError::new("auth_forbidden", "operation is not permitted")
}
pub(crate) fn unavailable() -> LoadError {
    LoadError::transient("auth_unavailable", "identity provider is unavailable")
}
pub(crate) fn config_error() -> LoadError {
    LoadError::new("auth_config", "invalid authentication configuration")
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    #[default]
    NoneRo,
    NoneRw,
    Oauth2,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub mode: AuthMode,
    pub oidc: Option<OidcConfig>,
    /// Optional registered OAuth client used to obtain tokens for callers.
    pub client: Option<crate::oauth::OAuthClientConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenValidation {
    #[default]
    Introspection,
    Jwt,
}

/// Provider-specific access-token conventions. Each profile is explicit; the
/// validator never falls back from one profile to another.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenProfile {
    /// RFC 9068 JWTs (`typ` `at+jwt`, `client_id`) and RFC 7662 introspection.
    #[default]
    Rfc9068,
    /// Casdoor JWTs (`typ` `JWT`, signed `tokenType` `access-token`, `azp`).
    Casdoor,
}

fn read_scope() -> String {
    "pdf2md:read".into()
}
fn write_scope() -> String {
    "pdf2md:write".into()
}
fn operate_scope() -> String {
    "pdf2md:operate".into()
}
fn jwt_scope_claim() -> String {
    "scope".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    #[serde(default)]
    pub validation: TokenValidation,
    #[serde(default)]
    pub token_profile: TokenProfile,
    /// Additional accepted access-token audiences, for example dedicated client
    /// IDs whose provider cannot bind a grant to the resource (RFC 8707).
    #[serde(default)]
    pub additional_audiences: Vec<String>,
    /// Optional issuer-documented access-token discriminator for introspection
    /// providers that omit token_type. This never replaces introspection.
    pub access_token_prefix: Option<String>,
    /// Explicit JWT scope convention: space-delimited scope or array-valued scp.
    #[serde(default = "jwt_scope_claim")]
    pub jwt_scope_claim: String,
    pub client_id: Option<String>,
    pub client_secret: Option<OidcSecret>,
    /// `private_key_jwt` signing key for introspection, used instead of
    /// `client_secret`.
    #[serde(default)]
    pub client_assertion: Option<ClientAssertionConfig>,
    #[serde(default = "read_scope")]
    pub read_scope: String,
    #[serde(default = "write_scope")]
    pub write_scope: String,
    #[serde(default = "operate_scope")]
    pub operate_scope: String,
    #[serde(default)]
    pub allowed_endpoint_origins: Vec<String>,
    pub ca_file: Option<PathBuf>,
}

/// Runtime secret reference. The value is never included in Debug or errors.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcSecret {
    pub env: Option<String>,
    pub file: Option<PathBuf>,
}
impl fmt::Debug for OidcSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcSecret([redacted])")
    }
}
impl OidcSecret {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.env.is_some() == self.file.is_some()
            || self.env.as_ref().is_some_and(|name| name.is_empty())
        {
            return Err(config_error());
        }
        Ok(())
    }
    pub(crate) fn resolve(&self) -> Result<String> {
        self.validate()?;
        let value = if let Some(name) = &self.env {
            std::env::var(name).map_err(|_| config_error())?
        } else {
            String::from_utf8(read_file(
                self.file.as_ref().expect("validated secret"),
                MAX_TOKEN,
            )?)
            .map_err(|_| config_error())?
            .trim_end_matches(['\r', '\n'])
            .to_owned()
        };
        if value.is_empty() || value.len() > MAX_TOKEN {
            return Err(config_error());
        }
        Ok(value)
    }
}

pub(crate) fn read_file(path: &std::path::Path, max: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| config_error())?;
    let metadata = file.metadata().map_err(|_| config_error())?;
    if !metadata.is_file() || metadata.len() > max as u64 {
        return Err(config_error());
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| config_error())?;
    if bytes.len() > max {
        return Err(config_error());
    }
    Ok(bytes)
}

pub(crate) fn https_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| config_error())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(config_error());
    }
    Ok(url)
}
pub(crate) fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}
impl OidcConfig {
    /// Whether an access token issued for `resource` passes the audience check.
    pub(crate) fn accepts_audience(&self, resource: &str) -> bool {
        self.audience == resource || self.additional_audiences.iter().any(|v| v == resource)
    }
}
impl AuthConfig {
    pub fn validate(&self) -> Result<()> {
        if self.mode != AuthMode::Oauth2 {
            return if self.oidc.is_none() && self.client.is_none() {
                Ok(())
            } else {
                Err(config_error())
            };
        }
        let oidc = self.oidc.as_ref().ok_or_else(config_error)?;
        https_url(&oidc.issuer)?;
        if oidc.audience.is_empty()
            || oidc.additional_audiences.len() > MAX_ADDITIONAL_AUDIENCES
            || oidc.additional_audiences.iter().any(|value| {
                value.is_empty()
                    || value.len() > 1024
                    || value == &oidc.audience
                    || value.bytes().any(|b| b.is_ascii_control())
            })
            || (oidc.token_profile == TokenProfile::Casdoor
                && (oidc.jwt_scope_claim != "scope" || oidc.access_token_prefix.is_some()))
            || !matches!(oidc.jwt_scope_claim.as_str(), "scope" | "scp")
            || (oidc.validation == TokenValidation::Introspection
                && oidc.jwt_scope_claim != "scope")
            || !valid_scope(&oidc.read_scope)
            || !valid_scope(&oidc.write_scope)
            || !valid_scope(&oidc.operate_scope)
            || oidc.read_scope == oidc.write_scope
            || oidc.operate_scope == oidc.read_scope
            || oidc.operate_scope == oidc.write_scope
        {
            return Err(config_error());
        }
        for origin in &oidc.allowed_endpoint_origins {
            let parsed = https_url(origin)?;
            if parsed.path() != "/" {
                return Err(config_error());
            }
        }
        if let Some(prefix) = &oidc.access_token_prefix
            && (oidc.validation != TokenValidation::Introspection
                || prefix.is_empty()
                || prefix.len() > 128
                || !prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)))
        {
            return Err(config_error());
        }
        if oidc.validation == TokenValidation::Introspection {
            // Introspection is an authenticated call: exactly one credential.
            if oidc.client_id.as_ref().is_none_or(|value| value.is_empty())
                || oidc.client_secret.is_some() == oidc.client_assertion.is_some()
            {
                return Err(config_error());
            }
            if let Some(secret) = &oidc.client_secret {
                secret.validate()?;
            }
            if let Some(assertion) = &oidc.client_assertion {
                assertion.validate()?;
            }
        }
        if let Some(client) = &self.client {
            client.validate(oidc)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    Shared,
    User { issuer: String, subject: String },
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    introspection_endpoint: Option<String>,
    jwks_uri: Option<String>,
    token_endpoint: Option<String>,
}
struct Provider {
    config: OidcConfig,
    client: reqwest::Client,
    /// Introspection client authentication; unused for JWT validation.
    auth: ClientAuth,
    metadata: Mutex<Option<Metadata>>,
    keys: Mutex<KeyCache>,
}
struct Metadata {
    discovery: Discovery,
    fetched: Instant,
}
#[derive(Default)]
struct KeyCache {
    keys: Option<JwkSet>,
    fetched: Option<Instant>,
    last_unknown_refresh: Option<Instant>,
}

/// Validates each operation independently; no successful-token cache is kept.
pub struct Authenticator {
    mode: AuthMode,
    provider: Option<Provider>,
}
impl Authenticator {
    pub async fn new(config: AuthConfig) -> Result<Self> {
        config.validate()?;
        crate::configure_tls();
        let provider = if config.mode == AuthMode::Oauth2 {
            let oidc = config.oidc.expect("validated OIDC configuration");
            let client = provider_client(&oidc)?;
            let auth = if oidc.validation == TokenValidation::Introspection {
                ClientAuth::load(oidc.client_secret.as_ref(), oidc.client_assertion.as_ref())?
            } else {
                ClientAuth::Public
            };
            Some(Provider {
                config: oidc,
                client,
                auth,
                metadata: Mutex::new(None),
                keys: Mutex::new(KeyCache::default()),
            })
        } else {
            None
        };
        Ok(Self {
            mode: config.mode,
            provider,
        })
    }

    /// `token` contains only the access-token value, without a Bearer prefix.
    pub async fn authenticate(&self, token: Option<&str>, write: bool) -> Result<Identity> {
        self.authorize(token, write, false).await
    }

    /// Validate current read/write permissions and optional operator-source grant.
    pub async fn authorize(
        &self,
        token: Option<&str>,
        write: bool,
        operate: bool,
    ) -> Result<Identity> {
        match self.mode {
            AuthMode::NoneRo if write || operate => Err(forbidden()),
            AuthMode::NoneRo | AuthMode::NoneRw => Ok(Identity::Shared),
            AuthMode::Oauth2 => {
                let token = token
                    .filter(|value| {
                        !value.is_empty()
                            && value.len() <= MAX_TOKEN
                            && !value
                                .bytes()
                                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
                    })
                    .ok_or_else(invalid)?;
                let provider = self.provider.as_ref().expect("OAuth provider initialized");
                let claims = match provider.config.validation {
                    TokenValidation::Introspection => provider.introspect(token).await?,
                    TokenValidation::Jwt => provider.jwt(token).await?,
                };
                let scopes: Vec<_> = claims
                    .scope
                    .as_deref()
                    .unwrap_or_default()
                    .split_ascii_whitespace()
                    .collect();
                if !scopes.contains(&provider.config.read_scope.as_str())
                    || (write && !scopes.contains(&provider.config.write_scope.as_str()))
                    || (operate && !scopes.contains(&provider.config.operate_scope.as_str()))
                {
                    return Err(forbidden());
                }
                Ok(Identity::User {
                    issuer: provider.config.issuer.clone(),
                    subject: claims.sub.ok_or_else(invalid)?,
                })
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct Claims {
    #[serde(default)]
    active: bool,
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<Audience>,
    exp: Option<i64>,
    iat: Option<i64>,
    nbf: Option<i64>,
    scope: Option<String>,
    scp: Option<serde_json::Value>,
    token_type: Option<String>,
    token_use: Option<String>,
    jti: Option<String>,
    client_id: Option<String>,
    azp: Option<String>,
    /// Casdoor's token-class claim.
    #[serde(rename = "tokenType")]
    casdoor_token_type: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
impl Audience {
    fn contains(&self, audience: &str) -> bool {
        match self {
            Self::One(value) => value == audience,
            Self::Many(values) => values.iter().any(|value| value == audience),
        }
    }
}
/// Accept a discovered provider endpoint only at the issuer origin or an
/// explicitly allowed origin.
/// Validate a provider endpoint. Unlike the issuer, an endpoint may carry a
/// query component, which RFC 6749 section 3.1 requires clients to retain.
pub(crate) fn provider_endpoint(config: &OidcConfig, value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| unavailable())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(unavailable());
    }
    let issuer = https_url(&config.issuer).map_err(|_| unavailable())?;
    if url.origin() != issuer.origin()
        && !config.allowed_endpoint_origins.iter().any(|allowed| {
            Url::parse(allowed).is_ok_and(|allowed| allowed.origin() == url.origin())
        })
    {
        return Err(unavailable());
    }
    Ok(url)
}

/// Build the HTTPS client used for provider calls, with optional extra trust.
pub(crate) fn provider_client(config: &OidcConfig) -> Result<reqwest::Client> {
    crate::configure_tls();
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(path) = &config.ca_file {
        let bytes = read_file(path, MAX_RESPONSE)?;
        let certificate = reqwest::Certificate::from_pem(&bytes).map_err(|_| config_error())?;
        builder = builder.add_root_certificate(certificate);
    }
    builder.build().map_err(|_| config_error())
}

/// Decode a JWT payload without verifying it. Use only for provider-issued
/// tokens whose authenticity is established separately (for example by
/// introspection of the exact token string).
fn unverified_payload(token: &str) -> Option<Claims> {
    use base64::Engine;
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

impl Provider {
    fn endpoint(&self, value: &str) -> Result<Url> {
        provider_endpoint(&self.config, value)
    }
    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: Url) -> Result<T> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| unavailable())?;
        decode_response(response).await
    }
    async fn discovery(&self) -> Result<Discovery> {
        let mut metadata = self.metadata.lock().await;
        if metadata
            .as_ref()
            .is_none_or(|value| value.fetched.elapsed() >= METADATA_TTL)
        {
            let endpoint = format!(
                "{}/.well-known/openid-configuration",
                self.config.issuer.trim_end_matches('/')
            );
            let discovery: Discovery = self.get_json(self.endpoint(&endpoint)?).await?;
            if discovery.issuer != self.config.issuer {
                return Err(unavailable());
            }
            match self.config.validation {
                TokenValidation::Introspection => {
                    self.endpoint(
                        discovery
                            .introspection_endpoint
                            .as_deref()
                            .ok_or_else(unavailable)?,
                    )?;
                }
                TokenValidation::Jwt => {
                    self.endpoint(discovery.jwks_uri.as_deref().ok_or_else(unavailable)?)?;
                }
            }
            *metadata = Some(Metadata {
                discovery,
                fetched: Instant::now(),
            });
        }
        let discovery = &metadata.as_ref().expect("metadata initialized").discovery;
        Ok(Discovery {
            issuer: discovery.issuer.clone(),
            introspection_endpoint: discovery.introspection_endpoint.clone(),
            jwks_uri: discovery.jwks_uri.clone(),
            token_endpoint: discovery.token_endpoint.clone(),
        })
    }
    fn validate_claims(&self, claims: &Claims, require_issuer: bool) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        if claims
            .sub
            .as_ref()
            .is_none_or(|sub| sub.is_empty() || sub.len() > 4096)
            || claims.aud.as_ref().is_none_or(|aud| {
                !aud.contains(&self.config.audience)
                    && !self
                        .config
                        .additional_audiences
                        .iter()
                        .any(|accepted| aud.contains(accepted))
            })
            || claims.exp.is_none_or(|exp| exp <= now)
            || claims.nbf.is_some_and(|nbf| nbf > now + CLOCK_SKEW_SECS)
            || claims.iat.is_some_and(|iat| iat > now + CLOCK_SKEW_SECS)
            || claims
                .iss
                .as_ref()
                .is_some_and(|iss| iss != &self.config.issuer)
            || (require_issuer && claims.iss.is_none())
        {
            return Err(invalid());
        }
        Ok(())
    }
    async fn introspect(&self, token: &str) -> Result<Claims> {
        if self
            .config
            .access_token_prefix
            .as_ref()
            .is_some_and(|prefix| !token.starts_with(prefix))
        {
            return Err(invalid());
        }
        // Casdoor introspection reports refresh tokens as active Bearer
        // tokens. Its tokens are JWTs whose exact string the provider looks
        // up, so the issued token-class claim distinguishes access tokens; the
        // introspected jti must also identify the same token.
        let casdoor_jti = if self.config.token_profile == TokenProfile::Casdoor {
            let payload = unverified_payload(token).ok_or_else(invalid)?;
            if payload.casdoor_token_type.as_deref() != Some(CASDOOR_TOKEN_TYPE) {
                return Err(invalid());
            }
            Some(
                payload
                    .jti
                    .filter(|value| !value.is_empty())
                    .ok_or_else(invalid)?,
            )
        } else {
            None
        };
        let discovery = self.discovery().await?;
        let request = self.client.post(
            self.endpoint(
                discovery
                    .introspection_endpoint
                    .as_deref()
                    .ok_or_else(unavailable)?,
            )?,
        );
        let mut form = vec![
            ("token", token.to_owned()),
            ("token_type_hint", "access_token".to_owned()),
        ];
        // A signed assertion names the token endpoint as its audience.
        let token_endpoint = match &self.auth {
            ClientAuth::Assertion(_) => discovery.token_endpoint.ok_or_else(unavailable)?,
            _ => String::new(),
        };
        let response = self
            .auth
            .apply(
                request,
                &mut form,
                self.config.client_id.as_ref().expect("validated client"),
                &token_endpoint,
            )?
            .form(&form)
            .send()
            .await
            .map_err(|_| unavailable())?;
        let claims: Claims = decode_response(response).await?;
        // An RFC 7662 type hint does not prove token class. Require a Bearer
        // type, or an explicit issuer-documented prefix when type is omitted.
        let access_type = match claims.token_type.as_deref() {
            Some(kind) => kind.eq_ignore_ascii_case("bearer"),
            None => self.config.access_token_prefix.is_some(),
        };
        if !claims.active
            || !access_type
            || casdoor_jti
                .as_ref()
                .is_some_and(|expected| claims.jti.as_ref() != Some(expected))
            || claims
                .token_use
                .as_ref()
                .is_some_and(|kind| kind != "access_token")
        {
            return Err(invalid());
        }
        self.validate_claims(&claims, false)?;
        Ok(claims)
    }
    async fn jwt(&self, token: &str) -> Result<Claims> {
        let header = decode_header(token).map_err(|_| invalid())?;
        let profile = self.config.token_profile;
        if header.alg != Algorithm::RS256
            || !header.typ.as_ref().is_some_and(|typ| match profile {
                TokenProfile::Rfc9068 => {
                    typ.eq_ignore_ascii_case("at+jwt")
                        || typ.eq_ignore_ascii_case("application/at+jwt")
                }
                TokenProfile::Casdoor => typ.eq_ignore_ascii_case("JWT"),
            })
            || header.jku.is_some()
            || header.x5u.is_some()
            || header.jwk.is_some()
            || header.crit.as_ref().is_some_and(|crit| !crit.is_empty())
            || header.enc.is_some()
            || header.zip.is_some()
        {
            return Err(invalid());
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|kid| !kid.is_empty())
            .ok_or_else(invalid)?;
        let discovery = self.discovery().await?;
        let mut cache = self.keys.lock().await;
        let stale = cache
            .fetched
            .is_none_or(|time| time.elapsed() >= METADATA_TTL);
        let unknown = cache
            .keys
            .as_ref()
            .is_some_and(|keys| keys.find(kid).is_none());
        let refresh_unknown = unknown
            && cache
                .last_unknown_refresh
                .is_none_or(|time| time.elapsed() >= KEY_REFRESH_INTERVAL);
        if stale || refresh_unknown {
            if unknown {
                cache.last_unknown_refresh = Some(Instant::now());
            }
            let keys: JwkSet = self
                .get_json(self.endpoint(discovery.jwks_uri.as_deref().ok_or_else(unavailable)?)?)
                .await?;
            cache.keys = Some(keys);
            cache.fetched = Some(Instant::now());
        }
        let jwk = cache
            .keys
            .as_ref()
            .and_then(|keys| keys.find(kid))
            .ok_or_else(invalid)?;
        let value = serde_json::to_value(jwk).map_err(|_| unavailable())?;
        if value.get("kty").and_then(|v| v.as_str()) != Some("RSA")
            || value
                .get("alg")
                .is_some_and(|v| v.as_str() != Some("RS256"))
            || value.get("use").is_some_and(|v| v.as_str() != Some("sig"))
            || value.get("key_ops").is_some_and(|v| {
                !v.as_array()
                    .is_some_and(|ops| ops.iter().any(|op| op.as_str() == Some("verify")))
            })
        {
            return Err(invalid());
        }
        let key = DecodingKey::from_jwk(jwk).map_err(|_| invalid())?;
        let mut validation = Validation::new(Algorithm::RS256);
        // Expiry is enforced without leeway. `validate_claims` checks `nbf`
        // and `iat` with the bounded clock-skew tolerance.
        validation.leeway = 0;
        validation.validate_nbf = false;
        validation.set_issuer(&[self.config.issuer.as_str()]);
        let client_claim = match profile {
            TokenProfile::Rfc9068 => "client_id",
            TokenProfile::Casdoor => "azp",
        };
        validation.set_required_spec_claims(&[
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "jti",
            client_claim,
        ]);
        let mut audiences = vec![self.config.audience.as_str()];
        audiences.extend(self.config.additional_audiences.iter().map(String::as_str));
        validation.set_audience(&audiences);
        let mut claims = decode::<Claims>(token, &key, &validation)
            .map_err(|_| invalid())?
            .claims;
        self.validate_claims(&claims, true)?;
        let client = match profile {
            TokenProfile::Rfc9068 => claims.client_id.as_ref(),
            TokenProfile::Casdoor => claims.azp.as_ref(),
        };
        if claims.iat.is_none()
            || claims.jti.as_ref().is_none_or(|value| value.is_empty())
            || client.is_none_or(|value| value.is_empty())
            || (profile == TokenProfile::Casdoor
                && claims.casdoor_token_type.as_deref() != Some(CASDOOR_TOKEN_TYPE))
        {
            return Err(invalid());
        }
        if self.config.jwt_scope_claim == "scp" {
            // Only the configured claim grants permissions. Do not merge or
            // fall back to the space-delimited scope claim.
            claims.scope = claims
                .scp
                .as_ref()
                .map(|value| {
                    let values = value.as_array().ok_or_else(invalid)?;
                    let scopes: Result<Vec<&str>> = values
                        .iter()
                        .map(|value| {
                            value
                                .as_str()
                                .filter(|scope| valid_scope(scope))
                                .ok_or_else(invalid)
                        })
                        .collect();
                    Ok::<_, LoadError>(scopes?.join(" "))
                })
                .transpose()?;
        }
        Ok(claims)
    }
}
pub(crate) async fn decode_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T> {
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE as u64)
    {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| unavailable())?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE {
            return Err(unavailable());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| unavailable())
}

// RFC 6749 section 2.3.1 applies form encoding before HTTP Basic encoding.
pub(crate) fn oauth_basic_component(value: &str) -> String {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("", value)
        .finish();
    encoded[1..].to_owned()
}
