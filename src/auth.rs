//! Transport-independent OAuth access-token validation.
//!
//! These types do not implement browser login or issue application tokens.
use crate::error::{LoadError, Result};
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

const MAX_RESPONSE: usize = 256 * 1024;
const MAX_TOKEN: usize = 64 * 1024;
const METADATA_TTL: Duration = Duration::from_secs(300);
const KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

fn invalid() -> LoadError {
    LoadError::new(
        "auth_invalid",
        "valid access-token credentials are required",
    )
}
fn forbidden() -> LoadError {
    LoadError::new("auth_forbidden", "operation is not permitted")
}
fn unavailable() -> LoadError {
    LoadError::transient("auth_unavailable", "identity provider is unavailable")
}
fn config_error() -> LoadError {
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
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenValidation {
    #[default]
    Introspection,
    Jwt,
}

fn read_scope() -> String {
    "pdf2md:read".into()
}
fn write_scope() -> String {
    "pdf2md:write".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    #[serde(default)]
    pub validation: TokenValidation,
    /// Optional issuer-documented access-token discriminator for introspection
    /// providers that omit token_type. This never replaces introspection.
    pub access_token_prefix: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<OidcSecret>,
    #[serde(default = "read_scope")]
    pub read_scope: String,
    #[serde(default = "write_scope")]
    pub write_scope: String,
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
    fn validate(&self) -> Result<()> {
        if self.env.is_some() == self.file.is_some()
            || self.env.as_ref().is_some_and(|name| name.is_empty())
        {
            return Err(config_error());
        }
        Ok(())
    }
    fn resolve(&self) -> Result<String> {
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

fn read_file(path: &std::path::Path, max: usize) -> Result<Vec<u8>> {
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

fn https_url(value: &str) -> Result<Url> {
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
fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}
impl AuthConfig {
    pub fn validate(&self) -> Result<()> {
        if self.mode != AuthMode::Oauth2 {
            return if self.oidc.is_none() {
                Ok(())
            } else {
                Err(config_error())
            };
        }
        let oidc = self.oidc.as_ref().ok_or_else(config_error)?;
        https_url(&oidc.issuer)?;
        if oidc.audience.is_empty()
            || !valid_scope(&oidc.read_scope)
            || !valid_scope(&oidc.write_scope)
            || oidc.read_scope == oidc.write_scope
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
            if oidc.client_id.as_ref().is_none_or(|value| value.is_empty()) {
                return Err(config_error());
            }
            oidc.client_secret
                .as_ref()
                .ok_or_else(config_error)?
                .validate()?;
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
}
struct Provider {
    config: OidcConfig,
    client: reqwest::Client,
    secret: Option<String>,
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
        let provider = if config.mode == AuthMode::Oauth2 {
            let oidc = config.oidc.expect("validated OIDC configuration");
            let mut builder = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none());
            if let Some(path) = &oidc.ca_file {
                let bytes = read_file(path, MAX_RESPONSE)?;
                let certificate =
                    reqwest::Certificate::from_pem(&bytes).map_err(|_| config_error())?;
                builder = builder.add_root_certificate(certificate);
            }
            let secret = if oidc.validation == TokenValidation::Introspection {
                Some(
                    oidc.client_secret
                        .as_ref()
                        .expect("validated secret")
                        .resolve()?,
                )
            } else {
                None
            };
            Some(Provider {
                config: oidc,
                client: builder.build().map_err(|_| config_error())?,
                secret,
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
        match self.mode {
            AuthMode::NoneRo if write => Err(forbidden()),
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
    token_type: Option<String>,
    token_use: Option<String>,
    jti: Option<String>,
    client_id: Option<String>,
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
impl Provider {
    fn endpoint(&self, value: &str) -> Result<Url> {
        let url = https_url(value).map_err(|_| unavailable())?;
        let issuer = https_url(&self.config.issuer).map_err(|_| unavailable())?;
        if url.origin() != issuer.origin()
            && !self.config.allowed_endpoint_origins.iter().any(|allowed| {
                Url::parse(allowed).is_ok_and(|allowed| allowed.origin() == url.origin())
            })
        {
            return Err(unavailable());
        }
        Ok(url)
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
        })
    }
    fn validate_claims(&self, claims: &Claims, require_issuer: bool) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        if claims
            .sub
            .as_ref()
            .is_none_or(|sub| sub.is_empty() || sub.len() > 4096)
            || claims
                .aud
                .as_ref()
                .is_none_or(|aud| !aud.contains(&self.config.audience))
            || claims.exp.is_none_or(|exp| exp <= now)
            || claims.nbf.is_some_and(|nbf| nbf > now)
            || claims.iat.is_some_and(|iat| iat > now)
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
        let discovery = self.discovery().await?;
        let response = self
            .client
            .post(
                self.endpoint(
                    discovery
                        .introspection_endpoint
                        .as_deref()
                        .ok_or_else(unavailable)?,
                )?,
            )
            .basic_auth(
                oauth_basic_component(self.config.client_id.as_ref().expect("validated client")),
                Some(oauth_basic_component(
                    self.secret.as_ref().expect("validated secret"),
                )),
            )
            .form(&[("token", token), ("token_type_hint", "access_token")])
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
        if header.alg != Algorithm::RS256
            || !header.typ.as_ref().is_some_and(|typ| {
                typ.eq_ignore_ascii_case("at+jwt") || typ.eq_ignore_ascii_case("application/at+jwt")
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
        validation.leeway = 0;
        validation.validate_nbf = true;
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.set_required_spec_claims(&[
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "jti",
            "client_id",
        ]);
        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|_| invalid())?
            .claims;
        self.validate_claims(&claims, true)?;
        if claims.iat.is_none()
            || claims.jti.as_ref().is_none_or(|value| value.is_empty())
            || claims
                .client_id
                .as_ref()
                .is_none_or(|value| value.is_empty())
        {
            return Err(invalid());
        }
        Ok(claims)
    }
}
async fn decode_response<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
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
fn oauth_basic_component(value: &str) -> String {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("", value)
        .finish();
    encoded[1..].to_owned()
}
