//! Registered OAuth 2.0 client for obtaining caller access tokens.
//!
//! The service remains a resource server: [`crate::auth`] validates every
//! access token independently of how it was obtained. This optional client
//! drives the provider's grants on behalf of callers: Authorization Code with
//! PKCE (RFC 6749 section 4.1, RFC 7636), Implicit (section 4.2), Client
//! Credentials (section 4.4), Device Authorization (RFC 8628), and Refresh
//! Token (section 6). The Resource Owner Password Credentials grant is
//! intentionally unsupported: the service never handles user passwords.
use crate::{
    auth::{
        AuthConfig, AuthMode, MAX_RESPONSE, MAX_TOKEN, OidcConfig, OidcSecret, config_error,
        oauth_basic_component, provider_client, provider_endpoint, unavailable, valid_scope,
    },
    error::{LoadError, Result},
};
use base64::Engine;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use url::Url;

const METADATA_TTL: Duration = Duration::from_secs(300);
const MAX_SCOPES: usize = 32;
/// Path of the Authorization Code redirect endpoint below `redirect_base_url`.
pub const CODE_CALLBACK_PATH: &str = "/oauth/callback";
/// Path of the Implicit redirect page below `redirect_base_url`.
pub const IMPLICIT_CALLBACK_PATH: &str = "/oauth/implicit";
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Grants this client can drive. ROPC (`password`) is deliberately absent and
/// is rejected as an unknown configuration value.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    Implicit,
    ClientCredentials,
    DeviceCode,
    RefreshToken,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthClientConfig {
    pub client_id: String,
    /// Omit for a public client. Required for `client_credentials`.
    pub client_secret: Option<OidcSecret>,
    pub grant_types: Vec<GrantType>,
    pub scopes: Vec<String>,
    /// Public origin of this service; required for browser grants.
    pub redirect_base_url: Option<String>,
    /// RFC 8707 resource indicator. Defaults to `[auth.oidc] audience`.
    pub resource: Option<String>,
}

fn loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

fn redirect_base(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| config_error())?;
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && loopback(&url));
    if !scheme_ok
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(config_error());
    }
    Ok(url)
}

impl OAuthClientConfig {
    pub(crate) fn validate(&self, oidc: &OidcConfig) -> Result<()> {
        let mut grants = std::collections::HashSet::new();
        if self.client_id.is_empty()
            || self.client_id.len() > 256
            || self.client_id.bytes().any(|b| b.is_ascii_control())
            || self.grant_types.is_empty()
            || !self.grant_types.iter().all(|grant| grants.insert(*grant))
            || self.scopes.is_empty()
            || self.scopes.len() > MAX_SCOPES
            || !self.scopes.iter().all(|scope| valid_scope(scope))
            || (self.grant_types.contains(&GrantType::ClientCredentials)
                && self.client_secret.is_none())
        {
            return Err(config_error());
        }
        if let Some(secret) = &self.client_secret {
            secret.validate()?;
        }
        let browser = self.grant_types.contains(&GrantType::AuthorizationCode)
            || self.grant_types.contains(&GrantType::Implicit);
        match &self.redirect_base_url {
            Some(value) => {
                redirect_base(value)?;
            }
            None if browser => return Err(config_error()),
            None => {}
        }
        let resource = self.resource.as_deref().unwrap_or(&oidc.audience);
        let parsed = Url::parse(resource).map_err(|_| config_error())?;
        // RFC 8707 section 2: any absolute URI without a fragment, such as a URN.
        if parsed.fragment().is_some() {
            return Err(config_error());
        }
        Ok(())
    }
}

/// Token endpoint result. Debug output never includes token values.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}
impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// RFC 8628 section 3.2 response. `device_code` is a credential.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    #[serde(default = "default_interval")]
    pub interval: u64,
}
fn default_interval() -> u64 {
    5
}
impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthorization")
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

/// A browser authorization request. Keep `state` and `code_verifier` private
/// to the user agent's session until the redirect returns.
pub struct AuthorizationRequest {
    pub url: Url,
    pub state: String,
    pub code_verifier: Option<String>,
}

#[derive(Deserialize, Clone)]
struct Metadata {
    issuer: String,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
}

pub struct OAuthClient {
    oidc: OidcConfig,
    config: OAuthClientConfig,
    http: reqwest::Client,
    secret: Option<String>,
    metadata: Mutex<Option<(Metadata, Instant)>>,
}

/// Random URL-safe value with 256 bits of entropy.
pub fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// RFC 7636 S256 code challenge.
pub fn code_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn valid_token_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN
        && !value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
}

fn oauth_error(code: &str) -> LoadError {
    match code {
        "authorization_pending" => LoadError::transient(
            "oauth_authorization_pending",
            "the user has not completed authorization yet",
        ),
        "slow_down" => {
            LoadError::transient("oauth_slow_down", "poll the token endpoint less often")
        }
        "access_denied" => LoadError::new("oauth_access_denied", "authorization was denied"),
        "expired_token" => LoadError::new("oauth_expired_token", "the device code has expired"),
        "invalid_grant" => LoadError::new(
            "oauth_invalid_grant",
            "the grant is invalid, expired, revoked or already used",
        ),
        "invalid_client" | "unauthorized_client" => LoadError::new(
            "oauth_client_rejected",
            "the provider rejected the registered client",
        ),
        "invalid_scope" => {
            LoadError::new("oauth_invalid_scope", "the provider rejected the scopes")
        }
        "invalid_target" => LoadError::new(
            "oauth_invalid_target",
            "the provider rejected the resource indicator",
        ),
        _ => LoadError::new("oauth_error", "the provider rejected the request"),
    }
}

/// Map an authorization-endpoint error parameter to a fixed public error.
pub fn authorization_error(code: &str) -> LoadError {
    match code {
        "access_denied" => LoadError::new("oauth_access_denied", "authorization was denied"),
        _ => LoadError::new(
            "oauth_error",
            "the provider rejected the authorization request",
        ),
    }
}

impl OAuthClient {
    /// Returns `None` unless OAuth2 mode configures `[auth.client]`.
    pub fn new(auth: &AuthConfig) -> Result<Option<Self>> {
        if auth.mode != AuthMode::Oauth2 {
            return Ok(None);
        }
        let (Some(oidc), Some(config)) = (auth.oidc.clone(), auth.client.clone()) else {
            return Ok(None);
        };
        config.validate(&oidc)?;
        let secret = config
            .client_secret
            .as_ref()
            .map(OidcSecret::resolve)
            .transpose()?;
        Ok(Some(Self {
            http: provider_client(&oidc)?,
            oidc,
            config,
            secret,
            metadata: Mutex::new(None),
        }))
    }

    pub fn enabled(&self, grant: GrantType) -> bool {
        self.config.grant_types.contains(&grant)
    }
    pub fn issuer(&self) -> &str {
        &self.oidc.issuer
    }
    pub fn scope(&self) -> String {
        self.config.scopes.join(" ")
    }
    fn resource(&self) -> &str {
        self.config
            .resource
            .as_deref()
            .unwrap_or(&self.oidc.audience)
    }
    /// Whether redirect cookies must carry the `Secure` attribute.
    pub fn secure_redirects(&self) -> bool {
        self.config
            .redirect_base_url
            .as_deref()
            .is_some_and(|value| value.starts_with("https:"))
    }
    pub fn redirect_uri(&self, grant: GrantType) -> Result<String> {
        let base = self
            .config
            .redirect_base_url
            .as_deref()
            .ok_or_else(config_error)?;
        let path = match grant {
            GrantType::AuthorizationCode => CODE_CALLBACK_PATH,
            GrantType::Implicit => IMPLICIT_CALLBACK_PATH,
            _ => return Err(config_error()),
        };
        Ok(format!("{}{path}", base.trim_end_matches('/')))
    }

    fn require(&self, grant: GrantType) -> Result<()> {
        if self.enabled(grant) {
            Ok(())
        } else {
            Err(LoadError::new(
                "oauth_grant_disabled",
                "this grant type is not enabled",
            ))
        }
    }

    async fn metadata(&self) -> Result<Metadata> {
        let mut cached = self.metadata.lock().await;
        if cached
            .as_ref()
            .is_none_or(|(_, fetched)| fetched.elapsed() >= METADATA_TTL)
        {
            let url = provider_endpoint(
                &self.oidc,
                &format!(
                    "{}/.well-known/openid-configuration",
                    self.oidc.issuer.trim_end_matches('/')
                ),
            )?;
            let response = self.http.get(url).send().await.map_err(|_| unavailable())?;
            let metadata: Metadata = crate::auth::decode_response(response).await?;
            if metadata.issuer != self.oidc.issuer {
                return Err(unavailable());
            }
            *cached = Some((metadata, Instant::now()));
        }
        Ok(cached.as_ref().expect("metadata cached").0.clone())
    }

    fn endpoint(&self, value: Option<&str>) -> Result<Url> {
        provider_endpoint(&self.oidc, value.ok_or_else(unavailable)?)
    }

    /// Build an Authorization Code (with PKCE S256) or Implicit request.
    pub async fn authorization_request(&self, grant: GrantType) -> Result<AuthorizationRequest> {
        self.require(grant)?;
        let metadata = self.metadata().await?;
        let mut url = self.endpoint(metadata.authorization_endpoint.as_deref())?;
        let state = random_token();
        let redirect_uri = self.redirect_uri(grant)?;
        let scope = self.scope();
        let code_verifier = (grant == GrantType::AuthorizationCode).then(random_token);
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("client_id", &self.config.client_id)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair(
                    "response_type",
                    if code_verifier.is_some() {
                        "code"
                    } else {
                        "token"
                    },
                )
                .append_pair("scope", &scope)
                .append_pair("state", &state)
                .append_pair("resource", self.resource());
            if let Some(verifier) = &code_verifier {
                query
                    .append_pair("code_challenge", &code_challenge(verifier))
                    .append_pair("code_challenge_method", "S256");
            }
        }
        Ok(AuthorizationRequest {
            url,
            state,
            code_verifier,
        })
    }

    /// RFC 9207: a present `iss` must match; providers that advertise the
    /// parameter must send it.
    pub async fn check_response_issuer(&self, iss: Option<&str>) -> Result<()> {
        let mismatch =
            || LoadError::new("oauth_issuer_mismatch", "unexpected authorization issuer");
        match iss {
            Some(value) if value == self.oidc.issuer => Ok(()),
            Some(_) => Err(mismatch()),
            None if self
                .metadata()
                .await?
                .authorization_response_iss_parameter_supported =>
            {
                Err(mismatch())
            }
            None => Ok(()),
        }
    }

    async fn token_request(&self, mut form: Vec<(&str, String)>) -> Result<TokenResponse> {
        let metadata = self.metadata().await?;
        let url = self.endpoint(metadata.token_endpoint.as_deref())?;
        let response = self.post(url, &mut form).await?;
        let token: TokenResponse = read_oauth(response).await?;
        if !valid_token_value(&token.access_token)
            || !token.token_type.eq_ignore_ascii_case("bearer")
            || token
                .refresh_token
                .as_deref()
                .is_some_and(|value| !valid_token_value(value))
        {
            return Err(unavailable());
        }
        Ok(token)
    }

    async fn post(&self, url: Url, form: &mut Vec<(&str, String)>) -> Result<reqwest::Response> {
        let mut request = self.http.post(url).header("accept", "application/json");
        match &self.secret {
            // RFC 6749 section 2.3.1 client_secret_basic.
            Some(secret) => {
                request = request.basic_auth(
                    oauth_basic_component(&self.config.client_id),
                    Some(oauth_basic_component(secret)),
                );
            }
            None => form.push(("client_id", self.config.client_id.clone())),
        }
        request.form(form).send().await.map_err(|_| unavailable())
    }

    /// Exchange an authorization code with its PKCE verifier.
    pub async fn exchange_code(&self, code: &str, code_verifier: &str) -> Result<TokenResponse> {
        self.require(GrantType::AuthorizationCode)?;
        if code.is_empty() || code.len() > 4096 {
            return Err(oauth_error("invalid_grant"));
        }
        self.token_request(vec![
            ("grant_type", "authorization_code".into()),
            ("code", code.into()),
            (
                "redirect_uri",
                self.redirect_uri(GrantType::AuthorizationCode)?,
            ),
            ("code_verifier", code_verifier.into()),
            ("resource", self.resource().into()),
        ])
        .await
    }

    /// Obtain an application token with the client's own credentials.
    pub async fn client_credentials(&self) -> Result<TokenResponse> {
        self.require(GrantType::ClientCredentials)?;
        self.token_request(vec![
            ("grant_type", "client_credentials".into()),
            ("scope", self.scope()),
            ("resource", self.resource().into()),
        ])
        .await
    }

    /// Start RFC 8628 device authorization.
    pub async fn device_authorization(&self) -> Result<DeviceAuthorization> {
        self.require(GrantType::DeviceCode)?;
        let metadata = self.metadata().await?;
        let url = self.endpoint(metadata.device_authorization_endpoint.as_deref())?;
        let mut form = vec![
            ("scope", self.scope()),
            ("resource", self.resource().into()),
        ];
        // RFC 8628 section 3.1 identifies the client in the request body; some
        // providers read it only from there even when the client authenticates.
        if self.secret.is_some() {
            form.push(("client_id", self.config.client_id.clone()));
        }
        let response = self.post(url, &mut form).await?;
        let device: DeviceAuthorization = read_oauth(response).await?;
        let verification = Url::parse(&device.verification_uri).map_err(|_| unavailable())?;
        if !valid_token_value(&device.device_code)
            || device.user_code.is_empty()
            || device.user_code.len() > 256
            || verification.scheme() != "https"
            || device.expires_in == 0
            || device.interval > 3600
        {
            return Err(unavailable());
        }
        Ok(device)
    }

    /// Poll once for a device-code token (RFC 8628 section 3.4).
    pub async fn poll_device(&self, device_code: &str) -> Result<TokenResponse> {
        self.require(GrantType::DeviceCode)?;
        if !valid_token_value(device_code) {
            return Err(oauth_error("invalid_grant"));
        }
        self.token_request(vec![
            ("grant_type", DEVICE_CODE_GRANT.into()),
            ("device_code", device_code.into()),
            ("resource", self.resource().into()),
        ])
        .await
    }

    /// Poll until the user approves, denies or the device code expires,
    /// honoring the provider interval and `slow_down` (RFC 8628 section 3.5).
    pub async fn wait_for_device(&self, device: &DeviceAuthorization) -> Result<TokenResponse> {
        let deadline = Instant::now() + Duration::from_secs(device.expires_in);
        let mut interval = Duration::from_secs(device.interval.max(1));
        loop {
            // Never wait past the device code's lifetime to report expiry.
            let remaining = deadline.saturating_duration_since(Instant::now());
            tokio::time::sleep(interval.min(remaining)).await;
            if Instant::now() >= deadline {
                return Err(oauth_error("expired_token"));
            }
            match self.poll_device(&device.device_code).await {
                Err(error) if error.code == "oauth_authorization_pending" => {}
                Err(error) if error.code == "oauth_slow_down" => {
                    interval += Duration::from_secs(5);
                }
                result => return result,
            }
        }
    }

    /// Exchange a refresh token. Providers may rotate it; store the new value.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse> {
        self.require(GrantType::RefreshToken)?;
        if !valid_token_value(refresh_token) {
            return Err(oauth_error("invalid_grant"));
        }
        self.token_request(vec![
            ("grant_type", "refresh_token".into()),
            ("refresh_token", refresh_token.into()),
            ("resource", self.resource().into()),
        ])
        .await
    }
}

/// Read a bounded OAuth JSON response. Error bodies are reduced to a fixed
/// public code; provider descriptions are never surfaced.
async fn read_oauth<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    if response
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
    if status.is_success() {
        return serde_json::from_slice(&bytes).map_err(|_| unavailable());
    }
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
    }
    if status.is_client_error()
        && let Ok(body) = serde_json::from_slice::<ErrorBody>(&bytes)
    {
        return Err(oauth_error(&body.error));
    }
    Err(unavailable())
}

/// Check that a redirect base URL parses; exposed for configuration tests.
pub fn valid_redirect_base_url(value: &str) -> bool {
    redirect_base(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc7636_appendix_b() {
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn random_tokens_are_unique_url_safe_values() {
        let first = random_token();
        assert_eq!(first.len(), 43);
        assert!(
            first
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_ne!(first, random_token());
    }

    #[test]
    fn redirect_base_requires_https_or_loopback_http_origin() {
        assert!(valid_redirect_base_url("https://pdf.example.com"));
        assert!(valid_redirect_base_url("http://127.0.0.1:8080/"));
        assert!(valid_redirect_base_url("http://localhost:8080"));
        assert!(!valid_redirect_base_url("http://pdf.example.com"));
        assert!(!valid_redirect_base_url("https://pdf.example.com/app"));
        assert!(!valid_redirect_base_url("https://user@pdf.example.com"));
        assert!(!valid_redirect_base_url("https://pdf.example.com/?x=1"));
    }

    #[test]
    fn provider_errors_map_to_fixed_public_codes() {
        assert_eq!(
            oauth_error("authorization_pending").code,
            "oauth_authorization_pending"
        );
        assert!(oauth_error("slow_down").retryable);
        assert_eq!(oauth_error("invalid_grant").code, "oauth_invalid_grant");
        assert_eq!(oauth_error("something else").code, "oauth_error");
    }
}
