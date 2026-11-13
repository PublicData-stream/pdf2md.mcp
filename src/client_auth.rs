//! Client authentication for requests this service sends to the provider.
//!
//! A confidential client authenticates either with a shared secret
//! (`client_secret_basic`, RFC 6749 section 2.3.1) or with a signed assertion
//! (`private_key_jwt`, RFC 7523 section 2.2). RFC 9700 section 2.5 recommends
//! the asymmetric method: the provider then stores only a public key.
use crate::{
    auth::{OidcSecret, config_error, oauth_basic_component, unavailable},
    error::Result,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::fmt;

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// Assertion lifetime in seconds. Each request signs a fresh assertion.
const ASSERTION_TTL_SECS: i64 = 60;

/// Signature algorithms for `private_key_jwt`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum AssertionAlgorithm {
    RS256,
    PS256,
    ES256,
    ES384,
    EdDSA,
}

/// `private_key_jwt` configuration (RFC 7523 section 2.2).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientAssertionConfig {
    /// PEM private key in PKCS#8 form. RSA keys may also use PKCS#1.
    pub key: OidcSecret,
    pub algorithm: AssertionAlgorithm,
    /// Optional `kid` header that names the key at the provider.
    pub key_id: Option<String>,
    /// `iss` claim. Defaults to the client ID, as RFC 7523 section 3 requires;
    /// set it only for a provider that expects another value.
    pub issuer: Option<String>,
}

fn printable(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.bytes().any(|b| b.is_ascii_control())
}

impl ClientAssertionConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        self.key.validate()?;
        if self.key_id.as_deref().is_some_and(|v| !printable(v, 256))
            || self.issuer.as_deref().is_some_and(|v| !printable(v, 2048))
        {
            return Err(config_error());
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    jti: String,
    iat: i64,
    exp: i64,
}

/// Loaded signing key for `private_key_jwt`. Debug output omits the key.
pub(crate) struct ClientAssertion {
    key: EncodingKey,
    header: Header,
    issuer: Option<String>,
}
impl fmt::Debug for ClientAssertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientAssertion([redacted])")
    }
}
impl ClientAssertion {
    fn load(config: &ClientAssertionConfig) -> Result<Self> {
        config.validate()?;
        let pem = config.key.resolve()?;
        let pem = pem.as_bytes();
        let (algorithm, key) = match config.algorithm {
            AssertionAlgorithm::RS256 => (Algorithm::RS256, EncodingKey::from_rsa_pem(pem)),
            AssertionAlgorithm::PS256 => (Algorithm::PS256, EncodingKey::from_rsa_pem(pem)),
            AssertionAlgorithm::ES256 => (Algorithm::ES256, EncodingKey::from_ec_pem(pem)),
            AssertionAlgorithm::ES384 => (Algorithm::ES384, EncodingKey::from_ec_pem(pem)),
            AssertionAlgorithm::EdDSA => (Algorithm::EdDSA, EncodingKey::from_ed_pem(pem)),
        };
        let key = key.map_err(|_| config_error())?;
        let mut header = Header::new(algorithm);
        header.kid = config.key_id.clone();
        let assertion = Self {
            key,
            header,
            issuer: config.issuer.clone(),
        };
        // Reject a key that does not fit the algorithm at startup rather than
        // on the first provider request.
        assertion
            .sign("client", "https://provider.invalid/token")
            .map_err(|_| config_error())?;
        Ok(assertion)
    }

    /// Sign a single-use assertion for the provider's token endpoint.
    fn sign(&self, client_id: &str, audience: &str) -> Result<String> {
        let now = chrono::Utc::now().timestamp();
        let claims = AssertionClaims {
            iss: self.issuer.as_deref().unwrap_or(client_id),
            sub: client_id,
            aud: audience,
            jti: crate::oauth::random_token(),
            iat: now,
            exp: now + ASSERTION_TTL_SECS,
        };
        jsonwebtoken::encode(&self.header, &claims, &self.key).map_err(|_| unavailable())
    }
}

/// How this service authenticates to the provider as a registered client.
#[derive(Debug)]
pub(crate) enum ClientAuth {
    /// Public client: identified by `client_id` only.
    Public,
    /// `client_secret_basic`.
    Secret(String),
    /// `private_key_jwt`.
    Assertion(Box<ClientAssertion>),
}
impl ClientAuth {
    /// Load the configured method. A client has at most one credential.
    pub(crate) fn load(
        secret: Option<&OidcSecret>,
        assertion: Option<&ClientAssertionConfig>,
    ) -> Result<Self> {
        match (secret, assertion) {
            (Some(_), Some(_)) => Err(config_error()),
            (Some(secret), None) => Ok(Self::Secret(secret.resolve()?)),
            (None, Some(assertion)) => {
                Ok(Self::Assertion(Box::new(ClientAssertion::load(assertion)?)))
            }
            (None, None) => Ok(Self::Public),
        }
    }

    /// Whether the client proves its identity to the provider.
    pub(crate) fn confidential(&self) -> bool {
        !matches!(self, Self::Public)
    }

    /// Add client authentication to a form request. `token_endpoint` is the
    /// provider's token endpoint URL, the audience of a signed assertion.
    pub(crate) fn apply(
        &self,
        request: reqwest::RequestBuilder,
        form: &mut Vec<(&'static str, String)>,
        client_id: &str,
        token_endpoint: &str,
    ) -> Result<reqwest::RequestBuilder> {
        Ok(match self {
            Self::Public => {
                form.push(("client_id", client_id.to_owned()));
                request
            }
            Self::Secret(secret) => request.basic_auth(
                oauth_basic_component(client_id),
                Some(oauth_basic_component(secret)),
            ),
            Self::Assertion(assertion) => {
                form.push(("client_id", client_id.to_owned()));
                form.push(("client_assertion_type", ASSERTION_TYPE.to_owned()));
                form.push((
                    "client_assertion",
                    assertion.sign(client_id, token_endpoint)?,
                ));
                request
            }
        })
    }
}
