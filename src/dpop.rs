//! DPoP proof validation for sender-constrained access tokens (RFC 9449).
//!
//! A DPoP-bound access token names a public key in its `cnf.jkt`
//! confirmation. Each request then carries a proof JWT signed with the
//! matching private key, so a copied token is useless without that key.
//! RFC 9700 section 2.2.1 recommends such sender-constrained tokens.
//!
//! This module checks one proof against one request. Whether the proven key
//! is the key the access token is bound to is decided in [`crate::auth`],
//! after the token itself has been validated.
use crate::{
    auth::config_error,
    error::{LoadError, Result},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::Jwk};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashSet, VecDeque},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use url::Url;

/// Proof signature algorithms this service accepts, in advertised order.
pub const SIGNING_ALGORITHMS: [&str; 5] = ["ES256", "ES384", "EdDSA", "PS256", "RS256"];
const MAX_PROOF: usize = 8 * 1024;
/// A proof is accepted for this long after its `iat`.
const MAX_AGE_SECS: i64 = 60;
/// Tolerated clock difference between the caller and this service.
const CLOCK_SKEW_SECS: i64 = 30;
/// Proofs remembered for replay detection. At capacity the oldest is dropped.
const REPLAY_CAPACITY: usize = 65_536;

/// A missing, malformed, mismatched or replayed proof.
pub(crate) fn invalid_proof() -> LoadError {
    LoadError::new("auth_dpop_invalid", "a valid DPoP proof is required")
}

/// `[auth.oidc.dpop]`: accept DPoP-bound access tokens.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopConfig {
    /// URL under which callers reach this service, for example
    /// `https://pdf.example.com`. A proof's `htu` must name this origin and
    /// path prefix followed by the request path. It is configured, never
    /// taken from request headers, so a proof made for another host is not
    /// accepted here.
    pub public_url: String,
    /// Refuse access tokens that are not DPoP-bound.
    #[serde(default)]
    pub required: bool,
}
impl DpopConfig {
    fn base(&self) -> Result<Url> {
        let url = Url::parse(&self.public_url).map_err(|_| config_error())?;
        let loopback = match url.host() {
            Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(config_error());
        }
        Ok(url)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.base().map(|_| ())
    }
}

/// The key that signed a verified DPoP proof for one request. It can only be
/// obtained from [`crate::auth::Authenticator::verify_dpop`].
#[derive(Debug)]
pub struct ProvenKey {
    thumbprint: String,
    /// Replay-detection identity of the proof.
    proof: [u8; 32],
    expires: i64,
    /// Set once the proof has been recorded, so that one request may
    /// authorize several operations with the same proof.
    recorded: AtomicBool,
}
impl ProvenKey {
    /// RFC 7638 SHA-256 thumbprint of the proof key (`jkt`).
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }
}

#[derive(Deserialize)]
struct ProofHeader {
    typ: Option<String>,
    alg: Option<String>,
    jwk: Option<serde_json::Map<String, serde_json::Value>>,
}
#[derive(Deserialize)]
struct ProofClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    ath: String,
}

fn member<'a>(jwk: &'a serde_json::Map<String, serde_json::Value>, name: &str) -> Result<&'a str> {
    jwk.get(name)
        .and_then(|value| value.as_str())
        .ok_or_else(invalid_proof)
}
/// Decode a canonical unpadded base64url key parameter.
fn parameter(jwk: &serde_json::Map<String, serde_json::Value>, name: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(member(jwk, name)?)
        .map_err(|_| invalid_proof())
}

/// Check that a public JWK fits `algorithm` and return its RFC 7638 SHA-256
/// thumbprint.
fn thumbprint(
    jwk: &serde_json::Map<String, serde_json::Value>,
    algorithm: Algorithm,
) -> Result<String> {
    // RFC 9449 section 4.3 item 7: the header must not carry a private key.
    if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
        .iter()
        .any(|name| jwk.contains_key(*name))
    {
        return Err(invalid_proof());
    }
    let canonical = match (algorithm, member(jwk, "kty")?) {
        (Algorithm::ES256 | Algorithm::ES384, "EC") => {
            let (curve, size) = if algorithm == Algorithm::ES256 {
                ("P-256", 32)
            } else {
                ("P-384", 48)
            };
            if member(jwk, "crv")? != curve
                || parameter(jwk, "x")?.len() != size
                || parameter(jwk, "y")?.len() != size
            {
                return Err(invalid_proof());
            }
            format!(
                r#"{{"crv":"{curve}","kty":"EC","x":"{}","y":"{}"}}"#,
                member(jwk, "x")?,
                member(jwk, "y")?
            )
        }
        (Algorithm::EdDSA, "OKP") => {
            if member(jwk, "crv")? != "Ed25519" || parameter(jwk, "x")?.len() != 32 {
                return Err(invalid_proof());
            }
            format!(
                r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
                member(jwk, "x")?
            )
        }
        (Algorithm::RS256 | Algorithm::PS256, "RSA") => {
            let modulus = parameter(jwk, "n")?;
            let exponent = parameter(jwk, "e")?;
            // 2048 to 8192 bits, without leading zero octets.
            if !(256..=1024).contains(&modulus.len())
                || modulus[0] == 0
                || exponent.is_empty()
                || exponent.len() > 8
                || exponent[0] == 0
            {
                return Err(invalid_proof());
            }
            format!(
                r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
                member(jwk, "e")?,
                member(jwk, "n")?
            )
        }
        _ => return Err(invalid_proof()),
    };
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

/// RFC 9449 section 4.3 item 9: compare URIs without query and fragment,
/// after scheme, host, default-port and dot-segment normalization.
fn same_target(claimed: &str, expected: &Url) -> bool {
    Url::parse(claimed).is_ok_and(|claimed| {
        claimed.scheme() == expected.scheme()
            && claimed.host() == expected.host()
            && claimed.port_or_known_default() == expected.port_or_known_default()
            && claimed.path() == expected.path()
            && claimed.username().is_empty()
            && claimed.password().is_none()
    })
}

struct Replay {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<([u8; 32], i64)>,
}

/// Verifies DPoP proofs for requests to this service.
pub(crate) struct Verifier {
    base: Url,
    replay: Mutex<Replay>,
}
impl Verifier {
    pub(crate) fn new(config: &DpopConfig) -> Result<Self> {
        Ok(Self {
            base: config.base()?,
            replay: Mutex::new(Replay {
                seen: HashSet::new(),
                order: VecDeque::new(),
            }),
        })
    }

    /// Check the proof sent with a request (RFC 9449 section 4.3). `path` is
    /// the request path without query; `access_token` is the token the
    /// request presents. Replay is checked separately by [`Self::record`].
    pub(crate) fn verify(
        &self,
        proof: &str,
        method: &str,
        path: &str,
        access_token: &str,
    ) -> Result<ProvenKey> {
        self.verify_at(
            proof,
            method,
            path,
            access_token,
            chrono::Utc::now().timestamp(),
        )
    }

    fn verify_at(
        &self,
        proof: &str,
        method: &str,
        path: &str,
        access_token: &str,
        now: i64,
    ) -> Result<ProvenKey> {
        if proof.len() > MAX_PROOF {
            return Err(invalid_proof());
        }
        let header: ProofHeader = proof
            .split('.')
            .next()
            .and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(invalid_proof)?;
        if !header
            .typ
            .as_deref()
            .is_some_and(|typ| typ.eq_ignore_ascii_case("dpop+jwt"))
        {
            return Err(invalid_proof());
        }
        // Only asymmetric algorithms from the fixed list; never `none` or HMAC.
        let algorithm = match header.alg.as_deref() {
            Some("ES256") => Algorithm::ES256,
            Some("ES384") => Algorithm::ES384,
            Some("EdDSA") => Algorithm::EdDSA,
            Some("PS256") => Algorithm::PS256,
            Some("RS256") => Algorithm::RS256,
            _ => return Err(invalid_proof()),
        };
        let jwk = header.jwk.ok_or_else(invalid_proof)?;
        let thumbprint = thumbprint(&jwk, algorithm)?;
        let key = serde_json::from_value::<Jwk>(serde_json::Value::Object(jwk))
            .ok()
            .and_then(|jwk| DecodingKey::from_jwk(&jwk).ok())
            .ok_or_else(invalid_proof)?;
        let mut validation = Validation::new(algorithm);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let claims = jsonwebtoken::decode::<ProofClaims>(proof, &key, &validation)
            .map_err(|_| invalid_proof())?
            .claims;

        let mut expected = self.base.clone();
        expected.set_path(&format!("{}{path}", self.base.path().trim_end_matches('/')));
        let token_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
        if claims.htm != method
            || !same_target(&claims.htu, &expected)
            || claims.iat > now + CLOCK_SKEW_SECS
            || claims.iat < now - MAX_AGE_SECS - CLOCK_SKEW_SECS
            || claims.jti.is_empty()
            || claims.jti.len() > 256
            || claims.ath != token_hash
        {
            return Err(invalid_proof());
        }
        let mut identity = Sha256::new();
        identity.update(thumbprint.as_bytes());
        identity.update([0]);
        identity.update(claims.jti.as_bytes());
        Ok(ProvenKey {
            thumbprint,
            proof: identity.finalize().into(),
            expires: claims.iat + MAX_AGE_SECS + CLOCK_SKEW_SECS,
            recorded: AtomicBool::new(false),
        })
    }

    /// Record a proof as used. A proof that another request already used is
    /// rejected (RFC 9449 section 11.1); the request that recorded it may
    /// authorize further operations.
    pub(crate) fn record(&self, key: &ProvenKey) -> Result<()> {
        if key.recorded.load(Ordering::Acquire) {
            return Ok(());
        }
        let now = chrono::Utc::now().timestamp();
        let mut replay = self.replay.lock().unwrap_or_else(|e| e.into_inner());
        while replay
            .order
            .front()
            .is_some_and(|(_, expires)| *expires < now)
            || replay.order.len() >= REPLAY_CAPACITY
        {
            if let Some((proof, _)) = replay.order.pop_front() {
                replay.seen.remove(&proof);
            }
        }
        if !replay.seen.insert(key.proof) {
            return Err(invalid_proof());
        }
        replay.order.push_back((key.proof, key.expires));
        key.recorded.store(true, Ordering::Release);
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/common/dpop_proof.rs"]
mod proof;

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::Algorithm;
    use serde_json::{Value, json};

    use super::proof::ProofKey;

    const TOKEN: &str = "access-token";
    const URL: &str = "https://pdf.example.com/v1/history";
    const RSA_KEY: &str = include_str!("../tests/common/synthetic-rsa-key.pem");

    fn verifier(public_url: &str) -> Verifier {
        Verifier::new(&DpopConfig {
            public_url: public_url.into(),
            required: false,
        })
        .unwrap()
    }
    fn check(proof: &str) -> Result<ProvenKey> {
        verifier("https://pdf.example.com").verify(proof, "GET", "/v1/history", TOKEN)
    }
    fn rejected(proof: &str) -> bool {
        check(proof).is_err_and(|error| error.code == "auth_dpop_invalid")
    }
    /// A proof whose header and claims were changed before signing.
    fn altered(key: &ProofKey, change: impl FnOnce(&mut Value, &mut Value)) -> String {
        let mut header = key.header();
        let mut claims = ProofKey::claims("GET", URL, TOKEN);
        change(&mut header, &mut claims);
        key.sign(&header, &claims)
    }

    #[test]
    fn valid_proofs_yield_the_rfc7638_thumbprint_for_every_algorithm() {
        for key in [
            ProofKey::es256(),
            ProofKey::es384(),
            ProofKey::ed25519(),
            ProofKey::rsa(RSA_KEY, Algorithm::RS256),
            ProofKey::rsa(RSA_KEY, Algorithm::PS256),
        ] {
            let proven = check(&key.proof("GET", URL, TOKEN)).unwrap();
            assert_eq!(proven.thumbprint(), key.thumbprint(), "{:?}", key.algorithm);
        }
    }

    #[test]
    fn proof_must_match_the_request_method_target_and_token() {
        let key = ProofKey::es256();
        assert!(rejected(&key.proof("POST", URL, TOKEN)));
        assert!(rejected(&key.proof("get", URL, TOKEN)));
        assert!(rejected(&key.proof("GET", URL, "another-token")));
        for other in [
            "https://pdf.example.com/v1/status",
            "https://other.example.com/v1/history",
            "http://pdf.example.com/v1/history",
            "https://pdf.example.com:8443/v1/history",
            "https://user@pdf.example.com/v1/history",
            "/v1/history",
        ] {
            assert!(rejected(&key.proof("GET", other, TOKEN)), "{other}");
        }
        // Query and fragment are ignored; scheme, host and default port are
        // compared after normalization (RFC 9449 section 4.3 item 9).
        for same in [
            "https://pdf.example.com/v1/history?limit=5#top",
            "HTTPS://PDF.EXAMPLE.COM:443/v1/history",
            "https://pdf.example.com/v1/./history",
        ] {
            assert!(check(&key.proof("GET", same, TOKEN)).is_ok(), "{same}");
        }
    }

    #[test]
    fn public_url_path_prefix_is_part_of_the_target() {
        let key = ProofKey::es256();
        let prefixed = verifier("https://example.com/pdf/");
        let verify =
            |url: &str| prefixed.verify(&key.proof("GET", url, TOKEN), "GET", "/v1/history", TOKEN);
        assert!(verify("https://example.com/pdf/v1/history").is_ok());
        assert!(verify("https://example.com/v1/history").is_err());
    }

    #[test]
    fn proof_header_must_be_a_dpop_jwt_with_a_public_asymmetric_key() {
        let key = ProofKey::es256();
        assert!(rejected(
            &altered(&key, |header, _| header["typ"] = json!("JWT"))
        ));
        assert!(rejected(&altered(&key, |header, _| {
            header.as_object_mut().unwrap().remove("typ");
        })));
        assert!(rejected(&altered(&key, |header, _| {
            header.as_object_mut().unwrap().remove("jwk");
        })));
        // A header that discloses private key material is refused.
        assert!(rejected(&altered(&key, |header, _| {
            header["jwk"]["d"] = json!("AAAA")
        })));
        // The key type and curve must fit the algorithm.
        assert!(rejected(&altered(&key, |header, _| {
            header["jwk"]["crv"] = json!("P-384")
        })));
        assert!(rejected(&altered(&key, |header, _| {
            header["alg"] = json!("ES384")
        })));
        // Unsigned and symmetric algorithms are never accepted.
        for algorithm in ["none", "HS256", "RS512"] {
            let mut header = key.header();
            header["alg"] = json!(algorithm);
            let forged = format!(
                "{}.{}.",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(ProofKey::claims("GET", URL, TOKEN).to_string())
            );
            assert!(rejected(&forged), "{algorithm}");
        }
        // The signature must come from the key named in the header.
        let other = ProofKey::es256();
        assert!(rejected(&altered(&key, |header, _| {
            header["jwk"] = other.jwk.clone()
        })));
        assert!(rejected("not-a-jwt"));
        assert!(rejected(&format!("{}.e30.AAAA", "A".repeat(MAX_PROOF))));
    }

    #[test]
    fn proof_claims_are_required_and_bounded_in_time() {
        let key = ProofKey::es256();
        for claim in ["jti", "htm", "htu", "iat", "ath"] {
            assert!(
                rejected(&altered(&key, |_, claims| {
                    claims.as_object_mut().unwrap().remove(claim);
                })),
                "{claim}"
            );
        }
        assert!(rejected(
            &altered(&key, |_, claims| claims["jti"] = json!(""))
        ));
        let now = chrono::Utc::now().timestamp();
        let at = |iat: i64| altered(&key, |_, claims| claims["iat"] = json!(iat));
        assert!(check(&at(now - MAX_AGE_SECS)).is_ok());
        assert!(check(&at(now + CLOCK_SKEW_SECS - 5)).is_ok());
        assert!(rejected(&at(now - MAX_AGE_SECS - CLOCK_SKEW_SECS - 5)));
        assert!(rejected(&at(now + CLOCK_SKEW_SECS + 5)));
    }

    #[test]
    fn a_proof_is_recorded_once_and_rejected_when_replayed() {
        let key = ProofKey::es256();
        let verifier = verifier("https://pdf.example.com");
        let proof = key.proof("GET", URL, TOKEN);
        let first = verifier
            .verify(&proof, "GET", "/v1/history", TOKEN)
            .unwrap();
        verifier.record(&first).unwrap();
        // The same request may authorize several operations.
        verifier.record(&first).unwrap();
        // The same proof in another request is a replay.
        let replayed = verifier
            .verify(&proof, "GET", "/v1/history", TOKEN)
            .unwrap();
        assert_eq!(
            verifier.record(&replayed).unwrap_err().code,
            "auth_dpop_invalid"
        );
        // A fresh proof from the same key is accepted.
        let fresh = verifier
            .verify(&key.proof("GET", URL, TOKEN), "GET", "/v1/history", TOKEN)
            .unwrap();
        verifier.record(&fresh).unwrap();
    }

    #[test]
    fn replay_memory_is_bounded_and_drops_the_oldest_proof() {
        let verifier = verifier("https://pdf.example.com");
        let now = chrono::Utc::now().timestamp();
        let entry = |index: usize| {
            let mut proof = [0u8; 32];
            proof[..8].copy_from_slice(&(index as u64).to_be_bytes());
            ProvenKey {
                thumbprint: String::new(),
                proof,
                expires: now + 60,
                recorded: AtomicBool::new(false),
            }
        };
        for index in 0..REPLAY_CAPACITY {
            verifier.record(&entry(index)).unwrap();
        }
        assert!(verifier.record(&entry(REPLAY_CAPACITY - 1)).is_err());
        verifier.record(&entry(REPLAY_CAPACITY)).unwrap();
        let replay = verifier.replay.lock().unwrap();
        assert_eq!(replay.seen.len(), REPLAY_CAPACITY);
        assert_eq!(replay.order.len(), REPLAY_CAPACITY);
    }

    #[test]
    fn public_url_must_be_an_https_or_loopback_origin_without_query() {
        let valid = |url: &str| {
            DpopConfig {
                public_url: url.into(),
                required: false,
            }
            .validate()
            .is_ok()
        };
        assert!(valid("https://pdf.example.com"));
        assert!(valid("https://example.com/pdf"));
        assert!(valid("http://127.0.0.1:8080"));
        assert!(!valid("http://pdf.example.com"));
        assert!(!valid("https://pdf.example.com/?x=1"));
        assert!(!valid("https://user@pdf.example.com"));
        assert!(!valid("pdf.example.com"));
    }
}
