//! Test-only DPoP proof signer (RFC 9449 section 4.2).
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, EncodingKey,
    jwk::{Jwk, ThumbprintHash},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub struct ProofKey {
    key: EncodingKey,
    pub algorithm: Algorithm,
    /// Public JWK placed in the proof header.
    pub jwk: Value,
}

#[allow(dead_code)]
impl ProofKey {
    pub fn es256() -> Self {
        let pem = rcgen::KeyPair::generate().unwrap().serialize_pem();
        let key = EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
        Self::public(key, Algorithm::ES256)
    }
    pub fn es384() -> Self {
        let pem = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
            .unwrap()
            .serialize_pem();
        let key = EncodingKey::from_ec_pem(pem.as_bytes()).unwrap();
        Self::public(key, Algorithm::ES384)
    }
    pub fn ed25519() -> Self {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let jwk =
            json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(pair.public_key_raw())});
        Self {
            key: EncodingKey::from_ed_pem(pair.serialize_pem().as_bytes()).unwrap(),
            algorithm: Algorithm::EdDSA,
            jwk,
        }
    }
    /// An RSA key from a PKCS#8 PEM, signing with `algorithm`.
    pub fn rsa(pem: &str, algorithm: Algorithm) -> Self {
        Self::public(
            EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
            algorithm,
        )
    }
    fn public(key: EncodingKey, algorithm: Algorithm) -> Self {
        let mut jwk =
            serde_json::to_value(Jwk::from_encoding_key(&key, algorithm).unwrap()).unwrap();
        // Keep only the key parameters, as a client's proof header would.
        jwk.as_object_mut().unwrap().remove("alg");
        Self {
            key,
            algorithm,
            jwk,
        }
    }

    /// RFC 7638 SHA-256 thumbprint, computed by the JWT library.
    pub fn thumbprint(&self) -> String {
        serde_json::from_value::<Jwk>(self.jwk.clone())
            .unwrap()
            .thumbprint(ThumbprintHash::SHA256)
            .unwrap()
    }

    pub fn header(&self) -> Value {
        json!({"typ":"dpop+jwt","alg":format!("{:?}", self.algorithm),"jwk":self.jwk})
    }
    pub fn claims(method: &str, url: &str, access_token: &str) -> Value {
        json!({
            "jti": URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>()),
            "htm": method,
            "htu": url,
            "iat": chrono::Utc::now().timestamp(),
            "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes())),
        })
    }
    /// Sign arbitrary header and claims with this key.
    pub fn sign(&self, header: &Value, claims: &Value) -> String {
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature =
            jsonwebtoken::crypto::sign(message.as_bytes(), &self.key, self.algorithm).unwrap();
        format!("{message}.{signature}")
    }
    /// A fresh, valid proof for one request.
    pub fn proof(&self, method: &str, url: &str, access_token: &str) -> String {
        self.sign(&self.header(), &Self::claims(method, url, access_token))
    }
}
