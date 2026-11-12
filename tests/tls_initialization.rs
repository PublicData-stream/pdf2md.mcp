//! This test runs alone in its process so TLS-server setup cannot mask client initialization.
use pdf2md_mcp::auth::{AuthConfig, Authenticator};

#[tokio::test]
async fn oauth_client_initializes_tls_without_a_prior_server_or_provider() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    let config: AuthConfig = serde_json::from_value(serde_json::json!({
        "mode": "oauth2",
        "oidc": {
            "issuer": "https://issuer.example",
            "audience": "pdf2md-api",
            "validation": "jwt"
        }
    }))
    .unwrap();
    Authenticator::new(config).await.unwrap();
    assert!(rustls::crypto::CryptoProvider::get_default().is_some());
}
