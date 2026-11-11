//! Opt-in real-provider acceptance. Run through scripts/test-authelia.py.
use pdf2md_mcp::{
    auth::{AuthConfig, Authenticator, Identity},
    config::Config,
    service::{CallerService, Operation, Response},
    storage::Store,
    workspace::WorkspaceRegistry,
};
use serde_json::Value;
use std::{io::Write, path::Path};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

fn token<'a>(fixture: &'a Value, key: &str) -> &'a str {
    fixture[key]["access_token"].as_str().expect("access token")
}
fn config(fixture: &Value, validation: &str) -> Config {
    let auth: AuthConfig = serde_json::from_value(serde_json::json!({
        "mode": "oauth2",
        "oidc": {
            "issuer": fixture["issuer"], "audience": fixture["audience"],
            "validation": validation, "client_id": fixture["client_id"],
            "jwt_scope_claim": if validation == "jwt" { "scp" } else { "scope" },
            "client_secret": {"file": fixture["secret_file"]},
            "ca_file": fixture["ca_file"],
            "access_token_prefix": if validation == "introspection" { Some("authelia_at_") } else { None }
        }
    }))
    .unwrap();
    Config {
        auth,
        ..Config::default()
    }
}
async fn identity(fixture: &Value, mode: &str, key: &str) -> (String, String) {
    let validator = Authenticator::new(config(fixture, mode).auth)
        .await
        .unwrap();
    match validator
        .authenticate(Some(token(fixture, key)), true)
        .await
        .unwrap()
    {
        Identity::User { issuer, subject } => (issuer, subject),
        Identity::Shared => panic!("OAuth must not become anonymous"),
    }
}
async fn seed(root: &Path, issuer: &str, subject: &str, bytes: &[u8]) -> String {
    let registry = WorkspaceRegistry::open(root).await.unwrap();
    let path = registry
        .resolve_identity(issuer, subject, None)
        .await
        .unwrap();
    let store = Store::open(&path, None).await.unwrap();
    let mut staged = store.staging_file().unwrap();
    staged.write_all(bytes).unwrap();
    store
        .accept(staged.path(), "same-source", "https", None, "same-attempt")
        .await
        .unwrap()
        .document_id
        .unwrap()
}

#[tokio::test]
#[ignore = "requires disposable real Authelia; run scripts/test-authelia.py"]
async fn real_authelia_tokens_enforce_scopes_isolation_revocation_and_expiry() {
    let fixture_path =
        std::env::var("PDF2MD_LIVE_AUTHELIA_FIXTURE").expect("live fixture required");
    let fixture: Value = serde_json::from_slice(&std::fs::read(fixture_path).unwrap()).unwrap();
    let phase = std::env::var("PDF2MD_LIVE_AUTHELIA_PHASE").unwrap_or_default();
    let introspection = Authenticator::new(config(&fixture, "introspection").auth)
        .await
        .unwrap();
    let jwt = Authenticator::new(config(&fixture, "jwt").auth)
        .await
        .unwrap();
    if phase == "expired" {
        let error = jwt
            .authenticate(Some(token(&fixture, "alice_jwt")), false)
            .await
            .unwrap_err();
        assert_eq!(error.code, "auth_invalid");
        assert!(
            introspection
                .authenticate(Some(token(&fixture, "bob_opaque")), false)
                .await
                .is_ok()
        );
        return;
    }
    if phase == "revoked" {
        let error = introspection
            .authenticate(Some(token(&fixture, "alice_opaque")), false)
            .await
            .unwrap_err();
        assert_eq!(error.code, "auth_invalid");
        // Local JWT validation has no immediate revocation guarantee.
        assert!(
            jwt.authenticate(Some(token(&fixture, "alice_jwt")), false)
                .await
                .is_ok()
        );
        return;
    }
    for key in ["alice_opaque", "bob_opaque"] {
        introspection
            .authenticate(Some(token(&fixture, key)), true)
            .await
            .unwrap();
    }
    for key in ["alice_jwt", "bob_jwt"] {
        jwt.authenticate(Some(token(&fixture, key)), true)
            .await
            .unwrap();
    }
    assert!(
        introspection
            .authenticate(Some(token(&fixture, "read_only")), false)
            .await
            .is_ok()
    );
    assert_eq!(
        introspection
            .authenticate(Some(token(&fixture, "read_only")), true)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    assert!(
        jwt.authenticate(Some(token(&fixture, "jwt_read_only")), false)
            .await
            .is_ok()
    );
    assert_eq!(
        jwt.authenticate(Some(token(&fixture, "jwt_read_only")), true)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    for name in ["refresh_token", "id_token"] {
        let value = fixture["alice_opaque"][name]
            .as_str()
            .expect("wrong-token fixture");
        assert_eq!(
            introspection
                .authenticate(Some(value), false)
                .await
                .unwrap_err()
                .code,
            "auth_invalid"
        );
        assert_eq!(
            jwt.authenticate(Some(value), false).await.unwrap_err().code,
            "auth_invalid"
        );
    }
    let alice = identity(&fixture, "introspection", "alice_opaque").await;
    let bob = identity(&fixture, "introspection", "bob_opaque").await;
    assert_ne!(alice.1, bob.1);
    assert_eq!(alice, identity(&fixture, "jwt", "alice_jwt").await);
    assert_eq!(bob, identity(&fixture, "jwt", "bob_jwt").await);
    for (mode, alice_key, bob_key) in [
        ("introspection", "alice_opaque", "bob_opaque"),
        ("jwt", "alice_jwt", "bob_jwt"),
    ] {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let alice_pdf = b"%PDF-1.7\nsynthetic alice\n%%EOF";
        let alice_id = seed(root.path(), &alice.0, &alice.1, alice_pdf).await;
        let bob_id = seed(
            root.path(),
            &bob.0,
            &bob.1,
            b"%PDF-1.7\nsynthetic bob\n%%EOF",
        )
        .await;
        let service = CallerService::new(root.path(), config(&fixture, mode), None)
            .await
            .unwrap();
        let cancel = CancellationToken::new();
        for (key, expected) in [(alice_key, &alice_id), (bob_key, &bob_id)] {
            match service
                .execute(
                    Some(token(&fixture, key)),
                    Operation::History { source: None },
                    &cancel,
                )
                .await
                .unwrap()
            {
                Response::Observations(rows) => {
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0].document_id.as_ref(), Some(expected));
                }
                _ => panic!("expected history"),
            }
        }
        assert!(
            service
                .execute(
                    Some(token(&fixture, bob_key)),
                    Operation::ReadPdf {
                        document_id: alice_id.clone()
                    },
                    &cancel
                )
                .await
                .is_err()
        );
        match service
            .execute(
                Some(token(&fixture, alice_key)),
                Operation::ReadPdf {
                    document_id: alice_id,
                },
                &cancel,
            )
            .await
            .unwrap()
        {
            Response::Pdf(mut stream) => {
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, alice_pdf);
            }
            _ => panic!("expected PDF stream"),
        }
        {
            let read_key = if mode == "introspection" {
                "read_only"
            } else {
                "jwt_read_only"
            };
            let error = service
                .execute(
                    Some(token(&fixture, read_key)),
                    Operation::AcquireHttps {
                        url: "https://example.test/private.pdf".into(),
                    },
                    &cancel,
                )
                .await
                .err()
                .expect("scope denial");
            assert_eq!(error.code, "auth_forbidden");
        }
    }
}
