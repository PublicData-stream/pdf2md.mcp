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

#[path = "common/conversion_pdf.rs"]
mod conversion_pdf;

struct HttpServer {
    service: std::sync::Arc<CallerService>,
    cancel: CancellationToken,
    server: tokio::task::JoinHandle<()>,
    base: String,
    client: reqwest::Client,
}
impl HttpServer {
    async fn start(root: &Path, fixture: &Value, mode: &str) -> Self {
        let service = std::sync::Arc::new(
            CallerService::new(root, config(fixture, mode), None)
                .await
                .unwrap(),
        );
        let cancel = CancellationToken::new();
        let router = pdf2md_mcp::http::router(service.clone(), cancel.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            service,
            cancel,
            server,
            base,
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
        }
    }
    async fn get(&self, path: &str, bearer: Option<&str>) -> reqwest::Response {
        let mut request = self.client.get(format!("{}{path}", self.base));
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        request.send().await.unwrap()
    }
    async fn upload(&self, bearer: &str, pdf: Vec<u8>) -> reqwest::Response {
        self.client
            .post(format!("{}/v1/documents", self.base))
            .bearer_auth(bearer)
            .header("content-type", "application/pdf")
            .body(pdf)
            .send()
            .await
            .unwrap()
    }
    async fn stop(self) {
        self.cancel.cancel();
        self.server.abort();
        let _ = self.server.await;
    }
}
async fn response_json(response: reqwest::Response) -> Value {
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires disposable real Authelia; run scripts/test-authelia.py"]
async fn real_http_provider_tokens_isolate_and_resume_accepted_jobs() {
    use reqwest::StatusCode;
    let fixture_path =
        std::path::PathBuf::from(std::env::var("PDF2MD_LIVE_AUTHELIA_FIXTURE").unwrap());
    let fixture: Value = serde_json::from_slice(&std::fs::read(&fixture_path).unwrap()).unwrap();
    let root = fixture_path.parent().unwrap().join("http-workspaces");
    let metadata = fixture_path.parent().unwrap().join("http-test-state.json");
    let phase = std::env::var("PDF2MD_LIVE_AUTHELIA_PHASE").unwrap_or_default();
    if phase == "expired" {
        let server = HttpServer::start(&root, &fixture, "jwt").await;
        assert_eq!(
            server
                .get("/v1/history", Some(token(&fixture, "alice_jwt")))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        server.stop().await;
        return;
    }
    if phase == "revoked" {
        let state: Value = serde_json::from_slice(&std::fs::read(&metadata).unwrap()).unwrap();
        let job = state["job"].as_str().unwrap();
        let server = HttpServer::start(&root, &fixture, "introspection").await;
        assert_eq!(
            server
                .get(
                    &format!("/v1/jobs/{job}"),
                    Some(token(&fixture, "alice_opaque"))
                )
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            server
                .get("/v1/history", Some(token(&fixture, "bob_opaque")))
                .await
                .status(),
            StatusCode::OK
        );
        let service = server.service.clone();
        let cancel = server.cancel.clone();
        let dispatcher = tokio::spawn(async move {
            service
                .run(
                    Path::new("unused-obscura-worker"),
                    Path::new(env!("CARGO_BIN_EXE_pdf2md-convert-worker")),
                    &cancel,
                )
                .await
                .unwrap()
        });
        // Observe conversion without reauthorizing Alice: accepted work is independent of later token revocation.
        let alice = identity(&fixture, "jwt", "alice_jwt").await;
        let registry = WorkspaceRegistry::open(&root).await.unwrap();
        let workspace = registry
            .resolve_identity(&alice.0, &alice.1, None)
            .await
            .unwrap();
        let attempt = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let history = Store::read_conversion_history(&workspace, None, None)
                    .await
                    .unwrap();
                if let Some(attempt) = history
                    .into_iter()
                    .find(|entry| entry.id == job && entry.status == "succeeded")
                {
                    break attempt;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("accepted conversion did not finish");
        assert_eq!(attempt.status, "succeeded");
        server.cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(5), dispatcher)
            .await
            .unwrap()
            .unwrap();
        server.stop().await;
        let server = HttpServer::start(&root, &fixture, "jwt").await;
        let response = server
            .get(
                &format!("/v1/jobs/{job}"),
                Some(token(&fixture, "alice_jwt")),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["status"], "succeeded");
        server.stop().await;
        return;
    }
    let pdf = conversion_pdf::sample_pdf();
    let server = HttpServer::start(&root, &fixture, "introspection").await;
    assert_eq!(
        server.get("/v1/history", None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    for name in ["id_token", "refresh_token"] {
        assert_eq!(
            server
                .get("/v1/history", fixture["alice_opaque"][name].as_str())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        server
            .upload(token(&fixture, "read_only"), pdf.clone())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let limited = server
        .client
        .post(format!("{}/v1/sources/absent/fetch", server.base))
        .bearer_auth(token(&fixture, "read_write"))
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::FORBIDDEN);
    let full = server
        .client
        .post(format!("{}/v1/sources/absent/fetch", server.base))
        .bearer_auth(token(&fixture, "alice_opaque"))
        .send()
        .await
        .unwrap();
    assert_eq!(full.status(), StatusCode::NOT_FOUND);
    let response = server
        .upload(token(&fixture, "alice_opaque"), pdf.clone())
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let result = response_json(response).await;
    let document = result["observation"]["document_id"].as_str().unwrap();
    let job = result["conversion_job"]["id"].as_str().unwrap();
    assert_eq!(result["conversion_job"]["status"], "queued");
    assert_eq!(
        server
            .get(
                &format!("/v1/documents/{document}/pdf"),
                Some(token(&fixture, "bob_opaque"))
            )
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        server
            .get(
                &format!("/v1/jobs/{job}"),
                Some(token(&fixture, "bob_opaque"))
            )
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let history = server
        .get("/v1/conversions", Some(token(&fixture, "alice_opaque")))
        .await;
    assert_eq!(history.status(), StatusCode::OK);
    assert!(
        response_json(history).await["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["id"] == job)
    );
    let mut bob_pdf = pdf.clone();
    bob_pdf.extend_from_slice(b"\n% bob synthetic document\n");
    let bob = server.upload(token(&fixture, "bob_opaque"), bob_pdf).await;
    assert_eq!(bob.status(), StatusCode::CREATED);
    let bob = response_json(bob).await;
    let bob_document = bob["observation"]["document_id"].as_str().unwrap();
    assert_eq!(
        server
            .get(
                &format!("/v1/documents/{bob_document}/pdf"),
                Some(token(&fixture, "alice_opaque"))
            )
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    std::fs::write(
        &metadata,
        serde_json::to_vec(&serde_json::json!({"job":job})).unwrap(),
    )
    .unwrap();
    server.stop().await;
    let server = HttpServer::start(&root, &fixture, "jwt").await;
    assert_eq!(
        server
            .upload(token(&fixture, "alice_jwt"), pdf.clone())
            .await
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        server
            .get(
                &format!("/v1/documents/{document}/pdf"),
                Some(token(&fixture, "alice_jwt"))
            )
            .await
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        pdf
    );
    assert_eq!(
        server
            .get(&format!("/v1/jobs/{job}"), Some(token(&fixture, "bob_jwt")))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        server
            .get(
                &format!("/v1/documents/{document}/pdf"),
                Some(token(&fixture, "bob_jwt"))
            )
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        server
            .upload(token(&fixture, "jwt_read_only"), pdf.clone())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .get("/v1/conversions", Some(token(&fixture, "alice_jwt")))
            .await
            .status(),
        StatusCode::OK
    );
    server.stop().await;
}
