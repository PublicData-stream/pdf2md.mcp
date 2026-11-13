//! Opt-in real-provider acceptance. Run through scripts/test-casdoor.py.
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
fn auth_config(fixture: &Value, validation: &str, client: Option<Value>) -> AuthConfig {
    serde_json::from_value(serde_json::json!({
        "mode": "oauth2",
        "oidc": {
            "issuer": fixture["issuer"], "audience": fixture["audience"],
            "validation": validation, "token_profile": "casdoor",
            // Casdoor binds Implicit and Client Credentials tokens to the client ID.
            "additional_audiences": [fixture["client_id"], fixture["machine_client_id"]],
            "client_id": fixture["client_id"],
            "client_secret": {"file": fixture["secret_file"]},
            "ca_file": fixture["ca_file"]
        },
        "client": client
    }))
    .unwrap()
}
fn config(fixture: &Value, validation: &str) -> Config {
    let auth = auth_config(fixture, validation, None);
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
#[ignore = "requires disposable real Casdoor; run scripts/test-casdoor.py"]
async fn real_casdoor_tokens_enforce_scopes_isolation_revocation_and_expiry() {
    let fixture_path = std::env::var("PDF2MD_LIVE_CASDOOR_FIXTURE").expect("live fixture required");
    let fixture: Value = serde_json::from_slice(&std::fs::read(fixture_path).unwrap()).unwrap();
    let phase = std::env::var("PDF2MD_LIVE_CASDOOR_PHASE").unwrap_or_default();
    let introspection = Authenticator::new(config(&fixture, "introspection").auth)
        .await
        .unwrap();
    let jwt = Authenticator::new(config(&fixture, "jwt").auth)
        .await
        .unwrap();
    if phase == "expired" {
        let error = jwt
            .authenticate(Some(token(&fixture, "short")), false)
            .await
            .unwrap_err();
        assert_eq!(error.code, "auth_invalid");
        assert!(
            introspection
                .authenticate(Some(token(&fixture, "bob")), false)
                .await
                .is_ok()
        );
        return;
    }
    if phase == "revoked" {
        let error = introspection
            .authenticate(Some(token(&fixture, "alice")), false)
            .await
            .unwrap_err();
        assert_eq!(error.code, "auth_invalid");
        // Local JWT validation has no immediate revocation guarantee.
        assert!(
            jwt.authenticate(Some(token(&fixture, "alice")), false)
                .await
                .is_ok()
        );
        return;
    }
    // The short-lived client issues the same user identity until expiry.
    assert_eq!(
        identity(&fixture, "jwt", "short").await,
        identity(&fixture, "jwt", "alice").await
    );
    for key in ["alice", "bob"] {
        introspection
            .authenticate(Some(token(&fixture, key)), true)
            .await
            .unwrap();
    }
    for key in ["alice", "bob"] {
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
        jwt.authenticate(Some(token(&fixture, "read_only")), false)
            .await
            .is_ok()
    );
    assert_eq!(
        jwt.authenticate(Some(token(&fixture, "read_only")), true)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    for name in ["refresh_token", "id_token"] {
        let value = fixture["alice"][name]
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
    let alice = identity(&fixture, "introspection", "alice").await;
    let bob = identity(&fixture, "introspection", "bob").await;
    assert_ne!(alice.1, bob.1);
    assert_eq!(alice, identity(&fixture, "jwt", "alice").await);
    assert_eq!(bob, identity(&fixture, "jwt", "bob").await);
    for (mode, alice_key, bob_key) in [("introspection", "alice", "bob"), ("jwt", "alice", "bob")] {
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
            let read_key = "read_only";
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
#[ignore = "requires disposable real Casdoor; run scripts/test-casdoor.py"]
async fn real_http_provider_tokens_isolate_and_resume_accepted_jobs() {
    use reqwest::StatusCode;
    let fixture_path =
        std::path::PathBuf::from(std::env::var("PDF2MD_LIVE_CASDOOR_FIXTURE").unwrap());
    let fixture: Value = serde_json::from_slice(&std::fs::read(&fixture_path).unwrap()).unwrap();
    let root = fixture_path.parent().unwrap().join("http-workspaces");
    let metadata = fixture_path.parent().unwrap().join("http-test-state.json");
    let phase = std::env::var("PDF2MD_LIVE_CASDOOR_PHASE").unwrap_or_default();
    if phase == "expired" {
        let server = HttpServer::start(&root, &fixture, "jwt").await;
        assert_eq!(
            server
                .get("/v1/history", Some(token(&fixture, "short")))
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
                .get(&format!("/v1/jobs/{job}"), Some(token(&fixture, "alice")))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            server
                .get("/v1/history", Some(token(&fixture, "bob")))
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
        let alice = identity(&fixture, "jwt", "alice").await;
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
            .get(&format!("/v1/jobs/{job}"), Some(token(&fixture, "alice")))
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
                .get("/v1/history", fixture["alice"][name].as_str())
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
        .bearer_auth(token(&fixture, "alice"))
        .send()
        .await
        .unwrap();
    assert_eq!(full.status(), StatusCode::NOT_FOUND);
    let response = server.upload(token(&fixture, "alice"), pdf.clone()).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let result = response_json(response).await;
    let document = result["observation"]["document_id"].as_str().unwrap();
    let job = result["conversion_job"]["id"].as_str().unwrap();
    assert_eq!(result["conversion_job"]["status"], "queued");
    assert_eq!(
        server
            .get(
                &format!("/v1/documents/{document}/pdf"),
                Some(token(&fixture, "bob"))
            )
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        server
            .get(&format!("/v1/jobs/{job}"), Some(token(&fixture, "bob")))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let history = server
        .get("/v1/conversions", Some(token(&fixture, "alice")))
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
    let bob = server.upload(token(&fixture, "bob"), bob_pdf).await;
    assert_eq!(bob.status(), StatusCode::CREATED);
    let bob = response_json(bob).await;
    let bob_document = bob["observation"]["document_id"].as_str().unwrap();
    assert_eq!(
        server
            .get(
                &format!("/v1/documents/{bob_document}/pdf"),
                Some(token(&fixture, "alice"))
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
            .upload(token(&fixture, "alice"), pdf.clone())
            .await
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        server
            .get(
                &format!("/v1/documents/{document}/pdf"),
                Some(token(&fixture, "alice"))
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
            .get(&format!("/v1/jobs/{job}"), Some(token(&fixture, "bob")))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        server
            .get(
                &format!("/v1/documents/{document}/pdf"),
                Some(token(&fixture, "bob"))
            )
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        server
            .upload(token(&fixture, "read_only"), pdf.clone())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .get("/v1/conversions", Some(token(&fixture, "alice")))
            .await
            .status(),
        StatusCode::OK
    );
    server.stop().await;
}

/// Emulate Casdoor's sign-in page for an authorization URL produced by pdf2md.
async fn casdoor_sign_in(fixture: &Value, location: &str, user: &str) -> String {
    let location = url::Url::parse(location).unwrap();
    let query: std::collections::HashMap<String, String> =
        location.query_pairs().into_owned().collect();
    assert!(
        location
            .as_str()
            .starts_with(fixture["issuer"].as_str().unwrap())
    );
    let kind = if query["response_type"] == "code" {
        "code"
    } else {
        "token"
    };
    let mut params = vec![
        ("clientId", query["client_id"].clone()),
        ("responseType", query["response_type"].clone()),
        ("redirectUri", query["redirect_uri"].clone()),
        ("type", kind.to_owned()),
        ("scope", query["scope"].clone()),
        ("state", query["state"].clone()),
        ("nonce", "live-test".to_owned()),
    ];
    for name in ["code_challenge", "code_challenge_method", "resource"] {
        if let Some(value) = query.get(name) {
            params.push((name, value.clone()));
        }
    }
    let response: Value = provider_client(fixture)
        .post(
            url::Url::parse_with_params(
                &format!("{}/api/login", fixture["issuer"].as_str().unwrap()),
                &params,
            )
            .unwrap(),
        )
        .json(&serde_json::json!({
            "application": query["client_id"], "organization": fixture["organization"],
            "username": user, "password": fixture["passwords"][user], "autoSignin": true, "type": kind,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["status"], "ok", "synthetic sign-in failed");
    response["data"].as_str().unwrap().to_owned()
}
fn provider_client(fixture: &Value) -> reqwest::Client {
    let ca = std::fs::read(fixture["ca_file"].as_str().unwrap()).unwrap();
    reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        .no_proxy()
        .build()
        .unwrap()
}
fn textarea(page: &str, id: &str) -> String {
    let start = page.find(&format!("id=\"{id}\"")).expect("token field");
    let value = &page[start..];
    let value = &value[value.find('>').unwrap() + 1..];
    value[..value.find("</textarea>").unwrap()].to_owned()
}
async fn subject(fixture: &Value, bearer: &str) -> String {
    let validator = Authenticator::new(config(fixture, "introspection").auth)
        .await
        .unwrap();
    match validator.authenticate(Some(bearer), false).await.unwrap() {
        Identity::User { subject, .. } => subject,
        Identity::Shared => panic!("OAuth must not become anonymous"),
    }
}

#[tokio::test]
#[ignore = "requires disposable real Casdoor; run scripts/test-casdoor.py"]
async fn real_casdoor_grants_through_the_registered_client() {
    use pdf2md_mcp::oauth::OAuthClient;
    use reqwest::StatusCode;
    let fixture_path = std::env::var("PDF2MD_LIVE_CASDOOR_FIXTURE").expect("live fixture required");
    let fixture: Value = serde_json::from_slice(&std::fs::read(fixture_path).unwrap()).unwrap();
    if !std::env::var("PDF2MD_LIVE_CASDOOR_PHASE")
        .unwrap_or_default()
        .is_empty()
    {
        return;
    }
    let alice = subject(&fixture, token(&fixture, "alice")).await;
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let client = serde_json::json!({
        "client_id": fixture["client_id"], "client_secret": {"file": fixture["secret_file"]},
        "grant_types": ["authorization_code", "implicit", "device_code", "refresh_token"],
        "scopes": ["pdf2md:read", "pdf2md:write"], "redirect_base_url": base,
    });
    let service = std::sync::Arc::new(
        CallerService::new(
            root.path(),
            Config {
                auth: auth_config(&fixture, "introspection", Some(client.clone())),
                ..Config::default()
            },
            None,
        )
        .await
        .unwrap(),
    );
    let cancel = CancellationToken::new();
    let router = pdf2md_mcp::http::router(service, cancel.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let api = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let history = |bearer: String| {
        let api = api.clone();
        let base = base.clone();
        async move {
            api.get(format!("{base}/v1/history"))
                .bearer_auth(bearer)
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    // Authorization Code with PKCE through /oauth/login and /oauth/callback.
    let login = api.get(format!("{base}/oauth/login")).send().await.unwrap();
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let location = login.headers()["location"].to_str().unwrap().to_owned();
    let cookie = login.headers()["set-cookie"].to_str().unwrap();
    let cookie = cookie.split(';').next().unwrap().to_owned();
    let state = url::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let code = casdoor_sign_in(&fixture, &location, "alice").await;
    let page = api
        .get(
            url::Url::parse_with_params(
                &format!("{base}/oauth/callback"),
                &[
                    ("code", code.as_str()),
                    ("state", &state),
                    ("iss", fixture["issuer"].as_str().unwrap()),
                ],
            )
            .unwrap(),
        )
        .header("cookie", cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let page = page.text().await.unwrap();
    let code_access = textarea(&page, "access-token");
    // The refresh token issued to the registered client stays out of the browser.
    assert!(!page.contains("refresh-token"));
    assert_eq!(history(code_access.clone()).await, StatusCode::OK);
    assert_eq!(subject(&fixture, &code_access).await, alice);

    // Implicit: Casdoor binds the token to the client ID, an additional audience.
    let login = api
        .get(format!("{base}/oauth/login?grant=implicit"))
        .send()
        .await
        .unwrap();
    let location = login.headers()["location"].to_str().unwrap().to_owned();
    assert!(location.contains("response_type=token"));
    let implicit = casdoor_sign_in(&fixture, &location, "alice").await;
    assert_eq!(history(implicit.clone()).await, StatusCode::OK);
    assert_eq!(subject(&fixture, &implicit).await, alice);
    let page = api
        .get(format!("{base}/oauth/implicit"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);

    // Device and refresh grants are not brokered over HTTP: the registered
    // client's credentials are not applied to a caller-supplied grant.
    let grant = "urn:ietf:params:oauth:grant-type:device_code";
    assert_eq!(
        api.post(format!("{base}/oauth/device"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    for body in [
        serde_json::json!({"grant_type": grant, "device_code": "device"}),
        serde_json::json!({"grant_type": "refresh_token", "refresh_token": "refresh"}),
    ] {
        assert_eq!(
            api.post(format!("{base}/oauth/token"))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    let registered = OAuthClient::new(&auth_config(&fixture, "introspection", Some(client)))
        .unwrap()
        .unwrap();

    // Device Authorization through the trusted client: start, observe
    // pending, approve as Bob, then poll.
    let device = registered.device_authorization().await.unwrap();
    assert_eq!(
        registered
            .poll_device(&device.device_code)
            .await
            .unwrap_err()
            .code,
        "oauth_authorization_pending"
    );
    let approved: Value = provider_client(&fixture)
        .post(format!("{}/api/login", fixture["issuer"].as_str().unwrap()))
        .bearer_auth(token(&fixture, "bob"))
        .json(&serde_json::json!({
            "application": fixture["client_id"], "organization": fixture["organization"],
            "type": "device", "userCode": device.user_code,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(approved["status"], "ok");
    let device_access = registered
        .poll_device(&device.device_code)
        .await
        .unwrap()
        .access_token;
    assert_eq!(history(device_access.clone()).await, StatusCode::OK);
    assert_eq!(
        subject(&fixture, &device_access).await,
        subject(&fixture, token(&fixture, "bob")).await
    );

    // Refresh Token through the trusted client. Casdoor rotates refresh
    // tokens by default.
    let request = registered
        .authorization_request(pdf2md_mcp::oauth::GrantType::AuthorizationCode)
        .await
        .unwrap();
    let code = casdoor_sign_in(&fixture, request.url.as_str(), "alice").await;
    let code_refresh = registered
        .exchange_code(&code, request.code_verifier.as_deref().unwrap())
        .await
        .unwrap()
        .refresh_token
        .expect("Authorization Code grant issues a refresh token");
    let refreshed = registered.refresh(&code_refresh).await.unwrap();
    assert_eq!(
        history(refreshed.access_token.clone()).await,
        StatusCode::OK
    );
    assert_eq!(subject(&fixture, &refreshed.access_token).await, alice);
    assert_eq!(
        registered.refresh(&code_refresh).await.unwrap_err().code,
        "oauth_invalid_grant"
    );

    // Client Credentials: an application identity with its own workspace.
    let machine = auth_config(
        &fixture,
        "jwt",
        Some(serde_json::json!({
            "client_id": fixture["machine_client_id"],
            "client_secret": {"file": fixture["secret_file"]},
            "grant_types": ["client_credentials"],
            "scopes": ["pdf2md:read", "pdf2md:write"],
        })),
    );
    let machine_token = OAuthClient::new(&machine)
        .unwrap()
        .unwrap()
        .client_credentials()
        .await
        .unwrap();
    assert_eq!(
        history(machine_token.access_token.clone()).await,
        StatusCode::OK
    );
    let machine_subject = subject(&fixture, &machine_token.access_token).await;
    assert_ne!(machine_subject, alice);
    cancel.cancel();
    server.abort();
}
