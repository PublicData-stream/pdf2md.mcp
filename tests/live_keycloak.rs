//! Opt-in real-provider acceptance. Run through scripts/test-keycloak.py.
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
            "validation": validation, "token_profile": "keycloak",
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
#[ignore = "requires disposable real Keycloak; run scripts/test-keycloak.py"]
async fn real_keycloak_tokens_enforce_scopes_isolation_revocation_and_expiry() {
    let fixture_path =
        std::env::var("PDF2MD_LIVE_KEYCLOAK_FIXTURE").expect("live fixture required");
    let fixture: Value = serde_json::from_slice(&std::fs::read(fixture_path).unwrap()).unwrap();
    let phase = std::env::var("PDF2MD_LIVE_KEYCLOAK_PHASE").unwrap_or_default();
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
#[ignore = "requires disposable real Keycloak; run scripts/test-keycloak.py"]
async fn real_http_provider_tokens_isolate_and_resume_accepted_jobs() {
    use reqwest::StatusCode;
    let fixture_path =
        std::path::PathBuf::from(std::env::var("PDF2MD_LIVE_KEYCLOAK_FIXTURE").unwrap());
    let fixture: Value = serde_json::from_slice(&std::fs::read(&fixture_path).unwrap()).unwrap();
    let root = fixture_path.parent().unwrap().join("http-workspaces");
    let metadata = fixture_path.parent().unwrap().join("http-test-state.json");
    let phase = std::env::var("PDF2MD_LIVE_KEYCLOAK_PHASE").unwrap_or_default();
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

/// Test-only automation of Keycloak's sign-in and consent pages: a cookie
/// jar, redirects within the provider, and HTML form submission.
struct ProviderBrowser {
    client: reqwest::Client,
    origin: url::Origin,
    cookies: std::collections::BTreeMap<String, String>,
}
enum Step {
    Page(url::Url, String),
    /// A redirect that leaves the provider, for example to the client.
    Left(url::Url),
}
impl ProviderBrowser {
    fn new(fixture: &Value) -> Self {
        let ca = std::fs::read(fixture["ca_file"].as_str().unwrap()).unwrap();
        Self {
            client: reqwest::Client::builder()
                .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .unwrap(),
            origin: url::Url::parse(fixture["issuer"].as_str().unwrap())
                .unwrap()
                .origin(),
            cookies: Default::default(),
        }
    }
    async fn browse(&mut self, mut url: url::Url, mut form: Option<Vec<(String, String)>>) -> Step {
        for _ in 0..10 {
            assert_eq!(url.origin(), self.origin, "left the provider unexpectedly");
            let cookie = self
                .cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            let request = match form.take() {
                Some(fields) => self.client.post(url.clone()).form(&fields),
                None => self.client.get(url.clone()),
            };
            let response = request.header("cookie", cookie).send().await.unwrap();
            for value in response.headers().get_all("set-cookie") {
                let pair = value.to_str().unwrap().split(';').next().unwrap();
                if let Some((name, value)) = pair.split_once('=') {
                    self.cookies.insert(name.trim().into(), value.into());
                }
            }
            if response.status().is_redirection() {
                let location = response.headers()["location"].to_str().unwrap();
                url = url.join(location).unwrap();
                if url.origin() != self.origin {
                    return Step::Left(url);
                }
                continue;
            }
            assert_eq!(response.status(), reqwest::StatusCode::OK, "provider page");
            return Step::Page(url, response.text().await.unwrap());
        }
        panic!("provider redirected too often");
    }
    /// Submit the sign-in form, and the consent form when the provider asks.
    async fn sign_in(&mut self, mut step: Step, fixture: &Value, user: &str) -> Step {
        let password = fixture["passwords"][user].as_str().unwrap();
        for fields in [
            vec![("username", user), ("password", password)],
            vec![("accept", "Yes")],
        ] {
            let Step::Page(url, page) = &step else {
                return step;
            };
            let (action, mut hidden) = html_form(page);
            hidden.extend(fields.iter().map(|(k, v)| ((*k).into(), (*v).into())));
            let action = url.join(&action).unwrap();
            step = self.browse(action, Some(hidden)).await;
        }
        step
    }
}
/// The action and hidden inputs of the first form of a provider page.
fn html_form(page: &str) -> (String, Vec<(String, String)>) {
    fn attribute(tag: &str, name: &str) -> Option<String> {
        let start = tag.find(&format!(" {name}=\""))? + name.len() + 3;
        let value = &tag[start..];
        Some(value[..value.find('"')?].replace("&amp;", "&"))
    }
    let form = &page[page.find("<form").expect("provider form")..];
    let action = attribute(&form[..form.find('>').unwrap()], "action").expect("form action");
    let mut hidden = Vec::new();
    for tag in form.split("<input").skip(1) {
        let tag = &tag[..tag.find('>').unwrap()];
        if attribute(tag, "type").as_deref() == Some("hidden")
            && let Some(name) = attribute(tag, "name")
        {
            hidden.push((name, attribute(tag, "value").unwrap_or_default()));
        }
    }
    (action, hidden)
}
/// Sign in at Keycloak for an authorization URL produced by pdf2md and return
/// the authorization code from the redirect to the client.
async fn keycloak_sign_in(fixture: &Value, location: &str, user: &str) -> String {
    let location = url::Url::parse(location).unwrap();
    assert!(
        location
            .as_str()
            .starts_with(fixture["issuer"].as_str().unwrap())
    );
    let state = location
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let mut browser = ProviderBrowser::new(fixture);
    let step = browser.browse(location, None).await;
    let Step::Left(redirect) = browser.sign_in(step, fixture, user).await else {
        panic!("synthetic sign-in failed");
    };
    let query: std::collections::HashMap<String, String> =
        redirect.query_pairs().into_owned().collect();
    assert_eq!(query["state"], state);
    assert_eq!(query["iss"], fixture["issuer"].as_str().unwrap());
    query["code"].clone()
}
/// Approve a device code as a user through Keycloak's verification pages.
async fn keycloak_approve_device(fixture: &Value, verification_uri: &str, user: &str) {
    let mut browser = ProviderBrowser::new(fixture);
    let step = browser
        .browse(url::Url::parse(verification_uri).unwrap(), None)
        .await;
    let Step::Page(url, _) = browser.sign_in(step, fixture, user).await else {
        panic!("device approval left the provider");
    };
    assert!(url.path().ends_with("/device/status"), "device approval");
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
#[ignore = "requires disposable real Keycloak; run scripts/test-keycloak.py"]
async fn real_keycloak_grants_through_the_registered_client() {
    use pdf2md_mcp::oauth::OAuthClient;
    use reqwest::StatusCode;
    let fixture_path =
        std::env::var("PDF2MD_LIVE_KEYCLOAK_FIXTURE").expect("live fixture required");
    let fixture: Value = serde_json::from_slice(&std::fs::read(fixture_path).unwrap()).unwrap();
    if !std::env::var("PDF2MD_LIVE_KEYCLOAK_PHASE")
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
        "client_id": fixture["web_client_id"], "client_secret": {"file": fixture["secret_file"]},
        "grant_types": ["authorization_code", "device_code", "refresh_token"],
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
    let code = keycloak_sign_in(&fixture, &location, "alice").await;
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

    // The Implicit grant is not offered.
    assert_eq!(
        api.get(format!("{base}/oauth/implicit"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

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
    keycloak_approve_device(
        &fixture,
        device
            .verification_uri_complete
            .as_deref()
            .expect("complete verification URI"),
        "bob",
    )
    .await;
    // Keycloak answers `slow_down` to a poll within the advertised interval.
    tokio::time::sleep(std::time::Duration::from_secs(device.interval)).await;
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

    // Refresh Token through the trusted client. The test realm revokes a
    // refresh token once it has been used.
    let request = registered.authorization_request().await.unwrap();
    let code = keycloak_sign_in(&fixture, request.url.as_str(), "alice").await;
    let code_refresh = registered
        .exchange_code(&code, &request.code_verifier)
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

#[path = "common/dpop_proof.rs"]
mod dpop_proof;

/// Resource-server configuration whose provider calls are authenticated with
/// a signed assertion instead of a shared secret.
fn assertion_auth_config(
    fixture: &Value,
    validation: &str,
    dpop: Option<Value>,
    client: Option<Value>,
) -> AuthConfig {
    serde_json::from_value(serde_json::json!({
        "mode": "oauth2",
        "oidc": {
            "issuer": fixture["issuer"], "audience": fixture["audience"],
            "validation": validation, "token_profile": "keycloak",
            "client_id": fixture["assertion_client_id"],
            "client_assertion": assertion(fixture),
            "ca_file": fixture["ca_file"],
            "dpop": dpop
        },
        "client": client
    }))
    .unwrap()
}
/// RFC 7523 assertion: issuer and subject are the client ID.
fn assertion(fixture: &Value) -> Value {
    serde_json::json!({
        "key": {"file": fixture["assertion_key_file"]},
        "algorithm": "RS256",
    })
}

#[tokio::test]
#[ignore = "requires disposable real Keycloak; run scripts/test-keycloak.py"]
async fn real_keycloak_accepts_signed_client_assertions_and_binds_tokens_to_dpop_keys() {
    use dpop_proof::ProofKey;
    use pdf2md_mcp::{auth::Credentials, oauth::OAuthClient};
    use reqwest::StatusCode;
    let fixture_path =
        std::env::var("PDF2MD_LIVE_KEYCLOAK_FIXTURE").expect("live fixture required");
    let fixture: Value = serde_json::from_slice(&std::fs::read(fixture_path).unwrap()).unwrap();
    if !std::env::var("PDF2MD_LIVE_KEYCLOAK_PHASE")
        .unwrap_or_default()
        .is_empty()
    {
        return;
    }
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let client = serde_json::json!({
        "client_id": fixture["assertion_client_id"], "client_assertion": assertion(&fixture),
        "grant_types": ["client_credentials"],
        "scopes": ["pdf2md:read", "pdf2md:write"],
    });
    // Introspection is authenticated with a signed assertion, and reports the
    // key a DPoP-bound token belongs to.
    let auth = assertion_auth_config(
        &fixture,
        "introspection",
        Some(serde_json::json!({"public_url": base})),
        Some(client),
    );
    let service = std::sync::Arc::new(
        CallerService::new(
            root.path(),
            Config {
                auth: auth.clone(),
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
    let api = reqwest::Client::builder().no_proxy().build().unwrap();
    let history_url = format!("{base}/v1/history");

    // private_key_jwt: Client Credentials without a shared secret.
    let signed = OAuthClient::new(&auth)
        .unwrap()
        .unwrap()
        .client_credentials()
        .await
        .unwrap()
        .access_token;
    let signed_subject =
        match Authenticator::new(assertion_auth_config(&fixture, "jwt", None, None))
            .await
            .unwrap()
            .authenticate(Some(&signed), true)
            .await
            .unwrap()
        {
            Identity::User { subject, .. } => subject,
            Identity::Shared => panic!("OAuth must not become anonymous"),
        };
    assert_ne!(
        signed_subject,
        subject(&fixture, token(&fixture, "alice")).await
    );
    assert_eq!(
        api.get(&history_url)
            .bearer_auth(&signed)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    // A user token passes the same assertion-authenticated introspection.
    assert_eq!(
        api.get(&history_url)
            .bearer_auth(token(&fixture, "alice"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    // DPoP: the provider binds a token to the key that signed the token
    // request's proof (RFC 9449 section 5). Introspection reports the binding.
    let key = ProofKey::es256();
    let endpoint = fixture["token_endpoint"].as_str().unwrap().to_owned();
    let mut claims = ProofKey::claims("POST", &endpoint, "");
    claims.as_object_mut().unwrap().remove("ath");
    let secret = std::fs::read_to_string(fixture["secret_file"].as_str().unwrap()).unwrap();
    let issued: Value = provider_client(&fixture)
        .post(&endpoint)
        .basic_auth(
            fixture["machine_client_id"].as_str().unwrap(),
            Some(secret.trim()),
        )
        .header("DPoP", key.sign(&key.header(), &claims))
        .form(&[
            ("grant_type", "client_credentials"),
            ("scope", "pdf2md:read pdf2md:write"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(issued["token_type"], "DPoP");
    let bound = issued["access_token"].as_str().expect("DPoP-bound token");
    let present = |scheme: &'static str, proof: Option<String>| {
        let mut request = api
            .get(&history_url)
            .header("authorization", format!("{scheme} {bound}"));
        if let Some(proof) = proof {
            request = request.header("dpop", proof);
        }
        async move { request.send().await.unwrap().status() }
    };
    let proof = key.proof("GET", &history_url, bound);
    assert_eq!(present("DPoP", Some(proof.clone())).await, StatusCode::OK);
    // A proof is accepted once.
    assert_eq!(present("DPoP", Some(proof)).await, StatusCode::UNAUTHORIZED);
    // The bound token is of no use without its key.
    assert_eq!(present("Bearer", None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(present("DPoP", None).await, StatusCode::UNAUTHORIZED);
    let other = ProofKey::es256().proof("GET", &history_url, bound);
    assert_eq!(present("DPoP", Some(other)).await, StatusCode::UNAUTHORIZED);
    // A proof for another token does not carry over.
    let stale = key.proof("GET", &history_url, &signed);
    assert_eq!(present("DPoP", Some(stale)).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        present("DPoP", Some(key.proof("GET", &history_url, bound))).await,
        StatusCode::OK
    );
    // Keycloak also writes the binding into the JWT (`cnf.jkt`), so local
    // validation confirms it without the provider.
    let local = Authenticator::new(assertion_auth_config(
        &fixture,
        "jwt",
        Some(serde_json::json!({"public_url": base})),
        None,
    ))
    .await
    .unwrap();
    let proven = local
        .verify_dpop(
            &key.proof("GET", &history_url, bound),
            "GET",
            "/v1/history",
            bound,
        )
        .unwrap();
    local
        .authorize_credentials(Credentials::dpop(bound, &proven), true, false)
        .await
        .unwrap();
    let stolen = ProofKey::es256();
    let stolen = local
        .verify_dpop(
            &stolen.proof("GET", &history_url, bound),
            "GET",
            "/v1/history",
            bound,
        )
        .unwrap();
    assert_eq!(
        local
            .authorize_credentials(Credentials::dpop(bound, &stolen), false, false)
            .await
            .unwrap_err()
            .code,
        "auth_invalid"
    );
    cancel.cancel();
    server.abort();
}
