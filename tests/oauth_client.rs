//! Registered OAuth client grants against a synthetic TLS provider.
use pdf2md_mcp::{
    auth::{AuthConfig, AuthMode, OidcConfig, OidcSecret, TokenProfile, TokenValidation},
    config::Config,
    http,
    oauth::{GrantType, OAuthClient, OAuthClientConfig, code_challenge},
    service::CallerService,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use reqwest::{StatusCode, redirect::Policy};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

const AUDIENCE: &str = "https://pdf2md.example/";

#[derive(Clone, Debug)]
struct Recorded {
    path: String,
    authorization: Option<String>,
    form: HashMap<String, String>,
}

struct Provider {
    issuer: String,
    ca: std::path::PathBuf,
    secret: std::path::PathBuf,
    requests: Arc<Mutex<Vec<Recorded>>>,
    token_responses: Arc<Mutex<VecDeque<(u16, Value)>>>,
    /// Discovery `code_challenge_methods_supported`; `None` omits the field.
    pkce_methods: Arc<Mutex<Option<Value>>>,
    task: JoinHandle<()>,
    _dir: TempDir,
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn token_json(access: &str) -> Value {
    json!({"access_token":access,"token_type":"Bearer","expires_in":3600,"scope":"pdf2md:read pdf2md:write","refresh_token":"refresh-1","id_token":"ignored"})
}

impl Provider {
    async fn start() -> Self {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, cert.pem()).unwrap();
        let secret = dir.path().join("client-secret");
        std::fs::write(&secret, "client secret+&").unwrap();
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let token_responses = Arc::new(Mutex::new(VecDeque::new()));
        let pkce_methods = Arc::new(Mutex::new(Some(json!(["S256"]))));
        let (origin, log, queue) = (issuer.clone(), requests.clone(), token_responses.clone());
        let pkce = pkce_methods.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, origin, log, queue) =
                    (acceptor.clone(), origin.clone(), log.clone(), queue.clone());
                let pkce = pkce.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut bytes = Vec::new();
                    let mut buf = [0u8; 4096];
                    let header_end = loop {
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&buf[..n]);
                        if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                            break end + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&bytes[..header_end]).to_string();
                    let length = head
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    while bytes.len() < header_end + length {
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        bytes.extend_from_slice(&buf[..n]);
                    }
                    let body = &bytes[header_end..];
                    let path = head
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_owned();
                    let authorization = head.lines().find_map(|line| {
                        line.to_ascii_lowercase()
                            .starts_with("authorization:")
                            .then(|| line["authorization:".len()..].trim().to_owned())
                    });
                    let form = url::form_urlencoded::parse(body).into_owned().collect();
                    let (status, value) = match path.as_str() {
                        "/.well-known/openid-configuration" => {
                            let mut discovery = json!({
                                "issuer": origin,
                                "authorization_endpoint": format!("{origin}/authorize?tenant=pdf2md"),
                                "token_endpoint": format!("{origin}/token?tenant=pdf2md"),
                                "device_authorization_endpoint": format!("{origin}/device"),
                                "introspection_endpoint": format!("{origin}/introspect"),
                                "jwks_uri": format!("{origin}/jwks"),
                                "authorization_response_iss_parameter_supported": true,
                            });
                            if let Some(methods) = pkce.lock().unwrap().clone() {
                                discovery["code_challenge_methods_supported"] = methods;
                            }
                            (200, discovery)
                        }
                        "/token?tenant=pdf2md" => {
                            log.lock().unwrap().push(Recorded {
                                path,
                                authorization,
                                form,
                            });
                            queue
                                .lock()
                                .unwrap()
                                .pop_front()
                                .unwrap_or_else(|| (200, token_json("access-1")))
                        }
                        "/device" => {
                            log.lock().unwrap().push(Recorded {
                                path,
                                authorization,
                                form,
                            });
                            (
                                200,
                                json!({"device_code":"device-1","user_code":"ab12cd","verification_uri":format!("{origin}/login/oauth/device/ab12cd"),"expires_in":60,"interval":1}),
                            )
                        }
                        _ => (404, json!({"error":"not_found"})),
                    };
                    let body = value.to_string();
                    let response = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self {
            issuer,
            ca,
            secret,
            requests,
            token_responses,
            pkce_methods,
            task,
            _dir: dir,
        }
    }

    fn auth(&self, grants: &[GrantType], redirect: Option<String>, secret: bool) -> AuthConfig {
        AuthConfig {
            mode: AuthMode::Oauth2,
            oidc: Some(OidcConfig {
                issuer: self.issuer.clone(),
                audience: AUDIENCE.into(),
                validation: TokenValidation::Jwt,
                token_profile: TokenProfile::Casdoor,
                additional_audiences: vec![],
                access_token_prefix: None,
                jwt_scope_claim: "scope".into(),
                client_id: None,
                client_secret: None,
                read_scope: "pdf2md:read".into(),
                write_scope: "pdf2md:write".into(),
                operate_scope: "pdf2md:operate".into(),
                allowed_endpoint_origins: vec![],
                ca_file: Some(self.ca.clone()),
            }),
            client: Some(OAuthClientConfig {
                client_id: "pdf2md-web".into(),
                client_secret: secret.then(|| OidcSecret {
                    env: None,
                    file: Some(self.secret.clone()),
                }),
                grant_types: grants.to_vec(),
                scopes: vec!["pdf2md:read".into(), "pdf2md:write".into()],
                redirect_base_url: redirect,
                resource: None,
            }),
        }
    }
    fn last(&self) -> Recorded {
        self.requests.lock().unwrap().last().cloned().unwrap()
    }
}

struct Api {
    base: String,
    client: reqwest::Client,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    _dir: TempDir,
}
impl Drop for Api {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
impl Api {
    async fn start(provider: &Provider, grants: &[GrantType]) -> Self {
        Self::start_as(provider, grants, true).await
    }
    /// `secret` selects a confidential client; `false` registers a public one.
    async fn start_as(provider: &Provider, grants: &[GrantType], secret: bool) -> Self {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let config = Config {
            auth: provider.auth(grants, Some(base.clone()), secret),
            ..Config::default()
        };
        let service = Arc::new(CallerService::new(dir.path(), config, None).await.unwrap());
        let cancel = CancellationToken::new();
        let router = http::router(service, cancel.clone());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            base,
            client: reqwest::Client::builder()
                .redirect(Policy::none())
                .no_proxy()
                .build()
                .unwrap(),
            cancel,
            task,
            _dir: dir,
        }
    }
    async fn get(&self, path: &str, cookie: Option<&str>) -> reqwest::Response {
        let mut request = self.client.get(format!("{}{path}", self.base));
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        request.send().await.unwrap()
    }
    async fn post(&self, path: &str, body: Value) -> reqwest::Response {
        self.client
            .post(format!("{}{path}", self.base))
            .json(&body)
            .send()
            .await
            .unwrap()
    }
    /// Start a browser login; return the authorization URL parameters and cookie.
    async fn login(&self) -> (HashMap<String, String>, String) {
        let response = self.get("/oauth/login", None).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .to_owned();
        (location.query_pairs().into_owned().collect(), cookie)
    }
}

fn cookie_pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_owned()
}

async fn code(response: reqwest::Response) -> (StatusCode, String) {
    let status = response.status();
    let body: Value = response.json().await.unwrap();
    (status, body["code"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn authorization_code_login_binds_state_pkce_issuer_and_browser_cookie() {
    let provider = Provider::start().await;
    let api = Api::start(&provider, &[GrantType::AuthorizationCode]).await;
    let (query, set_cookie) = api.login().await;
    assert_eq!(query["response_type"], "code");
    // RFC 6749 section 3.1: the endpoint query component is retained.
    assert_eq!(query["tenant"], "pdf2md");
    assert_eq!(query["client_id"], "pdf2md-web");
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["resource"], AUDIENCE);
    assert_eq!(query["scope"], "pdf2md:read pdf2md:write");
    assert_eq!(
        query["redirect_uri"],
        format!("{}/oauth/callback", api.base)
    );
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Lax"));
    assert!(
        !set_cookie.contains("Secure"),
        "loopback HTTP cannot set Secure"
    );
    let state = &query["state"];
    let cookie = cookie_pair(&set_cookie);
    let callback = format!(
        "/oauth/callback?code=abc&state={state}&iss={}",
        provider.issuer
    );

    // A callback without this browser's cookie is rejected (login CSRF).
    assert_eq!(
        code(api.get(&callback, None).await).await,
        (StatusCode::BAD_REQUEST, "oauth_state_mismatch".into())
    );
    // RFC 9207: the provider advertises iss, so a missing value is rejected.
    let missing_iss = format!("/oauth/callback?code=abc&state={state}");
    assert_eq!(
        code(api.get(&missing_iss, Some(&cookie)).await).await.1,
        "oauth_issuer_mismatch"
    );
    let (query, set_cookie) = api.login().await;
    let state = &query["state"];
    let cookie = cookie_pair(&set_cookie);
    let wrong_iss = format!("/oauth/callback?code=abc&state={state}&iss=https://evil.example");
    assert_eq!(
        code(api.get(&wrong_iss, Some(&cookie)).await).await.1,
        "oauth_issuer_mismatch"
    );
    assert!(provider.requests.lock().unwrap().is_empty());

    let (query, set_cookie) = api.login().await;
    let state = &query["state"];
    let cookie = cookie_pair(&set_cookie);
    let callback = format!(
        "/oauth/callback?code=abc&state={state}&iss={}",
        provider.issuer
    );
    let response = api.get(&callback, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    let page = response.text().await.unwrap();
    assert!(page.contains("access-1"));
    assert!(!page.contains("ignored"), "ID tokens are not displayed");
    // A refresh token issued to the registered client never reaches the browser.
    assert!(!page.contains("refresh-1") && !page.contains("refresh-token"));
    // The result page uses the shared same-origin stylesheet and copy script.
    assert!(page.contains("href=\"/oauth/oauth.css\"") && page.contains("src=\"/oauth/page.js\""));
    assert!(page.contains("data-copy=\"access-token\""));
    let request = provider.last();
    // RFC 6749 section 3.2: the endpoint query component is retained.
    assert_eq!(request.path, "/token?tenant=pdf2md");
    assert_eq!(request.form["grant_type"], "authorization_code");
    assert_eq!(request.form["code"], "abc");
    assert_eq!(request.form["resource"], AUDIENCE);
    assert_eq!(request.form["redirect_uri"], query["redirect_uri"]);
    assert_eq!(
        code_challenge(&request.form["code_verifier"]),
        query["code_challenge"]
    );
    assert!(!request.form.contains_key("client_id"));
    // RFC 6749 section 2.3.1 form-encodes the secret before Basic encoding.
    use base64::Engine;
    let basic = base64::engine::general_purpose::STANDARD.encode("pdf2md-web:client+secret%2B%26");
    assert_eq!(request.authorization.unwrap(), format!("Basic {basic}"));

    // The state is single-use.
    assert_eq!(
        code(api.get(&callback, Some(&cookie)).await).await.1,
        "oauth_state_mismatch"
    );
}

#[tokio::test]
async fn sign_in_requires_a_provider_that_supports_pkce_s256() {
    let grants = [GrantType::AuthorizationCode];
    let refused = (StatusCode::BAD_GATEWAY, "oauth_pkce_unsupported".to_owned());

    // Advertised methods without S256 are refused for every client type.
    let provider = Provider::start().await;
    *provider.pkce_methods.lock().unwrap() = Some(json!(["plain"]));
    for secret in [true, false] {
        let api = Api::start_as(&provider, &grants, secret).await;
        let response = api.get("/oauth/login", None).await;
        assert!(response.headers().get("set-cookie").is_none());
        assert!(response.headers().get("location").is_none());
        assert_eq!(code(response).await, refused);
    }

    // Without the advertisement a public client is refused, because PKCE is
    // its only protection for the authorization code.
    let provider = Provider::start().await;
    *provider.pkce_methods.lock().unwrap() = None;
    let api = Api::start_as(&provider, &grants, false).await;
    assert_eq!(code(api.get("/oauth/login", None).await).await, refused);
    let page = api
        .client
        .get(format!("{}/oauth/login", api.base))
        .header("accept", "text/html")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Provider not supported") && page.contains("oauth_pkce_unsupported"));

    // A confidential client still authenticates the code exchange and binds
    // the response with `state`, so it may sign in and keeps sending S256.
    let api = Api::start_as(&provider, &grants, true).await;
    let (query, _) = api.login().await;
    assert_eq!(query["code_challenge_method"], "S256");

    // A public client signs in once the provider lists S256.
    let provider = Provider::start().await;
    *provider.pkce_methods.lock().unwrap() = Some(json!(["plain", "S256"]));
    let api = Api::start_as(&provider, &grants, false).await;
    let (query, _) = api.login().await;
    assert_eq!(query["code_challenge_method"], "S256");
}

#[tokio::test]
async fn library_code_exchange_rejects_a_malformed_pkce_verifier() {
    let provider = Provider::start().await;
    let auth = provider.auth(
        &[GrantType::AuthorizationCode],
        Some("https://pdf.example.com".into()),
        true,
    );
    let client = OAuthClient::new(&auth).unwrap().unwrap();
    for verifier in ["short", &"a".repeat(129), &format!("{}+", "a".repeat(43))] {
        assert_eq!(
            client
                .exchange_code("abc", verifier)
                .await
                .unwrap_err()
                .code,
            "oauth_invalid_grant"
        );
    }
    assert!(provider.requests.lock().unwrap().is_empty());

    let request = client.authorization_request().await.unwrap();
    client
        .exchange_code("abc", &request.code_verifier)
        .await
        .unwrap();
    let sent = provider.last();
    assert_eq!(sent.form["code_verifier"], request.code_verifier);
    assert_eq!(sent.form["grant_type"], "authorization_code");
}

#[tokio::test]
async fn provider_errors_on_callback_and_token_exchange_are_fixed_public_codes() {
    let provider = Provider::start().await;
    let api = Api::start(&provider, &[GrantType::AuthorizationCode]).await;
    let (query, set_cookie) = api.login().await;
    let denied = format!(
        "/oauth/callback?error=access_denied&error_description=secret+detail&state={}&iss={}",
        query["state"], provider.issuer
    );
    let response = api.get(&denied, Some(&cookie_pair(&set_cookie))).await;
    let body = response.text().await.unwrap();
    assert!(body.contains("oauth_access_denied") && !body.contains("secret detail"));

    provider.token_responses.lock().unwrap().push_back((
        400,
        json!({"error":"invalid_grant","error_description":"private"}),
    ));
    let (query, set_cookie) = api.login().await;
    let callback = format!(
        "/oauth/callback?code=used&state={}&iss={}",
        query["state"], provider.issuer
    );
    let response = api.get(&callback, Some(&cookie_pair(&set_cookie))).await;
    assert_eq!(
        code(response).await,
        (StatusCode::BAD_REQUEST, "oauth_invalid_grant".into())
    );
}

#[tokio::test]
async fn implicit_grant_is_not_offered() {
    let provider = Provider::start().await;
    let api = Api::start(&provider, &[GrantType::AuthorizationCode]).await;
    // The login route always starts Authorization Code with PKCE, whatever
    // the query asks for.
    let response = api.get("/oauth/login?grant=implicit", None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    let query: HashMap<String, String> = location.query_pairs().into_owned().collect();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["code_challenge_method"], "S256");
    for path in ["/oauth/implicit", "/oauth/implicit.js"] {
        assert_eq!(api.get(path, None).await.status(), StatusCode::NOT_FOUND);
    }

    // Without the Authorization Code grant there are no browser routes.
    let api = Api::start(&provider, &[GrantType::DeviceCode]).await;
    for path in ["/oauth/login", "/oauth/callback", "/oauth/oauth.css"] {
        assert_eq!(api.get(path, None).await.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn device_and_refresh_grants_are_not_brokered_over_http() {
    let provider = Provider::start().await;
    let api = Api::start(
        &provider,
        &[
            GrantType::AuthorizationCode,
            GrantType::DeviceCode,
            GrantType::RefreshToken,
        ],
    )
    .await;
    // The registered client's credentials are never applied to a device code
    // or refresh token supplied by an HTTP caller.
    assert_eq!(
        api.post("/oauth/device", json!(null)).await.status(),
        StatusCode::NOT_FOUND
    );
    let grant = "urn:ietf:params:oauth:grant-type:device_code";
    for body in [
        json!({"grant_type":grant,"device_code":"device-1"}),
        json!({"grant_type":"refresh_token","refresh_token":"refresh-1"}),
        json!({"grant_type":"client_credentials"}),
    ] {
        assert_eq!(
            api.post("/oauth/token", body).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    assert!(provider.requests.lock().unwrap().is_empty());

    // The same grants stay available to the trusted CLI and library.
    let auth = provider.auth(
        &[GrantType::DeviceCode, GrantType::RefreshToken],
        None,
        true,
    );
    let client = OAuthClient::new(&auth).unwrap().unwrap();
    let device = client.device_authorization().await.unwrap();
    assert_eq!(device.user_code, "ab12cd");
    assert_eq!(provider.last().form["resource"], AUDIENCE);
    assert_eq!(provider.last().form["scope"], "pdf2md:read pdf2md:write");
    // RFC 8628 identifies the client in the body alongside its authentication.
    assert_eq!(provider.last().form["client_id"], "pdf2md-web");
    provider
        .token_responses
        .lock()
        .unwrap()
        .push_back((400, json!({"error":"authorization_pending"})));
    assert_eq!(
        client.poll_device("device-1").await.unwrap_err().code,
        "oauth_authorization_pending"
    );
    let tokens = client.poll_device("device-1").await.unwrap();
    assert_eq!(tokens.access_token, "access-1");
    assert_eq!(provider.last().form["grant_type"], grant);
    let refreshed = client.refresh("refresh-1").await.unwrap();
    assert_eq!(refreshed.refresh_token.as_deref(), Some("refresh-1"));
    assert_eq!(provider.last().form["grant_type"], "refresh_token");
    assert_eq!(provider.last().form["refresh_token"], "refresh-1");
    assert!(provider.last().authorization.unwrap().starts_with("Basic "));
}

#[tokio::test]
async fn library_client_credentials_and_device_polling_use_registered_client() {
    let provider = Provider::start().await;
    let auth = provider.auth(
        &[GrantType::ClientCredentials, GrantType::DeviceCode],
        None,
        true,
    );
    let client = OAuthClient::new(&auth).unwrap().unwrap();
    let tokens = client.client_credentials().await.unwrap();
    assert_eq!(tokens.access_token, "access-1");
    let request = provider.last();
    assert_eq!(request.form["grant_type"], "client_credentials");
    assert_eq!(request.form["scope"], "pdf2md:read pdf2md:write");
    assert!(request.authorization.unwrap().starts_with("Basic "));
    assert!(!format!("{tokens:?}").contains("access-1"));
    assert_eq!(
        client.refresh("refresh-1").await.unwrap_err().code,
        "oauth_grant_disabled"
    );

    let device = client.device_authorization().await.unwrap();
    provider
        .token_responses
        .lock()
        .unwrap()
        .push_back((400, json!({"error":"authorization_pending"})));
    let tokens = client.wait_for_device(&device).await.unwrap();
    assert_eq!(tokens.access_token, "access-1");
    provider
        .token_responses
        .lock()
        .unwrap()
        .push_back((400, json!({"error":"access_denied"})));
    assert_eq!(
        client.wait_for_device(&device).await.unwrap_err().code,
        "oauth_access_denied"
    );
    // Expiry is reported within the code lifetime, not after a long interval.
    let mut short = device.clone();
    short.expires_in = 1;
    short.interval = 3600;
    let expired = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.wait_for_device(&short),
    )
    .await
    .expect("device expiry is reported without waiting for the interval");
    assert_eq!(expired.unwrap_err().code, "oauth_expired_token");
    provider
        .token_responses
        .lock()
        .unwrap()
        .push_back((200, json!({"access_token":"a","token_type":"DPoP"})));
    assert_eq!(
        client.client_credentials().await.unwrap_err().code,
        "auth_unavailable"
    );
}

#[tokio::test]
async fn public_clients_send_client_id_without_basic_authentication() {
    let provider = Provider::start().await;
    let auth = provider.auth(&[GrantType::RefreshToken], None, false);
    let client = OAuthClient::new(&auth).unwrap().unwrap();
    client.refresh("refresh-1").await.unwrap();
    let request = provider.last();
    assert!(request.authorization.is_none());
    assert_eq!(request.form["client_id"], "pdf2md-web");
}

#[test]
fn client_configuration_rejects_password_and_implicit_grants_and_incomplete_flows() {
    let base = r#"
[auth]
mode = "oauth2"
[auth.oidc]
issuer = "https://id.example"
audience = "https://pdf.example/"
validation = "jwt"
token_profile = "casdoor"
[auth.client]
client_id = "pdf2md"
scopes = ["pdf2md:read"]
"#;
    let parse = |extra: &str| -> Result<(), String> {
        let config: Config =
            toml::from_str(&format!("{base}{extra}")).map_err(|e| e.to_string())?;
        config.validate().map_err(|e| e.code)
    };
    assert!(parse("grant_types = [\"device_code\", \"refresh_token\"]\n").is_ok());
    assert!(parse("grant_types = [\"password\"]\n").is_err());
    assert!(
        parse("grant_types = [\"implicit\"]\nredirect_base_url = \"https://pdf.example\"\n")
            .is_err()
    );
    assert!(parse("grant_types = []\n").is_err());
    assert!(parse("grant_types = [\"device_code\", \"device_code\"]\n").is_err());
    // Client Credentials requires a confidential client.
    assert!(parse("grant_types = [\"client_credentials\"]\n").is_err());
    assert!(
        parse("grant_types = [\"client_credentials\"]\nclient_secret = { env = \"PDF2MD_TEST_SECRET\" }\n")
            .is_ok()
    );
    // Authorization Code needs the public service origin for its redirect URI.
    assert!(parse("grant_types = [\"authorization_code\"]\n").is_err());
    assert!(
        parse(
            "grant_types = [\"authorization_code\"]\nredirect_base_url = \"https://pdf.example\"\n"
        )
        .is_ok()
    );
    assert!(
        parse(
            "grant_types = [\"authorization_code\"]\nredirect_base_url = \"http://pdf.example\"\n"
        )
        .is_err()
    );
    // RFC 8707 resources may be any absolute URI without a fragment.
    assert!(parse("grant_types = [\"device_code\"]\nresource = \"urn:pdf2md:api\"\n").is_ok());
    assert!(
        parse("grant_types = [\"device_code\"]\nresource = \"https://pdf.example/#api\"\n")
            .is_err()
    );
    assert!(parse("grant_types = [\"device_code\"]\nresource = \"pdf2md-api\"\n").is_err());
    // Client settings are rejected outside OAuth2 mode.
    let anonymous: Config = toml::from_str(
        "[auth]\nmode = \"none_rw\"\n[auth.client]\nclient_id = \"x\"\ngrant_types = [\"device_code\"]\nscopes = [\"a\"]\n",
    )
    .unwrap();
    assert!(anonymous.validate().is_err());
}

#[tokio::test]
async fn browser_navigation_errors_render_html_pages_while_api_errors_stay_json() {
    let provider = Provider::start().await;
    let api = Api::start(&provider, &[GrantType::AuthorizationCode]).await;
    let html = |path: String, cookie: Option<String>| {
        let mut request = api
            .client
            .get(format!("{}{path}", api.base))
            .header("accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8");
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        request.send()
    };

    let response = html("/oauth/callback?code=abc&state=unknown".into(), None)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("style-src 'self'")
    );
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let page = response.text().await.unwrap();
    assert!(page.contains("Sign-in expired") && page.contains("oauth_state_mismatch"));
    assert!(page.contains(&request_id), "the page shows the request ID");
    assert!(page.contains("href=\"/oauth/login\""));

    // Provider error descriptions stay hidden on the HTML page too.
    let (query, set_cookie) = api.login().await;
    let denied = format!(
        "/oauth/callback?error=access_denied&error_description=secret+detail&state={}&iss={}",
        query["state"], provider.issuer
    );
    let page = html(denied, Some(cookie_pair(&set_cookie)))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Access denied") && page.contains("oauth_access_denied"));
    assert!(!page.contains("secret detail"));

    // Shared assets carry their media types.
    let css = api.get("/oauth/oauth.css", None).await;
    assert_eq!(css.headers()["content-type"], "text/css; charset=utf-8");
    assert!(css.text().await.unwrap().contains("color-scheme: dark"));
    let script = api.get("/oauth/page.js", None).await;
    assert_eq!(
        script.headers()["content-type"],
        "application/javascript; charset=utf-8"
    );
    assert!(script.text().await.unwrap().contains("clipboard"));
}
