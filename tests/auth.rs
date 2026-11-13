use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use pdf2md_mcp::auth::{
    AuthConfig, AuthMode, Authenticator, Identity, OidcConfig, OidcSecret, TokenProfile,
    TokenValidation,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

#[path = "common/conversion_pdf.rs"]
mod conversion_pdf;

struct Fixture {
    config: AuthConfig,
    issuer: String,
    introspection: Arc<Mutex<Value>>,
    jwks: Arc<Mutex<Value>>,
    intro_count: Arc<AtomicUsize>,
    key_count: Arc<AtomicUsize>,
    metadata: Arc<Mutex<Option<Value>>>,
    task: JoinHandle<()>,
    _dir: TempDir,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new(method: TokenValidation) -> Self {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let CertifiedKey {
            cert,
            signing_key: key_pair,
        } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, cert.pem()).unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "test-secret").unwrap();
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let config = AuthConfig {
            mode: AuthMode::Oauth2,
            oidc: Some(OidcConfig {
                issuer: issuer.clone(),
                audience: "https://pdf2md.example/mcp".into(),
                validation: method,
                token_profile: TokenProfile::Rfc9068,
                additional_audiences: vec![],
                access_token_prefix: None,
                jwt_scope_claim: "scope".into(),
                client_id: Some("pdf2md-test".into()),
                client_secret: Some(OidcSecret {
                    env: None,
                    file: Some(secret),
                }),
                client_assertion: None,
                read_scope: "pdf2md:read".into(),
                write_scope: "pdf2md:write".into(),
                operate_scope: "pdf2md:operate".into(),
                allowed_endpoint_origins: vec![],
                ca_file: Some(ca),
            }),
            client: None,
        };
        let introspection = Arc::new(Mutex::new(claims(&issuer)));
        let jwks = Arc::new(Mutex::new(json!({"keys":[jwk("first")]})));
        let metadata = Arc::new(Mutex::new(None::<Value>));
        let intro_count = Arc::new(AtomicUsize::new(0));
        let key_count = Arc::new(AtomicUsize::new(0));
        let (intro_data, keys_data, meta_data, counter, key_counter, origin) = (
            introspection.clone(),
            jwks.clone(),
            metadata.clone(),
            intro_count.clone(),
            key_count.clone(),
            issuer.clone(),
        );
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, intro_data, keys_data, meta_data, counter, key_counter, origin) = (
                    acceptor.clone(),
                    intro_data.clone(),
                    keys_data.clone(),
                    meta_data.clone(),
                    counter.clone(),
                    key_counter.clone(),
                    origin.clone(),
                );
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut bytes = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&buf[..n]);
                        if bytes.windows(4).any(|v| v == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8_lossy(&bytes);
                    let path = request.split_whitespace().nth(1).unwrap_or_default();
                    let body = match path {
                        "/.well-known/openid-configuration" => meta_data.lock().unwrap().clone().unwrap_or_else(|| json!({"issuer":origin,"introspection_endpoint":format!("{origin}/introspect"),"jwks_uri":format!("{origin}/jwks")})),
                        "/introspect" => {
                            counter.fetch_add(1,Ordering::SeqCst);
                            assert!(request.contains("authorization: Basic "));
                            intro_data.lock().unwrap().clone()
                        },
                        "/jwks" => {
                            key_counter.fetch_add(1,Ordering::SeqCst);
                            keys_data.lock().unwrap().clone()
                        },
                        _ => json!({"unexpected":true}),
                    }.to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self {
            config,
            issuer,
            introspection,
            jwks,
            metadata,
            intro_count,
            key_count,
            task,
            _dir: dir,
        }
    }
}
fn claims(issuer: &str) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({"active":true,"token_type":"Bearer","iss":issuer,"sub":"alice","aud":"https://pdf2md.example/mcp","exp":now+600,"iat":now-1,"scope":"pdf2md:read pdf2md:write","jti":"synthetic","client_id":"pdf2md-test"})
}
fn token(issuer: &str, kid: &str, update: impl FnOnce(&mut Value)) -> String {
    let mut claims = claims(issuer);
    update(&mut claims);
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some(kid.into());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_KEY.as_bytes()).unwrap(),
    )
    .unwrap()
}
/// Casdoor-format access token: `typ` `JWT`, signed `tokenType`, and `azp`.
fn casdoor_token(issuer: &str, kid: &str, update: impl FnOnce(&mut Value)) -> String {
    let mut claims = claims(issuer);
    let object = claims.as_object_mut().unwrap();
    object.remove("client_id");
    object.remove("token_type");
    object.insert("azp".into(), json!("pdf2md-test"));
    object.insert("tokenType".into(), json!("access-token"));
    update(&mut claims);
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".into());
    header.kid = Some(kid.into());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_KEY.as_bytes()).unwrap(),
    )
    .unwrap()
}
fn jwk(kid: &str) -> Value {
    json!({"kty":"RSA","use":"sig","alg":"RS256","kid":kid,"n":TEST_MODULUS,"e":"AQAB"})
}

#[tokio::test]
async fn anonymous_modes_enforce_write_policy_and_ignore_untrusted_identity() {
    let auth = Authenticator::new(AuthConfig::default()).await.unwrap();
    assert_eq!(
        auth.authenticate(None, false).await.unwrap(),
        Identity::Shared
    );
    assert_eq!(
        auth.authenticate(Some("forged-user"), false).await.unwrap(),
        Identity::Shared
    );
    assert_eq!(
        auth.authenticate(None, true).await.unwrap_err().code,
        "auth_forbidden"
    );
    let rw = Authenticator::new(AuthConfig {
        mode: AuthMode::NoneRw,
        oidc: None,
        client: None,
    })
    .await
    .unwrap();
    assert_eq!(rw.authenticate(None, true).await.unwrap(), Identity::Shared);
}

#[tokio::test]
async fn introspection_checks_each_operation_scopes_and_revocation() {
    let fixture = Fixture::new(TokenValidation::Introspection).await;
    let auth = Authenticator::new(fixture.config.clone()).await.unwrap();
    assert_eq!(
        auth.authenticate(None, false).await.unwrap_err().code,
        "auth_invalid"
    );
    assert_eq!(fixture.intro_count.load(Ordering::SeqCst), 0);
    assert_eq!(
        auth.authenticate(Some("opaque-access-token"), true)
            .await
            .unwrap(),
        Identity::User {
            issuer: fixture.issuer.clone(),
            subject: "alice".into()
        }
    );
    fixture.introspection.lock().unwrap()["scope"] = json!("pdf2md:read");
    auth.authenticate(Some("opaque-access-token"), false)
        .await
        .unwrap();
    assert_eq!(
        auth.authenticate(Some("opaque-access-token"), true)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    fixture.introspection.lock().unwrap()["active"] = json!(false);
    assert_eq!(
        auth.authenticate(Some("opaque-access-token"), false)
            .await
            .unwrap_err()
            .code,
        "auth_invalid"
    );
    assert_eq!(fixture.intro_count.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn introspection_rejects_wrong_audience_issuer_expiry_and_non_access_tokens() {
    let fixture = Fixture::new(TokenValidation::Introspection).await;
    let auth = Authenticator::new(fixture.config.clone()).await.unwrap();
    for (field, value) in [
        ("aud", json!("another-service")),
        ("iss", json!("https://other.example")),
        ("exp", json!(0)),
        ("token_type", json!("")),
        ("token_use", json!("refresh_token")),
        ("sub", json!("")),
        ("nbf", json!(chrono::Utc::now().timestamp() + 100)),
    ] {
        let mut response = claims(&fixture.issuer);
        response[field] = value;
        *fixture.introspection.lock().unwrap() = response;
        assert_eq!(
            auth.authenticate(Some("opaque"), false)
                .await
                .unwrap_err()
                .code,
            "auth_invalid",
            "field {field}"
        );
    }
}

#[tokio::test]
async fn provider_discovery_and_network_failures_fail_closed() {
    let fixture = Fixture::new(TokenValidation::Introspection).await;
    *fixture.metadata.lock().unwrap() = Some(
        json!({"issuer":"https://untrusted.example","introspection_endpoint":format!("{}/introspect",fixture.issuer)}),
    );
    let auth = Authenticator::new(fixture.config.clone()).await.unwrap();
    assert_eq!(
        auth.authenticate(Some("opaque"), false)
            .await
            .unwrap_err()
            .code,
        "auth_unavailable"
    );
    assert_eq!(fixture.intro_count.load(Ordering::SeqCst), 0);
    *fixture.metadata.lock().unwrap() = Some(
        json!({"issuer":fixture.issuer,"introspection_endpoint":"https://untrusted.example/introspect"}),
    );
    assert_eq!(
        auth.authenticate(Some("opaque"), false)
            .await
            .unwrap_err()
            .code,
        "auth_unavailable"
    );
    fixture.task.abort();
    assert_eq!(
        auth.authenticate(Some("opaque"), false)
            .await
            .unwrap_err()
            .code,
        "auth_unavailable"
    );
}

#[tokio::test]
async fn jwt_verifies_signature_claims_scopes_and_key_rotation() {
    let fixture = Fixture::new(TokenValidation::Jwt).await;
    let auth = Authenticator::new(fixture.config.clone()).await.unwrap();
    let signed = token(&fixture.issuer, "first", |_| {});
    auth.authenticate(Some(&signed), true).await.unwrap();
    assert_eq!(fixture.key_count.load(Ordering::SeqCst), 1);
    for (field, value) in [
        ("aud", json!("another-service")),
        ("iss", json!("https://other.example")),
        ("exp", json!(0)),
        ("sub", json!("")),
        ("iat", json!(chrono::Utc::now().timestamp() + 100)),
        ("jti", Value::Null),
        ("client_id", Value::Null),
    ] {
        let bad = token(&fixture.issuer, "first", |claims| claims[field] = value);
        assert_eq!(
            auth.authenticate(Some(&bad), false).await.unwrap_err().code,
            "auth_invalid",
            "field {field}"
        );
    }
    let readonly = token(&fixture.issuer, "first", |claims| {
        claims["scope"] = json!("pdf2md:read")
    });
    assert_eq!(
        auth.authenticate(Some(&readonly), true)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    *fixture.jwks.lock().unwrap() = json!({"keys":[jwk("rotated")]});
    let rotated = token(&fixture.issuer, "rotated", |_| {});
    auth.authenticate(Some(&rotated), false).await.unwrap();
    assert_eq!(fixture.key_count.load(Ordering::SeqCst), 2);
    let unknown = token(&fixture.issuer, "unknown", |_| {});
    assert_eq!(
        auth.authenticate(Some(&unknown), false)
            .await
            .unwrap_err()
            .code,
        "auth_invalid"
    );
    assert_eq!(fixture.key_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn jwt_rejects_id_tokens_wrong_algorithms_token_keys_and_bad_signatures() {
    let fixture = Fixture::new(TokenValidation::Jwt).await;
    let auth = Authenticator::new(fixture.config.clone()).await.unwrap();
    let key = EncodingKey::from_rsa_pem(TEST_KEY.as_bytes()).unwrap();
    for update in [0, 1, 2] {
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("first".into());
        match update {
            0 => header.typ = Some("JWT".into()),
            1 => header.jku = Some("https://untrusted.example/keys".into()),
            _ => header.crit = Some(vec!["unsupported".into()]),
        };
        let signed = encode(&header, &claims(&fixture.issuer), &key).unwrap();
        assert_eq!(
            auth.authenticate(Some(&signed), false)
                .await
                .unwrap_err()
                .code,
            "auth_invalid"
        );
    }
    let mut header = Header::new(Algorithm::HS256);
    header.typ = Some("at+jwt".into());
    header.kid = Some("first".into());
    let bad = encode(
        &header,
        &claims(&fixture.issuer),
        &EncodingKey::from_secret(b"synthetic"),
    )
    .unwrap();
    assert_eq!(
        auth.authenticate(Some(&bad), false).await.unwrap_err().code,
        "auth_invalid"
    );
    let signed = token(&fixture.issuer, "first", |_| {});
    let mut parts: Vec<String> = signed.split('.').map(str::to_owned).collect();
    let replacement = if parts[2].starts_with('a') { "b" } else { "a" };
    parts[2].replace_range(0..1, replacement);
    assert_eq!(
        auth.authenticate(Some(&parts.join(".")), false)
            .await
            .unwrap_err()
            .code,
        "auth_invalid"
    );
}

#[test]
fn configuration_rejects_incomplete_oauth_and_keeps_secrets_redacted() {
    assert!(
        AuthConfig {
            mode: AuthMode::Oauth2,
            oidc: None,
            client: None,
        }
        .validate()
        .is_err()
    );
    assert!(toml::from_str::<AuthConfig>("mode='oauth2'\nunknown='field'").is_err());
    assert!(toml::from_str::<OidcSecret>("literal='private'").is_err());
    let secret = OidcSecret {
        env: Some("PRIVATE_REFERENCE".into()),
        file: None,
    };
    assert_eq!(format!("{secret:?}"), "OidcSecret([redacted])");
}

#[tokio::test]
async fn section_reads_require_read_scope_and_stay_in_the_callers_workspace() {
    use pdf2md_mcp::{config::Config, service::CallerService};
    use std::{io::Write, path::Path, time::Duration};
    use tokio_util::sync::CancellationToken;

    let fixture = Fixture::new(TokenValidation::Introspection).await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let service = Arc::new(
        CallerService::new(
            dir.path(),
            Config {
                auth: fixture.config.clone(),
                ..Config::default()
            },
            None,
        )
        .await
        .unwrap(),
    );
    let cancel = CancellationToken::new();
    let mut upload = service.prepare_upload(Some("alice-token")).await.unwrap();
    upload.write_all(&conversion_pdf::sample_pdf()).unwrap();
    let conversion = service
        .finish_upload(upload, &cancel)
        .await
        .unwrap()
        .conversion_job
        .unwrap()
        .id;
    let runner = {
        let service = service.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            service
                .run(
                    Path::new("unused-browser-worker"),
                    Path::new(env!("CARGO_BIN_EXE_pdf2md-convert-worker")),
                    &cancel,
                )
                .await
                .unwrap();
        })
    };
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let job = service
                .get_job(Some("alice-token"), &conversion)
                .await
                .unwrap();
            if job.status == "succeeded" {
                break;
            }
            assert!(
                job.status == "queued" || job.status == "running",
                "{}",
                job.status
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    cancel.cancel();
    runner.await.unwrap();
    let request_cancel = CancellationToken::new();
    fixture.introspection.lock().unwrap()["scope"] = json!("pdf2md:read");
    let inventory = service
        .call_tool(
            Some("alice-readonly"),
            "list",
            json!({"kind":"blocks","conversion_id":conversion}),
            &request_cancel,
        )
        .await
        .unwrap()
        .data;
    let args = json!({"conversion_id":conversion,"selectors":[{"kind":"block","id":inventory["items"][0]["id"]}]});
    let read = service
        .call_tool(
            Some("alice-readonly"),
            "read-section",
            args.clone(),
            &request_cancel,
        )
        .await
        .unwrap()
        .data;
    assert!(read["bytes"].as_u64().unwrap() > 0);
    fixture.introspection.lock().unwrap()["sub"] = json!("bob");
    assert_eq!(
        service
            .call_tool(
                Some("bob-token"),
                "read-section",
                args.clone(),
                &request_cancel
            )
            .await
            .err()
            .unwrap()
            .code,
        "conversion_not_found"
    );
    fixture.introspection.lock().unwrap()["sub"] = json!("alice");
    fixture.introspection.lock().unwrap()["scope"] = json!("pdf2md:write");
    assert_eq!(
        service
            .call_tool(
                Some("alice-writeonly"),
                "read-section",
                args,
                &request_cancel
            )
            .await
            .err()
            .unwrap()
            .code,
        "auth_forbidden"
    );
}

#[tokio::test]
async fn caller_boundary_keeps_user_history_and_known_pdf_hashes_private() {
    use pdf2md_mcp::{
        config::Config,
        service::{CallerService, Operation, Response},
        storage::Store,
        workspace::WorkspaceRegistry,
    };
    use std::io::Write;
    use tokio_util::sync::CancellationToken;
    let fixture = Fixture::new(TokenValidation::Introspection).await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let registry = WorkspaceRegistry::open(dir.path()).await.unwrap();
    let alice = registry
        .resolve_identity(&fixture.issuer, "alice", None)
        .await
        .unwrap();
    let store = Store::open(&alice, None).await.unwrap();
    let mut input = store.staging_file().unwrap();
    input
        .write_all(b"%PDF-1.7\nsynthetic-private-alice")
        .unwrap();
    let observation = store
        .accept(input.path(), "same-source", "https", None, "same-attempt")
        .await
        .unwrap();
    let document_id = observation.document_id.unwrap();
    drop(input);
    drop(store);
    drop(registry);
    let service = CallerService::new(
        dir.path(),
        Config {
            auth: fixture.config.clone(),
            ..Config::default()
        },
        None,
    )
    .await
    .unwrap();
    let cancel = CancellationToken::new();
    let Response::Observations(history) = service
        .execute(
            Some("alice-token"),
            Operation::History { source: None },
            &cancel,
        )
        .await
        .unwrap()
    else {
        panic!("history response")
    };
    assert_eq!(history.len(), 1);
    fixture.introspection.lock().unwrap()["sub"] = json!("bob");
    let Response::Observations(history) = service
        .execute(
            Some("bob-token"),
            Operation::History { source: None },
            &cancel,
        )
        .await
        .unwrap()
    else {
        panic!("history response")
    };
    assert!(history.is_empty());
    let error = service
        .execute(
            Some("bob-token"),
            Operation::ReadPdf {
                document_id: document_id.clone(),
            },
            &cancel,
        )
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, "document_not_found");
    fixture.introspection.lock().unwrap()["sub"] = json!("alice");
    let Response::Pdf(mut stream) = service
        .execute(
            Some("alice-token"),
            Operation::ReadPdf { document_id },
            &cancel,
        )
        .await
        .unwrap()
    else {
        panic!("PDF response")
    };
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"%PDF-1.7\nsynthetic-private-alice");
    fixture.introspection.lock().unwrap()["sub"] = json!("no-scope-user");
    fixture.introspection.lock().unwrap()["scope"] = json!("");
    assert_eq!(
        service
            .execute(
                Some("no-scope-token"),
                Operation::History { source: None },
                &cancel
            )
            .await
            .err()
            .unwrap()
            .code,
        "auth_forbidden"
    );
    let registry = WorkspaceRegistry::open(dir.path()).await.unwrap();
    assert_eq!(registry.list().await.unwrap().len(), 2);
}

#[tokio::test]
async fn introspection_requires_a_token_class_and_accepts_explicit_prefix() {
    let mut fixture = Fixture::new(TokenValidation::Introspection).await;
    fixture
        .introspection
        .lock()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("token_type");
    let strict = Authenticator::new(fixture.config.clone()).await.unwrap();
    assert_eq!(
        strict
            .authenticate(Some("vendor_at_synthetic"), false)
            .await
            .unwrap_err()
            .code,
        "auth_invalid"
    );
    fixture.config.oidc.as_mut().unwrap().access_token_prefix = Some("vendor_at_".into());
    let prefixed = Authenticator::new(fixture.config.clone()).await.unwrap();
    prefixed
        .authenticate(Some("vendor_at_synthetic"), true)
        .await
        .unwrap();
    let requests = fixture.intro_count.load(Ordering::SeqCst);
    for token in ["vendor_rt_synthetic", "vendor_ac_synthetic", "unprefixed"] {
        assert_eq!(
            prefixed
                .authenticate(Some(token), false)
                .await
                .unwrap_err()
                .code,
            "auth_invalid"
        );
    }
    assert_eq!(fixture.intro_count.load(Ordering::SeqCst), requests);
    for (field, value) in [
        ("token_type", json!("refresh_token")),
        ("token_use", json!("refresh_token")),
        ("active", json!(false)),
        ("aud", json!("other-service")),
    ] {
        let mut response = claims(&fixture.issuer);
        response.as_object_mut().unwrap().remove("token_type");
        response[field] = value;
        *fixture.introspection.lock().unwrap() = response;
        assert_eq!(
            prefixed
                .authenticate(Some("vendor_at_synthetic"), false)
                .await
                .unwrap_err()
                .code,
            "auth_invalid"
        );
    }
    for prefix in ["", "has whitespace", "not.a.prefix", &"a".repeat(129)] {
        fixture.config.oidc.as_mut().unwrap().access_token_prefix = Some(prefix.into());
        assert!(fixture.config.validate().is_err());
    }
    let oidc = fixture.config.oidc.as_mut().unwrap();
    oidc.access_token_prefix = Some("vendor_at_".into());
    oidc.validation = TokenValidation::Jwt;
    assert!(fixture.config.validate().is_err());
}

#[tokio::test]
async fn jwt_scp_array_grants_only_explicitly_selected_valid_scopes() {
    let mut fixture = Fixture::new(TokenValidation::Jwt).await;
    fixture.config.oidc.as_mut().unwrap().jwt_scope_claim = "scp".into();
    let selected = Authenticator::new(fixture.config.clone()).await.unwrap();
    let full = token(&fixture.issuer, "first", |claims| {
        claims.as_object_mut().unwrap().remove("scope");
        claims["scp"] = json!(["pdf2md:read", "pdf2md:write"]);
    });
    selected.authenticate(Some(&full), true).await.unwrap();
    // A conflicting unselected scope claim cannot remove or add permissions.
    let dual = token(&fixture.issuer, "first", |claims| {
        claims["scope"] = json!("unselected");
        claims["scp"] = json!(["pdf2md:read", "pdf2md:write"]);
    });
    selected.authenticate(Some(&dual), true).await.unwrap();
    let readonly = token(&fixture.issuer, "first", |claims| {
        claims["scp"] = json!(["pdf2md:read"])
    });
    selected.authenticate(Some(&readonly), false).await.unwrap();
    assert_eq!(
        selected
            .authenticate(Some(&readonly), true)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    let missing = token(&fixture.issuer, "first", |_| {});
    assert_eq!(
        selected
            .authenticate(Some(&missing), false)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    let empty = token(&fixture.issuer, "first", |claims| claims["scp"] = json!([]));
    assert_eq!(
        selected
            .authenticate(Some(&empty), false)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    for malformed in [
        json!("pdf2md:read pdf2md:write"),
        json!({"pdf2md:read":true}),
        json!(["pdf2md:read", 123]),
        json!(["pdf2md:read pdf2md:write"]),
        json!([""]),
    ] {
        let bad = token(&fixture.issuer, "first", |claims| claims["scp"] = malformed);
        assert_eq!(
            selected
                .authenticate(Some(&bad), false)
                .await
                .unwrap_err()
                .code,
            "auth_invalid"
        );
    }
    fixture.config.oidc.as_mut().unwrap().jwt_scope_claim = "scope".into();
    let default_claim = Authenticator::new(fixture.config.clone()).await.unwrap();
    // Unselected scp grants no permission, even if it contains the write scope.
    let only_scp = token(&fixture.issuer, "first", |claims| {
        claims.as_object_mut().unwrap().remove("scope");
        claims["scp"] = json!(["pdf2md:read", "pdf2md:write"]);
    });
    assert_eq!(
        default_claim
            .authenticate(Some(&only_scp), false)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    let conflict = token(&fixture.issuer, "first", |claims| {
        claims["scope"] = json!("pdf2md:read");
        claims["scp"] = json!(["pdf2md:read", "pdf2md:write"]);
    });
    assert_eq!(
        default_claim
            .authenticate(Some(&conflict), true)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    let ignored_extension = token(&fixture.issuer, "first", |claims| {
        claims["scp"] = json!("ignored-extension")
    });
    default_claim
        .authenticate(Some(&ignored_extension), true)
        .await
        .unwrap();
    fixture.config.oidc.as_mut().unwrap().jwt_scope_claim = "unrecognized".into();
    assert!(fixture.config.validate().is_err());
    let oidc = fixture.config.oidc.as_mut().unwrap();
    oidc.validation = TokenValidation::Introspection;
    oidc.jwt_scope_claim = "scp".into();
    assert!(fixture.config.validate().is_err());
}

async fn seed_pdf(root: &std::path::Path, label: &str, bytes: &[u8]) -> String {
    use pdf2md_mcp::storage::Store;
    use std::io::Write;
    let store = Store::open(root, None).await.unwrap();
    let mut input = store.staging_file().unwrap();
    input.write_all(bytes).unwrap();
    store
        .accept(input.path(), label, "manual", None, "attempt")
        .await
        .unwrap()
        .document_id
        .unwrap()
}

#[tokio::test]
async fn active_pdf_streams_pin_all_32_workspaces_and_idle_eviction_recovers_capacity() {
    use pdf2md_mcp::{
        config::Config,
        service::{CallerService, Operation, Response},
        storage::Store,
        workspace::WorkspaceRegistry,
    };
    use tokio_util::sync::CancellationToken;
    let fixture = Fixture::new(TokenValidation::Introspection).await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let registry = WorkspaceRegistry::open(dir.path()).await.unwrap();
    let bytes = b"%PDF-1.7\ncache-pressure-synthetic";
    let mut roots = Vec::new();
    let mut document_id = String::new();
    for user in 0..33 {
        let path = registry
            .resolve_identity(&fixture.issuer, &format!("user-{user}"), None)
            .await
            .unwrap();
        document_id = seed_pdf(&path, "same-source", bytes).await;
        roots.push(path);
    }
    let service = CallerService::new(
        dir.path(),
        Config {
            auth: fixture.config.clone(),
            http: pdf2md_mcp::config::HttpConfig {
                downloads: 64,
                ..Default::default()
            },
            ..Config::default()
        },
        None,
    )
    .await
    .unwrap();
    let cancel = CancellationToken::new();
    let mut streams = Vec::new();
    for user in 0..32 {
        fixture.introspection.lock().unwrap()["sub"] = json!(format!("user-{user}"));
        let Response::Pdf(stream) = service
            .execute(
                Some("synthetic-token"),
                Operation::ReadPdf {
                    document_id: document_id.clone(),
                },
                &cancel,
            )
            .await
            .unwrap()
        else {
            panic!("PDF response")
        };
        streams.push(stream);
    }
    // Existing cached workspaces remain usable concurrently at full capacity.
    let (first, second) = tokio::join!(
        service.execute(Some("synthetic-token"), Operation::Status, &cancel),
        service.execute(
            Some("synthetic-token"),
            Operation::History { source: None },
            &cancel
        )
    );
    assert!(first.is_ok());
    assert!(second.is_ok());
    fixture.introspection.lock().unwrap()["sub"] = json!("user-32");
    assert_eq!(
        service
            .execute(
                Some("synthetic-token"),
                Operation::ReadPdf {
                    document_id: document_id.clone()
                },
                &cancel
            )
            .await
            .err()
            .unwrap()
            .code,
        "service_busy"
    );
    drop(streams.remove(0));
    let Response::Pdf(mut newest) = service
        .execute(
            Some("synthetic-token"),
            Operation::ReadPdf { document_id },
            &cancel,
        )
        .await
        .unwrap()
    else {
        panic!("PDF response")
    };
    // The released stream permits its idle store to be evicted and reopened.
    let reopened = Store::open(&roots[0], None).await.unwrap();
    assert_eq!(reopened.history(None).await.unwrap().len(), 1);
    drop(reopened);
    let mut output = Vec::new();
    newest.read_to_end(&mut output).await.unwrap();
    assert_eq!(output, bytes);
    output.clear();
    streams[0].read_to_end(&mut output).await.unwrap();
    assert_eq!(output, bytes);
    drop(service);
    // Streams retain ownership even after their host is dropped.
    assert_eq!(
        Store::open(&roots[1], None).await.err().unwrap().code,
        "storage_locked"
    );
    drop(streams);
    drop(newest);
    assert!(Store::open(&roots[1], None).await.is_ok());
}

#[tokio::test]
async fn oauth_and_both_anonymous_modes_preserve_and_hide_each_others_data() {
    use pdf2md_mcp::{
        config::Config,
        service::{CallerService, Operation, Response},
        storage::Store,
        workspace::WorkspaceRegistry,
    };
    use tokio_util::sync::CancellationToken;
    let fixture = Fixture::new(TokenValidation::Introspection).await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let operator_id = seed_pdf(dir.path(), "operator-only", b"%PDF-1.7\noperator-private").await;
    let registry = WorkspaceRegistry::open(dir.path()).await.unwrap();
    let shared = registry.resolve_shared(None).await.unwrap();
    let shared_id = seed_pdf(&shared, "shared-only", b"%PDF-1.7\nanonymous-shared").await;
    let alice = registry
        .resolve_identity(&fixture.issuer, "alice", None)
        .await
        .unwrap();
    let alice_id = seed_pdf(&alice, "alice-only", b"%PDF-1.7\nalice-private").await;
    let cancel = CancellationToken::new();
    for auth in [
        fixture.config.clone(),
        AuthConfig {
            mode: AuthMode::NoneRo,
            oidc: None,
            client: None,
        },
        AuthConfig {
            mode: AuthMode::NoneRw,
            oidc: None,
            client: None,
        },
        fixture.config.clone(),
    ] {
        let private = auth.mode == AuthMode::Oauth2;
        let service = CallerService::new(
            dir.path(),
            Config {
                auth,
                ..Config::default()
            },
            None,
        )
        .await
        .unwrap();
        let Response::Observations(history) = service
            .execute(
                Some("alice-token"),
                Operation::History { source: None },
                &cancel,
            )
            .await
            .unwrap()
        else {
            panic!("history response")
        };
        assert_eq!(history.len(), 1);
        assert_eq!(
            history[0].source_id,
            if private { "alice-only" } else { "shared-only" }
        );
        let visible_id = if private { &alice_id } else { &shared_id };
        let hidden_id = if private { &shared_id } else { &alice_id };
        let Response::Pdf(mut stream) = service
            .execute(
                Some("alice-token"),
                Operation::ReadPdf {
                    document_id: visible_id.clone(),
                },
                &cancel,
            )
            .await
            .unwrap()
        else {
            panic!("PDF response")
        };
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(
            bytes,
            if private {
                b"%PDF-1.7\nalice-private".as_slice()
            } else {
                b"%PDF-1.7\nanonymous-shared".as_slice()
            }
        );
        for hidden in [hidden_id, &operator_id] {
            assert_eq!(
                service
                    .execute(
                        Some("alice-token"),
                        Operation::ReadPdf {
                            document_id: hidden.clone()
                        },
                        &cancel
                    )
                    .await
                    .err()
                    .unwrap()
                    .code,
                "document_not_found"
            );
        }
        drop(stream);
        drop(service);
    }
    assert_eq!(
        Store::read_history(dir.path(), None, None).await.unwrap()[0].source_id,
        "operator-only"
    );
    assert_eq!(registry.list().await.unwrap().len(), 2);
}

// Deliberately public, generated synthetic RSA key, used only for token fixtures.
const TEST_KEY: &str = include_str!("common/synthetic-rsa-key.pem");
const TEST_MODULUS: &str = "kfqAX58zY9qGTqRr7sSfhilbOHoPaSVCvYdAEUz2xynP33YNPQzrJMTh5A4dnPeyH5NENDxTsTm0amkXNt7SoBL4oz70N0Aeb3EEl12LaVV-T6Rsg7gN_daWrUMp5FqKYsX4xPlZcUYfHV0AlVQYY76GBEb4MM_LpkmNwxv9DVUtPxf0WmahmBk4qaksK521F6i7MG4YdjjhngVj0Hhj7M2ZOOtn5cp9dGYUZ0jTIz95Vm-_gztlh0LS0f4I8yKkEBhw4uOF8GQXtPjDdLZBGyi2Dr8-uvCwygfO-3RPxHbUgbD6XDS8YeLq02hr54B-WGSCsTJtC4lxn0sFQygolw";

#[tokio::test]
async fn operate_scope_is_additional_to_read_and_write_for_introspection_and_jwt() {
    for validation in [TokenValidation::Introspection, TokenValidation::Jwt] {
        let fixture = Fixture::new(validation).await;
        let auth = Authenticator::new(fixture.config.clone()).await.unwrap();
        let missing = match validation {
            TokenValidation::Introspection => "synthetic-opaque".to_owned(),
            TokenValidation::Jwt => token(&fixture.issuer, "first", |_| {}),
        };
        assert_eq!(
            auth.authorize(Some(&missing), true, true)
                .await
                .unwrap_err()
                .code,
            "auth_forbidden"
        );
        assert!(auth.authenticate(Some(&missing), true).await.is_ok());
        fixture.introspection.lock().unwrap()["scope"] =
            json!("pdf2md:read pdf2md:write pdf2md:operate");
        let granted = match validation {
            TokenValidation::Introspection => "synthetic-opaque".to_owned(),
            TokenValidation::Jwt => token(&fixture.issuer, "first", |claims| {
                claims["scope"] = json!("pdf2md:read pdf2md:write pdf2md:operate")
            }),
        };
        assert!(auth.authorize(Some(&granted), true, true).await.is_ok());
        fixture.introspection.lock().unwrap()["scope"] = json!("pdf2md:read pdf2md:operate");
        let no_write = match validation {
            TokenValidation::Introspection => "synthetic-opaque".to_owned(),
            TokenValidation::Jwt => token(&fixture.issuer, "first", |claims| {
                claims["scope"] = json!("pdf2md:read pdf2md:operate")
            }),
        };
        assert_eq!(
            auth.authorize(Some(&no_write), true, true)
                .await
                .unwrap_err()
                .code,
            "auth_forbidden"
        );
    }
    let fixture = Fixture::new(TokenValidation::Jwt).await;
    let mut config = fixture.config.clone();
    config.oidc.as_mut().unwrap().operate_scope = "pdf2md:write".into();
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn durable_jobs_are_private_and_global_capacity_covers_multiple_identities() {
    use pdf2md_mcp::{
        config::{Config, Mode, Source},
        service::CallerService,
    };
    let fixture = Fixture::new(TokenValidation::Introspection).await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = Config {
        auth: fixture.config.clone(),
        ..Config::default()
    };
    config.conversion.enabled = false;
    config.http.per_workspace_jobs = 2;
    config.http.total_jobs = 2;
    let mut source = Source::one_off("https://example.com/operator.pdf".into(), Mode::Https);
    source.id = "operator".into();
    source.interval_secs = Some(60);
    config.sources.push(source);
    config.http.published_sources.push("operator".into());
    let service = CallerService::new(dir.path(), config, None).await.unwrap();
    assert_eq!(
        service
            .submit_source(Some("alice"), "operator", None)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    fixture.introspection.lock().unwrap()["scope"] =
        json!("pdf2md:read pdf2md:write pdf2md:operate");
    let alice = service
        .submit_source(Some("alice"), "operator", Some("same-key"))
        .await
        .unwrap();
    assert!(
        service
            .set_schedule(Some("alice"), "operator", true)
            .await
            .unwrap()
            .enabled
    );
    fixture.introspection.lock().unwrap()["sub"] = json!("bob");
    assert!(service.jobs(Some("bob")).await.unwrap().is_empty());
    assert!(service.schedules(Some("bob")).await.unwrap().is_empty());
    assert_eq!(
        service
            .get_job(Some("bob"), &alice.id)
            .await
            .unwrap_err()
            .code,
        "job_not_found"
    );
    assert_eq!(
        service
            .cancel_job(Some("bob"), &alice.id)
            .await
            .unwrap_err()
            .code,
        "job_not_found"
    );
    let bob = service
        .submit_source(Some("bob"), "operator", Some("same-key"))
        .await
        .unwrap();
    assert_ne!(alice.id, bob.id);
    assert_eq!(
        service
            .submit_acquisition(Some("bob"), "https://example.com/third.pdf".into(), None)
            .await
            .unwrap_err()
            .code,
        "job_capacity"
    );
    fixture.introspection.lock().unwrap()["sub"] = json!("alice");
    assert_eq!(
        service
            .submit_source(Some("alice"), "operator", Some("same-key"))
            .await
            .unwrap()
            .id,
        alice.id
    );
    fixture.introspection.lock().unwrap()["active"] = json!(false);
    assert_eq!(
        service.jobs(Some("alice")).await.unwrap_err().code,
        "auth_invalid"
    );
}

#[tokio::test]
async fn casdoor_jwt_profile_requires_signed_access_token_class_and_azp() {
    let mut fixture = Fixture::new(TokenValidation::Jwt).await;
    fixture.config.oidc.as_mut().unwrap().token_profile = TokenProfile::Casdoor;
    let auth = Authenticator::new(fixture.config.clone()).await.unwrap();
    let issuer = fixture.issuer.clone();
    assert_eq!(
        auth.authenticate(Some(&casdoor_token(&issuer, "first", |_| {})), true)
            .await
            .unwrap(),
        Identity::User {
            issuer: issuer.clone(),
            subject: "alice".into()
        }
    );
    for token in [
        // Casdoor refresh and ID tokens share the signing key and format.
        casdoor_token(&issuer, "first", |c| {
            c["tokenType"] = json!("refresh-token")
        }),
        casdoor_token(&issuer, "first", |c| c["tokenType"] = json!("id-token")),
        casdoor_token(&issuer, "first", |c| {
            c.as_object_mut().unwrap().remove("tokenType");
        }),
        casdoor_token(&issuer, "first", |c| {
            c.as_object_mut().unwrap().remove("azp");
        }),
        casdoor_token(&issuer, "first", |c| c["aud"] = json!(["pdf2md-test"])),
        // The RFC 9068 header type is not part of the Casdoor profile.
        token(&issuer, "first", |c| c["tokenType"] = json!("access-token")),
    ] {
        assert_eq!(
            auth.authenticate(Some(&token), false)
                .await
                .unwrap_err()
                .code,
            "auth_invalid"
        );
    }
    // The default RFC 9068 profile rejects Casdoor's generic JWT type.
    fixture.config.oidc.as_mut().unwrap().token_profile = TokenProfile::Rfc9068;
    let strict = Authenticator::new(fixture.config.clone()).await.unwrap();
    assert_eq!(
        strict
            .authenticate(Some(&casdoor_token(&issuer, "first", |_| {})), false)
            .await
            .unwrap_err()
            .code,
        "auth_invalid"
    );
}

#[tokio::test]
async fn additional_audiences_accept_client_bound_grants_in_both_validators() {
    let mut fixture = Fixture::new(TokenValidation::Jwt).await;
    let issuer = fixture.issuer.clone();
    let oidc = fixture.config.oidc.as_mut().unwrap();
    oidc.token_profile = TokenProfile::Casdoor;
    let machine = casdoor_token(&issuer, "first", |c| {
        c["aud"] = json!(["pdf2md-machine"]);
        c["sub"] = json!("admin/pdf2md-machine");
    });
    let auth = Authenticator::new(fixture.config.clone()).await.unwrap();
    assert!(auth.authenticate(Some(&machine), false).await.is_err());
    fixture.config.oidc.as_mut().unwrap().additional_audiences = vec!["pdf2md-machine".into()];
    let auth = Authenticator::new(fixture.config.clone()).await.unwrap();
    assert_eq!(
        auth.authenticate(Some(&machine), false).await.unwrap(),
        Identity::User {
            issuer: issuer.clone(),
            subject: "admin/pdf2md-machine".into()
        }
    );
    let other = casdoor_token(&issuer, "first", |c| c["aud"] = json!(["other-client"]));
    assert!(auth.authenticate(Some(&other), false).await.is_err());

    let mut introspection = Fixture::new(TokenValidation::Introspection).await;
    introspection
        .config
        .oidc
        .as_mut()
        .unwrap()
        .additional_audiences = vec!["pdf2md-machine".into()];
    introspection.introspection.lock().unwrap()["aud"] = json!(["pdf2md-machine"]);
    let auth = Authenticator::new(introspection.config.clone())
        .await
        .unwrap();
    auth.authenticate(Some("opaque"), false).await.unwrap();

    for audiences in [
        vec![String::new()],
        vec!["https://pdf2md.example/mcp".into()],
        vec!["bad\u{7}".into()],
        (0..17).map(|i| format!("client-{i}")).collect(),
    ] {
        fixture.config.oidc.as_mut().unwrap().additional_audiences = audiences;
        assert!(fixture.config.validate().is_err());
    }
}

#[tokio::test]
async fn casdoor_introspection_rejects_refresh_tokens_before_and_after_provider_lookup() {
    let mut fixture = Fixture::new(TokenValidation::Introspection).await;
    fixture.config.oidc.as_mut().unwrap().token_profile = TokenProfile::Casdoor;
    let auth = Authenticator::new(fixture.config.clone()).await.unwrap();
    let issuer = fixture.issuer.clone();
    auth.authenticate(Some(&casdoor_token(&issuer, "first", |_| {})), true)
        .await
        .unwrap();
    let requests = fixture.intro_count.load(Ordering::SeqCst);
    // Casdoor's introspection reports refresh tokens as active Bearer tokens.
    for token in [
        casdoor_token(&issuer, "first", |c| {
            c["tokenType"] = json!("refresh-token")
        }),
        casdoor_token(&issuer, "first", |c| c["tokenType"] = json!("id-token")),
        casdoor_token(&issuer, "first", |c| {
            c.as_object_mut().unwrap().remove("jti");
        }),
        "opaque-not-a-jwt".into(),
        "a.%%%.c".into(),
    ] {
        assert_eq!(
            auth.authenticate(Some(&token), false)
                .await
                .unwrap_err()
                .code,
            "auth_invalid"
        );
    }
    assert_eq!(fixture.intro_count.load(Ordering::SeqCst), requests);
    // The introspected record must describe the same token.
    let other = casdoor_token(&issuer, "first", |c| c["jti"] = json!("another-token"));
    assert_eq!(
        auth.authenticate(Some(&other), false)
            .await
            .unwrap_err()
            .code,
        "auth_invalid"
    );
    for (prefix, claim) in [(Some("vendor_at_"), "scope"), (None, "scp")] {
        let oidc = fixture.config.oidc.as_mut().unwrap();
        oidc.access_token_prefix = prefix.map(Into::into);
        oidc.jwt_scope_claim = claim.into();
        oidc.validation = if claim == "scp" {
            TokenValidation::Jwt
        } else {
            TokenValidation::Introspection
        };
        assert!(fixture.config.validate().is_err());
    }
}

#[tokio::test]
async fn small_clock_skew_is_tolerated_for_issue_time_but_never_for_expiry() {
    let now = chrono::Utc::now().timestamp();
    let jwt = Fixture::new(TokenValidation::Jwt).await;
    let auth = Authenticator::new(jwt.config.clone()).await.unwrap();
    // A token issued by a provider whose clock is a few seconds ahead.
    let fresh = token(&jwt.issuer, "first", |claims| {
        claims["iat"] = json!(now + 5);
        claims["nbf"] = json!(now + 5);
    });
    auth.authenticate(Some(&fresh), false).await.unwrap();
    for (field, value) in [
        ("nbf", json!(now + 100)),
        ("iat", json!(now + 100)),
        ("exp", json!(now - 2)),
    ] {
        let bad = token(&jwt.issuer, "first", |claims| claims[field] = value);
        assert_eq!(
            auth.authenticate(Some(&bad), false).await.unwrap_err().code,
            "auth_invalid",
            "field {field}"
        );
    }

    let remote = Fixture::new(TokenValidation::Introspection).await;
    let auth = Authenticator::new(remote.config.clone()).await.unwrap();
    let mut response = claims(&remote.issuer);
    response["iat"] = json!(now + 5);
    response["nbf"] = json!(now + 5);
    *remote.introspection.lock().unwrap() = response;
    auth.authenticate(Some("opaque"), false).await.unwrap();
    let mut response = claims(&remote.issuer);
    response["exp"] = json!(now - 2);
    *remote.introspection.lock().unwrap() = response;
    assert_eq!(
        auth.authenticate(Some("opaque"), false)
            .await
            .unwrap_err()
            .code,
        "auth_invalid"
    );
}
