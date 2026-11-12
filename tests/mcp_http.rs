use pdf2md_mcp::{config::Config, http, service::CallerService};
use rmcp::{
    ClientHandler, ClientLifecycleMode, ClientServiceExt, ServiceExt,
    model::{CallToolRequestParams, ClientConfig, ProtocolVersion},
    transport::StreamableHttpClientTransport,
};
use std::{io::Write, path::Path, sync::Arc, time::Duration};
#[path = "common/conversion_pdf.rs"]
mod conversion_pdf;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct LegacyClient;
impl ClientHandler for LegacyClient {
    fn get_info(&self) -> ClientConfig {
        let mut info = ClientConfig::default();
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info
    }
}

#[tokio::test]
async fn sdk_clients_discover_eight_tools_and_call_for_both_versions() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = Config::default();
    config.mcp.enabled = true;
    config.auth.mode = pdf2md_mcp::auth::AuthMode::NoneRw;
    let service = Arc::new(CallerService::new(dir.path(), config, None).await.unwrap());
    let mut upload = service.prepare_upload(None).await.unwrap();
    upload.write_all(&conversion_pdf::sample_pdf()).unwrap();
    let accepted = service
        .finish_upload(upload, &CancellationToken::new())
        .await
        .unwrap();
    let job = accepted.conversion_job.unwrap();
    let job_id = job.id.clone();
    let dispatch_cancel = CancellationToken::new();
    let dispatcher = service.clone();
    let dispatch_token = dispatch_cancel.clone();
    let dispatch = tokio::spawn(async move {
        dispatcher
            .run(
                Path::new("unused"),
                Path::new(env!("CARGO_BIN_EXE_pdf2md-convert-worker")),
                &dispatch_token,
            )
            .await
            .unwrap();
    });
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let state = service.get_job(None, &job_id).await.unwrap();
            if state.status == "succeeded" {
                break;
            }
            assert!(
                state.status == "queued" || state.status == "running",
                "conversion failed: {}",
                state.status
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    dispatch_cancel.cancel();
    dispatch.await.unwrap();
    let cancel = CancellationToken::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let markdown = service
        .call_tool(
            None,
            "read",
            serde_json::json!({"conversion_id":job_id}),
            &cancel,
        )
        .await
        .unwrap()
        .text
        .unwrap();
    let app = http::router(service, cancel.clone());
    let shutdown = cancel.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .unwrap()
    });
    let modern = ()
        .serve_with_lifecycle(
            StreamableHttpClientTransport::from_uri(url.clone()),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .unwrap();
    let list = modern.list_tools(None).await.unwrap();
    assert_eq!(list.tools.len(), 8);
    let section_tool = list
        .tools
        .iter()
        .find(|t| t.name == "read-section")
        .unwrap();
    assert_eq!(
        section_tool.annotations.as_ref().unwrap().read_only_hint,
        Some(true)
    );
    assert_eq!(
        section_tool.input_schema["properties"]["selectors"]["maxItems"],
        500
    );
    let inventory = modern
        .call_tool(
            CallToolRequestParams::new("list").with_arguments(
                serde_json::json!({"kind":"blocks","conversion_id":job_id})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .unwrap()
        .structured_content
        .unwrap();
    let span = &inventory["items"][0];
    let section_args =
        serde_json::json!({"conversion_id":job_id,"selectors":[{"kind":"block","id":span["id"]}]});
    let expected_text =
        &markdown[span["start"].as_u64().unwrap() as usize..span["end"].as_u64().unwrap() as usize];
    let output = modern
        .call_tool(CallToolRequestParams::new("list"))
        .await
        .unwrap();
    assert_eq!(output.is_error, Some(false));
    for (name, args) in [
        ("read", serde_json::json!({"conversion_id":job_id})),
        ("read-section", section_args.clone()),
        (
            "read-page",
            serde_json::json!({"conversion_id":job_id,"pages":"1"}),
        ),
        ("table", serde_json::json!({"conversion_id":job_id})),
        ("count", serde_json::json!({"conversion_id":job_id})),
        ("size", serde_json::json!({"conversion_id":job_id})),
        (
            "rg",
            serde_json::json!({"pattern":"First","conversion_ids":[job_id]}),
        ),
    ] {
        let result = modern
            .call_tool(
                CallToolRequestParams::new(name).with_arguments(args.as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(false), "{name}: {result:?}");
        if name == "read-section" {
            let data = result.structured_content.as_ref().unwrap();
            assert_eq!(data["results"][0]["text"], expected_text);
            assert_eq!(data["results"][0]["span"], *span);
            let text = result.content[0].as_text().unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&text.text).unwrap(),
                *data
            );
        }
    }
    let error = modern
        .call_tool(CallToolRequestParams::new("read-section"))
        .await
        .unwrap();
    assert_eq!(error.is_error, Some(true));
    assert_eq!(
        error.structured_content.unwrap()["code"],
        "invalid_arguments"
    );
    modern.cancel().await.unwrap();
    let legacy = LegacyClient
        .serve(StreamableHttpClientTransport::from_uri(url))
        .await
        .unwrap();
    assert_eq!(
        legacy.peer_info().unwrap().protocol_version,
        ProtocolVersion::V_2025_11_25
    );
    assert_eq!(legacy.list_tools(None).await.unwrap().tools.len(), 8);
    for (name, args) in [
        ("list", serde_json::json!({})),
        ("read", serde_json::json!({"conversion_id":job_id})),
        ("read-section", section_args),
        (
            "read-page",
            serde_json::json!({"conversion_id":job_id,"pages":"1"}),
        ),
        ("table", serde_json::json!({"conversion_id":job_id})),
        ("count", serde_json::json!({"conversion_id":job_id})),
        ("size", serde_json::json!({"conversion_id":job_id})),
        (
            "rg",
            serde_json::json!({"pattern":"First","conversion_ids":[job_id]}),
        ),
    ] {
        let result = legacy
            .call_tool(
                CallToolRequestParams::new(name).with_arguments(args.as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(false), "legacy {name}: {result:?}");
        if name == "read-section" {
            assert_eq!(
                result.structured_content.unwrap()["results"][0]["text"],
                expected_text
            );
        }
    }
    let error = legacy
        .call_tool(CallToolRequestParams::new("read-section"))
        .await
        .unwrap();
    assert_eq!(error.is_error, Some(true));
    legacy.cancel().await.unwrap();
    cancel.cancel();
    server.await.unwrap();
}

#[tokio::test]
async fn oauth_challenges_and_metadata_and_origins_are_enforced() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = Config {
        auth: serde_json::from_value(serde_json::json!({"mode":"oauth2","oidc":{"issuer":"https://auth.example.com","audience":"existing-audience","validation":"jwt"}})).unwrap(),
        ..Config::default()
    };
    config.mcp.enabled = true;
    config.mcp.resource_url = Some("https://pdf.example.com/mcp".into());
    config.mcp.allowed_origins = vec!["https://client.example.com".into()];
    let service = Arc::new(CallerService::new(dir.path(), config, None).await.unwrap());
    let cancel = CancellationToken::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let shutdown = cancel.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, http::router(service, cancel))
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .unwrap()
    });
    let client = reqwest::Client::new();
    let response = client.post(format!("{url}/mcp")).send().await.unwrap();
    assert_eq!(response.status(), 401);
    let challenge = response.headers()["www-authenticate"].to_str().unwrap();
    assert!(challenge.contains("https://pdf.example.com/.well-known/oauth-protected-resource/mcp"));
    assert!(challenge.contains("pdf2md:read"));
    let response = client
        .get(format!("{url}/.well-known/oauth-protected-resource/mcp"))
        .send()
        .await
        .unwrap();
    let metadata: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(metadata["resource"], "https://pdf.example.com/mcp");
    assert_eq!(
        metadata["authorization_servers"][0],
        "https://auth.example.com"
    );
    assert_eq!(
        metadata["scopes_supported"],
        serde_json::json!(["pdf2md:read"])
    );
    let response = client
        .post(format!("{url}/mcp"))
        .header("origin", "https://client.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        401,
        "allowed origin reaches authentication"
    );
    let response = client
        .post(format!("{url}/mcp"))
        .header("authorization", "Bearer one")
        .header("authorization", "Bearer two")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert!(response.headers().contains_key("www-authenticate"));
    let response = client
        .post(format!("{url}/mcp"))
        .header("origin", "https://evil.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    server.abort();
}

#[test]
fn mcp_config_rejects_missing_resource_and_unbounded_limits() {
    let mut config = Config::default();
    config.mcp.enabled = true;
    config.mcp.search_max_limit = usize::MAX;
    assert!(config.validate().is_err());
    config.mcp.search_max_limit = 1000;
    config.auth = serde_json::from_value(serde_json::json!({"mode":"oauth2","oidc":{"issuer":"https://auth.example.com","audience":"existing-audience","validation":"jwt"}})).unwrap();
    assert!(config.validate().is_err());
    config.mcp.resource_url = Some("https://pdf.example.com/mcp".into());
    assert!(config.validate().is_ok());
}

#[tokio::test]
async fn disabled_endpoint_returns_not_found() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let service = Arc::new(
        CallerService::new(dir.path(), Config::default(), None)
            .await
            .unwrap(),
    );
    let cancel = CancellationToken::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, http::router(service, cancel))
            .await
            .unwrap()
    });
    assert_eq!(
        reqwest::Client::new()
            .post(url)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    server.abort();
}
