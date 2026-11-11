#[path = "common/conversion_pdf.rs"]
mod conversion_pdf;

use std::{sync::Arc, time::Duration};

use pdf2md_mcp::{auth::AuthMode, config::Config, http, service::CallerService};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

struct Server {
    _directory: tempfile::TempDir,
    service: Arc<CallerService>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    base: String,
    client: Client,
}

impl Server {
    async fn new(mode: AuthMode) -> Self {
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let mut config = Config::default();
        config.auth.mode = mode;
        let service = Arc::new(
            CallerService::new(directory.path(), config, None)
                .await
                .unwrap(),
        );
        let cancel = CancellationToken::new();
        let router = http::router(service.clone(), cancel.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            _directory: directory,
            service,
            cancel,
            task,
            base,
            client: Client::new(),
        }
    }
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
    async fn upload(&self, body: Vec<u8>, content_type: &str) -> reqwest::Response {
        self.client
            .post(self.url("/v1/documents"))
            .header("content-type", content_type)
            .body(body)
            .send()
            .await
            .unwrap()
    }
    async fn get(&self, path: &str) -> reqwest::Response {
        self.client.get(self.url(path)).send().await.unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

async fn json_body(response: reqwest::Response) -> Value {
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}

fn multipart(fields: &[(&str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, data) in fields {
        body.extend_from_slice(format!("--test-boundary\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"sample.pdf\"\r\nContent-Type: application/pdf\r\n\r\n").as_bytes());
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--test-boundary--\r\n");
    body
}

#[tokio::test]
async fn health_and_offline_docs_and_read_only_upload() {
    let server = Server::new(AuthMode::NoneRo).await;
    for path in [
        "/healthz",
        "/readyz",
        "/openapi.json",
        "/docs",
        "/docs.js",
        "/docs.css",
    ] {
        let response = server.get(path).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()["cache-control"], "no-store");
        let text = response.text().await.unwrap();
        if path.starts_with("/docs") {
            assert!(
                !text.contains("src=\"https://"),
                "external script in {path}"
            );
            assert!(
                !text.contains("href=\"https://"),
                "external stylesheet in {path}"
            );
            assert!(
                !text.contains("fetch(\"https://"),
                "external request in {path}"
            );
        }
        if path == "/openapi.json" {
            let spec: Value = serde_json::from_str(&text).unwrap();
            assert!(spec["paths"]["/v1/documents"].is_object());
        }
    }
    let denied = server
        .upload(conversion_pdf::sample_pdf(), "application/pdf")
        .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let history: Value = json_body(server.get("/v1/history").await).await;
    assert_eq!(history["items"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn uploads_pdf_multipart_and_paginates_history() {
    let server = Server::new(AuthMode::NoneRw).await;
    let pdf = conversion_pdf::sample_pdf();
    let response = server.upload(pdf.clone(), "application/pdf").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let first: Value = json_body(response).await;
    let document = first["observation"]["document_id"].as_str().unwrap();
    assert_eq!(first["conversion_job"]["status"], "queued");
    let response = server
        .upload(
            multipart(&[("file", &pdf)]),
            "multipart/form-data; boundary=test-boundary",
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let second: Value = json_body(response).await;
    assert_eq!(second["observation"]["document_id"], document);
    assert_eq!(
        second["conversion_job"]["id"],
        first["conversion_job"]["id"]
    );
    let response = server.get(&format!("/v1/documents/{document}/pdf")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes().await.unwrap().as_ref(), pdf);
    assert_eq!(
        server
            .get(&format!("/v1/documents/{}/pdf", "0".repeat(64)))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let first_page: Value = json_body(server.get("/v1/history?limit=1").await).await;
    assert_eq!(first_page["items"].as_array().unwrap().len(), 1);
    let cursor = first_page["next_cursor"].as_str().unwrap();
    let second_page: Value = json_body(
        server
            .get(&format!("/v1/history?limit=1&cursor={cursor}"))
            .await,
    )
    .await;
    assert_eq!(second_page["items"].as_array().unwrap().len(), 1);
    assert_ne!(
        first_page["items"][0]["attempt_id"],
        second_page["items"][0]["attempt_id"]
    );
    assert!(second_page["next_cursor"].is_null());
    for query in ["limit=0", "limit=1001", "cursor=bad"] {
        assert_eq!(
            server.get(&format!("/v1/history?{query}")).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn invalid_uploads_and_json_are_rejected_without_history() {
    let server = Server::new(AuthMode::NoneRw).await;
    let pdf = conversion_pdf::sample_pdf();
    for body in [
        multipart(&[("other", &pdf)]),
        multipart(&[("file", &pdf), ("file", &pdf)]),
        multipart(&[]),
    ] {
        assert_eq!(
            server
                .upload(body, "multipart/form-data; boundary=test-boundary")
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        server.upload(pdf, "text/plain").await.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert!(
        !server
            .upload(b"not a PDF".to_vec(), "application/pdf")
            .await
            .status()
            .is_success()
    );
    for data in [json!({}), json!({"url":"http://127.0.0.1/", "extra":true})] {
        let response = server
            .client
            .post(server.url("/v1/acquisitions"))
            .header("content-type", "application/json")
            .body(data.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let response = server
        .client
        .post(server.url("/v1/acquisitions"))
        .header("content-type", "application/json")
        .body(format!("{{\"url\":\"{}\"}}", "x".repeat(65536)))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let history: Value = json_body(server.get("/v1/history").await).await;
    assert_eq!(history["items"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn queued_conversion_produces_downloadable_bundle() {
    let server = Server::new(AuthMode::NoneRw).await;
    let uploaded: Value = json_body(
        server
            .upload(conversion_pdf::sample_pdf(), "application/pdf")
            .await,
    )
    .await;
    let job_id = uploaded["conversion_job"]["id"].as_str().unwrap();
    let service = server.service.clone();
    let cancel = server.cancel.clone();
    let worker = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pdf2md-convert-worker"));
    let dispatcher = tokio::spawn(async move {
        service
            .run(
                std::path::Path::new("unused-obscura-worker"),
                &worker,
                &cancel,
            )
            .await
            .unwrap();
    });
    let job = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let job: Value = json_body(server.get(&format!("/v1/jobs/{job_id}")).await).await;
            match job["status"].as_str().unwrap() {
                "succeeded" => break job,
                "failed" | "cancelled" | "interrupted" => panic!("conversion job failed: {job}"),
                _ => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .expect("conversion timed out");
    let conversion = job["conversion_id"].as_str().unwrap();
    let prefix = format!("/v1/conversions/{conversion}");
    let manifest: Value = json_body(server.get(&format!("{prefix}/manifest")).await).await;
    let markdown = server
        .get(&format!("{prefix}/markdown"))
        .await
        .text()
        .await
        .unwrap();
    assert!(markdown.contains("First page"));
    let asset = manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["path"].as_str())
        .find(|path| path.starts_with("assets/"))
        .expect("fixture image asset");
    let asset_response = server
        .get(&format!(
            "{prefix}/assets/{}",
            asset.trim_start_matches("assets/")
        ))
        .await;
    assert_eq!(asset_response.status(), StatusCode::OK);
    assert!(!asset_response.bytes().await.unwrap().is_empty());
    let bundle = server.get(&format!("{prefix}/bundle.zip")).await;
    assert_eq!(bundle.status(), StatusCode::OK);
    let bytes = bundle.bytes().await.unwrap();
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    assert!(archive.by_name("document.md").is_ok());
    assert!(archive.by_name("manifest.json").is_ok());
    assert!(archive.by_name(asset).is_ok());
    server.cancel.cancel();
    tokio::time::timeout(Duration::from_secs(10), dispatcher)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn disconnected_upload_does_not_publish_or_hold_admission() {
    use tokio::io::AsyncWriteExt;

    let server = Server::new(AuthMode::NoneRw).await;
    let address = server.base.strip_prefix("http://").unwrap();
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.write_all(b"POST /v1/documents HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/pdf\r\nContent-Length: 10000\r\n\r\n%PDF-1.4\n").await.unwrap();
    socket.shutdown().await.unwrap();
    drop(socket);
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let response = server
                .upload(conversion_pdf::sample_pdf(), "application/pdf")
                .await;
            if response.status() == StatusCode::CREATED {
                break json_body(response).await;
            }
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("upload admission was not released after disconnect");
    assert!(result["observation"]["document_id"].is_string());
    let history = json_body(server.get("/v1/history").await).await;
    assert_eq!(history["items"].as_array().unwrap().len(), 1);
}
