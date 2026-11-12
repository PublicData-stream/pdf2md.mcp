use crate::{
    config::{Header, Source},
    error::{LoadError, Result},
    model::Acquired,
    policy::{NetworkPolicy, origin, sanitized_url},
};
use futures_util::StreamExt;
use reqwest::{
    Client, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue, LOCATION},
};
use std::{
    collections::HashSet,
    path::Path,
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;

fn transport_error(e: reqwest::Error) -> LoadError {
    if e.is_timeout() {
        LoadError::transient("request_timeout", "HTTPS request timed out")
    } else if e.is_connect() {
        LoadError::transient(
            "connect_failed",
            "HTTPS connection or certificate verification failed",
        )
    } else {
        LoadError::transient("network_failed", "HTTPS transport failed")
    }
}

pub fn scoped_headers(headers: &[Header], url: &str) -> Result<HeaderMap> {
    let mut result = HeaderMap::new();
    for h in headers {
        if origin(&h.origin)? != origin(url)? {
            continue;
        }
        let name = HeaderName::from_bytes(h.name.as_bytes())
            .map_err(|_| LoadError::new("header_config", "invalid header name"))?;
        if [
            "host",
            "connection",
            "content-length",
            "transfer-encoding",
            "proxy-authorization",
            "proxy-connection",
            "upgrade",
        ]
        .contains(&name.as_str())
        {
            return Err(LoadError::new(
                "header_config",
                "transport control headers cannot be overridden",
            ));
        }
        let mut value = HeaderValue::from_str(&h.value.resolve()?)
            .map_err(|_| LoadError::new("header_config", "invalid header value"))?;
        value.set_sensitive(true);
        result.insert(name, value);
    }
    Ok(result)
}

pub async fn acquire(
    source: &Source,
    output: &Path,
    policy: &NetworkPolicy,
    max_bytes: u64,
    deadline: Instant,
) -> Result<Acquired> {
    acquire_inner(source, output, policy, max_bytes, deadline, None).await
}

async fn acquire_inner(
    source: &Source,
    output: &Path,
    policy: &NetworkPolicy,
    max_bytes: u64,
    deadline: Instant,
    additional_root: Option<reqwest::Certificate>,
) -> Result<Acquired> {
    let mut current = policy.validate_url(&source.url)?;
    current.set_fragment(None);
    let mut seen = HashSet::new();
    for _ in 0..=10 {
        if !seen.insert(current.as_str().to_owned()) {
            return Err(LoadError::new("redirect_loop", "HTTPS redirect loop"));
        }
        let addresses = policy.resolve(&current).await?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(LoadError::new("run_timeout", "loading deadline exceeded"));
        }
        crate::configure_tls();
        let mut builder = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve_to_addrs(current.host_str().expect("validated URL"), &addresses)
            .connect_timeout(Duration::from_secs(30).min(remaining))
            .timeout(remaining)
            .user_agent(concat!("pdf2md-mcp/", env!("CARGO_PKG_VERSION")));
        if let Some(root) = additional_root.clone() {
            builder = builder.add_root_certificate(root);
        }
        let client = builder
            .build()
            .map_err(|_| LoadError::new("transport_config", "cannot configure HTTPS client"))?;
        let response = client
            .get(current.clone())
            .headers(scoped_headers(&source.headers, current.as_str())?)
            .send()
            .await
            .map_err(transport_error)?;
        let status = response.status();
        if matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
            let next = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    LoadError::new("redirect_invalid", "redirect has no valid destination")
                })?;
            let mut target = current
                .join(next)
                .map_err(|_| LoadError::new("redirect_invalid", "invalid redirect destination"))?;
            target.set_fragment(None);
            current = policy.validate_url(target.as_str())?;
            continue;
        }
        if status != StatusCode::OK {
            let retryable = matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504);
            let mut e = LoadError::new(
                &format!("http_{}", status.as_u16()),
                "upstream returned an unsuccessful HTTP status",
            );
            e.retryable = retryable;
            e.retry_after_secs = response
                .headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok())
                .and_then(retry_after);
            return Err(e);
        }
        if response.content_length().is_some_and(|v| v > max_bytes) {
            return Err(LoadError::new(
                "size_limit",
                "PDF exceeds configured byte limit",
            ));
        }
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).truncate(true).create(true);
        #[cfg(unix)]
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let mut file = options.open(output).await.map_err(crate::error::io_error)?;
        let mut stream = response.bytes_stream();
        let mut bytes = 0u64;
        let mut prefix = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(transport_error)?;
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| LoadError::new("size_limit", "PDF exceeds byte limit"))?;
            if bytes > max_bytes {
                return Err(LoadError::new(
                    "size_limit",
                    "PDF exceeds configured byte limit",
                ));
            }
            if prefix.len() < 1024 {
                prefix.extend_from_slice(&chunk[..chunk.len().min(1024 - prefix.len())]);
            }
            file.write_all(&chunk)
                .await
                .map_err(crate::error::io_error)?;
        }
        if !prefix.windows(5).any(|w| w == b"%PDF-") {
            return Err(LoadError::new(
                "not_pdf",
                "response has no PDF header within the first 1024 bytes",
            ));
        }
        file.sync_all().await.map_err(crate::error::io_error)?;
        return Ok(Acquired {
            bytes,
            final_url: sanitized_url(current.as_str()).unwrap_or_default(),
        });
    }
    Err(LoadError::new(
        "redirect_limit",
        "HTTPS redirect limit exceeded",
    ))
}

pub fn retry_after(value: &str) -> Option<u64> {
    value.parse().ok().or_else(|| {
        httpdate::parse_http_date(value)
            .ok()?
            .duration_since(std::time::SystemTime::now())
            .ok()
            .map(|d| d.as_secs())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::{io::AsyncReadExt, net::TcpListener};

    pub(crate) async fn tls_fixture(
        response: Vec<u8>,
    ) -> (
        NetworkPolicy,
        reqwest::Certificate,
        tokio::task::JoinHandle<()>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["fixture.example".into()]).unwrap();
        let root = reqwest::Certificate::from_der(cert.cert.der()).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let policy = NetworkPolicy::test_fixture("fixture.example", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(stream).await else {
                return;
            };
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                match stream.read_u8().await {
                    Ok(v) => header.push(v),
                    Err(_) => return,
                }
            }
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        });
        (policy, root, handle)
    }

    #[tokio::test]
    async fn tls_pdf_is_stored_exactly_and_query_is_redacted() {
        let body = b"%PDF-1.7\nsynthetic\0payload\n%%EOF\n";
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend(body);
        let (policy, root, server) = tls_fixture(response).await;
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let path = dir.path().join("result.pdf");
        let source = Source::one_off(
            "https://fixture.example/a?token=private".into(),
            crate::config::Mode::Https,
        );
        let result = acquire_inner(
            &source,
            &path,
            &policy,
            1024,
            Instant::now() + Duration::from_secs(5),
            Some(root),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(path).await.unwrap(), body);
        assert_eq!(result.final_url, "https://fixture.example/");
        server.await.unwrap();
    }
    #[tokio::test]
    async fn chunked_body_cannot_evade_limit() {
        let response=b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8\r\n%PDF-1.7\r\n8\r\n12345678\r\n0\r\n\r\n".to_vec();
        let (policy, root, server) = tls_fixture(response).await;
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let source = Source::one_off(
            "https://fixture.example/pdf".into(),
            crate::config::Mode::Https,
        );
        let error = acquire_inner(
            &source,
            &d.path().join("out"),
            &policy,
            12,
            Instant::now() + Duration::from_secs(5),
            Some(root),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "size_limit");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn compressed_response_limit_counts_decoded_bytes() {
        // gzip.compress(b'%PDF-1.7\n' + b'x' * 4096, mtime=0).
        let compressed = [
            31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 237, 193, 49, 13, 0, 32, 12, 0, 176, 127, 62, 118,
            142, 100, 23, 6, 8, 55, 114, 144, 143, 15, 210, 54, 207, 218, 213, 99, 198, 5, 0, 0, 0,
            190, 247, 0, 175, 102, 118, 134, 9, 16, 0, 0,
        ];
        let mut response=format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",compressed.len()).into_bytes();
        response.extend(compressed);
        let (policy, root, server) = tls_fixture(response).await;
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let source = Source::one_off(
            "https://fixture.example/pdf".into(),
            crate::config::Mode::Https,
        );
        let error = acquire_inner(
            &source,
            &dir.path().join("out"),
            &policy,
            128,
            Instant::now() + Duration::from_secs(5),
            Some(root),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "size_limit");
        server.await.unwrap();
    }
    #[tokio::test]
    async fn https_downgrade_redirect_is_rejected() {
        let (policy,root,server)=tls_fixture(b"HTTP/1.1 302 Found\r\nLocation: http://fixture.example/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()).await;
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let source = Source::one_off(
            "https://fixture.example/pdf".into(),
            crate::config::Mode::Https,
        );
        let error = acquire_inner(
            &source,
            &d.path().join("out"),
            &policy,
            1024,
            Instant::now() + Duration::from_secs(5),
            Some(root),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "network_policy");
        server.await.unwrap();
    }
    #[tokio::test]
    async fn invalid_certificate_is_rejected() {
        let (policy, _, server) =
            tls_fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let source = Source::one_off(
            "https://fixture.example/pdf".into(),
            crate::config::Mode::Https,
        );
        assert!(
            acquire_inner(
                &source,
                &d.path().join("out"),
                &policy,
                1024,
                Instant::now() + Duration::from_secs(5),
                None
            )
            .await
            .is_err()
        );
        server.await.unwrap();
    }
    #[test]
    fn credentials_do_not_follow_cross_origin_requests() {
        use crate::config::Secret;
        let h = Header {
            name: "Authorization".into(),
            origin: "https://first.example".into(),
            value: Secret {
                literal: Some("Bearer private".into()),
                env: None,
                file: None,
            },
        };
        assert_eq!(
            scoped_headers(std::slice::from_ref(&h), "https://first.example/pdf")
                .unwrap()
                .len(),
            1
        );
        assert!(
            scoped_headers(&[h], "https://other.example/pdf")
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    #[ignore = "writes a 1024 MiB synthetic PDF under /tmp; run explicitly"]
    async fn direct_default_1024_mib_boundary() {
        use crate::model::DEFAULT_MAX_BYTES;
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {DEFAULT_MAX_BYTES}\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let offset = response.len();
        response.resize(offset + DEFAULT_MAX_BYTES as usize, b' ');
        response[offset..offset + 9].copy_from_slice(b"%PDF-1.7\n");
        let (policy, root, server) = tls_fixture(response).await;
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let path = dir.path().join("large.pdf");
        let source = Source::one_off(
            "https://fixture.example/pdf".into(),
            crate::config::Mode::Https,
        );
        let acquired = acquire_inner(
            &source,
            &path,
            &policy,
            DEFAULT_MAX_BYTES,
            Instant::now() + Duration::from_secs(120),
            Some(root),
        )
        .await
        .unwrap();
        assert_eq!(acquired.bytes, DEFAULT_MAX_BYTES);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), DEFAULT_MAX_BYTES);
        server.await.unwrap();
        let declared = DEFAULT_MAX_BYTES + 1;
        let (policy, root, server) = tls_fixture(
            format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n")
                .into_bytes(),
        )
        .await;
        let error = acquire_inner(
            &source,
            &path,
            &policy,
            DEFAULT_MAX_BYTES,
            Instant::now() + Duration::from_secs(5),
            Some(root),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "size_limit");
        server.await.unwrap();
    }
}
