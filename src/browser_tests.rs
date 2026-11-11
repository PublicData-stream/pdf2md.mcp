use crate::{
    browser,
    model::{BrowserCookie, BrowserJob, BrowserStep},
    policy::{BrowserProxy, NetworkPolicy},
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

fn worker() -> PathBuf {
    std::env::var_os("PDF2MD_TEST_WORKER")
        .expect("PDF2MD_TEST_WORKER is required")
        .into()
}
fn pdf() -> Vec<u8> {
    let mut v = b"%PDF-1.7\n".to_vec();
    v.extend(vec![b'x'; 2 * 1024 * 1024]);
    v.extend(b"\n%%EOF\n");
    v
}

async fn fixture() -> (
    BrowserProxy,
    mpsc::UnboundedReceiver<String>,
    JoinHandle<()>,
) {
    let cert = std::fs::read(
        std::env::var_os("PDF2MD_TEST_CERT_FILE").expect("PDF2MD_TEST_CERT_FILE is required"),
    )
    .unwrap();
    let key = std::fs::read(
        std::env::var_os("PDF2MD_TEST_KEY_FILE").expect("PDF2MD_TEST_KEY_FILE is required"),
    )
    .unwrap();
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert)],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
        )
        .unwrap();
    let tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let policy = NetworkPolicy::test_fixture("fixture.example", listener.local_addr().unwrap());
    let proxy = BrowserProxy::start(policy).await.unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let tls = tls.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let Ok(mut socket) = tls.accept(socket).await else {
                    return;
                };
                let mut request = Vec::new();
                while request.len() < 16384 && !request.ends_with(b"\r\n\r\n") {
                    match socket.read_u8().await {
                        Ok(b) => request.push(b),
                        Err(_) => return,
                    }
                }
                let head = String::from_utf8_lossy(&request).to_string();
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or(0);
                if length > 16384 {
                    return;
                }
                let mut body = vec![0; length];
                if socket.read_exact(&mut body).await.is_err() {
                    return;
                }
                let request = format!("{}{}", head, String::from_utf8_lossy(&body));
                let _ = tx.send(request.clone());
                let path = request.lines().next().unwrap_or("");
                if path.contains("/hang") {
                    tokio::time::sleep(Duration::from_secs(45)).await;
                    return;
                }
                if path.contains("/rate") {
                    let _ = socket.write_all(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    return;
                }
                if path.contains("/large-exact") || path.contains("/large-over") {
                    let extra = usize::from(path.contains("/large-over"));
                    let len = 512usize * 1024 * 1024 + extra;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
                    );
                    if socket.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    let mut block = vec![b'x'; 1024 * 1024];
                    block[..9].copy_from_slice(b"%PDF-1.7\n");
                    if socket.write_all(&block).await.is_err() {
                        return;
                    }
                    block[..9].fill(b'x');
                    for _ in 1..512 {
                        if socket.write_all(&block).await.is_err() {
                            return;
                        }
                    }
                    if extra != 0 {
                        let _ = socket.write_all(b"x").await;
                    }
                    return;
                }
                if path.contains("/nav-large") {
                    let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 67108865\r\nConnection: close\r\n\r\n").await;
                    let block = vec![b'a'; 1024 * 1024];
                    for _ in 0..64 {
                        if socket.write_all(&block).await.is_err() {
                            return;
                        }
                    }
                    let _ = socket.write_all(b"a").await;
                    return;
                }
                if path.contains("/attack?") {
                    let target = path.split_whitespace().nth(1).unwrap();
                    let url = url::Url::parse(&format!("https://fixture.example{target}")).unwrap();
                    let values: std::collections::HashMap<_, _> =
                        url.query_pairs().into_owned().collect();
                    let html = format!(
                        "<html><body><script>fetch({}).then(r=>r.text()).then(x=>fetch('/leak?value='+x)).catch(()=>{{}})</script><script>fetch({}).then(()=>fetch('/private-hit')).catch(()=>{{}})</script><script>fetch('/pdf')</script></body></html>",
                        serde_json::to_string(values.get("file").unwrap()).unwrap(),
                        serde_json::to_string(values.get("local").unwrap()).unwrap()
                    );
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        html.len()
                    );
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(html.as_bytes()).await;
                    return;
                }
                let (kind, body) = if path.contains("/pdf") {
                    ("application/pdf", pdf())
                } else {
                    ("text/html", br#"<html><body><input id="secret"><button id="go">Go</button><a id="link" href="/pdf">PDF</a><form action="/pdf" method="post"><input name="token" value="form-value"><button id="submit" type="submit">Submit</button></form><script>document.querySelector('#go').addEventListener('click', function() { fetch('/pdf?value=' + document.querySelector('#secret').value); });</script></body></html>"#.to_vec())
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&body).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (proxy, rx, task)
}
fn job(proxy: &BrowserProxy, output: PathBuf, raw: bool) -> BrowserJob {
    BrowserJob {
        url: if raw {
            "https://fixture.example/pdf"
        } else {
            "https://fixture.example/"
        }
        .into(),
        output,
        max_bytes: 4 * 1024 * 1024,
        timeout_secs: 30,
        proxy_url: proxy.url.clone(),
        allowed_origins: vec!["https://fixture.example".into()],
        cookies: vec![BrowserCookie {
            name: "session".into(),
            value: "fixture-secret".into(),
            origin: "https://fixture.example".into(),
        }],
        steps: vec![],
        response_url_glob: "*".into(),
        raw,
    }
}
#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_raw_pdf_and_cookie() {
    let (proxy, mut requests, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let out = dir.path().join("out.pdf");
    let result = browser::acquire(
        job(&proxy, out.clone(), true),
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(result.bytes, pdf().len() as u64);
    assert_eq!(std::fs::read(out).unwrap(), pdf());
    let request = requests.recv().await.unwrap().to_ascii_lowercase();
    assert!(request.contains("cookie: session=fixture-secret"));
    task.abort();
}
#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_workflow_fetch_after_fill_and_click() {
    let (proxy, mut requests, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let out = dir.path().join("out.pdf");
    let mut j = job(&proxy, out.clone(), false);
    j.response_url_glob = "*pdf*".into();
    j.steps = vec![
        BrowserStep::Fill {
            selector: "#secret".into(),
            value: "fixture-value".into(),
            origin: "https://fixture.example".into(),
        },
        BrowserStep::Click {
            selector: "#go".into(),
        },
        BrowserStep::WaitPdf { timeout_secs: 10 },
    ];
    browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(out).unwrap(), pdf());
    let mut found = false;
    while let Ok(request) = requests.try_recv() {
        if request.contains("/pdf?value=fixture-value") {
            found = true;
        }
    }
    assert!(found, "expected fetch with filled value");
    task.abort();
}
#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_cancellation_stops_worker() {
    let (proxy, mut requests, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let out = dir.path().join("out.pdf");
    let mut j = job(&proxy, out.clone(), true);
    j.url = "https://fixture.example/hang".into();
    let token = CancellationToken::new();
    let stop = token.clone();
    let run =
        tokio::spawn(
            async move { browser::acquire(j, &worker(), 4 * 1024 * 1024 * 1024, &stop).await },
        );
    tokio::time::timeout(Duration::from_secs(10), requests.recv())
        .await
        .unwrap()
        .unwrap();
    token.cancel();
    let error = tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, "cancelled");
    assert!(!out.exists());
    task.abort();
}

#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_rejects_invalid_proxy_without_direct_fallback() {
    let (proxy, _, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut j = job(&proxy, dir.path().join("out.pdf"), true);
    j.proxy_url = "http://user:pass@127.0.0.1:1234".into();
    let e = browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "invalid_proxy");
    task.abort();
}

#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_raw_retry_after_and_size_limit() {
    let (proxy, _, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut j = job(&proxy, dir.path().join("rate.pdf"), true);
    j.url = "https://fixture.example/rate".into();
    let error = browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "http_429");
    assert!(error.retryable);
    assert_eq!(error.retry_after_secs, Some(7));
    let mut j = job(&proxy, dir.path().join("large.pdf"), true);
    j.max_bytes = 1024;
    let error = browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "size_limit");
    task.abort();
}

#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_navigation_limit_is_distinct() {
    let (proxy, _, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut j = job(&proxy, dir.path().join("out.pdf"), false);
    j.url = "https://fixture.example/nav-large".into();
    j.max_bytes = 80 * 1024 * 1024;
    let e = browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "upstream_limit");
    task.abort();
}

#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_click_link_captures_navigation_pdf() {
    let (proxy, _, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let out = dir.path().join("out.pdf");
    let mut j = job(&proxy, out.clone(), false);
    j.response_url_glob = "*pdf*".into();
    j.steps = vec![
        BrowserStep::Click {
            selector: "#link".into(),
        },
        BrowserStep::WaitPdf { timeout_secs: 10 },
    ];
    browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(out).unwrap(), pdf());
    task.abort();
}

#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_watchdog_kills_and_reaps_mock_worker() {
    use std::os::unix::fs::PermissionsExt;
    let (proxy, _, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let pidfile = dir.path().join("pid");
    let script = dir.path().join("worker.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho $$ > '{}'\nexec sleep 30\n",
            pidfile.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut j = job(&proxy, dir.path().join("out.pdf"), true);
    j.timeout_secs = 1;
    let e = browser::acquire(
        j,
        &script,
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "browser_timeout");
    let pid = std::fs::read_to_string(&pidfile).unwrap();
    assert!(!std::path::Path::new(&format!("/proc/{}", pid.trim())).exists());
    let j = job(&proxy, dir.path().join("out2.pdf"), true);
    let e = browser::acquire(j, &script, 1, &CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(e.code, "browser_memory_limit");
    let pid = std::fs::read_to_string(&pidfile).unwrap();
    assert!(!std::path::Path::new(&format!("/proc/{}", pid.trim())).exists());
    task.abort();
}

#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_form_post_captures_navigation_pdf() {
    let (proxy, mut requests, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let out = dir.path().join("out.pdf");
    let mut j = job(&proxy, out.clone(), false);
    j.response_url_glob = "*pdf*".into();
    j.steps = vec![
        BrowserStep::Click {
            selector: "#submit".into(),
        },
        BrowserStep::WaitPdf { timeout_secs: 10 },
    ];
    browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(out).unwrap(), pdf());
    let mut found = false;
    while let Ok(request) = requests.try_recv() {
        if request.starts_with("POST /pdf ") && request.contains("token=form-value") {
            found = true;
        }
    }
    assert!(found, "expected original form POST and body");
    task.abort();
}

#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_trusted_script_fetch() {
    let (proxy, _, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let out = dir.path().join("out.pdf");
    let mut j = job(&proxy, out.clone(), false);
    j.response_url_glob = "*pdf*".into();
    j.steps = vec![
        BrowserStep::Script {
            javascript: "fetch('/pdf')".into(),
        },
        BrowserStep::WaitPdf { timeout_secs: 10 },
    ];
    browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(out).unwrap(), pdf());
    task.abort();
}

#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_workflow_retry_after_on_matched_fetch() {
    let (proxy, _, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut j = job(&proxy, dir.path().join("out.pdf"), false);
    j.response_url_glob = "*rate*".into();
    j.steps = vec![
        BrowserStep::Script {
            javascript: "fetch('/rate')".into(),
        },
        BrowserStep::WaitPdf { timeout_secs: 1 },
    ];
    let e = browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "http_429");
    assert!(e.retryable);
    assert_eq!(e.retry_after_secs, Some(7));
    task.abort();
}

#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_runtime_cancel_removes_staging_and_reaps_worker() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = crate::storage::Store::open(dir.path(), None).await.unwrap();
    let pidfile = dir.path().join("pid");
    let script = dir.path().join("worker.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho $$ > '{}'\nexec sleep 30\n",
            pidfile.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut source = crate::config::Source::one_off(
        "https://fixture.example/".into(),
        crate::config::Mode::Browser,
    );
    source.response_url_glob = Some("*pdf*".into());
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let run = tokio::spawn(async move {
        crate::runtime::fetch(
            &store,
            &crate::config::Config::default(),
            &source,
            &script,
            &stop,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !pidfile.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    cancel.cancel();
    let e = tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(e.code, "cancelled");
    let pid = std::fs::read_to_string(pidfile).unwrap();
    assert!(!std::path::Path::new(&format!("/proc/{}", pid.trim())).exists());
    assert_eq!(
        std::fs::read_dir(dir.path().join(".staging"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
#[ignore = "requires 512 MiB TLS fixture; run RUN_LARGE_PDF_TESTS=1 scripts/test-browser.sh"]
async fn browser_e2e_large_raw_exact_and_over_limit() {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let (proxy, _, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let output = dir.path().join("exact.pdf");
    let mut j = job(&proxy, output.clone(), true);
    j.url = "https://fixture.example/large-exact".into();
    j.max_bytes = 512 * 1024 * 1024;
    j.timeout_secs = 120;
    let acquired = browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(acquired.bytes, 512 * 1024 * 1024);
    let mut expected = Sha256::new();
    let mut block = vec![b'x'; 1024 * 1024];
    block[..9].copy_from_slice(b"%PDF-1.7\n");
    expected.update(&block);
    block[..9].fill(b'x');
    for _ in 1..512 {
        expected.update(&block);
    }
    let mut actual = Sha256::new();
    let mut f = std::fs::File::open(output).unwrap();
    loop {
        let n = f.read(&mut block).unwrap();
        if n == 0 {
            break;
        }
        actual.update(&block[..n]);
    }
    assert_eq!(actual.finalize(), expected.finalize());
    let mut j = job(&proxy, dir.path().join("over.pdf"), true);
    j.url = "https://fixture.example/large-over".into();
    j.max_bytes = 512 * 1024 * 1024;
    j.timeout_secs = 120;
    let e = browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "size_limit");
    task.abort();
}

#[tokio::test]
#[ignore = "requires 30 second upstream timeout; run RUN_SLOW_BROWSER_TESTS=1 scripts/test-browser.sh"]
async fn browser_e2e_slow_upstream_request_timeout_is_retryable() {
    let (proxy, _, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let output = dir.path().join("out.pdf");
    let mut j = job(&proxy, output.clone(), true);
    j.url = "https://fixture.example/hang".into();
    j.timeout_secs = 50;
    let e = browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "upstream_timeout");
    assert!(e.retryable);
    assert!(!output.exists());
    task.abort();
}

#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_matching_transient_then_pdf_returns_pdf() {
    let (proxy, mut requests, task) = fixture().await;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let output = dir.path().join("out.pdf");
    let mut j = job(&proxy, output.clone(), false);
    j.steps = vec![
        BrowserStep::Script {
            javascript: "fetch('/rate')".into(),
        },
        BrowserStep::Settle { milliseconds: 500 },
        BrowserStep::Script {
            javascript: "fetch('/pdf')".into(),
        },
        BrowserStep::WaitPdf { timeout_secs: 10 },
    ];
    browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(output).unwrap(), pdf());
    let mut seen_rate = false;
    let mut seen_pdf = false;
    while let Ok(req) = requests.try_recv() {
        seen_rate |= req.contains("/rate");
        seen_pdf |= req.contains("/pdf");
    }
    assert!(seen_rate && seen_pdf);
    task.abort();
}

#[tokio::test]
#[ignore = "requires built worker and local TLS fixture; run scripts/test-browser.sh"]
async fn browser_e2e_file_and_private_subrequests_are_blocked() {
    let (proxy, mut requests, task) = fixture().await;
    let private = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let output = dir.path().join("out.pdf");
    let secret = dir.path().join("private.txt");
    std::fs::write(&secret, "file-fixture-secret").unwrap();
    let private_url = format!("http://{}/probe", private.local_addr().unwrap());
    let file_url = url::Url::from_file_path(&secret).unwrap().to_string();
    let mut attack = url::Url::parse("https://fixture.example/attack").unwrap();
    attack
        .query_pairs_mut()
        .append_pair("file", &file_url)
        .append_pair("local", &private_url);
    let mut j = job(&proxy, output.clone(), false);
    j.url = attack.to_string();
    j.response_url_glob = "*pdf*".into();
    j.steps = vec![
        BrowserStep::WaitPdf { timeout_secs: 10 },
        BrowserStep::Settle { milliseconds: 500 },
    ];
    browser::acquire(
        j,
        &worker(),
        4 * 1024 * 1024 * 1024,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(output).unwrap(), pdf());
    assert!(
        tokio::time::timeout(Duration::from_millis(500), private.accept())
            .await
            .is_err()
    );
    while let Ok(req) = requests.try_recv() {
        assert!(
            !req.contains("/leak?")
                && !req.contains("/private-hit")
                && !req.contains("file-fixture-secret")
        );
    }
    task.abort();
}
