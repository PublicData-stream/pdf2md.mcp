use pdf2md_mcp::{auth::AuthMode, config::Config, service::CallerService};
use serde_json::{Value, json};
use std::{io::Write, path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[path = "common/conversion_pdf.rs"]
mod conversion_pdf;

struct Fixture {
    _root: tempfile::TempDir,
    service: Arc<CallerService>,
    conversion: String,
    cancel: CancellationToken,
    runner: tokio::task::JoinHandle<pdf2md_mcp::error::Result<()>>,
}
impl Fixture {
    async fn new(configure: impl FnOnce(&mut Config)) -> Self {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let mut config = Config::default();
        config.auth.mode = AuthMode::NoneRw;
        config.conversion.enabled = false;
        configure(&mut config);
        let service = Arc::new(CallerService::new(root.path(), config, None).await.unwrap());
        let mut upload = service.prepare_upload(None).await.unwrap();
        upload.write_all(&conversion_pdf::sample_pdf()).unwrap();
        let accepted = service
            .finish_upload(upload, &CancellationToken::new())
            .await
            .unwrap();
        let conversion = service
            .submit_conversion(
                None,
                accepted.observation.document_id.as_deref().unwrap(),
                None,
                false,
                None,
            )
            .await
            .unwrap()
            .id;
        let cancel = CancellationToken::new();
        let runner = {
            let service = service.clone();
            let token = cancel.clone();
            tokio::spawn(async move {
                service
                    .run(
                        Path::new("unused-browser-worker"),
                        Path::new(env!("CARGO_BIN_EXE_pdf2md-convert-worker")),
                        &token,
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let job = service.get_job(None, &conversion).await.unwrap();
                if job.status == "succeeded" {
                    break;
                }
                assert!(
                    job.status == "queued" || job.status == "running",
                    "conversion failed: {}",
                    job.status
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        Self {
            _root: root,
            service,
            conversion,
            cancel,
            runner,
        }
    }
    async fn call(
        &self,
        name: &str,
        args: Value,
    ) -> pdf2md_mcp::error::Result<pdf2md_mcp::service::tools::ToolOutput> {
        self.service
            .call_tool(None, name, args, &CancellationToken::new())
            .await
    }
    async fn stop(self) {
        self.cancel.cancel();
        self.runner.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn reads_selected_pages_and_independent_line_and_byte_measurements() {
    let fixture = Fixture::new(|_| {}).await;
    let id = &fixture.conversion;
    let read = fixture
        .call("read", json!({"conversion_id":id}))
        .await
        .unwrap();
    let text = read.text.unwrap();
    assert!(text.contains("First page") && text.contains("Second page"));
    let pages = fixture
        .call("read-page", json!({"conversion_id":id,"pages":"2,1,2"}))
        .await
        .unwrap()
        .data;
    assert_eq!(pages["pages"].as_array().unwrap().len(), 2);
    assert!(
        pages["pages"][0]["text"]
            .as_str()
            .unwrap()
            .contains("First page")
    );
    assert!(
        pages["pages"][1]["text"]
            .as_str()
            .unwrap()
            .contains("Second page")
    );
    assert_eq!(
        fixture
            .call("read-page", json!({"conversion_id":id,"pages":"1,3"}))
            .await
            .err()
            .unwrap()
            .code,
        "page_not_found"
    );
    let table = fixture
        .call("table", json!({"conversion_id":id}))
        .await
        .unwrap();
    assert_eq!(table.data["status"], "absent");
    let count = fixture
        .call("count", json!({"conversion_id":id}))
        .await
        .unwrap()
        .data;
    let expected = text.bytes().filter(|b| *b == b'\n').count()
        + usize::from(!text.is_empty() && !text.ends_with('\n'));
    assert_eq!(count["results"][0]["value"], expected);
    let size=fixture.call("size",json!({"conversion_id":id,"selectors":[{"kind":"whole"},{"kind":"lines","start":1,"end":1}]})).await.unwrap().data;
    assert_eq!(size["results"][0]["value"], text.len());
    assert_eq!(size["results"][1]["value"], text.find('\n').unwrap() + 1);
    assert_eq!(
        fixture
            .call(
                "count",
                json!({"conversion_id":id,"selectors":[{"kind":"whole"},{"kind":"whole"}]})
            )
            .await
            .err()
            .unwrap()
            .code,
        "invalid_arguments"
    );
    assert_eq!(
        fixture
            .call("read", json!({"conversion_id":id,"path":"/etc/passwd"}))
            .await
            .err()
            .unwrap()
            .code,
        "invalid_arguments"
    );
    fixture.stop().await;
}

#[tokio::test]
async fn search_pages_bind_cursor_and_reject_bad_regex() {
    if std::process::Command::new("rg")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let fixture = Fixture::new(|_| {}).await;
    let id = &fixture.conversion;
    let first = fixture
        .call(
            "rg",
            json!({"pattern":"page","conversion_ids":[id],"limit":1}),
        )
        .await
        .unwrap()
        .data;
    assert_eq!(first["results"].as_array().unwrap().len(), 1);
    assert_eq!(first["partial"], true);
    let cursor = first["next_cursor"].as_str().unwrap();
    assert_eq!(
        fixture
            .call(
                "rg",
                json!({"pattern":"other","conversion_ids":[id],"limit":1,"cursor":cursor})
            )
            .await
            .err()
            .unwrap()
            .code,
        "invalid_cursor"
    );
    let mut bad = cursor.to_owned();
    bad.push('x');
    assert_eq!(
        fixture
            .call(
                "rg",
                json!({"pattern":"page","conversion_ids":[id],"limit":1,"cursor":bad})
            )
            .await
            .err()
            .unwrap()
            .code,
        "invalid_cursor"
    );
    let mut next = Some(cursor.to_owned());
    let mut count = 1;
    while let Some(cursor) = next {
        let result = fixture
            .call(
                "rg",
                json!({"pattern":"page","conversion_ids":[id],"limit":1,"cursor":cursor}),
            )
            .await
            .unwrap()
            .data;
        count += result["results"].as_array().unwrap().len();
        next = result["next_cursor"].as_str().map(str::to_owned);
        assert!(count < 100);
    }
    assert!(count >= 2);
    assert_eq!(
        fixture
            .call("rg", json!({"pattern":"[","conversion_ids":[id]}))
            .await
            .err()
            .unwrap()
            .code,
        "search_failed"
    );
    let all = fixture
        .call("rg", json!({"pattern":"First page"}))
        .await
        .unwrap()
        .data;
    assert!(!all["results"].as_array().unwrap().is_empty());
    let context = fixture
        .call(
            "rg",
            json!({"pattern":"First page","conversion_ids":[id],"context":1}),
        )
        .await
        .unwrap()
        .data;
    let events = context["results"].as_array().unwrap();
    assert!(events.iter().any(|row| row["event"]["type"] == "match"));
    assert!(events.iter().any(|row| row["event"]["type"] == "context"));
    fixture.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn cancelling_search_reaps_its_process() {
    use std::os::unix::fs::PermissionsExt;
    let work = tempfile::tempdir_in("/tmp").unwrap();
    let executable = work.path().join("slow-rg");
    let pidfile = work.path().join("pid");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nexec /bin/sleep 60\n",
            pidfile.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = Fixture::new(|config| config.mcp.rg_path = executable).await;
    let cancel = CancellationToken::new();
    let task = {
        let service = fixture.service.clone();
        let id = fixture.conversion.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            service
                .call_tool(
                    None,
                    "rg",
                    json!({"pattern":"page","conversion_ids":[id]}),
                    &cancel,
                )
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        while !pidfile.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let pid: i32 = std::fs::read_to_string(pidfile).unwrap().parse().unwrap();
    cancel.cancel();
    assert_eq!(task.await.unwrap().err().unwrap().code, "cancelled");
    // A reaped process no longer has a process-table entry.
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    fixture.stop().await;
}

#[tokio::test]
async fn inventory_cursor_is_bound_to_arguments_and_expires_on_restart() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = Config::default();
    config.auth.mode = AuthMode::NoneRw;
    config.conversion.enabled = false;
    let service = CallerService::new(root.path(), config.clone(), None)
        .await
        .unwrap();
    for suffix in ["one", "two"] {
        let mut upload = service.prepare_upload(None).await.unwrap();
        upload
            .write_all(format!("%PDF-1.4\n{suffix}\n%%EOF\n").as_bytes())
            .unwrap();
        service
            .finish_upload(upload, &CancellationToken::new())
            .await
            .unwrap();
    }
    let result = service
        .call_tool(None, "list", json!({"limit":1}), &CancellationToken::new())
        .await
        .unwrap()
        .data;
    let cursor = result["next_cursor"].as_str().unwrap().to_owned();
    assert_eq!(
        service
            .call_tool(
                None,
                "list",
                json!({"limit":2,"cursor":cursor}),
                &CancellationToken::new()
            )
            .await
            .err()
            .unwrap()
            .code,
        "invalid_cursor"
    );
    drop(service);
    let service = CallerService::new(root.path(), config, None).await.unwrap();
    assert_eq!(
        service
            .call_tool(
                None,
                "list",
                json!({"limit":1,"cursor":cursor}),
                &CancellationToken::new()
            )
            .await
            .err()
            .unwrap()
            .code,
        "invalid_cursor"
    );
}

#[tokio::test]
async fn small_page_and_structural_measures_work_when_whole_read_exceeds_limit() {
    let fixture = Fixture::new(|config| config.mcp.max_read_bytes = 100).await;
    let id = &fixture.conversion;
    assert_eq!(
        fixture
            .call("read", json!({"conversion_id":id}))
            .await
            .err()
            .unwrap()
            .code,
        "size_limit"
    );
    let page = fixture
        .call("read-page", json!({"conversion_id":id,"pages":"1"}))
        .await
        .unwrap()
        .data;
    assert!(
        page["pages"][0]["text"]
            .as_str()
            .unwrap()
            .contains("First page")
    );
    let blocks = fixture
        .call("list", json!({"kind":"blocks","conversion_id":id}))
        .await
        .unwrap()
        .data;
    let block_id = blocks["items"].as_array().unwrap().first().unwrap()["id"]
        .as_str()
        .unwrap();
    let measured = fixture
        .call(
            "count",
            json!({"conversion_id":id,"selectors":[{"kind":"block","id":block_id}]}),
        )
        .await
        .unwrap()
        .data;
    assert!(measured["results"][0]["value"].as_u64().unwrap() > 0);
    fixture.stop().await;
}
