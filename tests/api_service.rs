use pdf2md_mcp::{
    auth::AuthMode,
    config::{Config, Mode, Source, Step},
    service::CallerService,
};
use std::{io::Write, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

fn writable(automatic: bool) -> Config {
    let mut config = Config::default();
    config.auth.mode = AuthMode::NoneRw;
    config.conversion.enabled = automatic;
    config
}
fn published(config: &mut Config, id: &str, interval: Option<u64>) {
    let mut source = Source::one_off("https://example.com/synthetic.pdf".into(), Mode::Obscura);
    source.id = id.into();
    source.interval_secs = interval;
    config.sources.push(source);
    config.http.published_sources.push(id.into());
}
fn worker(path: &Path, script: &str) {
    std::fs::write(path, format!("#!/usr/bin/env python3\n{script}")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}
async fn wait_terminal(service: &CallerService, id: &str) -> String {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let job = service.get_job(None, id).await.unwrap();
            if job.status != "queued" && job.status != "running" {
                break job.status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn uploads_follow_automatic_configuration_and_verified_download_admission() {
    for automatic in [true, false] {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let mut config = writable(automatic);
        config.http.downloads = 1;
        let service = CallerService::new(root.path(), config, None).await.unwrap();
        let mut upload = service.prepare_upload(None).await.unwrap();
        upload
            .write_all(b"%PDF-1.7\nsynthetic upload\n%%EOF")
            .unwrap();
        let accepted = service
            .finish_upload(upload, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(accepted.conversion_job.is_some(), automatic);
        assert_eq!(
            service.jobs(None).await.unwrap().len(),
            usize::from(automatic)
        );
        let document = accepted.observation.document_id.unwrap();
        let mut stream = service.read_pdf(None, &document).await.unwrap();
        assert_eq!(
            service.read_pdf(None, &document).await.err().unwrap().code,
            "service_busy"
        );
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"%PDF-1.7\nsynthetic upload\n%%EOF");
        drop(stream);
        assert!(service.read_pdf(None, &document).await.is_ok());
    }
}

#[tokio::test]
async fn uploads_fail_without_publication_and_drop_releases_staging_and_admission() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = writable(false);
    config.limits.max_bytes = 16;
    let service = CallerService::new(root.path(), config, None).await.unwrap();
    let mut upload = service.prepare_upload(None).await.unwrap();
    assert!(upload.write_all(&[b'a'; 17]).is_err());
    drop(upload);
    let mut upload = service.prepare_upload(None).await.unwrap();
    upload.write_all(b"not a PDF").unwrap();
    assert_eq!(
        service
            .finish_upload(upload, &CancellationToken::new())
            .await
            .unwrap_err()
            .code,
        "invalid_pdf"
    );
    assert!(service.history(None, None).await.unwrap().is_empty());
    let mut upload = service.prepare_upload(None).await.unwrap();
    upload.write_all(b"%PDF-1.7\n").unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        service
            .finish_upload(upload, &cancel)
            .await
            .unwrap_err()
            .code,
        "cancelled"
    );
    assert!(service.history(None, None).await.unwrap().is_empty());
    assert!(service.prepare_upload(None).await.is_ok());
}

#[tokio::test]
async fn read_only_denies_every_mutation_and_source_catalog_is_sanitized() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = Config::default();
    published(&mut config, "visible", Some(60));
    let service = CallerService::new(root.path(), config, None).await.unwrap();
    assert_eq!(
        service.prepare_upload(None).await.err().unwrap().code,
        "auth_forbidden"
    );
    assert_eq!(
        service
            .submit_acquisition(None, "https://example.com/a".into(), None)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    assert_eq!(
        service
            .submit_source(None, "visible", None)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    assert_eq!(
        service
            .submit_conversion(None, &"a".repeat(64), None, false, None)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    assert_eq!(
        service.cancel_job(None, "missing").await.unwrap_err().code,
        "auth_forbidden"
    );
    assert_eq!(
        service
            .retry_job(None, "missing", None)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    assert_eq!(
        service
            .set_schedule(None, "visible", true)
            .await
            .unwrap_err()
            .code,
        "auth_forbidden"
    );
    let catalog = serde_json::to_value(service.sources(None).await.unwrap()).unwrap();
    assert_eq!(catalog[0]["id"], "visible");
    assert!(catalog[0].get("url").is_none());
}

#[tokio::test]
async fn idempotency_survives_restart_capacity_and_rejects_command_conflicts() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = writable(false);
    config.http.per_workspace_jobs = 1;
    config.http.total_jobs = 1;
    let service = CallerService::new(root.path(), config.clone(), None)
        .await
        .unwrap();
    let first = service
        .submit_acquisition(None, "https://example.com/a".into(), Some("first"))
        .await
        .unwrap();
    assert_eq!(
        service
            .submit_acquisition(None, "https://example.com/a".into(), Some("first"))
            .await
            .unwrap()
            .id,
        first.id
    );
    assert_eq!(
        service
            .submit_acquisition(None, "https://example.com/b".into(), None)
            .await
            .unwrap_err()
            .code,
        "job_capacity"
    );
    assert_eq!(
        service
            .submit_acquisition(None, "https://example.com/b".into(), Some("first"))
            .await
            .unwrap_err()
            .code,
        "idempotency_conflict"
    );
    drop(service);
    let service = CallerService::new(root.path(), config, None).await.unwrap();
    assert_eq!(
        service
            .submit_acquisition(None, "https://example.com/a".into(), Some("first"))
            .await
            .unwrap()
            .id,
        first.id
    );
    assert_eq!(
        service.get_job(None, &first.id).await.unwrap().status,
        "queued"
    );
    assert_eq!(
        service.cancel_job(None, &first.id).await.unwrap().status,
        "cancelled"
    );
    let retry = service
        .retry_job(None, &first.id, Some("retry"))
        .await
        .unwrap();
    assert_ne!(retry.id, first.id);
    assert_eq!(retry.retry_of.as_deref(), Some(first.id.as_str()));
    assert_eq!(
        service
            .retry_job(None, &first.id, Some("retry"))
            .await
            .unwrap()
            .id,
        retry.id
    );
    assert_eq!(
        service.get_job(None, &first.id).await.unwrap().status,
        "cancelled"
    );
}

#[tokio::test]
async fn automatic_conversion_reservation_prevents_queue_oversubscription() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = writable(true);
    config.http.per_workspace_jobs = 2;
    config.http.total_jobs = 2;
    let service = CallerService::new(root.path(), config, None).await.unwrap();
    service
        .submit_acquisition(None, "https://example.com/a".into(), None)
        .await
        .unwrap();
    assert_eq!(
        service
            .submit_acquisition(None, "https://example.com/b".into(), None)
            .await
            .unwrap_err()
            .code,
        "job_capacity"
    );
    assert_eq!(
        service.prepare_upload(None).await.err().unwrap().code,
        "job_capacity"
    );
}

#[tokio::test]
async fn changed_source_pauses_schedule_and_interrupts_queue_until_explicit_reenable() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = writable(false);
    published(&mut config, "published", Some(60));
    let service = CallerService::new(root.path(), config.clone(), None)
        .await
        .unwrap();
    let queued = service
        .submit_source(None, "published", None)
        .await
        .unwrap();
    let schedule = service.set_schedule(None, "published", true).await.unwrap();
    assert!(schedule.next_due <= chrono::Utc::now().timestamp());
    drop(service);
    config.sources[0].url = "https://example.com/changed.pdf".into();
    let service = CallerService::new(root.path(), config, None).await.unwrap();
    let job = service.get_job(None, &queued.id).await.unwrap();
    assert_eq!(job.status, "interrupted");
    assert_eq!(job.error_code.as_deref(), Some("config_changed"));
    let schedules = service.schedules(None).await.unwrap();
    assert!(!schedules[0].enabled);
    assert_eq!(schedules[0].status, "paused");
    assert!(
        service
            .set_schedule(None, "published", true)
            .await
            .unwrap()
            .enabled
    );
    assert_eq!(
        service
            .submit_source(None, "unknown", None)
            .await
            .unwrap_err()
            .code,
        "source_not_found"
    );
}

#[tokio::test]
async fn dispatcher_runs_accepted_source_and_shutdown_preserves_queued_jobs() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let executable = root.path().join("fixture-worker");
    worker(
        &executable,
        "import json,sys\nj=json.load(sys.stdin)\nb=b'%PDF-1.7\\nsynthetic\\n%%EOF'\nwith open(j['output'],'xb') as f:f.write(b)\njson.dump({'status':'ok','acquired':{'bytes':len(b),'final_url':j['url']}},sys.stdout)\n",
    );
    let mut config = writable(false);
    published(&mut config, "published", Some(60));
    let service = Arc::new(CallerService::new(root.path(), config, None).await.unwrap());
    let queued = service
        .submit_source(None, "published", None)
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let running = {
        let service = service.clone();
        let cancel = cancel.clone();
        let executable = executable.clone();
        tokio::spawn(async move {
            service
                .run(&executable, Path::new("no-conversion-worker"), &cancel)
                .await
        })
    };
    assert_eq!(wait_terminal(&service, &queued.id).await, "succeeded");
    cancel.cancel();
    running.await.unwrap().unwrap();
    let queued = service
        .submit_source(None, "published", None)
        .await
        .unwrap();
    assert_eq!(
        service.get_job(None, &queued.id).await.unwrap().status,
        "queued"
    );
    assert_eq!(service.history(None, None).await.unwrap().len(), 1);
}

#[tokio::test]
async fn scripts_are_frozen_until_restart_and_content_changes_invalidate_grants() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let script = root.path().join("operator.js");
    std::fs::write(&script, "original").unwrap();
    let executable = root.path().join("fixture-worker");
    worker(
        &executable,
        "import json,sys\nj=json.load(sys.stdin)\nassert j['steps'][0]['javascript']=='original'\nb=b'%PDF-1.7\\nscript snapshot\\n%%EOF'\nwith open(j['output'],'xb') as f:f.write(b)\njson.dump({'status':'ok','acquired':{'bytes':len(b),'final_url':j['url']}},sys.stdout)\n",
    );
    let mut config = writable(false);
    published(&mut config, "scripted", Some(60));
    config.sources[0].mode = Mode::Browser;
    config.sources[0].response_url_glob = Some("*.pdf".into());
    config.sources[0].steps = vec![Step::Script {
        file: script.clone(),
    }];
    let service = Arc::new(
        CallerService::new(root.path(), config.clone(), None)
            .await
            .unwrap(),
    );
    let queued = service.submit_source(None, "scripted", None).await.unwrap();
    service.set_schedule(None, "scripted", true).await.unwrap();
    std::fs::write(&script, "changed").unwrap();
    let cancel = CancellationToken::new();
    let running = {
        let service = service.clone();
        let cancel = cancel.clone();
        let executable = executable.clone();
        tokio::spawn(async move {
            service
                .run(&executable, Path::new("no-conversion-worker"), &cancel)
                .await
        })
    };
    assert_eq!(wait_terminal(&service, &queued.id).await, "succeeded");
    cancel.cancel();
    running.await.unwrap().unwrap();
    drop(service);
    let service = CallerService::new(root.path(), config, None).await.unwrap();
    assert!(!service.schedules(None).await.unwrap()[0].enabled);
}

#[tokio::test]
async fn streaming_upload_reservations_allow_unrelated_admission_and_release_on_drop() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = writable(true);
    config.limits.concurrency = 2;
    config.http.per_workspace_jobs = 3;
    config.http.total_jobs = 3;
    let service = CallerService::new(root.path(), config, None).await.unwrap();
    let upload = service.prepare_upload(None).await.unwrap();
    let queued = tokio::time::timeout(
        Duration::from_secs(10),
        service.submit_acquisition(None, "https://example.com/independent.pdf".into(), None),
    )
    .await
    .expect("an upload must not hold the admission mutex")
    .unwrap();
    assert_eq!(queued.status, "queued");
    assert_eq!(
        service.prepare_upload(None).await.err().unwrap().code,
        "job_capacity"
    );
    drop(upload);
    // Dropping a disconnected upload releases its reserved automatic-conversion slot.
    let upload = service.prepare_upload(None).await.unwrap();
    drop(upload);
    assert_eq!(
        service.cancel_job(None, &queued.id).await.unwrap().status,
        "cancelled"
    );
    let mut first = service.prepare_upload(None).await.unwrap();
    first.write_all(b"%PDF-1.7\nfirst\n%%EOF").unwrap();
    let second = service.prepare_upload(None).await.unwrap();
    drop(second);
    let accepted = service
        .finish_upload(first, &CancellationToken::new())
        .await
        .unwrap();
    assert!(accepted.conversion_job.is_some());
}

#[tokio::test]
async fn conversion_caller_cancel_is_cancelled_but_host_shutdown_is_interrupted_and_reaped() {
    for shutdown in [false, true] {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let executable = root.path().join("slow-conversion-worker");
        let marker = root.path().join("worker.pid");
        std::fs::write(&executable, format!("#!/usr/bin/python3\nimport os,sys,time\nsys.stdin.buffer.read()\nwith open({:?},'w') as f:f.write(str(os.getpid()))\ntime.sleep(60)\n", marker.to_str().unwrap())).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let service = Arc::new(
            CallerService::new(root.path(), writable(false), None)
                .await
                .unwrap(),
        );
        let mut upload = service.prepare_upload(None).await.unwrap();
        upload
            .write_all(b"%PDF-1.7\nconversion cancellation fixture\n%%EOF")
            .unwrap();
        let observation = service
            .finish_upload(upload, &CancellationToken::new())
            .await
            .unwrap()
            .observation;
        let document = observation.document_id.unwrap();
        let job = service
            .submit_conversion(None, &document, None, false, None)
            .await
            .unwrap();
        let queued = if shutdown {
            Some(
                service
                    .submit_conversion(None, &document, Some("1"), false, None)
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let cancel = CancellationToken::new();
        let running = {
            let service = service.clone();
            let cancel = cancel.clone();
            let executable = executable.clone();
            tokio::spawn(async move {
                service
                    .run(Path::new("no-browser-worker"), &executable, &cancel)
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while !marker.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("conversion worker started");
        let pid: i32 = std::fs::read_to_string(&marker).unwrap().parse().unwrap();
        if shutdown {
            cancel.cancel();
        } else {
            service.cancel_job(None, &job.id).await.unwrap();
            assert_eq!(wait_terminal(&service, &job.id).await, "cancelled");
            cancel.cancel();
        }
        tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let expected = if shutdown { "interrupted" } else { "cancelled" };
        assert_eq!(
            service.get_job(None, &job.id).await.unwrap().status,
            expected
        );
        let history = service
            .conversion_history(None, Some(&document))
            .await
            .unwrap();
        assert_eq!(
            history
                .iter()
                .find(|attempt| attempt.id == job.id)
                .unwrap()
                .status,
            expected
        );
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "worker must be reaped before dispatch stops"
        );
        if let Some(queued) = queued {
            assert_eq!(
                service.get_job(None, &queued.id).await.unwrap().status,
                "queued"
            );
        }
    }
}

#[tokio::test]
async fn matching_conversion_reuses_pending_job_even_at_full_capacity() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = writable(false);
    config.http.per_workspace_jobs = 1;
    config.http.total_jobs = 1;
    let service = CallerService::new(root.path(), config, None).await.unwrap();
    let mut upload = service.prepare_upload(None).await.unwrap();
    upload
        .write_all(b"%PDF-1.7\nconversion reuse fixture\n%%EOF")
        .unwrap();
    let document = service
        .finish_upload(upload, &CancellationToken::new())
        .await
        .unwrap()
        .observation
        .document_id
        .unwrap();
    let first = service
        .submit_conversion(None, &document, None, false, Some("first"))
        .await
        .unwrap();
    assert_eq!(
        service
            .submit_conversion(None, &document, None, false, None)
            .await
            .unwrap()
            .id,
        first.id
    );
    assert_eq!(
        service
            .submit_conversion(None, &document, None, true, Some("forced-pending"))
            .await
            .unwrap()
            .id,
        first.id
    );
    assert_eq!(
        service
            .submit_conversion(None, &document, None, true, Some("forced-pending"))
            .await
            .unwrap()
            .id,
        first.id
    );
    assert_eq!(
        service
            .submit_conversion(None, &document, Some("1"), false, None)
            .await
            .unwrap_err()
            .code,
        "job_capacity"
    );
    assert_eq!(service.jobs(None).await.unwrap().len(), 1);
}

#[tokio::test]
async fn caller_pages_are_bounded_and_preserve_filter_and_ordering() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let service = CallerService::new(root.path(), writable(true), None)
        .await
        .unwrap();
    let mut accepted = Vec::new();
    for index in 0..3 {
        let mut upload = service.prepare_upload(None).await.unwrap();
        upload
            .write_all(format!("%PDF-1.7\npage fixture {index}\n%%EOF").as_bytes())
            .unwrap();
        accepted.push(
            service
                .finish_upload(upload, &CancellationToken::new())
                .await
                .unwrap(),
        );
    }
    for (index, accepted) in accepted.iter().enumerate() {
        let page = service.history_page(None, None, 1, index).await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].attempt_id, accepted.observation.attempt_id);
        let filtered = service
            .history_page(None, Some(&accepted.observation.source_id), 1, 0)
            .await
            .unwrap();
        assert_eq!(filtered[0].attempt_id, accepted.observation.attempt_id);
        assert_eq!(
            service.jobs_page(None, 1, index).await.unwrap()[0].id,
            accepted.conversion_job.as_ref().unwrap().id
        );
        let conversions = service
            .conversion_history_page(None, accepted.observation.document_id.as_deref(), 1, 0)
            .await
            .unwrap();
        assert_eq!(conversions.len(), 1);
        assert_eq!(
            conversions[0].id,
            accepted.conversion_job.as_ref().unwrap().id
        );
    }
    assert!(
        service
            .history_page(None, None, 1, 3)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(service.status_page(None, 2, 0).await.unwrap().len(), 2);
    assert_eq!(service.status_page(None, 2, 2).await.unwrap().len(), 1);
}

#[test]
fn http_configuration_defaults_and_allowlist_validation_are_explicit() {
    let defaults = Config::default();
    assert_eq!(defaults.http.bind, "127.0.0.1:8080");
    assert!(defaults.http.published_sources.is_empty());
    assert_eq!(defaults.http.per_workspace_jobs, 100);
    assert_eq!(defaults.http.total_jobs, 1000);
    assert_eq!(defaults.http.downloads, 4);
    for invalid in [
        "[http]\nbind='not an address'",
        "[http]\ntotal_jobs=0",
        "[http]\nper_workspace_jobs=1001",
        "[http]\ndownloads=0",
        "[http]\npublished_sources=['unknown']",
    ] {
        let config: Config = toml::from_str(invalid).unwrap();
        assert!(config.validate().is_err());
    }
    let mut duplicate = writable(false);
    published(&mut duplicate, "visible", None);
    duplicate.http.published_sources.push("visible".into());
    assert!(duplicate.validate().is_err());
}

#[tokio::test]
async fn dispatcher_progresses_fairly_beyond_the_workspace_cache_bound() {
    use pdf2md_mcp::{
        auth::AuthConfig, jobs::JobCommand, storage::Store, workspace::WorkspaceRegistry,
    };
    use sha2::{Digest, Sha256};
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let executable = root.path().join("workspace-worker");
    let starts = root.path().join("starts");
    worker(
        &executable,
        &format!(
            "import json,sys,time\nj=json.load(sys.stdin)\nworkspace=j['output'].split('/.staging/')[0].rsplit('/',1)[1]\nwith open({:?},'a') as f:f.write(workspace+'\\n')\ntime.sleep(0.03)\nb=b'%PDF-1.7\\ncache fairness fixture\\n%%EOF'\nwith open(j['output'],'xb') as f:f.write(b)\njson.dump({{'status':'ok','acquired':{{'bytes':len(b),'final_url':j['url']}}}},sys.stdout)\n",
            starts.to_str().unwrap()
        ),
    );
    let mut config = writable(false);
    config.auth = serde_json::from_value::<AuthConfig>(serde_json::json!({"mode":"oauth2","oidc":{"issuer":"https://auth.example.com","audience":"pdf-service-test","validation":"jwt"}})).unwrap();
    config.limits.concurrency = 2;
    published(&mut config, "published", None);
    let mut fingerprint = Sha256::new();
    fingerprint.update(serde_json::to_vec(&config.sources[0]).unwrap());
    fingerprint.update(
        serde_json::to_vec(&(
            config.limits.max_bytes,
            config.limits.timeout_secs,
            config.limits.worker_max_rss_mib,
        ))
        .unwrap(),
    );
    let command = JobCommand::FetchSource {
        source_id: "published".into(),
        fingerprint: hex::encode(fingerprint.finalize()),
    };
    let registry = WorkspaceRegistry::open(root.path()).await.unwrap();
    let mut paths = Vec::new();
    for index in 0..33 {
        let path = registry
            .resolve_identity("https://auth.example.com", &format!("user-{index}"), None)
            .await
            .unwrap();
        let store = Store::open(&path, None).await.unwrap();
        store.enqueue_job(&command, None, 100).await.unwrap();
        drop(store);
        paths.push(path);
    }
    // Give the first owner a backlog and require all other owners to get a first turn.
    let first = registry.list().await.unwrap()[0].id.clone();
    let path = registry.resolve_existing(&first).await.unwrap();
    let store = Store::open(&path, None).await.unwrap();
    for _ in 0..2 {
        store.enqueue_job(&command, None, 100).await.unwrap();
    }
    drop(store);
    let service = Arc::new(CallerService::new(root.path(), config, None).await.unwrap());
    let cancel = CancellationToken::new();
    let running = {
        let service = service.clone();
        let cancel = cancel.clone();
        let executable = executable.clone();
        tokio::spawn(async move {
            service
                .run(&executable, Path::new("no-conversion-worker"), &cancel)
                .await
        })
    };
    let progressed = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let log = std::fs::read_to_string(&starts).unwrap_or_default();
            if log.lines().count() >= 35 {
                break log;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    cancel.cancel();
    running.await.unwrap().unwrap();
    let log = progressed.expect("all 33 workspaces must progress with a 32-handle cache");
    let unique: std::collections::HashSet<_> = log.lines().take(33).collect();
    assert_eq!(
        unique.len(),
        33,
        "a backlog must wait until every eligible workspace gets a turn"
    );
    drop(service);
    // Eviction and shutdown release ownership, so an operator can reopen every workspace.
    for path in paths {
        assert!(Store::open(&path, None).await.is_ok());
    }
}

#[tokio::test]
async fn batch_artifact_reader_pins_workspace_and_download_admission() {
    #[path = "common/conversion_pdf.rs"]
    mod conversion_pdf;
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = writable(true);
    config.http.downloads = 1;
    let service = Arc::new(CallerService::new(root.path(), config, None).await.unwrap());
    let mut upload = service.prepare_upload(None).await.unwrap();
    upload.write_all(&conversion_pdf::sample_pdf()).unwrap();
    let accepted = service
        .finish_upload(upload, &CancellationToken::new())
        .await
        .unwrap();
    let document = accepted.observation.document_id.unwrap();
    let job = accepted.conversion_job.unwrap();
    let cancel = CancellationToken::new();
    let host = service.clone();
    let shutdown = cancel.clone();
    let dispatch = tokio::spawn(async move {
        host.run(
            Path::new("unused"),
            Path::new(env!("CARGO_BIN_EXE_pdf2md-convert-worker")),
            &shutdown,
        )
        .await
    });
    assert_eq!(wait_terminal(&service, &job.id).await, "succeeded");
    cancel.cancel();
    dispatch.await.unwrap().unwrap();
    let bundle = service.read_bundle(None, &job.id).await.unwrap();
    let mut artifact = bundle.read_artifact(0).await.unwrap();
    drop(bundle);
    assert_eq!(
        service.read_pdf(None, &document).await.err().unwrap().code,
        "service_busy"
    );
    let mut bytes = Vec::new();
    artifact.read_to_end(&mut bytes).await.unwrap();
    assert!(!bytes.is_empty());
    drop(artifact);
    assert!(service.read_pdf(None, &document).await.is_ok());
}
