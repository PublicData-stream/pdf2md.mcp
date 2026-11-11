use pdf2md_mcp::{jobs::JobCommand, storage::Store};

#[tokio::test]
async fn idempotency_capacity_and_restart_recovery() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open(dir.path(), None).await.unwrap();
    let command = JobCommand::AcquireHttps {
        url: "https://example.com/a.pdf".into(),
    };
    let (queued, created) = store.enqueue_job(&command, Some("one"), 1).await.unwrap();
    assert!(created);
    assert_eq!(
        store
            .enqueue_job(&command, Some("one"), 1)
            .await
            .unwrap()
            .0
            .id,
        queued.id
    );
    let different = JobCommand::AcquireHttps {
        url: "https://example.com/b.pdf".into(),
    };
    assert_eq!(
        store
            .enqueue_job(&different, Some("one"), 1)
            .await
            .unwrap_err()
            .code,
        "idempotency_conflict"
    );
    assert_eq!(
        store
            .enqueue_job(&different, None, 1)
            .await
            .unwrap_err()
            .code,
        "job_capacity"
    );
    assert_eq!(
        store.claim_job(&queued.id).await.unwrap().unwrap().status,
        "running"
    );
    drop(store);
    let store = Store::open(dir.path(), None).await.unwrap();
    assert_eq!(store.job(&queued.id).await.unwrap().status, "interrupted");
    let (queued, _) = store.enqueue_job(&different, None, 1).await.unwrap();
    drop(store);
    let store = Store::open(dir.path(), None).await.unwrap();
    assert_eq!(store.job(&queued.id).await.unwrap().status, "queued");
    assert_eq!(
        store.cancel_job(&queued.id).await.unwrap().status,
        "cancelled"
    );
}

#[tokio::test]
async fn schedule_enqueues_without_overlapping_work() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open(dir.path(), None).await.unwrap();
    store
        .set_schedule("source", true, 1, "fingerprint")
        .await
        .unwrap();
    let jobs = store.enqueue_due_schedules_bounded(4, 1).await.unwrap();
    assert_eq!(jobs.len(), 1);
    store
        .set_schedule("source", true, 1, "fingerprint")
        .await
        .unwrap();
    assert!(
        store
            .enqueue_due_schedules_bounded(4, 1)
            .await
            .unwrap()
            .is_empty()
    );
    store.reconcile_sources(&[]).await.unwrap();
    assert_eq!(
        store.job(&jobs[0].id).await.unwrap().error_code.as_deref(),
        Some("config_changed")
    );
    assert!(!store.schedules().await.unwrap()[0].enabled);
}

#[tokio::test]
async fn accepted_document_and_automatic_conversion_publish_together() {
    use pdf2md_mcp::conversion::ConversionOptions;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open_with_conversion(dir.path(), None, Some(ConversionOptions::default()))
        .await
        .unwrap();
    let staged = store.staging_file().unwrap();
    std::fs::write(staged.path(), b"%PDF-1.7\nsynthetic\n%%EOF\n").unwrap();
    let observation = store
        .accept(staged.path(), "upload", "manual", None, "attempt")
        .await
        .unwrap();
    let conversion = store
        .conversion_for_observation(&observation.attempt_id)
        .await
        .unwrap()
        .unwrap();
    let job = store.job(&conversion.id).await.unwrap();
    assert_eq!(job.status, "queued");
    assert_eq!(job.document_id, observation.document_id);
    assert_eq!(job.conversion_id.as_deref(), Some(conversion.id.as_str()));
    store.cancel_job(&job.id).await.unwrap();
    assert!(store.pending_conversions().await.unwrap().is_empty());
}

#[tokio::test]
async fn postgres_jobs_schedule_publication_and_bounded_pages() {
    let Ok(database) = std::env::var("PDF2MD_TEST_POSTGRES_URL") else {
        return;
    };
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open_with_conversion(dir.path(), Some(&database), Some(Default::default()))
        .await
        .unwrap();
    let command = JobCommand::AcquireHttps {
        url: "https://example.com/a.pdf".into(),
    };
    let (job, _) = store
        .enqueue_job(&command, Some("pg-idempotency"), 4)
        .await
        .unwrap();
    assert_eq!(
        store
            .enqueue_job(&command, Some("pg-idempotency"), 4)
            .await
            .unwrap()
            .0
            .id,
        job.id
    );
    assert_eq!(store.jobs_page(1, 0).await.unwrap().len(), 1);
    store.claim_job(&job.id).await.unwrap();
    store
        .finish_job(&job.id, "failed", Some("fixture"))
        .await
        .unwrap();
    let staged = store.staging_file().unwrap();
    std::fs::write(staged.path(), b"%PDF-1.7\nsynthetic\n%%EOF\n").unwrap();
    store
        .accept(staged.path(), "upload", "upload", None, "pg-upload")
        .await
        .unwrap();
    assert_eq!(store.history_page(None, 1, 0).await.unwrap().len(), 1);
    assert_eq!(store.status_page(1, 0).await.unwrap().len(), 1);
    assert_eq!(
        store
            .conversion_history_page(None, 1, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(store.queued_jobs_by_kind(true, 1).await.unwrap().len(), 1);
    store
        .set_schedule("source", true, 3600, "fingerprint")
        .await
        .unwrap();
    assert_eq!(
        store
            .enqueue_due_schedules_bounded(8, 1)
            .await
            .unwrap()
            .len(),
        1
    );
    drop(store);
    let reopened = Store::open(dir.path(), Some(&database)).await.unwrap();
    assert_eq!(reopened.job(&job.id).await.unwrap().status, "failed");
}

#[tokio::test]
async fn retry_keys_include_parent_and_conflicting_conversion_retry_is_rejected() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open(dir.path(), None).await.unwrap();
    let command = JobCommand::AcquireHttps {
        url: "https://example.com/a.pdf".into(),
    };
    let (a, _) = store.enqueue_job(&command, None, 10).await.unwrap();
    let (b, _) = store.enqueue_job(&command, None, 10).await.unwrap();
    store.cancel_job(&a.id).await.unwrap();
    store.cancel_job(&b.id).await.unwrap();
    let (retry, _) = store
        .enqueue_retry_job(&command, Some("retry-key"), 10, Some(&a.id))
        .await
        .unwrap();
    assert_eq!(retry.retry_of.as_deref(), Some(a.id.as_str()));
    assert_eq!(
        store
            .enqueue_retry_job(&command, Some("retry-key"), 10, Some(&a.id))
            .await
            .unwrap()
            .0
            .id,
        retry.id
    );
    assert_eq!(
        store
            .enqueue_retry_job(&command, Some("retry-key"), 10, Some(&b.id))
            .await
            .unwrap_err()
            .code,
        "idempotency_conflict"
    );
    let staged = store.staging_file().unwrap();
    std::fs::write(staged.path(), b"%PDF-1.7\nfixture\n%%EOF").unwrap();
    let doc = store
        .accept(staged.path(), "upload", "upload", None, "retry-upload")
        .await
        .unwrap()
        .document_id
        .unwrap();
    let convert = JobCommand::Convert {
        document_id: doc,
        options: Default::default(),
        force: true,
    };
    let (attempt, _) = store.enqueue_job(&convert, None, 10).await.unwrap();
    store.cancel_job(&attempt.id).await.unwrap();
    let (new, _) = store
        .enqueue_retry_job(&convert, None, 10, Some(&attempt.id))
        .await
        .unwrap();
    assert_eq!(new.retry_of.as_deref(), Some(attempt.id.as_str()));
    assert_eq!(
        store
            .enqueue_retry_job(&convert, None, 10, Some(&attempt.id))
            .await
            .unwrap_err()
            .code,
        "job_conflict"
    );
}
