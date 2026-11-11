use pdf2md_mcp::{manual, storage::Store};
use std::io::Write;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn sqlite_paths_escape_reserved_characters_and_metadata_redacts_paths() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let root = dir.path().join("space ?#% path");
    let store = Store::open(&root, None).await.unwrap();
    store
        .record_failure(
            "source",
            "https",
            Some("https://example.com/private/token?secret=value#fragment"),
            "redact",
            "test",
        )
        .await
        .unwrap();
    let history = Store::read_history(&root, None, None).await.unwrap();
    assert_eq!(history[0].url.as_deref(), Some("https://example.com/"));
    drop(store);
    assert_eq!(
        Store::open(&root, None)
            .await
            .unwrap()
            .history(None)
            .await
            .unwrap()
            .len(),
        1
    );
}

async fn exercise_store(url: Option<&str>) {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open(dir.path(), url).await.unwrap();
    let mut input = store.staging_file().unwrap();
    input.write_all(b"%PDF-1.7\nsynthetic\n%%EOF").unwrap();
    let first = store
        .accept(input.path(), "source", "http", None, "attempt-1")
        .await
        .unwrap();
    input.write_all(b"changed").unwrap();
    let second = store
        .record_failure("source", "http", None, "attempt-2", "network")
        .await
        .unwrap();
    assert_eq!(second.outcome, "failed");
    assert_eq!(store.history(Some("source")).await.unwrap().len(), 2);
    assert_eq!(
        Store::read_history(dir.path(), url, Some("source"))
            .await
            .unwrap()
            .len(),
        2
    );
    store.set_next_due("source", 42).await.unwrap();
    assert_eq!(store.next_due("source").await.unwrap(), Some(42));
    let object = dir.path().join("objects").join(first.document_id.unwrap());
    assert_eq!(
        std::fs::read(&object).unwrap(),
        b"%PDF-1.7\nsynthetic\n%%EOF"
    );
    drop(input);
    drop(store);
    let reopened = Store::open(dir.path(), url).await.unwrap();
    assert_eq!(reopened.history(None).await.unwrap().len(), 2);
    drop(reopened);
    std::fs::remove_file(&object).unwrap();
    std::fs::write(object, b"corrupt").unwrap();
    assert!(Store::open(dir.path(), url).await.is_err());
}
#[tokio::test]
async fn sqlite_persists_observations_and_detects_corruption() {
    exercise_store(None).await;
}
#[tokio::test]
async fn postgres_persists_observations_when_configured() {
    if let Ok(url) = std::env::var("PDF2MD_TEST_POSTGRES_URL") {
        exercise_store(Some(&url)).await;
    }
}
#[tokio::test]
async fn manual_scan_preserves_originals_skips_unchanged_and_records_revisions() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open(dir.path(), None).await.unwrap();
    let path = dir.path().join("pdfs").join("test.PDF");
    std::fs::write(&path, b"%PDF-1.7\nfirst").unwrap();
    let cancel = CancellationToken::new();
    let first = manual::scan(&store, 100, &cancel).await.unwrap();
    assert_eq!(first.len(), 1);
    assert!(manual::scan(&store, 100, &cancel).await.unwrap().is_empty());
    std::fs::write(&path, b"%PDF-1.7\nsecond").unwrap();
    let second = manual::scan(&store, 100, &cancel).await.unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(first[0].source_id, second[0].source_id);
    assert_ne!(first[0].document_id, second[0].document_id);
    assert_eq!(std::fs::read(path).unwrap(), b"%PDF-1.7\nsecond");
}

#[tokio::test]
async fn archive_deduplicates_objects_and_preserves_reverted_history() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open(dir.path(), None).await.unwrap();
    let mut first = store.staging_file().unwrap();
    first.write_all(b"%PDF-1.7 first").unwrap();
    let a = store
        .accept(first.path(), "source", "http", None, "a")
        .await
        .unwrap();
    let same = store
        .accept(first.path(), "source", "http", None, "b")
        .await
        .unwrap();
    let mut second = store.staging_file().unwrap();
    second.write_all(b"%PDF-1.7 second").unwrap();
    let b = store
        .accept(second.path(), "source", "http", None, "c")
        .await
        .unwrap();
    let reverted = store
        .accept(first.path(), "source", "http", None, "d")
        .await
        .unwrap();
    assert_eq!(a.document_id, same.document_id);
    assert_eq!(same.outcome, "unchanged");
    assert_eq!(reverted.outcome, "accepted");
    assert_ne!(a.document_id, b.document_id);
    assert_eq!(a.document_id, reverted.document_id);
    assert_eq!(store.history(Some("source")).await.unwrap().len(), 4);
    assert_eq!(
        std::fs::read_dir(dir.path().join("objects"))
            .unwrap()
            .count(),
        2
    );
}

#[tokio::test]
async fn locked_store_and_unsafe_paths_are_rejected() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open(dir.path(), None).await.unwrap();
    assert!(Store::open(dir.path(), None).await.is_err());
    let external = tempfile::NamedTempFile::new_in("/tmp").unwrap();
    std::fs::write(external.path(), b"%PDF-1.7 external").unwrap();
    let link = dir.path().join("linked.pdf");
    symlink(external.path(), &link).unwrap();
    assert!(
        store
            .accept(&link, "source", "http", None, "link")
            .await
            .is_err()
    );
    drop(store);
    std::fs::remove_dir(dir.path().join("pdfs")).unwrap();
    symlink("objects", dir.path().join("pdfs")).unwrap();
    assert!(Store::open(dir.path(), None).await.is_err());
}

#[tokio::test]
async fn startup_cleans_partial_files_and_detects_missing_objects() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open(dir.path(), None).await.unwrap();
    let mut staged = store.staging_file().unwrap();
    staged.write_all(b"%PDF-1.7 test").unwrap();
    let obs = store
        .accept(staged.path(), "source", "http", None, "one")
        .await
        .unwrap();
    drop(staged);
    drop(store);
    let partial = dir.path().join(".staging").join(".partial-stale");
    std::fs::write(&partial, b"partial").unwrap();
    let reopened = Store::open(dir.path(), None).await.unwrap();
    assert!(!partial.exists());
    drop(reopened);
    std::fs::remove_file(dir.path().join("objects").join(obs.document_id.unwrap())).unwrap();
    assert!(Store::open(dir.path(), None).await.is_err());
}

#[tokio::test]
async fn manual_scan_defers_files_that_change_during_stability_window() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open(dir.path(), None).await.unwrap();
    let path = dir.path().join("pdfs").join("slow.pdf");
    std::fs::write(&path, b"%PDF-1.7 incomplete").unwrap();
    let update = path.clone();
    let writer = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        std::fs::write(update, b"%PDF-1.7 completed").unwrap();
    });
    let observed = manual::scan(&store, 100, &CancellationToken::new())
        .await
        .unwrap();
    writer.await.unwrap();
    assert_eq!(observed[0].error_code.as_deref(), Some("file_changed"));
    let accepted = manual::scan(&store, 100, &CancellationToken::new())
        .await
        .unwrap();
    assert!(accepted[0].document_id.is_some());
}

#[tokio::test]
async fn postgres_connection_loss_does_not_write_without_reacquiring_ownership() {
    use sqlx::{Connection, PgConnection};
    let Ok(url) = std::env::var("PDF2MD_TEST_POSTGRES_URL") else {
        return;
    };
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open(dir.path(), Some(&url)).await.unwrap();
    let id = uuid::Uuid::parse_str(
        std::fs::read_to_string(dir.path().join("store-id"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    let bytes = id.as_bytes();
    let key = i64::from_be_bytes(bytes[..8].try_into().unwrap());
    let upper = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as i64;
    let lower = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as i64;
    let mut controller = PgConnection::connect(&url).await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pid FROM pg_locks WHERE locktype='advisory' AND classid::bigint=$1 AND objid::bigint=$2 AND granted")
        .bind(upper).bind(lower).fetch_one(&mut controller).await.unwrap();
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .fetch_one(&mut controller)
        .await
        .unwrap();
    assert!(terminated);
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(&mut controller)
        .await
        .unwrap();
    assert!(acquired);
    assert!(
        store
            .record_failure("source", "http", None, "lost-owner", "test")
            .await
            .is_err()
    );
    let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
        .bind(key)
        .fetch_one(&mut controller)
        .await
        .unwrap();
    assert!(unlocked);
}

#[tokio::test]
async fn read_history_works_during_writer_ownership_without_creating_missing_root() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let missing = dir.path().join("missing");
    assert!(Store::read_history(&missing, None, None).await.is_err());
    assert!(!missing.exists());
    let store = Store::open(dir.path(), None).await.unwrap();
    store
        .record_failure("source", "https", None, "read-1", "failure")
        .await
        .unwrap();
    let history = Store::read_history(dir.path(), None, Some("source"))
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].attempt_id, "read-1");
}

#[tokio::test]
async fn publication_checks_deadline_and_cancellation_before_committing() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let store = Store::open(dir.path(), None).await.unwrap();
    let mut file = store.staging_file().unwrap();
    file.write_all(b"%PDF-1.7 test").unwrap();
    let cancel = CancellationToken::new();
    let result = store
        .accept_before(
            file.path(),
            "source",
            "https",
            None,
            "expired",
            std::time::Instant::now(),
            &cancel,
        )
        .await;
    assert_eq!(result.unwrap_err().code, "run_timeout");
    cancel.cancel();
    let result = store
        .accept_before(
            file.path(),
            "source",
            "https",
            None,
            "cancelled",
            std::time::Instant::now() + std::time::Duration::from_secs(10),
            &cancel,
        )
        .await;
    assert_eq!(result.unwrap_err().code, "cancelled");
    assert!(store.history(None).await.unwrap().is_empty());
    assert_eq!(
        std::fs::read_dir(dir.path().join("objects"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn new_store_and_archive_are_private_to_the_owner() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let root = dir.path().join("new-store");
    let store = Store::open(&root, None).await.unwrap();
    for name in ["", "objects", ".staging", "pdfs", "store-id", ".lock"] {
        let mode = std::fs::metadata(root.join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "{name} grants group or other access");
    }
    let mut staged = store.staging_file().unwrap();
    staged.write_all(b"%PDF-1.7 private").unwrap();
    let observation = store
        .accept(staged.path(), "source", "https", None, "private")
        .await
        .unwrap();
    let mode = std::fs::metadata(root.join("objects").join(observation.document_id.unwrap()))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o400);
}
