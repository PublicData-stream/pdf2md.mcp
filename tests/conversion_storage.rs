use pdf2md_mcp::{conversion::ConversionOptions, storage::Store};

#[tokio::test]
async fn auto_requests_are_durable_deduplicated_and_opt_in() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let input = root.path().join("input.pdf");
    std::fs::write(&input, b"%PDF-1.4\n%%EOF\n").unwrap();
    let store = Store::open(root.path(), None).await.unwrap();
    let first = store
        .accept(&input, "one", "manual", None, "one")
        .await
        .unwrap();
    assert!(store.pending_conversions().await.unwrap().is_empty());
    drop(store);
    let store = Store::open_with_conversion(root.path(), None, Some(ConversionOptions::default()))
        .await
        .unwrap();
    let second = store
        .accept(&input, "one", "manual", None, "two")
        .await
        .unwrap();
    assert_eq!(first.document_id, second.document_id);
    store
        .accept(&input, "one", "manual", None, "three")
        .await
        .unwrap();
    let requests = store.pending_conversions().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].automatic);
    assert_eq!(
        store
            .conversion_for_observation("two")
            .await
            .unwrap()
            .unwrap()
            .id,
        requests[0].id
    );
    let explicit = store
        .request_conversion(
            first.document_id.as_deref().unwrap(),
            &ConversionOptions::default(),
            false,
        )
        .await
        .unwrap();
    assert_eq!(explicit.id, requests[0].id);
    let history = Store::read_conversion_history(root.path(), None, None)
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    drop(store);
    let store = Store::open(root.path(), None).await.unwrap();
    assert_eq!(store.pending_conversions().await.unwrap().len(), 1);
    assert!(
        store
            .request_conversion(&"0".repeat(64), &ConversionOptions::default(), false)
            .await
            .is_err()
    );
}

async fn db(root: &std::path::Path) -> sqlx::AnyPool {
    sqlx::any::install_default_drivers();
    let uri = url::Url::from_file_path(root.join("metadata.sqlite3")).unwrap();
    sqlx::AnyPool::connect(&format!("sqlite://{}?mode=rw", uri.path()))
        .await
        .unwrap()
}

#[tokio::test]
async fn v1_read_only_then_migration_and_interrupted_recovery() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let input = root.path().join("input.pdf");
    std::fs::write(&input, b"%PDF-1.4\n%%EOF\n").unwrap();
    let store = Store::open(root.path(), None).await.unwrap();
    let observation = store
        .accept(&input, "one", "manual", None, "first")
        .await
        .unwrap();
    drop(store);
    let pool = db(root.path()).await;
    sqlx::query("DROP TABLE conversion_attempts")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE schema_version SET version=1")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    assert!(
        Store::read_conversion_history(root.path(), None, None)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        Store::read_history(root.path(), None, None)
            .await
            .unwrap()
            .len(),
        1
    );
    let store = Store::open(root.path(), None).await.unwrap();
    let attempt = store
        .request_conversion(
            observation.document_id.as_deref().unwrap(),
            &ConversionOptions::default(),
            false,
        )
        .await
        .unwrap();
    drop(store);
    let pool = db(root.path()).await;
    sqlx::query("UPDATE conversion_attempts SET status='running' WHERE id=$1")
        .bind(&attempt.id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let store = Store::open(root.path(), None).await.unwrap();
    assert!(store.pending_conversions().await.unwrap().is_empty());
    let history = Store::read_conversion_history(root.path(), None, None)
        .await
        .unwrap();
    assert_eq!(history[0].status, "interrupted");
    let retry = store
        .request_conversion(
            observation.document_id.as_deref().unwrap(),
            &ConversionOptions::default(),
            false,
        )
        .await
        .unwrap();
    assert_ne!(retry.id, attempt.id);
}

#[tokio::test]
async fn corrupt_published_bundle_prevents_store_open() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let input = root.path().join("input.pdf");
    std::fs::write(&input, b"%PDF-1.4\n%%EOF\n").unwrap();
    let store = Store::open(root.path(), None).await.unwrap();
    let observation = store
        .accept(&input, "one", "manual", None, "first")
        .await
        .unwrap();
    let attempt = store
        .request_conversion(
            observation.document_id.as_deref().unwrap(),
            &ConversionOptions::default(),
            false,
        )
        .await
        .unwrap();
    drop(store);
    let bundle = "a".repeat(64);
    std::fs::create_dir(root.path().join("conversions").join(&bundle)).unwrap();
    std::fs::write(
        root.path()
            .join("conversions")
            .join(&bundle)
            .join("manifest.json"),
        b"corrupt",
    )
    .unwrap();
    let pool = db(root.path()).await;
    sqlx::query("UPDATE conversion_attempts SET status='succeeded',bundle_id=$1 WHERE id=$2")
        .bind(&bundle)
        .bind(&attempt.id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    assert_eq!(
        Store::open(root.path(), None).await.err().unwrap().code,
        "storage_corrupt"
    );
}

#[tokio::test]
async fn automatic_enqueue_failure_rolls_back_observation() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let input = root.path().join("input.pdf");
    std::fs::write(&input, b"%PDF-1.4\n%%EOF\n").unwrap();
    let store = Store::open_with_conversion(root.path(), None, Some(ConversionOptions::default()))
        .await
        .unwrap();
    let pool = db(root.path()).await;
    sqlx::query("CREATE TRIGGER fail_conversion BEFORE INSERT ON conversion_attempts BEGIN SELECT RAISE(ABORT, 'test'); END").execute(&pool).await.unwrap();
    assert!(
        store
            .accept(&input, "one", "manual", None, "first")
            .await
            .is_err()
    );
    assert!(store.history(None).await.unwrap().is_empty());
    pool.close().await;
}

#[tokio::test]
async fn store_rejects_changing_conversion_concurrency() {
    use pdf2md_mcp::conversion::ConversionLimits;
    use tokio_util::sync::CancellationToken;
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let input = root.path().join("input.pdf");
    std::fs::write(&input, b"%PDF-1.4\n%%EOF\n").unwrap();
    let store = Store::open(root.path(), None).await.unwrap();
    let observation = store
        .accept(&input, "one", "manual", None, "first")
        .await
        .unwrap();
    let attempt = store
        .request_conversion(
            observation.document_id.as_deref().unwrap(),
            &ConversionOptions::default(),
            false,
        )
        .await
        .unwrap();
    let limits = ConversionLimits::default();
    let _ = store
        .process_conversion(
            &attempt.id,
            &limits,
            std::path::Path::new("/nonexistent-pdf2md-worker"),
            &CancellationToken::new(),
        )
        .await;
    let mut changed = limits;
    changed.concurrency = 2;
    let err = store
        .process_conversion(
            &attempt.id,
            &changed,
            std::path::Path::new("/nonexistent-pdf2md-worker"),
            &CancellationToken::new(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(err.code, "conversion_limits");
}

// Run only against an otherwise empty, disposable PostgreSQL 18 database.
#[tokio::test]
async fn postgres_migration_bundle_export_and_namespace_isolation() {
    use pdf2md_mcp::conversion::{Artifact, ConversionManifest};
    use sha2::{Digest, Sha256};
    let Ok(url) = std::env::var("PDF2MD_TEST_CONVERSION_POSTGRES_URL") else {
        return;
    };
    let one = tempfile::tempdir_in("/tmp").unwrap();
    let two = tempfile::tempdir_in("/tmp").unwrap();
    let input = one.path().join("input.pdf");
    std::fs::write(&input, b"%PDF-1.4\n%%EOF\n").unwrap();
    let store = Store::open(one.path(), Some(&url)).await.unwrap();
    let observation = store
        .accept(&input, "one", "manual", None, "first")
        .await
        .unwrap();
    drop(store);
    sqlx::any::install_default_drivers();
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    sqlx::query("DROP TABLE conversion_attempts")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE schema_version SET version=1")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        Store::read_conversion_history(one.path(), Some(&url), None)
            .await
            .unwrap()
            .is_empty()
    );
    let store =
        Store::open_with_conversion(one.path(), Some(&url), Some(ConversionOptions::default()))
            .await
            .unwrap();
    let same = store
        .accept(&input, "one", "manual", None, "second")
        .await
        .unwrap();
    assert_eq!(same.document_id, observation.document_id);
    let pending = store.pending_conversions().await.unwrap();
    assert_eq!(pending.len(), 1);
    let other = Store::open(two.path(), Some(&url)).await.unwrap();
    assert!(other.pending_conversions().await.unwrap().is_empty());
    assert!(
        other
            .open_document(observation.document_id.as_deref().unwrap())
            .await
            .is_err()
    );
    let document = observation.document_id.unwrap();
    let options = ConversionOptions::default();
    let content = b"hello\n";
    let manifest = ConversionManifest {
        format_version: 1,
        document_id: document.clone(),
        converter: "historical-converter/1".into(),
        options: options.clone(),
        pages: vec![1],
        warnings: vec![],
        artifacts: vec![Artifact {
            path: "document.md".into(),
            sha256: format!("{:x}", Sha256::digest(content)),
            bytes: content.len() as u64,
        }],
    };
    let json = serde_json::to_vec(&manifest).unwrap();
    let bundle = format!("{:x}", Sha256::digest(&json));
    let dir = one.path().join("conversions").join(&bundle);
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("manifest.json"), &json).unwrap();
    std::fs::write(dir.join("document.md"), content).unwrap();
    let ns = std::fs::read_to_string(one.path().join("store-id")).unwrap();
    sqlx::query("UPDATE conversion_attempts SET status='succeeded',bundle_id=$1,profile_key=$2 WHERE namespace=$3 AND id=$4").bind(&bundle).bind(format!("{:x}", Sha256::digest(serde_json::to_vec(&(&document, &manifest.converter, &options)).unwrap()))).bind(ns.trim()).bind(&pending[0].id).execute(&pool).await.unwrap();
    let output = one.path().join("export");
    Store::export_conversion(one.path(), Some(&url), &pending[0].id, &output)
        .await
        .unwrap();
    assert_eq!(std::fs::read(output.join("document.md")).unwrap(), content);
    assert!(
        Store::export_conversion(
            two.path(),
            Some(&url),
            &pending[0].id,
            &two.path().join("export")
        )
        .await
        .is_err()
    );
    drop(other);
    drop(store);
    pool.close().await;
    let store = Store::open(one.path(), Some(&url)).await.unwrap();
    assert!(store.pending_conversions().await.unwrap().is_empty());
}

#[tokio::test]
async fn concurrent_requests_share_one_pending_attempt() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let input = root.path().join("input.pdf");
    std::fs::write(&input, b"%PDF-1.4\n%%EOF\n").unwrap();
    let store = Store::open(root.path(), None).await.unwrap();
    let doc = store
        .accept(&input, "one", "manual", None, "one")
        .await
        .unwrap()
        .document_id
        .unwrap();
    let options = ConversionOptions::default();
    let (a, b) = tokio::join!(
        store.request_conversion(&doc, &options, false),
        store.request_conversion(&doc, &options, false)
    );
    assert_eq!(a.unwrap().id, b.unwrap().id);
    assert_eq!(store.pending_conversions().await.unwrap().len(), 1);
}

#[tokio::test]
async fn interrupted_publication_removes_orphan_but_preserves_committed_bundle() {
    use pdf2md_mcp::conversion::{Artifact, CONVERTER, ConversionManifest};
    use sha2::{Digest, Sha256};
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let input = root.path().join("input.pdf");
    std::fs::write(&input, b"%PDF-1.4\n%%EOF\n").unwrap();
    let store = Store::open(root.path(), None).await.unwrap();
    let document = store
        .accept(&input, "one", "manual", None, "first")
        .await
        .unwrap()
        .document_id
        .unwrap();
    let kept = store
        .request_conversion(&document, &ConversionOptions::default(), false)
        .await
        .unwrap();
    let options = ConversionOptions {
        pages: Some(vec![1]),
    };
    let interrupted = store
        .request_conversion(&document, &options, false)
        .await
        .unwrap();
    let make_bundle = |opts: ConversionOptions, content: &[u8]| {
        let manifest = ConversionManifest {
            format_version: 1,
            document_id: document.clone(),
            converter: CONVERTER.into(),
            options: opts,
            pages: vec![1],
            warnings: vec![],
            artifacts: vec![Artifact {
                path: "document.md".into(),
                sha256: format!("{:x}", Sha256::digest(content)),
                bytes: content.len() as u64,
            }],
        };
        let json = serde_json::to_vec(&manifest).unwrap();
        let id = format!("{:x}", Sha256::digest(&json));
        let path = root.path().join("conversions").join(&id);
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("manifest.json"), json).unwrap();
        std::fs::write(path.join("document.md"), content).unwrap();
        id
    };
    let kept_bundle = make_bundle(ConversionOptions::default(), b"kept\n");
    let orphan = make_bundle(options, b"orphan\n");
    drop(store);
    let pool = db(root.path()).await;
    sqlx::query("UPDATE conversion_attempts SET status='succeeded', bundle_id=$1 WHERE id=$2")
        .bind(&kept_bundle)
        .bind(&kept.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE conversion_attempts SET status='running', bundle_id=NULL WHERE id=$1")
        .bind(&interrupted.id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let store = Store::open(root.path(), None).await.unwrap();
    assert!(root.path().join("conversions").join(&kept_bundle).is_dir());
    assert!(!root.path().join("conversions").join(&orphan).exists());
    let history = Store::read_conversion_history(root.path(), None, None)
        .await
        .unwrap();
    assert_eq!(
        history
            .iter()
            .find(|a| a.id == interrupted.id)
            .unwrap()
            .status,
        "interrupted"
    );
    let output = root.path().join("export-kept");
    Store::export_conversion(root.path(), None, &kept.id, &output)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(output.join("document.md")).unwrap(),
        b"kept\n"
    );
    drop(store);
}
