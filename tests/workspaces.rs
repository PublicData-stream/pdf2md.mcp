use pdf2md_mcp::{storage::Store, workspace::WorkspaceRegistry};
use std::io::Write;

#[tokio::test]
async fn identities_and_shared_workspace_are_stable_and_physically_separate() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let operator = Store::open(dir.path(), None).await.unwrap();
    operator
        .record_failure("private", "https", None, "operator", "test")
        .await
        .unwrap();
    let registry = WorkspaceRegistry::open(dir.path()).await.unwrap();
    let shared = registry.resolve_shared(None).await.unwrap();
    let alice = registry
        .resolve_identity("https://issuer.example", "alice", None)
        .await
        .unwrap();
    let bob = registry
        .resolve_identity("https://issuer.example", "bob", None)
        .await
        .unwrap();
    let other_issuer = registry
        .resolve_identity("https://other.example", "alice", None)
        .await
        .unwrap();
    assert_ne!(shared, alice);
    assert_ne!(alice, bob);
    assert_ne!(alice, other_issuer);
    assert_eq!(
        alice,
        registry
            .resolve_identity("https://issuer.example", "alice", None)
            .await
            .unwrap()
    );
    let store = Store::open(&alice, None).await.unwrap();
    let mut staged = store.staging_file().unwrap();
    staged.write_all(b"%PDF-1.7\ntest").unwrap();
    let document = store
        .accept(staged.path(), "a", "https", None, "a")
        .await
        .unwrap()
        .document_id
        .unwrap();
    assert!(alice.join("objects").join(&document).exists());
    assert!(!bob.join("objects").join(&document).exists());
    assert_eq!(
        registry
            .resolve_identity("https://issuer.example", "alice", None)
            .await
            .unwrap(),
        alice
    );
    assert!(
        Store::read_history(&bob, None, None)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(operator.history(None).await.unwrap().len(), 1);
    let list = registry.list().await.unwrap();
    assert_eq!(list.len(), 4);
    let id = alice.file_name().unwrap().to_str().unwrap();
    assert_eq!(registry.resolve_existing(id).await.unwrap(), alice);
    assert!(registry.resolve_existing("../objects").await.is_err());
}

#[tokio::test]
async fn concurrent_provisioning_reuses_one_workspace_and_failed_initialization_recovers() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let registry = WorkspaceRegistry::open(dir.path()).await.unwrap();
    assert!(
        registry
            .resolve_identity("issuer", "subject", Some("invalid"))
            .await
            .is_err()
    );
    assert!(registry.list().await.unwrap().is_empty());
    let (a, b) = tokio::join!(
        registry.resolve_identity("issuer", "subject", None),
        registry.resolve_identity("issuer", "subject", None)
    );
    assert_eq!(a.unwrap(), b.unwrap());
    assert_eq!(registry.list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn rejects_changed_store_id() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let registry = WorkspaceRegistry::open(dir.path()).await.unwrap();
    let path = registry.resolve_shared(None).await.unwrap();
    let id = path.file_name().unwrap().to_str().unwrap();
    std::fs::write(path.join("store-id"), uuid::Uuid::new_v4().to_string()).unwrap();
    assert!(registry.resolve_existing(id).await.is_err());
    assert!(registry.resolve_shared(None).await.is_err());
}

#[tokio::test]
async fn rejects_workspace_directory_symlink() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let registry = WorkspaceRegistry::open(dir.path()).await.unwrap();
    let path = registry.resolve_shared(None).await.unwrap();
    let id = path.file_name().unwrap().to_str().unwrap().to_owned();
    let moved = dir.path().join("moved");
    std::fs::rename(&path, &moved).unwrap();
    symlink(&moved, &path).unwrap();
    assert!(registry.resolve_existing(&id).await.is_err());
    assert!(registry.resolve_shared(None).await.is_err());
}

#[tokio::test]
async fn postgres_workspaces_keep_metadata_and_objects_separate_when_configured() {
    let Ok(url) = std::env::var("PDF2MD_TEST_POSTGRES_URL") else {
        return;
    };
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let registry = WorkspaceRegistry::open(dir.path()).await.unwrap();
    let alice_path = registry
        .resolve_identity("issuer", "alice", Some(&url))
        .await
        .unwrap();
    let bob_path = registry
        .resolve_identity("issuer", "bob", Some(&url))
        .await
        .unwrap();
    let alice = Store::open(&alice_path, Some(&url)).await.unwrap();
    let bob = Store::open(&bob_path, Some(&url)).await.unwrap();
    let mut alice_input = alice.staging_file().unwrap();
    let mut bob_input = bob.staging_file().unwrap();
    alice_input.write_all(b"%PDF-1.7\nshared content").unwrap();
    bob_input.write_all(b"%PDF-1.7\nshared content").unwrap();
    let first = alice
        .accept(alice_input.path(), "source", "https", None, "attempt")
        .await
        .unwrap();
    let second = bob
        .accept(bob_input.path(), "source", "https", None, "attempt")
        .await
        .unwrap();
    assert_eq!(first.document_id, second.document_id);
    let shared_id = first.document_id.unwrap();
    assert!(alice_path.join("objects").join(&shared_id).is_file());
    assert!(bob_path.join("objects").join(&shared_id).is_file());
    let mut private = alice.staging_file().unwrap();
    private.write_all(b"%PDF-1.7\nalice only").unwrap();
    let private_id = alice
        .accept(private.path(), "source", "https", None, "private")
        .await
        .unwrap()
        .document_id
        .unwrap();
    assert!(alice.open_document(&private_id).await.is_ok());
    assert!(bob.open_document(&private_id).await.is_err());
    assert!(!bob_path.join("objects").join(&private_id).exists());
    assert_eq!(alice.history(Some("source")).await.unwrap().len(), 2);
    assert_eq!(bob.history(Some("source")).await.unwrap().len(), 1);
    alice.set_next_due("source", 11).await.unwrap();
    bob.set_next_due("source", 22).await.unwrap();
    assert_eq!(alice.next_due("source").await.unwrap(), Some(11));
    assert_eq!(bob.next_due("source").await.unwrap(), Some(22));
}
