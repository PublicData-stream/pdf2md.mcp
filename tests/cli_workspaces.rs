use pdf2md_mcp::workspace::WorkspaceRegistry;
use std::{path::Path, process::Command};

fn cli(root: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pdf2md-mcp"))
        .arg("--data-dir")
        .arg(root)
        .args(args)
        .env("TMPDIR", "/tmp")
        .output()
        .unwrap()
}

#[tokio::test]
async fn trusted_cli_selects_workspaces_without_publishing_operator_history() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    assert!(cli(root.path(), &["scan"]).status.success());
    std::fs::write(root.path().join("pdfs/private.pdf"), b"%PDF-1.7\noperator").unwrap();
    // Default auth mode is RO for callers; operator CLI writes still succeed.
    assert!(cli(root.path(), &["scan"]).status.success());
    assert!(
        cli(root.path(), &["--workspace", "shared", "scan"])
            .status
            .success()
    );
    let registry = WorkspaceRegistry::open(root.path()).await.unwrap();
    let shared = registry.resolve_shared(None).await.unwrap();
    std::fs::write(shared.join("pdfs/shared.pdf"), b"%PDF-1.7\nshared").unwrap();
    assert!(
        cli(root.path(), &["--workspace", "shared", "scan"])
            .status
            .success()
    );
    let operator: serde_json::Value = serde_json::from_slice(
        cli(root.path(), &["history", "--json"])
            .stdout
            .split(|b| *b == b'\n')
            .find(|line| !line.is_empty())
            .unwrap(),
    )
    .unwrap();
    let public: serde_json::Value = serde_json::from_slice(
        cli(root.path(), &["--workspace", "shared", "history", "--json"])
            .stdout
            .split(|b| *b == b'\n')
            .find(|line| !line.is_empty())
            .unwrap(),
    )
    .unwrap();
    assert_ne!(operator["document_id"], public["document_id"]);
    let listed = cli(root.path(), &["workspaces", "--json"]);
    assert!(listed.status.success());
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["kind"], "shared");
    assert!(
        !cli(root.path(), &["--workspace", "../objects", "history"])
            .status
            .success()
    );
}
