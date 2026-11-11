use pdf2md_mcp::{
    auth::AuthMode,
    config::Config,
    service::{CallerService, Operation, Response},
    storage::Store,
    workspace::WorkspaceRegistry,
};
use std::io::Write;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn default_ro_denies_acquisition_without_history_and_hides_operator_data() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let operator = Store::open(root.path(), None).await.unwrap();
    operator
        .record_failure("operator-private", "https", None, "attempt", "test")
        .await
        .unwrap();
    drop(operator);
    let service = CallerService::new(root.path(), Config::default(), None)
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let denied = service
        .execute(
            None,
            Operation::AcquireHttps {
                url: "https://example.com/private.pdf".into(),
            },
            &cancel,
        )
        .await;
    assert_eq!(denied.err().unwrap().code, "auth_forbidden");
    let Response::Observations(history) = service
        .execute(None, Operation::History { source: None }, &cancel)
        .await
        .unwrap()
    else {
        panic!("history response")
    };
    assert!(history.is_empty());
    assert_eq!(
        Store::read_history(root.path(), None, None).await.unwrap()[0].source_id,
        "operator-private"
    );
}

#[tokio::test]
async fn shared_modes_preserve_data_and_stream_only_owned_pdfs() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let registry = WorkspaceRegistry::open(root.path()).await.unwrap();
    let shared = registry.resolve_shared(None).await.unwrap();
    let store = Store::open(&shared, None).await.unwrap();
    let mut staged = store.staging_file().unwrap();
    let bytes = b"%PDF-1.7\nshared synthetic\n%%EOF";
    staged.write_all(bytes).unwrap();
    let obs = store
        .accept(staged.path(), "shared", "manual", None, "attempt")
        .await
        .unwrap();
    drop(store);
    let cancel = CancellationToken::new();
    for mode in [AuthMode::NoneRo, AuthMode::NoneRw] {
        let mut config = Config::default();
        config.auth.mode = mode;
        let service = CallerService::new(root.path(), config, None).await.unwrap();
        let Response::Pdf(mut stream) = service
            .execute(
                Some("ignored-anonymous-credential"),
                Operation::ReadPdf {
                    document_id: obs.document_id.clone().unwrap(),
                },
                &cancel,
            )
            .await
            .unwrap()
        else {
            panic!("PDF response")
        };
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, bytes);
        let missing = service
            .execute(
                None,
                Operation::ReadPdf {
                    document_id: "a".repeat(64),
                },
                &cancel,
            )
            .await;
        assert_eq!(missing.err().unwrap().code, "document_not_found");
        drop(stream);
    }
}

#[tokio::test]
async fn anonymous_rw_admits_https_only_and_cancellation_has_no_acquisition_effects() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let mut config = Config::default();
    config.auth.mode = AuthMode::NoneRw;
    let service = CallerService::new(root.path(), config, None).await.unwrap();
    let cancel = CancellationToken::new();
    let result = service
        .execute(
            None,
            Operation::AcquireHttps {
                url: "http://127.0.0.1/private.pdf".into(),
            },
            &cancel,
        )
        .await;
    assert_ne!(result.err().unwrap().code, "auth_forbidden");
    cancel.cancel();
    let result = service
        .execute(
            None,
            Operation::AcquireHttps {
                url: "https://example.com/test.pdf".into(),
            },
            &cancel,
        )
        .await;
    assert_eq!(result.err().unwrap().code, "cancelled");
    let Response::Observations(history) = service
        .execute(
            None,
            Operation::History { source: None },
            &CancellationToken::new(),
        )
        .await
        .unwrap()
    else {
        panic!("history response")
    };
    assert!(history.is_empty());
}

#[test]
fn omitted_auth_is_ro_and_oidc_files_are_resolved_relative_to_config() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "[auth]\nmode='oauth2'\n[auth.oidc]\nissuer='https://auth.example.com'\naudience='https://pdf.example.com'\nclient_id='pdf'\nca_file='ca.pem'\nclient_secret={file='secret'}\n").unwrap();
    let config = Config::read(Some(&path)).unwrap();
    let oidc = config.auth.oidc.unwrap();
    assert_eq!(oidc.ca_file.unwrap(), dir.path().join("ca.pem"));
    assert_eq!(
        oidc.client_secret.unwrap().file.unwrap(),
        dir.path().join("secret")
    );
    assert_eq!(Config::default().auth.mode, AuthMode::NoneRo);
}
