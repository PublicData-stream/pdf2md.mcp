use clap::{Parser, Subcommand};
use fs2::FileExt;
use futures_util::{StreamExt, stream};
use pdf2md_mcp::{
    config::{Config, Mode, Source},
    conversion::{self, ConversionAttempt, ConversionOptions},
    error::{LoadError, Result},
    manual,
    model::Observation,
    runtime,
    storage::Store,
    workspace::WorkspaceRegistry,
};
use std::{path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(version, about = "Acquire, archive, and convert PDFs to Markdown")]
struct Cli {
    #[arg(long, global = true, default_value = "pdf2md-mcp-data")]
    data_dir: PathBuf,
    /// Trusted operator selection; caller identities cannot supply this selector.
    #[arg(long, global = true, default_value = "operator")]
    workspace: String,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Name of an environment variable containing an external PostgreSQL 18+ URL.
    #[arg(long, global = true)]
    database_url_env: Option<String>,
    #[arg(long, global = true, default_value = "pdf2md-obscura-worker")]
    worker: PathBuf,
    #[arg(long, global = true)]
    conversion_worker: Option<PathBuf>,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the workspace-authorized HTTP/OpenAPI API.
    Serve {
        #[arg(long)]
        listen: Option<std::net::SocketAddr>,
    },
    /// Inspect or revoke durable polling grants in the selected workspace.
    Schedules {
        #[command(subcommand)]
        action: ScheduleCommand,
    },
    /// List initialized caller workspaces (trusted operator operation).
    Workspaces,
    /// Load a named TOML source now.
    Fetch {
        #[arg(required_unless_present="all",conflicts_with="all",num_args=1..)]
        source: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// Load one URL, without browser navigation steps.
    FetchUrl {
        url: String,
        #[arg(long, value_enum, default_value = "https")]
        mode: Mode,
    },
    /// Register new and changed manually copied PDFs.
    Scan,
    /// Watch manual files only.
    Watch,
    /// Watch manual files and poll sources with configured intervals.
    Run,
    /// Convert a stored PDF; page numbers are one-based and inclusive.
    Convert {
        document_id: String,
        #[arg(long)]
        pages: Option<String>,
        #[arg(long)]
        force: bool,
    },
    /// Show conversion attempts independently from acquisition history.
    ConversionHistory { document_id: Option<String> },
    /// Export a successful conversion into a new directory.
    Export {
        conversion_id: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Show the latest observation for each source.
    Status,
    /// Show all observations, optionally restricted to a source.
    History { source: Option<String> },
    /// Obtain an access token with the configured `[auth.client]`.
    Oauth {
        #[command(subcommand)]
        grant: OauthCommand,
    },
}

/// Token-acquisition grants. Tokens are printed as JSON on standard output;
/// Resource Owner Password Credentials is not supported.
#[derive(Subcommand)]
enum OauthCommand {
    /// Client Credentials grant with the client's own secret.
    ClientCredentials,
    /// Device Authorization grant: approve the printed code in a browser.
    Device,
    /// Refresh Token grant; reads the refresh token from an environment variable.
    Refresh {
        #[arg(long)]
        refresh_token_env: String,
    },
}

async fn oauth(config: &Config, grant: &OauthCommand) -> Result<()> {
    let client = pdf2md_mcp::oauth::OAuthClient::new(&config.auth)?.ok_or_else(|| {
        LoadError::new(
            "config_invalid",
            "OAuth2 mode with an [auth.client] section is required",
        )
    })?;
    let tokens = match grant {
        OauthCommand::ClientCredentials => client.client_credentials().await?,
        OauthCommand::Device => {
            let device = client.device_authorization().await?;
            eprintln!(
                "Open {} and confirm the code {} within {} seconds.",
                device
                    .verification_uri_complete
                    .as_deref()
                    .unwrap_or(&device.verification_uri),
                device.user_code,
                device.expires_in
            );
            client.wait_for_device(&device).await?
        }
        OauthCommand::Refresh { refresh_token_env } => {
            let value = std::env::var(refresh_token_env).map_err(|_| {
                LoadError::new(
                    "config_invalid",
                    "refresh token environment variable unavailable",
                )
            })?;
            client.refresh(&value).await?
        }
    };
    println!(
        "{}",
        serde_json::to_string(&tokens).expect("serializable token response")
    );
    Ok(())
}

#[derive(Subcommand)]
enum ScheduleCommand {
    List,
    Disable { source_id: String },
}

async fn serve(
    cli: &Cli,
    mut config: Config,
    database_url: Option<String>,
    listen: Option<std::net::SocketAddr>,
) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if cli.workspace != "operator" {
        return Err(LoadError::new(
            "config_invalid",
            "serve selects workspaces from caller authentication",
        ));
    }
    if let Some(address) = listen {
        config.http.bind = address.to_string();
    }
    config.validate()?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&cli.data_dir)
        .map_err(pdf2md_mcp::error::io_error)?;
    let owner = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(cli.data_dir.join(".serve.lock"))
        .map_err(pdf2md_mcp::error::io_error)?;
    if !owner
        .metadata()
        .map_err(pdf2md_mcp::error::io_error)?
        .is_file()
    {
        return Err(LoadError::new(
            "storage_locked",
            "invalid server ownership file",
        ));
    }
    owner
        .try_lock_exclusive()
        .map_err(|_| LoadError::new("storage_locked", "server already owns this data root"))?;
    let address = config.http.bind.clone();
    let service = Arc::new(
        pdf2md_mcp::service::CallerService::new(&cli.data_dir, config, database_url).await?,
    );
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .map_err(pdf2md_mcp::error::io_error)?;
    eprintln!(
        "HTTP listener {}",
        listener.local_addr().map_err(pdf2md_mcp::error::io_error)?
    );
    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();
    let signal = tokio::spawn(async move {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _=tokio::signal::ctrl_c()=>{},
            _=async{match &mut terminate {Some(signal)=>{signal.recv().await;},None=>std::future::pending::<()>().await}}=>{}
        }
        signal_cancel.cancel();
    });
    let dispatcher_service = service.clone();
    let dispatcher_cancel = cancel.clone();
    let worker = cli.worker.clone();
    let converter = conversion_worker(cli);
    let dispatch = tokio::spawn(async move {
        let result = dispatcher_service
            .run(&worker, &converter, &dispatcher_cancel)
            .await;
        dispatcher_cancel.cancel();
        result
    });
    let result = axum::serve(listener, pdf2md_mcp::http::router(service, cancel.clone()))
        .with_graceful_shutdown(cancel.clone().cancelled_owned())
        .await
        .map_err(pdf2md_mcp::error::io_error);
    cancel.cancel();
    let dispatched = dispatch
        .await
        .map_err(|_| LoadError::new("service_failed", "job dispatcher failed"))?;
    signal.abort();
    dispatched?;
    result
}

fn emit(obs: &Observation, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string(obs).expect("serializable observation")
        );
    } else {
        println!(
            "{} {} {} {} bytes {}",
            obs.source_id,
            obs.outcome,
            obs.document_id.as_deref().unwrap_or("-"),
            obs.bytes,
            obs.error_code.as_deref().unwrap_or("")
        );
    }
}

fn emit_conversion(attempt: &ConversionAttempt, json: bool, stderr: bool) {
    let value = if json {
        serde_json::to_string(attempt).expect("serializable conversion")
    } else {
        format!(
            "conversion {} {} {} {}",
            attempt.id,
            attempt.document_id,
            attempt.status,
            attempt.error_code.as_deref().unwrap_or("")
        )
    };
    if stderr {
        eprintln!("{value}");
    } else {
        println!("{value}");
    }
}

fn conversion_worker(cli: &Cli) -> PathBuf {
    cli.conversion_worker.clone().unwrap_or_else(|| {
        // Core builds install both binaries together; PATH remains a portable fallback.
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("pdf2md-convert-worker")))
            .filter(|p| p.is_file())
            .unwrap_or_else(|| PathBuf::from("pdf2md-convert-worker"))
    })
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(&cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            if cli.json {
                eprintln!(
                    "{}",
                    serde_json::to_string(&error).expect("serializable error")
                );
            } else {
                eprintln!("{error}");
            }
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: &Cli) -> Result<()> {
    let config = Config::read(cli.config.as_deref())?;
    let name = cli
        .database_url_env
        .as_ref()
        .or(config.database_url_env.as_ref());
    let database_url = name
        .map(|name| {
            std::env::var(name).map_err(|_| {
                LoadError::new(
                    "database_config",
                    "database URL environment variable unavailable",
                )
            })
        })
        .transpose()?;
    if let Command::Serve { listen } = &cli.command {
        return serve(cli, config, database_url, *listen).await;
    }
    if let Command::Oauth { grant } = &cli.command {
        return oauth(&config, grant).await;
    }
    if matches!(cli.command, Command::Workspaces) {
        let registry = WorkspaceRegistry::open(&cli.data_dir).await?;
        let entries = registry.list().await?;
        if cli.json {
            println!(
                "{}",
                serde_json::to_string(&entries).expect("serializable workspaces")
            );
        } else {
            for entry in entries {
                println!("{} {}", entry.id, entry.kind);
            }
        }
        return Ok(());
    }
    let data_dir = if cli.workspace == "operator" {
        cli.data_dir.clone()
    } else {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&cli.data_dir)
            .map_err(pdf2md_mcp::error::io_error)?;
        let registry = WorkspaceRegistry::open(&cli.data_dir).await?;
        if cli.workspace == "shared" {
            registry.resolve_shared(database_url.as_deref()).await?
        } else {
            registry.resolve_existing(&cli.workspace).await?
        }
    };
    if let Command::Schedules { action } = &cli.command {
        let store = Store::open(&data_dir, database_url.as_deref()).await?;
        match action {
            ScheduleCommand::List => {
                for schedule in store.schedules().await? {
                    println!(
                        "{}",
                        serde_json::to_string(&schedule).expect("serializable schedule")
                    );
                }
            }
            ScheduleCommand::Disable { source_id } => {
                let schedule = store
                    .schedules()
                    .await?
                    .into_iter()
                    .find(|s| &s.source_id == source_id)
                    .ok_or_else(|| LoadError::new("source_not_found", "schedule unavailable"))?;
                store
                    .set_schedule(
                        source_id,
                        false,
                        schedule.interval_secs,
                        &schedule.fingerprint,
                    )
                    .await?;
                println!(
                    "{}",
                    serde_json::to_string(&store.schedules().await?)
                        .expect("serializable schedules")
                );
            }
        }
        return Ok(());
    }
    match &cli.command {
        Command::ConversionHistory { document_id } => {
            for attempt in Store::read_conversion_history(
                &data_dir,
                database_url.as_deref(),
                document_id.as_deref(),
            )
            .await?
            {
                emit_conversion(&attempt, cli.json, false);
            }
            return Ok(());
        }
        Command::Export {
            conversion_id,
            output,
        } => {
            let manifest =
                Store::export_conversion(&data_dir, database_url.as_deref(), conversion_id, output)
                    .await?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string(&manifest).expect("serializable manifest")
                );
            } else {
                println!("exported {}", conversion_id);
            }
            return Ok(());
        }
        _ => {}
    }
    if matches!(cli.command, Command::Status | Command::History { .. }) {
        let source = match &cli.command {
            Command::History { source } => source.as_deref(),
            _ => None,
        };
        let observations = Store::read_history(&data_dir, database_url.as_deref(), source).await?;
        if matches!(cli.command, Command::Status) {
            let mut latest = std::collections::BTreeMap::new();
            for obs in observations {
                latest.insert(obs.source_id.clone(), obs);
            }
            for obs in latest.values() {
                emit(obs, cli.json);
            }
        } else {
            for obs in observations {
                emit(&obs, cli.json);
            }
        }
        return Ok(());
    }
    let automatic = config.conversion.enabled.then(ConversionOptions::default);
    let store = Store::open_with_conversion(&data_dir, database_url.as_deref(), automatic).await?;
    let conversion_worker = conversion_worker(cli);
    let mut acquired = Vec::new();
    let cancel = CancellationToken::new();
    let shutdown = cancel.clone();
    let signal_task = tokio::spawn(async move {
        #[cfg(unix)]
        {
            if let Ok(mut term) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        shutdown.cancel();
    });
    let result = async {
        match &cli.command {
            Command::Serve { .. }
            | Command::Oauth { .. }
            | Command::Schedules { .. }
            | Command::Workspaces
            | Command::ConversionHistory { .. }
            | Command::Export { .. } => {
                unreachable!("handled before opening store")
            }
            Command::Convert {
                document_id,
                pages,
                force,
            } => {
                let options = pages
                    .as_deref()
                    .map(ConversionOptions::parse_pages)
                    .transpose()?
                    .unwrap_or_default();
                let request = store
                    .request_conversion(document_id, &options, *force)
                    .await?;
                let attempt = if request.status == "pending" {
                    store
                        .process_conversion(
                            &request.id,
                            &config.conversion.limits,
                            &conversion_worker,
                            &cancel,
                        )
                        .await?
                } else {
                    request
                };
                emit_conversion(&attempt, cli.json, false);
                if attempt.status != "succeeded" {
                    return Err(LoadError::new(
                        attempt.error_code.as_deref().unwrap_or("conversion_failed"),
                        "PDF conversion failed",
                    ));
                }
            }
            Command::Fetch { source, all } => {
                if !all
                    && source
                        .iter()
                        .any(|id| !config.sources.iter().any(|s| &s.id == id))
                {
                    return Err(LoadError::new(
                        "source_not_found",
                        "source ID not found in configuration",
                    ));
                }
                let selected: Vec<_> = config
                    .sources
                    .iter()
                    .filter(|s| *all || source.contains(&s.id))
                    .collect();
                if selected.is_empty() {
                    return Err(LoadError::new("source_not_found", "no sources selected"));
                }
                let mut jobs = stream::iter(
                    selected
                        .into_iter()
                        .map(|s| runtime::fetch(&store, &config, s, &cli.worker, &cancel)),
                )
                .buffer_unordered(config.limits.concurrency);
                let mut failure = None;
                while let Some(result) = jobs.next().await {
                    match result {
                        Ok(obs) => {
                            emit(&obs, cli.json);
                            acquired.push(obs);
                        }
                        Err(e) => {
                            if e.code.starts_with("storage_") {
                                cancel.cancel();
                            }
                            failure.get_or_insert(e);
                        }
                    }
                }
                if let Some(e) = failure {
                    return Err(e);
                }
            }
            Command::FetchUrl { url, mode } => {
                if matches!(mode, Mode::Browser) {
                    return Err(LoadError::new(
                        "config_invalid",
                        "browser workflows require a named source",
                    ));
                }
                let source = Source::one_off(url.clone(), *mode);
                let obs = runtime::fetch(&store, &config, &source, &cli.worker, &cancel).await?;
                emit(&obs, cli.json);
                acquired.push(obs);
            }
            Command::Scan => {
                let mut failed = false;
                for obs in manual::scan(&store, config.limits.max_bytes, &cancel).await? {
                    failed |= obs.outcome == "failed";
                    emit(&obs, cli.json);
                    acquired.push(obs);
                }
                if failed {
                    return Err(LoadError::new(
                        "scan_failed",
                        "one or more manual PDFs could not be accepted",
                    ));
                }
            }
            Command::Watch | Command::Run => {
                let daemon = async {
                    let result = runtime::daemon(
                        &store,
                        &config,
                        &cli.worker,
                        matches!(cli.command, Command::Run),
                        &cancel,
                        |o| emit(o, cli.json),
                    )
                    .await;
                    cancel.cancel();
                    result
                };
                let conversions = async {
                    if config.conversion.enabled {
                        let result = conversion::orchestration::dispatch(
                            &store,
                            &config.conversion.limits,
                            &conversion_worker,
                            &cancel,
                            |a| emit_conversion(a, cli.json, true),
                        )
                        .await;
                        cancel.cancel();
                        result
                    } else {
                        cancel.cancelled().await;
                        Ok(())
                    }
                };
                let (acquisition, conversion) = tokio::join!(daemon, conversions);
                conversion?;
                acquisition?;
            }
            Command::History { source } => {
                for obs in store.history(source.as_deref()).await? {
                    emit(&obs, cli.json)
                }
            }
            Command::Status => {
                let mut latest = std::collections::BTreeMap::new();
                for obs in store.history(None).await? {
                    latest.insert(obs.source_id.clone(), obs);
                }
                for obs in latest.values() {
                    emit(obs, cli.json);
                }
            }
        }
        Ok(())
    }
    .await;
    let conversion_result = async {
        if config.conversion.enabled {
            let mut seen = std::collections::BTreeSet::new();
            for observation in acquired {
                if let Some(request) = store
                    .conversion_for_observation(&observation.attempt_id)
                    .await?
                    && seen.insert(request.id.clone())
                {
                    let attempt = if request.status == "pending" && !cancel.is_cancelled() {
                        store
                            .process_conversion(
                                &request.id,
                                &config.conversion.limits,
                                &conversion_worker,
                                &cancel,
                            )
                            .await?
                    } else {
                        request
                    };
                    emit_conversion(&attempt, cli.json, true);
                }
            }
        }
        Ok::<_, LoadError>(())
    }
    .await;
    cancel.cancel();
    signal_task.abort();
    result.and(conversion_result)
}
