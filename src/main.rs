use clap::{Parser, Subcommand};
use futures_util::{StreamExt, stream};
use pdf2md_mcp::{
    config::{Config, Mode, Source},
    error::{LoadError, Result},
    manual,
    model::Observation,
    runtime,
    storage::Store,
};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    version,
    about = "Acquire and archive PDFs; conversion and MCP transport are not implemented"
)]
struct Cli {
    #[arg(long, global = true, default_value = "pdf2md-mcp-data")]
    data_dir: PathBuf,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Name of an environment variable containing an external PostgreSQL 18+ URL.
    #[arg(long, global = true)]
    database_url_env: Option<String>,
    #[arg(long, global = true, default_value = "pdf2md-obscura-worker")]
    worker: PathBuf,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
    /// Show the latest observation for each source.
    Status,
    /// Show all observations, optionally restricted to a source.
    History { source: Option<String> },
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
    if matches!(cli.command, Command::Status | Command::History { .. }) {
        let source = match &cli.command {
            Command::History { source } => source.as_deref(),
            _ => None,
        };
        let observations =
            Store::read_history(&cli.data_dir, database_url.as_deref(), source).await?;
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
    let store = Store::open(&cli.data_dir, database_url.as_deref()).await?;
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
                        Ok(obs) => emit(&obs, cli.json),
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
                emit(
                    &runtime::fetch(&store, &config, &source, &cli.worker, &cancel).await?,
                    cli.json,
                );
            }
            Command::Scan => {
                let mut failed = false;
                for obs in manual::scan(&store, config.limits.max_bytes, &cancel).await? {
                    failed |= obs.outcome == "failed";
                    emit(&obs, cli.json);
                }
                if failed {
                    return Err(LoadError::new(
                        "scan_failed",
                        "one or more manual PDFs could not be accepted",
                    ));
                }
            }
            Command::Watch | Command::Run => {
                runtime::daemon(
                    &store,
                    &config,
                    &cli.worker,
                    matches!(cli.command, Command::Run),
                    &cancel,
                    |o| emit(o, cli.json),
                )
                .await?
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
    cancel.cancel();
    signal_task.abort();
    result
}
