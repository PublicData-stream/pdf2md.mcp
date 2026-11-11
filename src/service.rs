//! Transport-independent caller boundary. The CLI and raw stores remain trusted APIs.
use crate::{
    auth::{Authenticator, Identity},
    config::{Config, Mode, Source},
    error::{LoadError, Result, io_error},
    model::Observation,
    runtime,
    storage::Store,
    workspace::WorkspaceRegistry,
};
use std::{
    collections::{BTreeMap, HashMap},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::{Mutex, Semaphore},
};
use tokio_util::sync::CancellationToken;

/// Operations deliberately exclude operator sources, scripts, files and credentials.
pub enum Operation {
    Status,
    History { source: Option<String> },
    ReadPdf { document_id: String },
    AcquireHttps { url: String },
}

pub enum Response {
    Observations(Vec<Observation>),
    Acquired(Observation),
    Pdf(PdfStream),
}

/// A verified PDF stream that retains workspace ownership until dropped.
pub struct PdfStream {
    file: tokio::fs::File,
    _store: Arc<Store>,
}

impl AsyncRead for PdfStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.file).poll_read(cx, buf)
    }
}

struct CachedStore {
    store: Arc<Store>,
    used: Instant,
}

pub struct CallerService {
    auth: Authenticator,
    registry: WorkspaceRegistry,
    database_url: Option<String>,
    config: Config,
    stores: Mutex<HashMap<PathBuf, CachedStore>>,
    acquisitions: Semaphore,
}

impl CallerService {
    /// Initialize once per host; no listener or OAuth login endpoints are started.
    pub async fn new(root: &Path, config: Config, database_url: Option<String>) -> Result<Self> {
        config.validate()?;
        let auth = Authenticator::new(config.auth.clone()).await?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)
            .map_err(io_error)?;
        let registry = WorkspaceRegistry::open(root).await?;
        let service = Self {
            auth,
            registry,
            database_url,
            acquisitions: Semaphore::new(config.limits.concurrency),
            config,
            stores: Mutex::new(HashMap::new()),
        };
        // Shared-workspace creation is host initialization, never a caller write.
        if !matches!(service.config.auth.mode, crate::auth::AuthMode::Oauth2) {
            let path = service
                .registry
                .resolve_shared(service.database_url.as_deref())
                .await?;
            service.store(path).await?;
        }
        Ok(service)
    }

    async fn store(&self, path: PathBuf) -> Result<Arc<Store>> {
        let mut stores = self.stores.lock().await;
        if let Some(entry) = stores.get_mut(&path) {
            entry.used = Instant::now();
            return Ok(entry.store.clone());
        }
        if stores.len() >= 32 {
            let oldest = stores
                .iter()
                .filter(|(_, entry)| Arc::strong_count(&entry.store) == 1)
                .min_by_key(|(_, entry)| entry.used)
                .map(|(path, _)| path.clone());
            match oldest {
                Some(path) => {
                    stores.remove(&path);
                }
                None => {
                    return Err(LoadError::transient(
                        "service_busy",
                        "all workspace handles are active",
                    ));
                }
            }
        }
        let store = Arc::new(Store::open(&path, self.database_url.as_deref()).await?);
        stores.insert(
            path,
            CachedStore {
                store: store.clone(),
                used: Instant::now(),
            },
        );
        Ok(store)
    }

    /// Pass the raw bearer value, not an HTTP Authorization header. Every call revalidates it.
    pub async fn execute(
        &self,
        token: Option<&str>,
        operation: Operation,
        cancel: &CancellationToken,
    ) -> Result<Response> {
        let write = matches!(operation, Operation::AcquireHttps { .. });
        let identity = self.auth.authenticate(token, write).await?;
        if cancel.is_cancelled() {
            return Err(LoadError::new("cancelled", "operation cancelled"));
        }
        let _admission = if write {
            Some(self.acquisitions.try_acquire().map_err(|_| {
                LoadError::transient("service_busy", "acquisition capacity unavailable")
            })?)
        } else {
            None
        };
        let path = match identity {
            Identity::Shared => {
                self.registry
                    .resolve_shared(self.database_url.as_deref())
                    .await?
            }
            Identity::User { issuer, subject } => {
                self.registry
                    .resolve_identity(&issuer, &subject, self.database_url.as_deref())
                    .await?
            }
        };
        let store = self.store(path).await?;
        match operation {
            Operation::Status => {
                let mut latest = BTreeMap::new();
                for obs in store.history(None).await? {
                    latest.insert(obs.source_id.clone(), obs);
                }
                Ok(Response::Observations(latest.into_values().collect()))
            }
            Operation::History { source } => Ok(Response::Observations(
                store.history(source.as_deref()).await?,
            )),
            Operation::ReadPdf { document_id } => {
                let file = store.open_document(&document_id).await?;
                Ok(Response::Pdf(PdfStream {
                    file: tokio::fs::File::from_std(file),
                    _store: store,
                }))
            }
            Operation::AcquireHttps { url } => {
                let source = Source::one_off(url, Mode::Https);
                // A fresh source cannot reference operator secrets, scripts or configuration.
                Ok(Response::Acquired(
                    runtime::fetch(&store, &self.config, &source, Path::new(""), cancel).await?,
                ))
            }
        }
    }
}
