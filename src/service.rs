//! Transport-independent, workspace-scoped caller boundary.
use crate::{
    auth::{AuthMode, Authenticator, Credentials, Identity},
    config::{Config, Mode, Source, Step},
    conversion::{ConversionAttempt, ConversionManifest, ConversionOptions},
    error::{LoadError, Result, io_error},
    jobs::{Job, JobCommand, Schedule},
    model::Observation,
    runtime,
    storage::Store,
    workspace::{WorkspaceInfo, WorkspaceRegistry},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore},
};
use tokio_util::sync::CancellationToken;

mod dispatcher;
pub mod tools;

/// Compatibility API for callers of the original transport-independent service.
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

/// A verified stream that pins workspace ownership and download admission.
pub struct AssetStream {
    file: tokio::fs::File,
    pub bytes: u64,
    _store: Arc<Store>,
    _permit: OwnedSemaphorePermit,
}
pub type PdfStream = AssetStream;
impl AsyncRead for AssetStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.file).poll_read(cx, buf)
    }
}

struct BundleLease {
    bundle: crate::conversion::store::VerifiedBundle,
    _store: Arc<Store>,
    _permit: OwnedSemaphorePermit,
}
/// A verified manifest and workspace lease for bounded batch artifact reads.
pub struct CallerBundle {
    inner: Arc<BundleLease>,
}
pub struct BundleArtifactStream {
    file: tokio::fs::File,
    _lease: Arc<BundleLease>,
}
impl AsyncRead for BundleArtifactStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.file).poll_read(cx, buf)
    }
}
impl CallerBundle {
    pub fn manifest(&self) -> &ConversionManifest {
        self.inner.bundle.manifest()
    }
    pub async fn read_artifact(&self, index: usize) -> Result<BundleArtifactStream> {
        let lease = self.inner.clone();
        let file = tokio::task::spawn_blocking(move || lease.bundle.open_artifact(index))
            .await
            .map_err(|_| LoadError::new("storage_io", "artifact verification failed"))??;
        Ok(BundleArtifactStream {
            file: tokio::fs::File::from_std(file),
            _lease: self.inner.clone(),
        })
    }
}
/// Verified caller workspace. Its path and raw storage interface remain private.
pub struct AuthorizedWorkspace {
    store: Arc<Store>,
}

/// Streaming upload admission. Dropping it removes its private staging file.
pub struct UploadSession {
    staged: tempfile::NamedTempFile,
    workspace: AuthorizedWorkspace,
    reservation: Option<UploadReservation>,
    _permit: OwnedSemaphorePermit,
    max_bytes: u64,
    deadline: Instant,
}
impl UploadSession {
    pub fn file_mut(&mut self) -> &mut tempfile::NamedTempFile {
        &mut self.staged
    }
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}
impl Write for UploadSession {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let length = self.staged.as_file().metadata()?.len();
        if length.saturating_add(bytes.len() as u64) > self.max_bytes {
            return Err(std::io::Error::other("upload byte limit exceeded"));
        }
        self.staged.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.staged.flush()
    }
}
#[derive(Debug, Serialize)]
pub struct UploadResult {
    pub observation: Observation,
    pub conversion_job: Option<Job>,
}
#[derive(Debug, Clone, Serialize)]
pub struct PublishedSource {
    pub id: String,
    pub mode: String,
    pub interval_secs: Option<u64>,
}
/// Reservations are short synchronous bookkeeping, so upload cancellation needs no async Drop.
struct UploadReservation {
    reservations: Arc<std::sync::Mutex<HashMap<PathBuf, usize>>>,
    workspace: PathBuf,
    units: usize,
}
impl Drop for UploadReservation {
    fn drop(&mut self) {
        let mut reservations = self
            .reservations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(count) = reservations.get_mut(&self.workspace) {
            *count = count.saturating_sub(self.units);
            if *count == 0 {
                reservations.remove(&self.workspace);
            }
        }
    }
}
struct PublishedDefinition {
    source: Source,
    fingerprint: String,
}
struct CachedStore {
    store: Arc<Store>,
    used: Instant,
}
struct RunningJob {
    cancel: CancellationToken,
    explicit: Arc<AtomicBool>,
}
pub struct CallerService {
    auth: Authenticator,
    oauth: Option<Arc<crate::oauth::OAuthClient>>,
    tool_state: tools::ToolState,
    registry: WorkspaceRegistry,
    database_url: Option<String>,
    config: Config,
    stores: Mutex<HashMap<PathBuf, CachedStore>>,
    acquisitions: Arc<Semaphore>,
    conversions: Arc<Semaphore>,
    downloads: Arc<Semaphore>,
    admission: Arc<Mutex<()>>,
    reservations: Arc<std::sync::Mutex<HashMap<PathBuf, usize>>>,
    definitions: HashMap<String, PublishedDefinition>,
    _scripts: tempfile::TempDir,
    wake: Notify,
    running: Mutex<HashMap<(PathBuf, String), RunningJob>>,
}
fn busy() -> LoadError {
    LoadError::transient("service_busy", "service capacity unavailable")
}
fn capacity() -> LoadError {
    LoadError::transient("job_capacity", "job capacity reached")
}
fn source_unavailable() -> LoadError {
    LoadError::new("source_not_found", "published source unavailable")
}

impl CallerService {
    pub async fn new(root: &Path, config: Config, database_url: Option<String>) -> Result<Self> {
        config.validate()?;
        let auth = Authenticator::new(config.auth.clone()).await?;
        let oauth = crate::oauth::OAuthClient::new(&config.auth)?.map(Arc::new);
        let scripts = tempfile::Builder::new()
            .prefix("pdf2md-source-snapshot-")
            .tempdir_in("/tmp")
            .map_err(io_error)?;
        let definitions = snapshot_definitions(&config, scripts.path())?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)
            .map_err(io_error)?;
        let registry = WorkspaceRegistry::open(root).await?;
        let service = Self {
            auth,
            oauth,
            tool_state: tools::ToolState::new(config.mcp.search_concurrency),
            registry,
            database_url,
            acquisitions: Arc::new(Semaphore::new(config.limits.concurrency)),
            conversions: Arc::new(Semaphore::new(config.conversion.limits.concurrency)),
            downloads: Arc::new(Semaphore::new(config.http.downloads)),
            admission: Arc::new(Mutex::new(())),
            reservations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            config,
            stores: Mutex::new(HashMap::new()),
            definitions,
            _scripts: scripts,
            wake: Notify::new(),
            running: Mutex::new(HashMap::new()),
        };
        if !matches!(service.config.auth.mode, AuthMode::Oauth2) {
            let path = service
                .registry
                .resolve_shared(service.database_url.as_deref())
                .await?;
            service.store(path).await?;
        }
        // Reconcile durable grants before dispatch can start. Incompatible work is preserved.
        for info in service.registry.list().await? {
            let path = service.registry.resolve_existing(&info.id).await?;
            let store = service.store(path).await?;
            if service.eligible(&info) {
                store.reconcile_sources(&service.fingerprints()).await?;
            } else {
                store.pause_schedules("auth_mode_changed").await?;
            }
        }
        Ok(service)
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    /// Verify a request's DPoP proof; see [`Authenticator::verify_dpop`].
    pub fn verify_dpop(
        &self,
        proof: &str,
        method: &str,
        path: &str,
        access_token: &str,
    ) -> Result<crate::dpop::ProvenKey> {
        self.auth.verify_dpop(proof, method, path, access_token)
    }
    /// The registered OAuth client, when `[auth.client]` is configured.
    pub fn oauth_client(&self) -> Option<Arc<crate::oauth::OAuthClient>> {
        self.oauth.clone()
    }
    fn fingerprints(&self) -> Vec<(String, String)> {
        self.definitions
            .iter()
            .map(|(id, def)| (id.clone(), def.fingerprint.clone()))
            .collect()
    }
    fn eligible(&self, info: &WorkspaceInfo) -> bool {
        match self.config.auth.mode {
            AuthMode::NoneRo => false,
            AuthMode::NoneRw => info.kind == "shared",
            AuthMode::Oauth2 => {
                info.kind == "identity"
                    && self
                        .config
                        .auth
                        .oidc
                        .as_ref()
                        .is_some_and(|oidc| info.issuer.as_deref() == Some(&oidc.issuer))
            }
        }
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
            if let Some(path) = oldest {
                stores.remove(&path);
            } else {
                return Err(busy());
            }
        }
        let automatic = self
            .config
            .conversion
            .enabled
            .then(ConversionOptions::default);
        let store = Arc::new(
            Store::open_with_conversion(&path, self.database_url.as_deref(), automatic).await?,
        );
        stores.insert(
            path,
            CachedStore {
                store: store.clone(),
                used: Instant::now(),
            },
        );
        Ok(store)
    }
    /// Bearer values are revalidated for each caller operation, before resolving a workspace.
    pub async fn authorize<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        write: bool,
        operate: bool,
    ) -> Result<AuthorizedWorkspace> {
        let token: Credentials<'c> = token.into();
        let identity = self
            .auth
            .authorize_credentials(token, write, operate)
            .await?;
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
        Ok(AuthorizedWorkspace {
            store: self.store(path).await?,
        })
    }
    pub async fn history_page<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        source: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Observation>> {
        let token: Credentials<'c> = token.into();
        self.authorize(token, false, false)
            .await?
            .store
            .history_page(source, limit, offset)
            .await
    }
    pub async fn status_page<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Observation>> {
        let token: Credentials<'c> = token.into();
        self.authorize(token, false, false)
            .await?
            .store
            .status_page(limit, offset)
            .await
    }
    pub async fn jobs_page<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Job>> {
        let token: Credentials<'c> = token.into();
        self.authorize(token, false, false)
            .await?
            .store
            .jobs_page(limit, offset)
            .await
    }
    pub async fn conversion_history_page<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        document: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ConversionAttempt>> {
        let token: Credentials<'c> = token.into();
        self.authorize(token, false, false)
            .await?
            .store
            .conversion_history_page(document, limit, offset)
            .await
    }
    pub async fn history<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        source: Option<&str>,
    ) -> Result<Vec<Observation>> {
        let token: Credentials<'c> = token.into();
        self.authorize(token, false, false)
            .await?
            .store
            .history(source)
            .await
    }
    pub async fn conversion_history<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        document: Option<&str>,
    ) -> Result<Vec<ConversionAttempt>> {
        let token: Credentials<'c> = token.into();
        let workspace = self.authorize(token, false, false).await?;
        Store::read_conversion_history(
            workspace.store.root(),
            self.database_url.as_deref(),
            document,
        )
        .await
    }
    pub async fn read_pdf<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        document_id: &str,
    ) -> Result<PdfStream> {
        let token: Credentials<'c> = token.into();
        let workspace = self.authorize(token, false, false).await?;
        let permit = self
            .downloads
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let file = workspace.store.open_document(document_id).await?;
        let bytes = file.metadata().map_err(io_error)?.len();
        Ok(AssetStream {
            file: tokio::fs::File::from_std(file),
            bytes,
            _store: workspace.store,
            _permit: permit,
        })
    }
    pub async fn conversion_manifest<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        conversion_id: &str,
    ) -> Result<ConversionManifest> {
        let token: Credentials<'c> = token.into();
        self.authorize(token, false, false)
            .await?
            .store
            .verified_conversion_manifest(conversion_id)
            .await
    }
    pub async fn read_bundle<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        conversion_id: &str,
    ) -> Result<CallerBundle> {
        let token: Credentials<'c> = token.into();
        let workspace = self.authorize(token, false, false).await?;
        let permit = self
            .downloads
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let bundle = workspace.store.open_verified_bundle(conversion_id).await?;
        Ok(CallerBundle {
            inner: Arc::new(BundleLease {
                bundle,
                _store: workspace.store,
                _permit: permit,
            }),
        })
    }
    pub async fn read_artifact<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        conversion_id: &str,
        path: &str,
    ) -> Result<BundleArtifactStream> {
        let token: Credentials<'c> = token.into();
        let bundle = self.read_bundle(token, conversion_id).await?;
        let index = bundle
            .manifest()
            .artifacts
            .iter()
            .position(|artifact| artifact.path == path)
            .ok_or_else(|| LoadError::new("conversion_not_found", "artifact unavailable"))?;
        bundle.read_artifact(index).await
    }
    pub async fn prepare_upload<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
    ) -> Result<UploadSession> {
        let token: Credentials<'c> = token.into();
        let workspace = self.authorize(token, true, false).await?;
        let permit = self
            .acquisitions
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let _admission = self.admission.lock().await;
        let reservation = if self.config.conversion.enabled {
            self.check_capacity(&workspace.store, 1).await?;
            let path = workspace.store.root().to_owned();
            *self
                .reservations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .entry(path.clone())
                .or_default() += 1;
            Some(UploadReservation {
                reservations: self.reservations.clone(),
                workspace: path,
                units: 1,
            })
        } else {
            None
        };
        let staged = workspace.store.staging_file()?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(self.config.limits.timeout_secs))
            .ok_or_else(|| LoadError::new("config_invalid", "timeout is too large"))?;
        Ok(UploadSession {
            staged,
            workspace,
            reservation,
            _permit: permit,
            max_bytes: self.config.limits.max_bytes,
            deadline,
        })
    }
    pub async fn finish_upload(
        &self,
        mut session: UploadSession,
        cancel: &CancellationToken,
    ) -> Result<UploadResult> {
        session.staged.flush().map_err(io_error)?;
        if session.staged.as_file().metadata().map_err(io_error)?.len() > session.max_bytes {
            return Err(LoadError::new(
                "size_limit",
                "PDF exceeds configured byte limit",
            ));
        }
        let attempt = uuid::Uuid::new_v4().to_string();
        let source = format!("upload:{attempt}");
        let _admission = self.admission.lock().await;
        let observation = session
            .workspace
            .store
            .accept_before(
                session.staged.path(),
                &source,
                "upload",
                None,
                &attempt,
                session.deadline,
                cancel,
            )
            .await?;
        let conversion_job = match session
            .workspace
            .store
            .conversion_for_observation(&attempt)
            .await?
        {
            Some(conversion) => Some(session.workspace.store.job(&conversion.id).await?),
            None => None,
        };
        session.reservation.take();
        self.wake.notify_one();
        Ok(UploadResult {
            observation,
            conversion_job,
        })
    }
    pub async fn submit_acquisition<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        url: String,
        key: Option<&str>,
    ) -> Result<Job> {
        let token: Credentials<'c> = token.into();
        let workspace = self.authorize(token, true, false).await?;
        let source = Source::one_off(url.clone(), Mode::Https);
        crate::policy::NetworkPolicy::for_source(&source)?;
        self.enqueue(&workspace.store, JobCommand::AcquireHttps { url }, key)
            .await
    }
    pub async fn submit_source<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        source_id: &str,
        key: Option<&str>,
    ) -> Result<Job> {
        let token: Credentials<'c> = token.into();
        let workspace = self.authorize(token, true, true).await?;
        let definition = self
            .definitions
            .get(source_id)
            .ok_or_else(source_unavailable)?;
        self.enqueue(
            &workspace.store,
            JobCommand::FetchSource {
                source_id: source_id.into(),
                fingerprint: definition.fingerprint.clone(),
            },
            key,
        )
        .await
    }
    pub async fn submit_conversion<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        document_id: &str,
        pages: Option<&str>,
        force: bool,
        key: Option<&str>,
    ) -> Result<Job> {
        let token: Credentials<'c> = token.into();
        let workspace = self.authorize(token, true, false).await?;
        let options = pages
            .map(ConversionOptions::parse_pages)
            .transpose()?
            .unwrap_or_default();
        workspace.store.open_document(document_id).await?;
        self.enqueue(
            &workspace.store,
            JobCommand::Convert {
                document_id: document_id.into(),
                options,
                force,
            },
            key,
        )
        .await
    }
    async fn enqueue(
        &self,
        store: &Arc<Store>,
        command: JobCommand,
        key: Option<&str>,
    ) -> Result<Job> {
        self.enqueue_internal(store, command, key, None).await
    }
    async fn enqueue_internal(
        &self,
        store: &Arc<Store>,
        command: JobCommand,
        key: Option<&str>,
        retry_of: Option<&str>,
    ) -> Result<Job> {
        if key.is_some_and(|key| {
            key.is_empty() || key.len() > 128 || !key.bytes().all(|b| b.is_ascii_graphic())
        }) {
            return Err(LoadError::new(
                "idempotency_invalid",
                "invalid idempotency key",
            ));
        }
        let _admission = self.admission.lock().await;
        if let Some(key) = key
            && let Some(existing) = store.job_for_key(key).await?
        {
            let _ = existing;
            return Ok(store
                .enqueue_retry_job(
                    &command,
                    Some(key),
                    self.config.http.per_workspace_jobs,
                    retry_of,
                )
                .await?
                .0);
        }
        // Automatic conversion publication is reserved with the acquisition admission.
        if store.reusable_conversion(&command).await?.is_some() {
            return Ok(store
                .enqueue_retry_job(&command, key, self.config.http.per_workspace_jobs, retry_of)
                .await?
                .0);
        }
        let weight = self.weight(&command);
        self.check_capacity(store, weight).await?;
        let (job, _) = store
            .enqueue_retry_job(&command, key, self.config.http.per_workspace_jobs, retry_of)
            .await?;
        self.wake.notify_one();
        Ok(job)
    }
    fn weight(&self, command: &JobCommand) -> usize {
        if self.config.conversion.enabled && !matches!(command, JobCommand::Convert { .. }) {
            2
        } else {
            1
        }
    }
    async fn count_jobs(&self, store: &Store) -> Result<usize> {
        let (total, acquisitions) = store.active_job_counts().await?;
        let reserved = self
            .reservations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(store.root())
            .copied()
            .unwrap_or(0);
        Ok(total
            .saturating_add(if self.config.conversion.enabled {
                acquisitions
            } else {
                0
            })
            .saturating_add(reserved))
    }
    async fn check_capacity(&self, workspace: &Store, additional: usize) -> Result<()> {
        if self.count_jobs(workspace).await?.saturating_add(additional)
            > self.config.http.per_workspace_jobs
        {
            return Err(capacity());
        }
        if self.total_jobs().await?.saturating_add(additional) > self.config.http.total_jobs {
            return Err(capacity());
        }
        Ok(())
    }
    async fn total_jobs(&self) -> Result<usize> {
        let mut total = 0usize;
        for info in self.registry.list().await? {
            let path = self.registry.resolve_existing(&info.id).await?;
            let store = self.store(path).await?;
            total = total.saturating_add(self.count_jobs(&store).await?);
        }
        Ok(total)
    }
    pub async fn jobs<'c>(&self, token: impl Into<Credentials<'c>>) -> Result<Vec<Job>> {
        let token: Credentials<'c> = token.into();
        self.authorize(token, false, false)
            .await?
            .store
            .jobs()
            .await
    }
    pub async fn get_job<'c>(&self, token: impl Into<Credentials<'c>>, id: &str) -> Result<Job> {
        let token: Credentials<'c> = token.into();
        self.authorize(token, false, false)
            .await?
            .store
            .job(id)
            .await
    }
    pub async fn cancel_job<'c>(&self, token: impl Into<Credentials<'c>>, id: &str) -> Result<Job> {
        let token: Credentials<'c> = token.into();
        let workspace = self.authorize(token, true, false).await?;
        let store = &workspace.store;
        let current = store.job(id).await?;
        if matches!(current.command, JobCommand::FetchSource { .. }) {
            self.auth.authorize_credentials(token, true, true).await?;
        }
        if let Some(running) = self
            .running
            .lock()
            .await
            .get(&(store.root().to_owned(), id.into()))
        {
            running.explicit.store(true, Ordering::Release);
            running.cancel.cancel();
        }
        let job = store.cancel_job(id).await?;
        self.wake.notify_one();
        Ok(job)
    }
    pub async fn retry_job<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        id: &str,
        key: Option<&str>,
    ) -> Result<Job> {
        let token: Credentials<'c> = token.into();
        let workspace = self.authorize(token, true, false).await?;
        let job = workspace.store.job(id).await?;
        if !matches!(job.status.as_str(), "failed" | "cancelled" | "interrupted") {
            return Err(LoadError::new(
                "job_not_retryable",
                "only failed, cancelled or interrupted jobs may be retried",
            ));
        }
        let command = match job.command {
            JobCommand::FetchSource { source_id, .. } => {
                self.auth.authorize_credentials(token, true, true).await?;
                let definition = self
                    .definitions
                    .get(&source_id)
                    .ok_or_else(source_unavailable)?;
                JobCommand::FetchSource {
                    source_id,
                    fingerprint: definition.fingerprint.clone(),
                }
            }
            JobCommand::Convert {
                document_id,
                options,
                ..
            } => JobCommand::Convert {
                document_id,
                options,
                force: true,
            },
            other => other,
        };
        self.enqueue_internal(&workspace.store, command, key, Some(id))
            .await
    }
    pub async fn sources<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
    ) -> Result<Vec<PublishedSource>> {
        let token: Credentials<'c> = token.into();
        self.authorize(token, false, false).await?;
        let mut definitions: Vec<_> = self
            .definitions
            .values()
            .map(|d| PublishedSource {
                id: d.source.id.clone(),
                mode: d.source.mode.as_str().into(),
                interval_secs: d.source.interval_secs,
            })
            .collect();
        definitions.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(definitions)
    }
    pub async fn schedules<'c>(&self, token: impl Into<Credentials<'c>>) -> Result<Vec<Schedule>> {
        let token: Credentials<'c> = token.into();
        self.authorize(token, false, false)
            .await?
            .store
            .schedules()
            .await
    }
    pub async fn set_schedule<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        source_id: &str,
        enabled: bool,
    ) -> Result<Schedule> {
        let token: Credentials<'c> = token.into();
        let workspace = self.authorize(token, true, true).await?;
        let definition = self
            .definitions
            .get(source_id)
            .ok_or_else(source_unavailable)?;
        let interval = definition.source.interval_secs.ok_or_else(|| {
            LoadError::new(
                "schedule_unavailable",
                "operator source does not permit scheduling",
            )
        })?;
        let _admission = self.admission.lock().await;
        workspace
            .store
            .set_schedule(source_id, enabled, interval, &definition.fingerprint)
            .await?;
        self.wake.notify_one();
        workspace
            .store
            .schedules()
            .await?
            .into_iter()
            .find(|s| s.source_id == source_id)
            .ok_or_else(source_unavailable)
    }
    /// Compatibility calls retain their original synchronous acquisition behavior.
    pub async fn execute<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        operation: Operation,
        cancel: &CancellationToken,
    ) -> Result<Response> {
        let token: Credentials<'c> = token.into();
        let write = matches!(operation, Operation::AcquireHttps { .. });
        let workspace = self.authorize(token, write, false).await?;
        if cancel.is_cancelled() {
            return Err(LoadError::new("cancelled", "operation cancelled"));
        }
        match operation {
            Operation::Status => {
                let mut latest = BTreeMap::new();
                for obs in workspace.store.history(None).await? {
                    latest.insert(obs.source_id.clone(), obs);
                }
                Ok(Response::Observations(latest.into_values().collect()))
            }
            Operation::History { source } => Ok(Response::Observations(
                workspace.store.history(source.as_deref()).await?,
            )),
            Operation::ReadPdf { document_id } => {
                drop(workspace);
                Ok(Response::Pdf(self.read_pdf(token, &document_id).await?))
            }
            Operation::AcquireHttps { url } => {
                let _permit = self
                    .acquisitions
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| busy())?;
                let _admission = self.admission.lock().await;
                if self.config.conversion.enabled {
                    self.check_capacity(&workspace.store, 1).await?;
                }
                let source = Source::one_off(url, Mode::Https);
                let observation = runtime::fetch(
                    &workspace.store,
                    &self.config,
                    &source,
                    Path::new(""),
                    cancel,
                )
                .await?;
                self.wake.notify_one();
                Ok(Response::Acquired(observation))
            }
        }
    }
}

/// Freeze operator scripts once; neither callers nor live edits can alter an admitted grant.
fn snapshot_definitions(
    config: &Config,
    directory: &Path,
) -> Result<HashMap<String, PublishedDefinition>> {
    use std::io::Read;
    let mut definitions = HashMap::new();
    for source in &config.sources {
        if !config.http.published_sources.contains(&source.id) {
            continue;
        }
        let mut source_copy = source.clone();
        let mut hash = Sha256::new();
        hash.update(
            serde_json::to_vec(source)
                .map_err(|_| LoadError::new("source_config", "invalid source definition"))?,
        );
        hash.update(
            serde_json::to_vec(&(
                config.limits.max_bytes,
                config.limits.timeout_secs,
                config.limits.worker_max_rss_mib,
            ))
            .map_err(|_| LoadError::new("source_config", "invalid source limits"))?,
        );
        for (index, step) in source_copy.steps.iter_mut().enumerate() {
            if let Step::Script { file } = step {
                let input = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&file)
                    .map_err(|_| {
                        LoadError::new("script_unavailable", "operator script unavailable")
                    })?;
                if !input.metadata().map_err(io_error)?.is_file() {
                    return Err(LoadError::new(
                        "script_unavailable",
                        "operator script unavailable",
                    ));
                }
                let mut bytes = Vec::new();
                input
                    .take(1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(io_error)?;
                if bytes.len() > 1024 * 1024 || std::str::from_utf8(&bytes).is_err() {
                    return Err(LoadError::new(
                        "script_unavailable",
                        "operator script unavailable",
                    ));
                }
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(&bytes);
                let snapshot = directory.join(format!("{}-{index}.js", source.id));
                std::fs::write(&snapshot, bytes).map_err(io_error)?;
                *file = snapshot;
            }
        }
        definitions.insert(
            source.id.clone(),
            PublishedDefinition {
                source: source_copy,
                fingerprint: hex::encode(hash.finalize()),
            },
        );
    }
    Ok(definitions)
}
