use crate::error::{LoadError, Result, io_error};
use crate::model::Observation;
use fs2::FileExt;
use sha2::{Digest, Sha256};
use sqlx::{AnyPool, Connection, PgConnection, Row, any::AnyPoolOptions};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

fn db_error<E>(_: E) -> LoadError {
    LoadError::new("storage_database", "metadata database operation failed")
}
fn corrupt() -> LoadError {
    LoadError::new(
        "storage_corrupt",
        "stored document failed integrity verification",
    )
}

pub struct Store {
    root: PathBuf,
    namespace: String,
    pool: AnyPool,
    _lock: File,
}

impl Store {
    pub async fn open(root: &Path, database_url: Option<&str>) -> Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)
            .map_err(io_error)?;
        let root = fs::canonicalize(root).map_err(io_error)?;
        for name in ["objects", ".staging", "pdfs"] {
            let path = root.join(name);
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => sync_dir(&root)?,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(io_error(e)),
            };
            if !fs::symlink_metadata(&path)
                .map_err(io_error)?
                .file_type()
                .is_dir()
            {
                return Err(corrupt());
            }
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(root.join(".lock"))
            .map_err(io_error)?;
        if !lock.metadata().map_err(io_error)?.is_file() {
            return Err(corrupt());
        }
        lock.try_lock_exclusive()
            .map_err(|_| LoadError::new("storage_locked", "storage root is already in use"))?;
        let id_path = root.join("store-id");
        let namespace = if fs::symlink_metadata(&id_path).is_ok() {
            let f = open_regular(&id_path)?;
            let mut id = String::new();
            f.take(128).read_to_string(&mut id).map_err(io_error)?;
            id.trim().to_owned()
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&id_path)
                .map_err(io_error)?;
            file.write_all(id.as_bytes()).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            sync_dir(&root)?;
            id
        };
        let parsed = uuid::Uuid::parse_str(&namespace).map_err(|_| corrupt())?;
        sqlx::any::install_default_drivers();
        let mut advisory_key = None;
        let db_url = if let Some(url) = database_url {
            if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
                return Err(LoadError::new(
                    "storage_database",
                    "external database must be PostgreSQL",
                ));
            }
            let mut conn = PgConnection::connect(url).await.map_err(db_error)?;
            let version: i32 =
                sqlx::query_scalar("SELECT current_setting('server_version_num')::integer")
                    .fetch_one(&mut conn)
                    .await
                    .map_err(db_error)?;
            if version < 180000 {
                return Err(LoadError::new(
                    "storage_database_version",
                    "PostgreSQL 18 or newer is required",
                ));
            }
            let bytes = parsed.as_bytes();
            let key = i64::from_be_bytes(bytes[..8].try_into().map_err(|_| corrupt())?);
            advisory_key = Some(key);
            drop(conn);
            url.to_owned()
        } else {
            let path = root.join("metadata.sqlite3");
            if fs::symlink_metadata(&path).is_ok() {
                open_regular(&path)?;
            }
            let uri = url::Url::from_file_path(path).map_err(|_| corrupt())?;
            format!("sqlite://{}?mode=rwc", uri.path())
        };
        // Each PostgreSQL pool connection owns the advisory lock for its entire
        // lifetime. A replacement must reacquire it before it can serve queries.
        let pool = AnyPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(3))
            .after_connect(move |conn, _| {
                Box::pin(async move {
                    if let Some(key) = advisory_key {
                        let acquired: i32 = sqlx::query_scalar(
                            "SELECT CASE WHEN pg_try_advisory_lock($1) THEN 1 ELSE 0 END",
                        )
                        .bind(key)
                        .fetch_one(conn)
                        .await?;
                        if acquired != 1 {
                            return Err(sqlx::Error::Protocol(
                                "storage ownership unavailable".into(),
                            ));
                        }
                    }
                    Ok(())
                })
            })
            .connect(&db_url)
            .await
            .map_err(db_error)?;
        let mut migration = pool.begin().await.map_err(db_error)?;
        if advisory_key.is_some() {
            // The two-integer advisory-lock space is separate from store ownership.
            sqlx::query("SELECT pg_advisory_xact_lock(1885639730, 1)")
                .execute(&mut *migration)
                .await
                .map_err(db_error)?;
        }
        sqlx::query("CREATE TABLE IF NOT EXISTS schema_version (version BIGINT PRIMARY KEY)")
            .execute(&mut *migration)
            .await
            .map_err(db_error)?;
        let versions = sqlx::query("SELECT version FROM schema_version")
            .fetch_all(&mut *migration)
            .await
            .map_err(db_error)?;
        if versions.is_empty() {
            sqlx::query(
                "INSERT INTO schema_version (version) VALUES (1) ON CONFLICT(version) DO NOTHING",
            )
            .execute(&mut *migration)
            .await
            .map_err(db_error)?;
        } else if versions.len() != 1 || versions[0].try_get::<i64, _>(0).map_err(db_error)? != 1 {
            return Err(LoadError::new(
                "storage_database_version",
                "unsupported metadata schema version",
            ));
        }
        sqlx::query("CREATE TABLE IF NOT EXISTS observations (namespace TEXT NOT NULL, source_id TEXT NOT NULL, attempt_id TEXT NOT NULL, document_id TEXT, outcome TEXT NOT NULL, mode TEXT NOT NULL, bytes BIGINT NOT NULL, observed_at TEXT NOT NULL, url TEXT, error_code TEXT, PRIMARY KEY(namespace, attempt_id))").execute(&mut *migration).await.map_err(db_error)?;
        sqlx::query("CREATE TABLE IF NOT EXISTS schedule (namespace TEXT NOT NULL, source_id TEXT NOT NULL, due BIGINT NOT NULL, PRIMARY KEY(namespace, source_id))").execute(&mut *migration).await.map_err(db_error)?;
        migration.commit().await.map_err(db_error)?;
        let store = Self {
            root,
            namespace,
            pool,
            _lock: lock,
        };
        for entry in fs::read_dir(store.root.join(".staging")).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if entry.file_type().map_err(io_error)?.is_file() {
                fs::remove_file(entry.path()).map_err(io_error)?;
            }
        }
        let rows = sqlx::query("SELECT DISTINCT document_id FROM observations WHERE namespace = $1 AND document_id IS NOT NULL").bind(&store.namespace).fetch_all(&store.pool).await.map_err(db_error)?;
        for row in rows {
            let id: String = row.try_get(0).map_err(db_error)?;
            store.verify_object(&id)?;
        }
        Ok(store)
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn staging_file(&self) -> Result<tempfile::NamedTempFile> {
        tempfile::Builder::new()
            .prefix(".partial-")
            .tempfile_in(self.root.join(".staging"))
            .map_err(io_error)
    }
    fn verify_object(&self, id: &str) -> Result<()> {
        self.verify_object_controlled(id, None)
    }
    fn verify_object_controlled(
        &self,
        id: &str,
        control: Option<&PublicationControl<'_>>,
    ) -> Result<()> {
        if id.len() != 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(corrupt());
        }
        let (digest, _, _) = digest_file_controlled(&self.root.join("objects").join(id), control)
            .map_err(|e| {
            if e.code == "cancelled" || e.code == "run_timeout" {
                e
            } else {
                corrupt()
            }
        })?;
        if digest != id {
            return Err(corrupt());
        }
        Ok(())
    }
    pub async fn accept(
        &self,
        staged: &Path,
        source_id: &str,
        mode: &str,
        url: Option<&str>,
        attempt_id: &str,
    ) -> Result<Observation> {
        self.accept_inner(staged, source_id, mode, url, attempt_id, None)
            .await
    }
    /// Stop work before committing metadata when the deadline expires or cancellation is requested.
    /// An already-started database commit is allowed to complete.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_before(
        &self,
        staged: &Path,
        source_id: &str,
        mode: &str,
        url: Option<&str>,
        attempt_id: &str,
        deadline: std::time::Instant,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<Observation> {
        let control = PublicationControl { deadline, cancel };
        self.accept_inner(staged, source_id, mode, url, attempt_id, Some(&control))
            .await
    }
    async fn accept_inner(
        &self,
        staged: &Path,
        source_id: &str,
        mode: &str,
        url: Option<&str>,
        attempt_id: &str,
        control: Option<&PublicationControl<'_>>,
    ) -> Result<Observation> {
        check_control(control)?;
        let (id, bytes, valid) = digest_file_controlled(staged, control)?;
        if !valid {
            return Err(LoadError::new(
                "invalid_pdf",
                "input does not contain a PDF header",
            ));
        }
        let target = self.root.join("objects").join(&id);
        // Publish a private copy: the caller may still hold and modify the staging file.
        let mut private = self.staging_file()?;
        let mut source = open_regular(staged)?;
        let mut buffer = [0u8; 65536];
        loop {
            check_control(control)?;
            let n = source.read(&mut buffer).map_err(io_error)?;
            if n == 0 {
                break;
            }
            private.write_all(&buffer[..n]).map_err(io_error)?;
        }
        check_control(control)?;
        let mut permissions = private
            .as_file()
            .metadata()
            .map_err(io_error)?
            .permissions();
        permissions.set_readonly(true);
        private
            .as_file()
            .set_permissions(permissions)
            .map_err(io_error)?;
        private.as_file().sync_all().map_err(io_error)?;
        let (copied_id, copied_bytes, copied_valid) =
            digest_file_controlled(private.path(), control)?;
        if copied_id != id || copied_bytes != bytes || !copied_valid {
            return Err(LoadError::transient(
                "file_changed",
                "staged file changed during publication",
            ));
        }
        // Hard-link publication cannot replace an existing immutable object.
        check_control(control)?;
        match fs::hard_link(private.path(), &target) {
            Ok(()) => {
                File::open(&target)
                    .map_err(io_error)?
                    .sync_all()
                    .map_err(io_error)?;
                sync_dir(&self.root.join("objects"))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                self.verify_object_controlled(&id, control)?
            }
            Err(e) => return Err(io_error(e)),
        }
        let mut obs = Observation {
            source_id: source_id.into(),
            attempt_id: attempt_id.into(),
            document_id: Some(id),
            outcome: "accepted".into(),
            mode: mode.into(),
            bytes,
            observed_at: chrono::Utc::now().to_rfc3339(),
            url: url.and_then(crate::policy::sanitized_url),
            error_code: None,
        };
        self.insert(&mut obs, control).await?;
        Ok(obs)
    }
    pub async fn record_failure(
        &self,
        source_id: &str,
        mode: &str,
        url: Option<&str>,
        attempt_id: &str,
        code: &str,
    ) -> Result<Observation> {
        let mut obs = Observation {
            source_id: source_id.into(),
            attempt_id: attempt_id.into(),
            document_id: None,
            outcome: "failed".into(),
            mode: mode.into(),
            bytes: 0,
            observed_at: chrono::Utc::now().to_rfc3339(),
            url: url.and_then(crate::policy::sanitized_url),
            error_code: Some(code.into()),
        };
        self.insert(&mut obs, None).await?;
        Ok(obs)
    }
    async fn insert(
        &self,
        o: &mut Observation,
        control: Option<&PublicationControl<'_>>,
    ) -> Result<()> {
        check_control(control)?;
        let prepare = self.prepare_insert(o);
        let tx = if let Some(control) = control {
            tokio::select! {
                biased;
                _ = control.cancel.cancelled() => return Err(LoadError::new("cancelled", "loading cancelled")),
                _ = tokio::time::sleep_until(control.deadline.into()) => return Err(LoadError::new("run_timeout", "loading deadline exceeded")),
                result = prepare => result?,
            }
        } else {
            prepare.await?
        };
        check_control(control)?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }
    async fn prepare_insert<'a>(
        &'a self,
        o: &mut Observation,
    ) -> Result<sqlx::Transaction<'a, sqlx::Any>> {
        let bytes = i64::try_from(o.bytes).map_err(|_| corrupt())?;
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        o.observed_at = chrono::Utc::now().to_rfc3339();
        if let Some(id) = &o.document_id {
            let previous: Option<String> = sqlx::query_scalar("SELECT document_id FROM observations WHERE namespace=$1 AND source_id=$2 AND document_id IS NOT NULL ORDER BY observed_at DESC, attempt_id DESC LIMIT 1")
                .bind(&self.namespace).bind(&o.source_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
            if previous.as_ref() == Some(id) {
                o.outcome = "unchanged".into();
            }
        }
        sqlx::query("INSERT INTO observations (namespace, source_id, attempt_id, document_id, outcome, mode, bytes, observed_at, url, error_code) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)").bind(&self.namespace).bind(&o.source_id).bind(&o.attempt_id).bind(&o.document_id).bind(&o.outcome).bind(&o.mode).bind(bytes).bind(&o.observed_at).bind(&o.url).bind(&o.error_code).execute(&mut *tx).await.map_err(db_error)?;
        Ok(tx)
    }
    /// Read existing metadata without taking writer ownership or performing recovery.
    pub async fn read_history(
        root: &Path,
        database_url: Option<&str>,
        source: Option<&str>,
    ) -> Result<Vec<Observation>> {
        if !fs::symlink_metadata(root)
            .map_err(io_error)?
            .file_type()
            .is_dir()
        {
            return Err(corrupt());
        }
        let root = fs::canonicalize(root).map_err(io_error)?;
        let mut namespace = String::new();
        open_regular(&root.join("store-id"))?
            .take(128)
            .read_to_string(&mut namespace)
            .map_err(io_error)?;
        let namespace = namespace.trim();
        uuid::Uuid::parse_str(namespace).map_err(|_| corrupt())?;
        sqlx::any::install_default_drivers();
        let postgres = database_url.is_some();
        let db_url = if let Some(value) = database_url {
            if !value.starts_with("postgres://") && !value.starts_with("postgresql://") {
                return Err(LoadError::new(
                    "storage_database",
                    "external database must be PostgreSQL",
                ));
            }
            value.to_owned()
        } else {
            let path = root.join("metadata.sqlite3");
            open_regular(&path)?;
            let uri = url::Url::from_file_path(path).map_err(|_| corrupt())?;
            format!("sqlite://{}?mode=ro", uri.path())
        };
        let pool = AnyPoolOptions::new()
            .max_connections(1)
            .after_connect(move |conn, _| {
                Box::pin(async move {
                    if postgres {
                        sqlx::query("SET default_transaction_read_only = on")
                            .execute(conn)
                            .await?;
                    }
                    Ok(())
                })
            })
            .connect(&db_url)
            .await
            .map_err(db_error)?;
        if postgres {
            let version: i32 =
                sqlx::query_scalar("SELECT current_setting('server_version_num')::integer")
                    .fetch_one(&pool)
                    .await
                    .map_err(db_error)?;
            if version < 180000 {
                return Err(LoadError::new(
                    "storage_database_version",
                    "PostgreSQL 18 or newer is required",
                ));
            }
        }
        let versions = sqlx::query("SELECT version FROM schema_version")
            .fetch_all(&pool)
            .await
            .map_err(db_error)?;
        if versions.len() != 1 || versions[0].try_get::<i64, _>(0).map_err(db_error)? != 1 {
            return Err(LoadError::new(
                "storage_database_version",
                "unsupported metadata schema version",
            ));
        }
        read_history_rows(&pool, namespace, source).await
    }
    pub async fn history(&self, source: Option<&str>) -> Result<Vec<Observation>> {
        read_history_rows(&self.pool, &self.namespace, source).await
    }
    /// Trusted store operation: a digest is readable only when this store owns it.
    pub async fn open_document(&self, id: &str) -> Result<File> {
        if id.len() != 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(LoadError::new("document_not_found", "document unavailable"));
        }
        let found: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM observations WHERE namespace=$1 AND document_id=$2",
        )
        .bind(&self.namespace)
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(db_error)?;
        if found == 0 {
            return Err(LoadError::new("document_not_found", "document unavailable"));
        }
        self.verify_object(id)?;
        open_regular(&self.root.join("objects").join(id))
    }
    pub async fn next_due(&self, source: &str) -> Result<Option<i64>> {
        sqlx::query_scalar("SELECT due FROM schedule WHERE namespace=$1 AND source_id=$2")
            .bind(&self.namespace)
            .bind(source)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)
    }
    pub async fn set_next_due(&self, source: &str, due: i64) -> Result<()> {
        sqlx::query("INSERT INTO schedule(namespace,source_id,due) VALUES ($1,$2,$3) ON CONFLICT(namespace,source_id) DO UPDATE SET due=excluded.due").bind(&self.namespace).bind(source).bind(due).execute(&self.pool).await.map_err(db_error)?;
        Ok(())
    }
}
async fn read_history_rows(
    pool: &AnyPool,
    namespace: &str,
    source: Option<&str>,
) -> Result<Vec<Observation>> {
    let rows = if let Some(source) = source { sqlx::query("SELECT source_id,attempt_id,document_id,outcome,mode,bytes,observed_at,url,error_code FROM observations WHERE namespace=$1 AND source_id=$2 ORDER BY observed_at,attempt_id").bind(namespace).bind(source).fetch_all(pool).await } else { sqlx::query("SELECT source_id,attempt_id,document_id,outcome,mode,bytes,observed_at,url,error_code FROM observations WHERE namespace=$1 ORDER BY observed_at,attempt_id").bind(namespace).fetch_all(pool).await }.map_err(db_error)?;
    rows.into_iter()
        .map(|r| {
            let bytes: i64 = r.try_get(5).map_err(db_error)?;
            Ok(Observation {
                source_id: r.try_get(0).map_err(db_error)?,
                attempt_id: r.try_get(1).map_err(db_error)?,
                document_id: r.try_get(2).map_err(db_error)?,
                outcome: r.try_get(3).map_err(db_error)?,
                mode: r.try_get(4).map_err(db_error)?,
                bytes: u64::try_from(bytes).map_err(|_| corrupt())?,
                observed_at: r.try_get(6).map_err(db_error)?,
                url: r.try_get(7).map_err(db_error)?,
                error_code: r.try_get(8).map_err(db_error)?,
            })
        })
        .collect()
}
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)
}
fn open_regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(io_error)?;
    if !file.metadata().map_err(io_error)?.is_file() {
        return Err(corrupt());
    }
    Ok(file)
}
struct PublicationControl<'a> {
    deadline: std::time::Instant,
    cancel: &'a tokio_util::sync::CancellationToken,
}
fn check_control(control: Option<&PublicationControl<'_>>) -> Result<()> {
    if let Some(control) = control {
        if control.cancel.is_cancelled() {
            return Err(LoadError::new("cancelled", "loading cancelled"));
        }
        if std::time::Instant::now() >= control.deadline {
            return Err(LoadError::new("run_timeout", "loading deadline exceeded"));
        }
    }
    Ok(())
}
fn digest_file_controlled(
    path: &Path,
    control: Option<&PublicationControl<'_>>,
) -> Result<(String, u64, bool)> {
    let mut file = open_regular(path)?;
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut prefix = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        check_control(control)?;
        let n = file.read(&mut buf).map_err(io_error)?;
        if n == 0 {
            break;
        }
        if prefix.len() < 1024 {
            prefix.extend_from_slice(&buf[..n.min(1024 - prefix.len())]);
        }
        hash.update(&buf[..n]);
        count = count.checked_add(n as u64).ok_or_else(corrupt)?;
    }
    Ok((
        format!("{:x}", hash.finalize()),
        count,
        prefix.windows(5).any(|w| w == b"%PDF-"),
    ))
}
