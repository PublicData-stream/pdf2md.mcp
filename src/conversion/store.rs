use crate::{
    conversion::{
        ConversionAttempt, ConversionLimits, ConversionManifest, ConversionOptions, profile_key,
        worker,
    },
    error::{LoadError, Result, io_error},
    storage::{Store, corrupt, db_error, open_regular, sync_dir},
};
use sha2::{Digest, Sha256};
use sqlx::{Any, AnyPool, Row, Transaction, any::AnyPoolOptions};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn json<T: serde::Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|_| corrupt())
}
fn row(row: sqlx::any::AnyRow) -> Result<ConversionAttempt> {
    let opts: String = row.try_get("options").map_err(db_error)?;
    Ok(ConversionAttempt {
        id: row.try_get("id").map_err(db_error)?,
        document_id: row.try_get("document_id").map_err(db_error)?,
        profile_key: row.try_get("profile_key").map_err(db_error)?,
        options: serde_json::from_str(&opts).map_err(|_| corrupt())?,
        status: row.try_get("status").map_err(db_error)?,
        automatic: row.try_get::<i32, _>("automatic").map_err(db_error)? != 0,
        created_at: row.try_get("created_at").map_err(db_error)?,
        finished_at: row.try_get("finished_at").map_err(db_error)?,
        error_code: row.try_get("error_code").map_err(db_error)?,
        bundle_id: row.try_get("bundle_id").map_err(db_error)?,
    })
}
pub(crate) async fn insert(
    tx: &mut Transaction<'_, Any>,
    ns: &str,
    id: &str,
    document: &str,
    options: &ConversionOptions,
    automatic: bool,
) -> Result<()> {
    let key = profile_key(document, options)?;
    sqlx::query("INSERT INTO conversion_attempts(namespace,id,document_id,profile_key,options,status,automatic,created_at) VALUES($1,$2,$3,$4,$5,'pending',$6,$7)")
        .bind(ns).bind(id).bind(document).bind(key).bind(json(options)?).bind(i32::from(automatic)).bind(now()).execute(&mut **tx).await.map_err(db_error)?;
    Ok(())
}
pub(crate) async fn enqueue_automatic(
    tx: &mut Transaction<'_, Any>,
    ns: &str,
    document: &str,
    options: &ConversionOptions,
) -> Result<()> {
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM conversion_attempts WHERE namespace=$1 AND document_id=$2 AND automatic=1").bind(ns).bind(document).fetch_one(&mut **tx).await.map_err(db_error)?;
    if exists == 0 {
        let id = uuid::Uuid::new_v4().to_string();
        insert(tx, ns, &id, document, options, true).await?;
        crate::jobs::insert_job(
            tx,
            ns,
            &id,
            &crate::jobs::JobCommand::Convert {
                document_id: document.into(),
                options: options.clone(),
                force: false,
            },
            None,
        )
        .await?;
    }
    Ok(())
}
#[derive(Clone)]
pub(crate) struct VerifiedBundle {
    root: PathBuf,
    id: String,
    manifest: ConversionManifest,
}
impl VerifiedBundle {
    pub(crate) fn manifest(&self) -> &ConversionManifest {
        &self.manifest
    }
    pub(crate) fn open_artifact(&self, index: usize) -> Result<std::fs::File> {
        let artifact = self.manifest.artifacts.get(index).ok_or_else(corrupt)?;
        open_verified_artifact(&self.root, &self.id, artifact, None)
    }
    pub(crate) fn open_artifact_bounded(
        &self,
        index: usize,
        cancel: &CancellationToken,
        deadline: std::time::Instant,
    ) -> Result<std::fs::File> {
        let artifact = self.manifest.artifacts.get(index).ok_or_else(corrupt)?;
        open_verified_artifact(&self.root, &self.id, artifact, Some((cancel, deadline)))
    }
}
fn open_verified_artifact(
    root: &Path,
    bundle: &str,
    artifact: &crate::conversion::Artifact,
    control: Option<(&CancellationToken, std::time::Instant)>,
) -> Result<std::fs::File> {
    use std::io::{Seek, SeekFrom};
    let check = || -> Result<()> {
        if let Some((cancel, deadline)) = control {
            if cancel.is_cancelled() {
                return Err(LoadError::new("cancelled", "operation cancelled"));
            }
            if std::time::Instant::now() >= deadline {
                return Err(LoadError::new("search_timeout", "search timed out"));
            }
        }
        Ok(())
    };
    check()?;
    if !crate::conversion::valid_artifact_path(&artifact.path) {
        return Err(corrupt());
    }
    let base = root.join("conversions").join(bundle);
    dir(&base)?;
    if artifact.path.starts_with("assets/") {
        dir(&base.join("assets"))?;
    }
    let mut file = open_regular(&base.join(&artifact.path))?;
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0; 65536];
    loop {
        check()?;
        let n = file.read(&mut buffer).map_err(io_error)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).ok_or_else(corrupt)?;
        hash.update(&buffer[..n]);
    }
    check()?;
    if count != artifact.bytes || hex::encode(hash.finalize()) != artifact.sha256 {
        return Err(corrupt());
    }
    file.seek(SeekFrom::Start(0)).map_err(io_error)?;
    Ok(file)
}
impl Store {
    async fn conversion_attempt(&self, id: &str) -> Result<ConversionAttempt> {
        let q = "SELECT id,document_id,profile_key,options,status,automatic,created_at,finished_at,error_code,bundle_id FROM conversion_attempts WHERE namespace=$1 AND id=$2";
        let r = sqlx::query(q)
            .bind(&self.namespace)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?
            .ok_or_else(|| LoadError::new("conversion_not_found", "conversion unavailable"))?;
        row(r)
    }
    pub async fn request_conversion(
        &self,
        document_id: &str,
        options: &ConversionOptions,
        force: bool,
    ) -> Result<ConversionAttempt> {
        self.open_document(document_id).await?;
        let key = profile_key(document_id, options)?;
        let q = "SELECT id,document_id,profile_key,options,status,automatic,created_at,finished_at,error_code,bundle_id FROM conversion_attempts WHERE namespace=$1 AND profile_key=$2 AND (status IN ('pending','running') OR (status='succeeded' AND $3=0)) ORDER BY created_at DESC,id DESC LIMIT 1";
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        if let Some(r) = sqlx::query(q)
            .bind(&self.namespace)
            .bind(&key)
            .bind(i32::from(force))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?
        {
            return row(r);
        }
        let id = uuid::Uuid::new_v4().to_string();
        insert(&mut tx, &self.namespace, &id, document_id, options, false).await?;
        crate::jobs::insert_job(
            &mut tx,
            &self.namespace,
            &id,
            &crate::jobs::JobCommand::Convert {
                document_id: document_id.into(),
                options: options.clone(),
                force,
            },
            None,
        )
        .await?;
        tx.commit().await.map_err(db_error)?;
        self.conversion_attempt(&id).await
    }
    pub(crate) async fn open_verified_bundle(&self, id: &str) -> Result<VerifiedBundle> {
        let attempt = self.conversion_attempt(id).await?;
        if attempt.status != "succeeded" {
            return Err(LoadError::new(
                "conversion_not_found",
                "conversion unavailable",
            ));
        }
        let manifest = verify_attempt_contents(&self.root, &attempt, false)?;
        Ok(VerifiedBundle {
            root: self.root.clone(),
            id: attempt.bundle_id.ok_or_else(corrupt)?,
            manifest,
        })
    }
    pub async fn verified_conversion_manifest(&self, id: &str) -> Result<ConversionManifest> {
        let attempt = self.conversion_attempt(id).await?;
        if attempt.status != "succeeded" {
            return Err(LoadError::new(
                "conversion_not_found",
                "conversion unavailable",
            ));
        }
        verify_attempt_contents(&self.root, &attempt, false)
    }
    pub async fn open_conversion_artifact(&self, id: &str, path: &str) -> Result<std::fs::File> {
        let bundle = self.open_verified_bundle(id).await?;
        let index = bundle
            .manifest
            .artifacts
            .iter()
            .position(|artifact| artifact.path == path)
            .ok_or_else(|| LoadError::new("conversion_not_found", "artifact unavailable"))?;
        bundle.open_artifact(index)
    }
    pub async fn conversion_history_page(
        &self,
        document: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ConversionAttempt>> {
        let q = "SELECT id,document_id,profile_key,options,status,automatic,created_at,finished_at,error_code,bundle_id FROM conversion_attempts WHERE namespace=$1 AND ($2 IS NULL OR document_id=$2) ORDER BY created_at,id LIMIT $3 OFFSET $4";
        sqlx::query(q)
            .bind(&self.namespace)
            .bind(document)
            .bind(i64::try_from(limit).unwrap_or(i64::MAX))
            .bind(i64::try_from(offset).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(row)
            .collect()
    }
    pub async fn pending_conversions(&self) -> Result<Vec<ConversionAttempt>> {
        let q = "SELECT id,document_id,profile_key,options,status,automatic,created_at,finished_at,error_code,bundle_id FROM conversion_attempts WHERE namespace=$1 AND status='pending' ORDER BY created_at,id LIMIT 32";
        sqlx::query(q)
            .bind(&self.namespace)
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(row)
            .collect()
    }
    pub async fn conversion_for_observation(
        &self,
        attempt_id: &str,
    ) -> Result<Option<ConversionAttempt>> {
        let q = "SELECT id,document_id,profile_key,options,status,automatic,created_at,finished_at,error_code,bundle_id FROM conversion_attempts WHERE namespace=$1 AND automatic=1 AND document_id=(SELECT document_id FROM observations WHERE namespace=$1 AND attempt_id=$2) ORDER BY created_at,id LIMIT 1";
        sqlx::query(q)
            .bind(&self.namespace)
            .bind(attempt_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?
            .map(row)
            .transpose()
    }
    pub(crate) async fn verify_conversion_bundles(&self) -> Result<()> {
        let q = "SELECT id,document_id,profile_key,options,status,automatic,created_at,finished_at,error_code,bundle_id FROM conversion_attempts WHERE namespace=$1 AND status='succeeded'";
        let entries = sqlx::query(q)
            .bind(&self.namespace)
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?;
        let mut referenced = std::collections::HashSet::new();
        for entry in entries {
            let attempt = row(entry)?;
            verify_attempt(&self.root, &attempt)?;
            referenced.insert(attempt.bundle_id.ok_or_else(corrupt)?);
        }
        let parent = self.root.join("conversions");
        let mut removed = false;
        for entry in fs::read_dir(&parent).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name().into_string().map_err(|_| corrupt())?;
            if !entry.file_type().map_err(io_error)?.is_dir() {
                return Err(corrupt());
            }
            if name.starts_with(".partial-") || (valid_hash(&name) && !referenced.contains(&name)) {
                fs::remove_dir_all(entry.path()).map_err(io_error)?;
                removed = true;
            } else if !valid_hash(&name) {
                return Err(corrupt());
            }
        }
        if removed {
            sync_dir(&parent)?;
        }
        Ok(())
    }
    /// Convert with shared per-store admission, retaining ownership through publication.
    /// The first call fixes concurrency until reopen. Cancel the token and await this
    /// future for guaranteed worker reaping; do not abort an active conversion task.
    pub async fn process_conversion(
        &self,
        id: &str,
        limits: &ConversionLimits,
        worker_path: &Path,
        cancel: &CancellationToken,
    ) -> Result<ConversionAttempt> {
        limits.validate()?;
        let (capacity, slots) = self.conversion_slots.get_or_init(|| {
            (
                limits.concurrency,
                tokio::sync::Semaphore::new(limits.concurrency),
            )
        });
        if *capacity != limits.concurrency {
            return Err(LoadError::new(
                "conversion_limits",
                "conversion concurrency differs from active store settings",
            ));
        }
        let _permit = tokio::select! {
            _ = cancel.cancelled() => return Err(LoadError::new("cancelled", "conversion cancelled")),
            result = slots.acquire() => result.map_err(|_| LoadError::new("conversion_busy", "conversion capacity unavailable"))?,
        };
        if cancel.is_cancelled() {
            return Err(LoadError::new("cancelled", "conversion cancelled"));
        }
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let updated = sqlx::query("UPDATE conversion_attempts SET status='running' WHERE namespace=$1 AND id=$2 AND status='pending'").bind(&self.namespace).bind(id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
        if updated != 0 {
            sqlx::query("UPDATE api_jobs SET status='running',started_at=$1 WHERE namespace=$2 AND id=$3 AND status='queued'").bind(now()).bind(&self.namespace).bind(id).execute(&mut *tx).await.map_err(db_error)?;
        }
        tx.commit().await.map_err(db_error)?;
        if updated == 0 {
            return self.conversion_attempt(id).await;
        }
        let attempt = self.conversion_attempt(id).await?;
        // Queued attempts created with an older profile cannot be published under
        // the new converter identity. Keep the historical attempt immutable.
        if attempt.profile_key != profile_key(&attempt.document_id, &attempt.options)? {
            return self
                .finish_error(id, "conversion_profile_changed", false)
                .await;
        }
        let input = self.open_document(&attempt.document_id).await?;
        let tmp = tempfile::Builder::new()
            .prefix("pdf2md-conversion-")
            .tempdir_in("/tmp")
            .map_err(io_error)?;
        let result = worker::run(
            input,
            &attempt.options,
            limits,
            worker_path,
            tmp.path(),
            cancel,
        )
        .await;
        match result {
            Ok((summary, artifacts)) => {
                let manifest = ConversionManifest {
                    format_version: 2,
                    document_id: attempt.document_id.clone(),
                    converter: crate::conversion::CONVERTER.into(),
                    options: attempt.options.clone(),
                    pages: summary.pages,
                    warnings: summary.warnings,
                    artifacts,
                };
                let bytes = serde_json::to_vec(&manifest).map_err(|_| corrupt())?;
                let total = manifest
                    .artifacts
                    .iter()
                    .try_fold(bytes.len() as u64, |n, a| n.checked_add(a.bytes))
                    .ok_or_else(corrupt)?;
                if bytes.len() > 16 * 1024 * 1024 || total > limits.max_output_bytes {
                    return self.finish_error(id, "output_limit", false).await;
                }
                let bundle = hex::encode(Sha256::digest(&bytes));
                publish_bundle(&self.root, tmp.path(), &bundle, &bytes, &manifest)?;
                let mut tx = self.pool.begin().await.map_err(db_error)?;
                sqlx::query("UPDATE conversion_attempts SET status='succeeded',finished_at=$1,bundle_id=$2 WHERE namespace=$3 AND id=$4 AND status='running'").bind(now()).bind(bundle).bind(&self.namespace).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                sqlx::query("UPDATE api_jobs SET status='succeeded',finished_at=$1 WHERE namespace=$2 AND id=$3 AND status='running'").bind(now()).bind(&self.namespace).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                tx.commit().await.map_err(db_error)?;
                self.conversion_attempt(id).await
            }
            Err(e) => {
                if e.code.starts_with("storage_") {
                    return Err(e);
                }
                self.finish_error(id, &e.code, e.code == "cancelled").await
            }
        }
    }
    async fn finish_error(
        &self,
        id: &str,
        code: &str,
        cancelled: bool,
    ) -> Result<ConversionAttempt> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let status = if cancelled { "cancelled" } else { "failed" };
        sqlx::query("UPDATE conversion_attempts SET status=$1,finished_at=$2,error_code=$3 WHERE namespace=$4 AND id=$5 AND status='running'").bind(status).bind(now()).bind(code).bind(&self.namespace).bind(id).execute(&mut *tx).await.map_err(db_error)?;
        sqlx::query("UPDATE api_jobs SET status=$1,finished_at=$2,error_code=$3 WHERE namespace=$4 AND id=$5 AND status='running'").bind(status).bind(now()).bind(code).bind(&self.namespace).bind(id).execute(&mut *tx).await.map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        self.conversion_attempt(id).await
    }
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn dir(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)
        .map_err(io_error)?
        .file_type()
        .is_dir()
    {
        return Err(corrupt());
    }
    Ok(())
}
fn verify_bundle(root: &Path, id: &str) -> Result<ConversionManifest> {
    verify_bundle_contents(root, id, true)
}
fn verify_bundle_contents(
    root: &Path,
    id: &str,
    verify_contents: bool,
) -> Result<ConversionManifest> {
    if !valid_hash(id) {
        return Err(corrupt());
    }
    let base = root.join("conversions");
    dir(&base)?;
    let base = base.join(id);
    dir(&base)?;
    let mut f = open_regular(&base.join("manifest.json"))?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut f)
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > 16 * 1024 * 1024 || hex::encode(Sha256::digest(&bytes)) != id {
        return Err(corrupt());
    }
    let manifest: ConversionManifest = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
    if ![1, 2].contains(&manifest.format_version)
        || !valid_hash(&manifest.document_id)
        || manifest.artifacts.len() > crate::conversion::MAX_ARTIFACTS + 3
    {
        return Err(corrupt());
    }
    let mut names = std::collections::HashSet::new();
    for a in &manifest.artifacts {
        if !crate::conversion::valid_artifact_path(&a.path)
            || !valid_hash(&a.sha256)
            || !names.insert(a.path.as_str())
        {
            return Err(corrupt());
        }
        if a.path.starts_with("assets/") {
            dir(&base.join("assets"))?;
        }
        if verify_contents {
            let mut f = open_regular(&base.join(&a.path))?;
            let mut h = Sha256::new();
            let mut n = 0u64;
            let mut b = [0; 65536];
            loop {
                let k = f.read(&mut b).map_err(io_error)?;
                if k == 0 {
                    break;
                }
                n = n.checked_add(k as u64).ok_or_else(corrupt)?;
                h.update(&b[..k]);
            }
            if n != a.bytes || hex::encode(h.finalize()) != a.sha256 {
                return Err(corrupt());
            }
        }
    }
    if !names.contains("document.md")
        || (manifest.format_version == 2
            && (!names.contains("text-index.json") || !names.contains("outline.json")))
        || (manifest.format_version == 1
            && (names.contains("text-index.json") || names.contains("outline.json")))
    {
        return Err(corrupt());
    }
    Ok(manifest)
}
fn verify_attempt(root: &Path, attempt: &ConversionAttempt) -> Result<ConversionManifest> {
    verify_attempt_contents(root, attempt, true)
}
fn verify_attempt_contents(
    root: &Path,
    attempt: &ConversionAttempt,
    verify_contents: bool,
) -> Result<ConversionManifest> {
    let bundle = attempt.bundle_id.as_deref().ok_or_else(corrupt)?;
    let manifest = verify_bundle_contents(root, bundle, verify_contents)?;
    if manifest.document_id != attempt.document_id
        || manifest.options != attempt.options
        || manifest.converter.is_empty()
        || manifest.converter.len() > 256
        || crate::conversion::types::profile_key_for(
            &manifest.document_id,
            &manifest.converter,
            &manifest.options,
        )
        .map_err(|_| corrupt())?
            != attempt.profile_key
    {
        return Err(corrupt());
    }
    Ok(manifest)
}
fn publish_bundle(
    root: &Path,
    src: &Path,
    id: &str,
    bytes: &[u8],
    manifest: &ConversionManifest,
) -> Result<()> {
    let parent = root.join("conversions");
    dir(&parent)?;
    let temp = tempfile::Builder::new()
        .prefix(".partial-")
        .tempdir_in(&parent)
        .map_err(io_error)?;
    let mut names = std::collections::HashSet::new();
    for a in &manifest.artifacts {
        if !crate::conversion::valid_artifact_path(&a.path)
            || !valid_hash(&a.sha256)
            || !names.insert(a.path.as_str())
        {
            return Err(corrupt());
        }
        if a.path.starts_with("assets/") {
            let p = temp.path().join("assets");
            if !p.exists() {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(p)
                    .map_err(io_error)?;
            }
            dir(&src.join("assets"))?;
        }
        let mut input = open_regular(&src.join(&a.path))?;
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(temp.path().join(&a.path))
            .map_err(io_error)?;
        let mut h = Sha256::new();
        let mut n = 0u64;
        let mut b = [0; 65536];
        loop {
            let k = input.read(&mut b).map_err(io_error)?;
            if k == 0 {
                break;
            }
            n = n.checked_add(k as u64).ok_or_else(corrupt)?;
            if n > a.bytes {
                return Err(corrupt());
            }
            h.update(&b[..k]);
            out.write_all(&b[..k]).map_err(io_error)?;
        }
        if n != a.bytes || hex::encode(h.finalize()) != a.sha256 {
            return Err(corrupt());
        }
        let mut permissions = out.metadata().map_err(io_error)?.permissions();
        permissions.set_readonly(true);
        out.set_permissions(permissions).map_err(io_error)?;
        out.sync_all().map_err(io_error)?;
    }
    if !names.contains("document.md") {
        return Err(corrupt());
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp.path().join("manifest.json"))
        .map_err(io_error)?;
    f.write_all(bytes).map_err(io_error)?;
    let mut permissions = f.metadata().map_err(io_error)?.permissions();
    permissions.set_readonly(true);
    f.set_permissions(permissions).map_err(io_error)?;
    f.sync_all().map_err(io_error)?;
    if temp.path().join("assets").exists() {
        sync_dir(&temp.path().join("assets"))?;
    }
    sync_dir(temp.path())?;
    let dest = parent.join(id);
    // Link-free rename with NOREPLACE avoids overwriting an existing immutable bundle.
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(temp.path().as_os_str().as_bytes()).map_err(|_| corrupt())?;
    let to = std::ffi::CString::new(dest.as_os_str().as_bytes()).map_err(|_| corrupt())?;
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc != 0 {
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        verify_bundle(root, id)?;
    }
    sync_dir(&parent)?;
    Ok(())
}
async fn readonly(
    root: &Path,
    database_url: Option<&str>,
) -> Result<(PathBuf, String, AnyPool, i64)> {
    dir(root)?;
    let root = fs::canonicalize(root).map_err(io_error)?;
    let mut namespace = String::new();
    open_regular(&root.join("store-id"))?
        .take(128)
        .read_to_string(&mut namespace)
        .map_err(io_error)?;
    let namespace = namespace.trim().to_string();
    uuid::Uuid::parse_str(&namespace).map_err(|_| corrupt())?;
    sqlx::any::install_default_drivers();
    let pg = database_url.is_some();
    let url = if let Some(u) = database_url {
        if !u.starts_with("postgres://") && !u.starts_with("postgresql://") {
            return Err(LoadError::new(
                "storage_database",
                "external database must be PostgreSQL",
            ));
        }
        u.to_string()
    } else {
        let p = root.join("metadata.sqlite3");
        open_regular(&p)?;
        let u = url::Url::from_file_path(p).map_err(|_| corrupt())?;
        format!("sqlite://{}?mode=ro", u.path())
    };
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .after_connect(move |c, _| {
            Box::pin(async move {
                if pg {
                    sqlx::query("SET default_transaction_read_only = on")
                        .execute(c)
                        .await?;
                }
                Ok(())
            })
        })
        .connect(&url)
        .await
        .map_err(db_error)?;
    if pg {
        let v: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::integer")
            .fetch_one(&pool)
            .await
            .map_err(db_error)?;
        if v < 180000 {
            return Err(LoadError::new(
                "storage_database_version",
                "PostgreSQL 18 or newer is required",
            ));
        }
    }
    let v: Vec<i64> = sqlx::query_scalar("SELECT version FROM schema_version")
        .fetch_all(&pool)
        .await
        .map_err(db_error)?;
    if v.len() != 1 || ![1, 2, 3].contains(&v[0]) {
        return Err(LoadError::new(
            "storage_database_version",
            "unsupported metadata schema version",
        ));
    }
    Ok((root, namespace, pool, v[0]))
}
impl Store {
    pub async fn read_conversion_history(
        root: &Path,
        database_url: Option<&str>,
        document_id: Option<&str>,
    ) -> Result<Vec<ConversionAttempt>> {
        let (_, ns, pool, v) = readonly(root, database_url).await?;
        if v == 1 {
            return Ok(Vec::new());
        }
        let q = if document_id.is_some() {
            "SELECT id,document_id,profile_key,options,status,automatic,created_at,finished_at,error_code,bundle_id FROM conversion_attempts WHERE namespace=$1 AND document_id=$2 ORDER BY created_at,id"
        } else {
            "SELECT id,document_id,profile_key,options,status,automatic,created_at,finished_at,error_code,bundle_id FROM conversion_attempts WHERE namespace=$1 ORDER BY created_at,id"
        };
        let mut query = sqlx::query(q).bind(ns);
        if let Some(id) = document_id {
            query = query.bind(id);
        }
        query
            .fetch_all(&pool)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(row)
            .collect()
    }
    pub async fn export_conversion(
        root: &Path,
        database_url: Option<&str>,
        id: &str,
        output: &Path,
    ) -> Result<ConversionManifest> {
        let (root, ns, pool, v) = readonly(root, database_url).await?;
        if v == 1 {
            return Err(LoadError::new(
                "conversion_not_found",
                "conversion unavailable",
            ));
        }
        let q = "SELECT id,document_id,profile_key,options,status,automatic,created_at,finished_at,error_code,bundle_id FROM conversion_attempts WHERE namespace=$1 AND id=$2 AND status='succeeded'";
        let entry = sqlx::query(q)
            .bind(ns)
            .bind(id)
            .fetch_optional(&pool)
            .await
            .map_err(db_error)?
            .ok_or_else(|| LoadError::new("conversion_not_found", "conversion unavailable"))?;
        let attempt = row(entry)?;
        let manifest = verify_attempt(&root, &attempt)?;
        let bundle = attempt.bundle_id.as_ref().ok_or_else(corrupt)?;
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        dir(parent)?;
        let stage = tempfile::Builder::new()
            .prefix(".pdf2md-export-")
            .tempdir_in(parent)
            .map_err(io_error)?;
        for a in &manifest.artifacts {
            if a.path.starts_with("assets/") && !stage.path().join("assets").exists() {
                fs::create_dir(stage.path().join("assets")).map_err(io_error)?;
            }
            let mut input = open_regular(&root.join("conversions").join(bundle).join(&a.path))?;
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(stage.path().join(&a.path))
                .map_err(io_error)?;
            let mut hash = Sha256::new();
            let mut count = 0u64;
            let mut buffer = [0u8; 65536];
            loop {
                let n = input.read(&mut buffer).map_err(io_error)?;
                if n == 0 {
                    break;
                }
                count = count.checked_add(n as u64).ok_or_else(corrupt)?;
                if count > a.bytes {
                    return Err(corrupt());
                }
                hash.update(&buffer[..n]);
                out.write_all(&buffer[..n]).map_err(io_error)?;
            }
            if count != a.bytes || hex::encode(hash.finalize()) != a.sha256 {
                return Err(corrupt());
            }
            out.sync_all().map_err(io_error)?;
        }
        let manifest_bytes = serde_json::to_vec(&manifest).map_err(|_| corrupt())?;
        if hex::encode(Sha256::digest(&manifest_bytes)) != *bundle {
            return Err(corrupt());
        }
        let mut manifest_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(stage.path().join("manifest.json"))
            .map_err(io_error)?;
        manifest_file.write_all(&manifest_bytes).map_err(io_error)?;
        manifest_file.sync_all().map_err(io_error)?;
        if stage.path().join("assets").exists() {
            sync_dir(&stage.path().join("assets"))?;
        }
        sync_dir(stage.path())?;
        use std::os::unix::ffi::OsStrExt;
        let a =
            std::ffi::CString::new(stage.path().as_os_str().as_bytes()).map_err(|_| corrupt())?;
        let b = std::ffi::CString::new(output.as_os_str().as_bytes()).map_err(|_| corrupt())?;
        if unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        sync_dir(parent)?;
        Ok(manifest)
    }
}

#[cfg(test)]
mod artifact_tests {
    use super::*;

    #[test]
    fn bounded_artifact_verification_honors_cancel_and_deadline() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let bundle = root.path().join("conversions").join("test");
        std::fs::create_dir_all(&bundle).unwrap();
        let content = b"verified text";
        std::fs::write(bundle.join("document.md"), content).unwrap();
        let artifact = crate::conversion::Artifact {
            path: "document.md".into(),
            sha256: hex::encode(Sha256::digest(content)),
            bytes: content.len() as u64,
        };
        let cancel = CancellationToken::new();
        let future = std::time::Instant::now() + std::time::Duration::from_secs(60);
        assert!(
            open_verified_artifact(root.path(), "test", &artifact, Some((&cancel, future))).is_ok()
        );
        let expired = std::time::Instant::now();
        assert_eq!(
            open_verified_artifact(root.path(), "test", &artifact, Some((&cancel, expired)))
                .unwrap_err()
                .code,
            "search_timeout"
        );
        cancel.cancel();
        assert_eq!(
            open_verified_artifact(root.path(), "test", &artifact, Some((&cancel, future)))
                .unwrap_err()
                .code,
            "cancelled"
        );
    }
}
