//! Trusted workspace registry. Caller identities must be verified before resolution.
use crate::{
    error::{LoadError, Result, io_error},
    storage::Store,
};
use fs2::FileExt;
use serde::Serialize;
use sqlx::{Connection, Row, SqliteConnection, sqlite::SqliteConnectOptions};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

fn invalid() -> LoadError {
    LoadError::new("workspace_invalid", "workspace registry or path invalid")
}
fn database_error<E>(_: E) -> LoadError {
    LoadError::new("workspace_database", "workspace registry operation failed")
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceInfo {
    pub id: String,
    pub kind: String,
    pub issuer: Option<String>,
    pub subject: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WorkspaceRegistry {
    root: PathBuf,
}

fn directory(path: &Path, create: bool) -> Result<()> {
    if create {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    File::open(parent)
                        .and_then(|f| f.sync_all())
                        .map_err(io_error)?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_error(e)),
        }
    }
    let m = fs::symlink_metadata(path).map_err(io_error)?;
    if !m.file_type().is_dir() || m.permissions().mode() & 0o077 != 0 {
        return Err(invalid());
    }
    Ok(())
}

use std::os::unix::fs::DirBuilderExt;
fn regular(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .mode(0o600);
    if create {
        options.create(true);
    }
    let file = options.open(path).map_err(io_error)?;
    let m = file.metadata().map_err(io_error)?;
    if !m.is_file() || m.permissions().mode() & 0o077 != 0 {
        return Err(invalid());
    }
    Ok(file)
}

impl WorkspaceRegistry {
    pub async fn open(root: &Path) -> Result<Self> {
        // The existing operator root is not chmod'ed or moved.
        if !fs::symlink_metadata(root)
            .map_err(io_error)?
            .file_type()
            .is_dir()
        {
            return Err(invalid());
        }
        let root = fs::canonicalize(root).map_err(io_error)?;
        let registry = Self { root };
        let _guard = registry.lock().await?;
        directory(&registry.root.join("workspaces"), true)?;
        regular(&registry.root.join("workspaces.sqlite3"), true)?;
        let mut db = registry.connect().await?;
        sqlx::query("CREATE TABLE IF NOT EXISTS registry_version (version INTEGER PRIMARY KEY)")
            .execute(&mut db)
            .await
            .map_err(database_error)?;
        let versions: Vec<i64> = sqlx::query_scalar("SELECT version FROM registry_version")
            .fetch_all(&mut db)
            .await
            .map_err(database_error)?;
        if versions.is_empty() {
            sqlx::query("INSERT INTO registry_version(version) VALUES (1)")
                .execute(&mut db)
                .await
                .map_err(database_error)?;
        } else if versions != [1] {
            return Err(invalid());
        }
        sqlx::query("CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('shared','identity')), issuer TEXT, subject TEXT, ready INTEGER NOT NULL DEFAULT 0 CHECK(ready IN (0,1)), CHECK((kind='shared' AND issuer IS NULL AND subject IS NULL) OR (kind='identity' AND issuer IS NOT NULL AND subject IS NOT NULL)), UNIQUE(issuer, subject))").execute(&mut db).await.map_err(database_error)?;
        sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS one_shared_workspace ON workspaces(kind) WHERE kind='shared'").execute(&mut db).await.map_err(database_error)?;
        Ok(registry)
    }
    async fn lock(&self) -> Result<File> {
        let file = regular(&self.root.join(".workspaces.lock"), true)?;
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(file),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(25)).await
                }
                Err(e) => return Err(io_error(e)),
            }
        }
    }
    async fn connect(&self) -> Result<SqliteConnection> {
        let options = SqliteConnectOptions::new()
            .filename(self.root.join("workspaces.sqlite3"))
            .create_if_missing(false);
        SqliteConnection::connect_with(&options)
            .await
            .map_err(database_error)
    }
    pub async fn resolve_shared(&self, database_url: Option<&str>) -> Result<PathBuf> {
        self.resolve(None, database_url).await
    }
    pub async fn resolve_identity(
        &self,
        issuer: &str,
        subject: &str,
        database_url: Option<&str>,
    ) -> Result<PathBuf> {
        if issuer.is_empty() || subject.is_empty() {
            return Err(invalid());
        }
        self.resolve(Some((issuer, subject)), database_url).await
    }
    async fn resolve(
        &self,
        identity: Option<(&str, &str)>,
        database_url: Option<&str>,
    ) -> Result<PathBuf> {
        let _guard = self.lock().await?;
        directory(&self.root.join("workspaces"), false)?;
        regular(&self.root.join("workspaces.sqlite3"), false)?;
        let mut db = self.connect().await?;
        let found = if let Some((issuer, subject)) = identity {
            sqlx::query(
                "SELECT id, ready FROM workspaces WHERE kind='identity' AND issuer=? AND subject=?",
            )
            .bind(issuer)
            .bind(subject)
            .fetch_optional(&mut db)
            .await
        } else {
            sqlx::query("SELECT id, ready FROM workspaces WHERE kind='shared'")
                .fetch_optional(&mut db)
                .await
        }
        .map_err(database_error)?;
        let (id, ready) = if let Some(row) = found {
            (
                row.try_get::<String, _>(0).map_err(database_error)?,
                row.try_get::<i64, _>(1).map_err(database_error)? == 1,
            )
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            let (kind, issuer, subject) = match identity {
                Some((i, s)) => ("identity", Some(i), Some(s)),
                None => ("shared", None, None),
            };
            sqlx::query("INSERT INTO workspaces(id,kind,issuer,subject,ready) VALUES (?,?,?,?,0)")
                .bind(&id)
                .bind(kind)
                .bind(issuer)
                .bind(subject)
                .execute(&mut db)
                .await
                .map_err(database_error)?;
            (id, false)
        };
        let path = self.path(&id)?;
        if !ready {
            directory(&path, true)?;
            let id_path = path.join("store-id");
            if !id_path.exists() {
                let mut staged = tempfile::Builder::new()
                    .prefix(".store-id-")
                    .tempfile_in(&path)
                    .map_err(io_error)?;
                staged.write_all(id.as_bytes()).map_err(io_error)?;
                staged.as_file().sync_all().map_err(io_error)?;
                match fs::hard_link(staged.path(), &id_path) {
                    Ok(()) => File::open(&path)
                        .and_then(|f| f.sync_all())
                        .map_err(io_error)?,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(io_error(e)),
                }
            }
            self.validate(&id)?;
            let store = Store::open(&path, database_url).await?;
            drop(store);
            sqlx::query("UPDATE workspaces SET ready=1 WHERE id=?")
                .bind(&id)
                .execute(&mut db)
                .await
                .map_err(database_error)?;
        }
        self.validate(&id)?;
        Ok(path)
    }
    fn path(&self, id: &str) -> Result<PathBuf> {
        let uuid = uuid::Uuid::parse_str(id).map_err(|_| invalid())?;
        if uuid.to_string() != id {
            return Err(invalid());
        }
        Ok(self.root.join("workspaces").join(id))
    }
    fn validate(&self, id: &str) -> Result<()> {
        directory(&self.root.join("workspaces"), false)?;
        let path = self.path(id)?;
        directory(&path, false)?;
        let mut actual = String::new();
        regular(&path.join("store-id"), false)?
            .take(128)
            .read_to_string(&mut actual)
            .map_err(io_error)?;
        if actual != id {
            return Err(invalid());
        }
        Ok(())
    }
    pub async fn list(&self) -> Result<Vec<WorkspaceInfo>> {
        let _guard = self.lock().await?;
        let mut db = self.connect().await?;
        let rows =
            sqlx::query("SELECT id,kind,issuer,subject FROM workspaces WHERE ready=1 ORDER BY id")
                .fetch_all(&mut db)
                .await
                .map_err(database_error)?;
        rows.into_iter()
            .map(|r| {
                Ok(WorkspaceInfo {
                    id: r.try_get(0).map_err(database_error)?,
                    kind: r.try_get(1).map_err(database_error)?,
                    issuer: r.try_get(2).map_err(database_error)?,
                    subject: r.try_get(3).map_err(database_error)?,
                })
            })
            .collect()
    }
    pub async fn resolve_existing(&self, selector: &str) -> Result<PathBuf> {
        let _guard = self.lock().await?;
        self.path(selector)?;
        let mut db = self.connect().await?;
        let found: Option<i64> = sqlx::query_scalar("SELECT ready FROM workspaces WHERE id=?")
            .bind(selector)
            .fetch_optional(&mut db)
            .await
            .map_err(database_error)?;
        if found != Some(1) {
            return Err(LoadError::new("workspace_not_found", "workspace not found"));
        }
        self.validate(selector)?;
        self.path(selector)
    }
}
