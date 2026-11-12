use crate::{
    error::{LoadError, Result, io_error},
    model::Observation,
    storage::Store,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, Metadata, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

fn same(a: &Metadata, b: &Metadata) -> bool {
    a.is_file()
        && b.is_file()
        && a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
fn source_id(relative: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    format!(
        "manual:{}",
        hex::encode(Sha256::digest(relative.as_os_str().as_bytes()))
    )
}
fn candidate(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
}

pub async fn scan(
    store: &Store,
    max_bytes: u64,
    cancel: &CancellationToken,
) -> Result<Vec<Observation>> {
    let inbox = store.root().join("pdfs");
    let mut files: Vec<(PathBuf, Metadata)> = Vec::new();
    for entry in WalkDir::new(&inbox).follow_links(false) {
        if cancel.is_cancelled() {
            return Err(LoadError::new("cancelled", "manual scan cancelled"));
        }
        let entry = entry.map_err(|_| LoadError::new("storage_io", "inbox traversal failed"))?;
        if entry.file_type().is_file() && candidate(entry.path()) {
            files.push((
                entry.path().to_owned(),
                fs::symlink_metadata(entry.path()).map_err(io_error)?,
            ));
        }
    }
    if files.is_empty() {
        return Ok(Vec::new());
    }
    tokio::select! { _ = cancel.cancelled() => return Err(LoadError::new("cancelled", "manual scan cancelled")), _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {} }
    let mut observations = Vec::new();
    for (path, initial) in files {
        if cancel.is_cancelled() {
            return Err(LoadError::new("cancelled", "manual scan cancelled"));
        }
        let relative = path
            .strip_prefix(&inbox)
            .map_err(|_| LoadError::new("storage_io", "inbox path invalid"))?;
        let source = source_id(relative);
        let attempt = uuid::Uuid::new_v4().to_string();
        let result = copy_stable(store, &inbox, relative, &initial, max_bytes, cancel);
        match result {
            Ok((staged, digest)) => {
                let history = store.history(Some(&source)).await?;
                if history
                    .iter()
                    .rev()
                    .find(|o| o.document_id.is_some())
                    .and_then(|o| o.document_id.as_ref())
                    == Some(&digest)
                {
                    continue;
                }
                match store
                    .accept(staged.path(), &source, "manual", None, &attempt)
                    .await
                {
                    Ok(obs) => observations.push(obs),
                    Err(e) if e.code == "invalid_pdf" => observations.push(
                        store
                            .record_failure(&source, "manual", None, &attempt, &e.code)
                            .await?,
                    ),
                    Err(e) => return Err(e),
                }
            }
            Err(e) if e.code == "cancelled" => return Err(e),
            Err(e) if ["file_changed", "size_limit"].contains(&e.code.as_str()) => observations
                .push(
                    store
                        .record_failure(&source, "manual", None, &attempt, &e.code)
                        .await?,
                ),
            Err(e) => return Err(e),
        }
    }
    Ok(observations)
}
fn copy_stable(
    store: &Store,
    inbox: &Path,
    relative: &Path,
    initial: &Metadata,
    max_bytes: u64,
    cancel: &CancellationToken,
) -> Result<(tempfile::NamedTempFile, String)> {
    let path = inbox.join(relative);
    let current = fs::symlink_metadata(&path)
        .map_err(|_| LoadError::transient("file_changed", "inbox file changed during scan"))?;
    if !same(initial, &current) {
        return Err(LoadError::transient(
            "file_changed",
            "inbox file changed during scan",
        ));
    }
    if current.len() > max_bytes {
        return Err(LoadError::new(
            "size_limit",
            "input exceeds configured size limit",
        ));
    }
    let mut input = open_inbox_file(inbox, relative)?;
    if !same(&current, &input.metadata().map_err(io_error)?) {
        return Err(LoadError::transient(
            "file_changed",
            "inbox file changed during scan",
        ));
    }
    let mut staged = store.staging_file()?;
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        if cancel.is_cancelled() {
            return Err(LoadError::new("cancelled", "manual scan cancelled"));
        }
        let n = input.read(&mut buffer).map_err(io_error)?;
        if n == 0 {
            break;
        }
        bytes = bytes
            .checked_add(n as u64)
            .ok_or_else(|| LoadError::new("size_limit", "input exceeds configured size limit"))?;
        if bytes > max_bytes {
            return Err(LoadError::new(
                "size_limit",
                "input exceeds configured size limit",
            ));
        }
        hash.update(&buffer[..n]);
        staged.write_all(&buffer[..n]).map_err(io_error)?;
    }
    if !same(&current, &input.metadata().map_err(io_error)?)
        || !fs::symlink_metadata(&path).is_ok_and(|after| same(&current, &after))
    {
        return Err(LoadError::transient(
            "file_changed",
            "inbox file changed during scan",
        ));
    }
    staged.flush().map_err(io_error)?;
    Ok((staged, hex::encode(hash.finalize())))
}

// Resolve every component relative to an already-open directory without following links.
fn open_inbox_file(inbox: &Path, relative: &Path) -> Result<std::fs::File> {
    let changed = || LoadError::transient("file_changed", "inbox file changed during scan");
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(inbox)
        .map_err(|_| changed())?;
    let mut directory: OwnedFd = root.into();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(name) = component else {
            return Err(changed());
        };
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| changed())?;
        let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        if components.peek().is_some() {
            flags |= libc::O_DIRECTORY;
        }
        // The descriptor and C string remain valid for this call; ownership transfers below.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(changed());
        }
        let next = unsafe { OwnedFd::from_raw_fd(fd) };
        if components.peek().is_none() {
            return Ok(next.into());
        }
        directory = next;
    }
    Err(changed())
}
