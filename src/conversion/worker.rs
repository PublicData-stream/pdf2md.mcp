//! Bounded framed IPC with a disposable conversion subprocess.
use super::{
    engine,
    types::{Artifact, ConversionLimits, ConversionOptions, WorkerFrame, WorkerJob, WorkerSummary},
};
use crate::error::{LoadError, Result, io_error};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io::{BufRead, BufReader as StdBufReader, Read, Write},
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader},
    process::Command,
};
use tokio_util::sync::CancellationToken;

const HEADER: usize = 1024 * 1024;
const MAX_FRAMES: usize = 100_003;

#[cfg(unix)]
struct ProcessGroupGuard(Option<i32>);

#[cfg(unix)]
impl ProcessGroupGuard {
    fn kill(&self) {
        if let Some(pid) = self.0 {
            // SAFETY: the child is the leader of this process group; kill is async-signal-safe.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    fn disarm(&mut self) {
        self.0 = None;
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        self.kill();
    }
}
fn err(code: &str) -> LoadError {
    LoadError::new(code, "conversion worker failed")
}
fn frame(out: &mut impl Write, value: &impl Serialize) -> Result<()> {
    let data = serde_json::to_vec(value).map_err(|_| err("worker_protocol"))?;
    if data.len() > HEADER {
        return Err(err("worker_protocol"));
    }
    out.write_all(&data)
        .and_then(|_| out.write_all(b"\n"))
        .map_err(|_| err("worker_io"))
}

/// Entry point used only by the dedicated worker binary.
pub fn child_main() -> Result<()> {
    let mut input = StdBufReader::new(std::io::stdin().lock());
    let mut header = Vec::new();
    (&mut input)
        .take((HEADER + 1) as u64)
        .read_until(b'\n', &mut header)
        .map_err(|_| err("worker_protocol"))?;
    if header.len() > HEADER || !header.ends_with(b"\n") {
        return Err(err("worker_protocol"));
    }
    let job: WorkerJob = serde_json::from_slice(&header).map_err(|_| err("worker_protocol"))?;
    let mut pdf = Vec::new();
    (&mut input)
        .take(job.limits.max_bytes.saturating_add(1))
        .read_to_end(&mut pdf)
        .map_err(|_| err("worker_io"))?;
    let mut output = std::io::stdout().lock();
    let result = engine::convert(pdf, &job.options, &job.limits, |path, bytes| {
        frame(
            &mut output,
            &WorkerFrame::Artifact {
                path: path.to_string(),
                bytes: bytes.len() as u64,
            },
        )?;
        output.write_all(bytes).map_err(|_| err("worker_io"))
    });
    match result {
        Ok(summary) => frame(
            &mut output,
            &WorkerFrame::Complete {
                pages: summary.pages,
                warnings: summary.warnings,
            },
        )?,
        Err(e) => frame(&mut output, &WorkerFrame::Error { code: e.code })?,
    }
    output.flush().map_err(|_| err("worker_io"))
}

fn valid_path(path: &str) -> bool {
    if matches!(path, "document.md" | "text-index.json" | "outline.json") {
        return true;
    }
    let Some(rest) = path
        .strip_prefix("assets/page")
        .and_then(|p| p.strip_suffix(".png"))
    else {
        return false;
    };
    let Some((page, index)) = rest.split_once('_') else {
        return false;
    };
    !page.is_empty()
        && !index.is_empty()
        && page.bytes().all(|b| b.is_ascii_digit())
        && index.bytes().all(|b| b.is_ascii_digit())
        && !page.starts_with('0')
        && !index.starts_with('0')
        && page.len() <= 10
        && index.len() <= 10
}

async fn read_output(
    stdout: tokio::process::ChildStdout,
    staging: &Path,
    options: &ConversionOptions,
    limits: &ConversionLimits,
) -> Result<(WorkerSummary, Vec<Artifact>)> {
    let mut reader = BufReader::new(stdout);
    let mut seen = HashSet::new();
    let mut artifacts = Vec::new();
    let mut total = 0u64;
    loop {
        let mut header = Vec::new();
        (&mut reader)
            .take((HEADER + 1) as u64)
            .read_until(b'\n', &mut header)
            .await
            .map_err(|_| err("worker_protocol"))?;
        if header.len() > HEADER || !header.ends_with(b"\n") {
            return Err(err("worker_protocol"));
        }
        let record: WorkerFrame =
            serde_json::from_slice(&header).map_err(|_| err("worker_protocol"))?;
        match record {
            WorkerFrame::Artifact { path, bytes } => {
                if !valid_path(&path) || !seen.insert(path.clone()) || seen.len() > MAX_FRAMES {
                    return Err(err("worker_protocol"));
                }
                if (path == "text-index.json" && bytes > limits.max_index_bytes as u64)
                    || (path == "outline.json" && bytes > limits.max_outline_bytes as u64)
                {
                    return Err(err("worker_protocol"));
                }
                total = total
                    .checked_add(bytes)
                    .ok_or_else(|| err("output_limit"))?;
                // The storage adapter also counts the final manifest against this budget.
                if total > limits.max_output_bytes {
                    return Err(err("output_limit"));
                }
                if path.starts_with("assets/") {
                    let dir = staging.join("assets");
                    match tokio::fs::create_dir(&dir).await {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(io_error(e)),
                    }
                    let metadata = tokio::fs::symlink_metadata(&dir).await.map_err(io_error)?;
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        return Err(err("worker_protocol"));
                    }
                }
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
                }
                let file = opts.open(staging.join(&path)).map_err(io_error)?;
                let mut file = tokio::fs::File::from_std(file);
                let mut remaining = bytes;
                let mut hash = Sha256::new();
                let mut buffer = [0u8; 65536];
                while remaining > 0 {
                    let chunk = remaining.min(buffer.len() as u64) as usize;
                    let n = reader
                        .read(&mut buffer[..chunk])
                        .await
                        .map_err(|_| err("worker_protocol"))?;
                    if n == 0 {
                        return Err(err("worker_protocol"));
                    }
                    file.write_all(&buffer[..n]).await.map_err(io_error)?;
                    hash.update(&buffer[..n]);
                    remaining -= n as u64;
                }
                file.flush().await.map_err(io_error)?;
                artifacts.push(Artifact {
                    path,
                    sha256: hex::encode(hash.finalize()),
                    bytes,
                });
            }
            WorkerFrame::Complete { pages, warnings } => {
                if !seen.contains("document.md")
                    || !seen.contains("text-index.json")
                    || !seen.contains("outline.json")
                    || pages.is_empty()
                    || (options.pages.is_none()
                        && pages.iter().enumerate().any(|(i, p)| *p as usize != i + 1))
                    || pages.len() > limits.max_pages as usize
                    || pages.iter().any(|&p| p == 0 || p > limits.max_pages)
                    || pages.windows(2).any(|p| p[0] >= p[1])
                    || options
                        .pages
                        .as_ref()
                        .is_some_and(|expected| expected != &pages)
                    || seen.iter().filter(|p| p.starts_with("assets/")).any(|p| {
                        p.strip_prefix("assets/page")
                            .and_then(|x| x.split_once('_'))
                            .and_then(|(n, _)| n.parse::<u32>().ok())
                            .is_none_or(|n| pages.binary_search(&n).is_err())
                    })
                    || warnings.len() > limits.max_pages as usize + 1
                    || warnings.iter().any(|s| {
                        s != "parser_reported_warnings"
                            && !s
                                .strip_prefix("no_text_page:")
                                .and_then(|p| p.parse::<u32>().ok())
                                .is_some_and(|p| pages.binary_search(&p).is_ok())
                    })
                {
                    return Err(err("worker_protocol"));
                }
                let mut trailing = [0u8; 1];
                if reader
                    .read(&mut trailing)
                    .await
                    .map_err(|_| err("worker_protocol"))?
                    != 0
                {
                    return Err(err("worker_protocol"));
                }
                let markdown = tokio::fs::read_to_string(staging.join("document.md"))
                    .await
                    .map_err(|_| err("worker_protocol"))?;
                let index_bytes = tokio::fs::read(staging.join("text-index.json"))
                    .await
                    .map_err(|_| err("worker_protocol"))?;
                let outline_bytes = tokio::fs::read(staging.join("outline.json"))
                    .await
                    .map_err(|_| err("worker_protocol"))?;
                let index: super::index::TextIndex =
                    serde_json::from_slice(&index_bytes).map_err(|_| err("worker_protocol"))?;
                let outline: super::index::Outline =
                    serde_json::from_slice(&outline_bytes).map_err(|_| err("worker_protocol"))?;
                if index.sections.len() + index.blocks.len() > limits.max_index_entries {
                    return Err(err("worker_protocol"));
                }
                fn outline_within_limits(
                    entries: &[super::index::OutlineEntry],
                    depth: usize,
                    count: &mut usize,
                    limits: &ConversionLimits,
                ) -> bool {
                    if !entries.is_empty() && depth > limits.max_outline_depth {
                        return false;
                    }
                    for entry in entries {
                        *count += 1;
                        if *count > limits.max_outline_entries
                            || !outline_within_limits(&entry.children, depth + 1, count, limits)
                        {
                            return false;
                        }
                    }
                    true
                }
                if !outline_within_limits(&outline.entries, 1, &mut 0, limits) {
                    return Err(err("worker_protocol"));
                }
                super::index::validate_index(&index, &markdown, &pages)?;
                super::index::validate_outline(&outline)?;
                return Ok((WorkerSummary { pages, warnings }, artifacts));
            }
            WorkerFrame::Error { code } => {
                let code = match code.as_str() {
                    "input_limit" => "input_limit",
                    "invalid_pdf" => "invalid_pdf",
                    "encrypted_pdf" => "encrypted_pdf",
                    "page_limit" => "page_limit",
                    "invalid_pages" => "invalid_pages",
                    "conversion_failed" => "conversion_failed",
                    "image_failed" => "image_failed",
                    "image_limit" => "image_limit",
                    "output_limit" => "output_limit",
                    _ => "worker_failed",
                };
                return Err(err(code));
            }
        }
    }
}

/// Run the parser under an address-space limit.
///
/// Cancel through the token and await this future to guarantee the child is reaped.
/// Dropping or aborting the future kills its process group and relies on Tokio's
/// child drop/background reaper; it cannot synchronously await reaping.
pub async fn run(
    input: std::fs::File,
    options: &ConversionOptions,
    limits: &ConversionLimits,
    worker_path: &Path,
    staging: &Path,
    cancel: &CancellationToken,
) -> Result<(WorkerSummary, Vec<Artifact>)> {
    limits.validate()?;
    options.validate()?;
    if cancel.is_cancelled() {
        return Err(err("cancelled"));
    }
    let job = serde_json::to_vec(&WorkerJob {
        options: options.clone(),
        limits: limits.clone(),
    })
    .map_err(|_| err("worker_protocol"))?;
    if job.len() > HEADER {
        return Err(err("worker_protocol"));
    }
    let mut command = Command::new(worker_path);
    command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
        let bytes = limits
            .max_address_space_mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| err("worker_limit"))?;
        // SAFETY: only async-signal-safe setrlimit is called in the child before exec.
        unsafe {
            command.as_std_mut().pre_exec(move || {
                let limit = libc::rlimit {
                    rlim_cur: bytes as libc::rlim_t,
                    rlim_max: bytes as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    {
        return Err(err("worker_limit"));
    }
    let mut child = command.spawn().map_err(|_| err("worker_spawn"))?;
    #[cfg(unix)]
    let mut process_group = ProcessGroupGuard(child.id().map(|pid| pid as i32));
    let mut stdin = child.stdin.take().ok_or_else(|| err("worker_spawn"))?;
    let stdout = child.stdout.take().ok_or_else(|| err("worker_spawn"))?;
    let max_bytes = limits.max_bytes;
    let write = async move {
        stdin.write_all(&job).await.map_err(|_| err("worker_io"))?;
        stdin.write_all(b"\n").await.map_err(|_| err("worker_io"))?;
        let mut input = tokio::fs::File::from_std(input);
        input
            .seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(|_| err("worker_io"))?;
        let copied = tokio::io::copy(&mut input.take(max_bytes.saturating_add(1)), &mut stdin)
            .await
            .map_err(|_| err("worker_io"))?;
        if copied > max_bytes {
            return Err(err("input_limit"));
        }
        stdin.shutdown().await.map_err(|_| err("worker_io"))
    };
    let operation = async {
        let (_, output) = tokio::try_join!(write, read_output(stdout, staging, options, limits))?;
        let status = child.wait().await.map_err(|_| err("worker_io"))?;
        if !status.success() {
            return Err(err("worker_failed"));
        }
        Ok(output)
    };
    let result = tokio::select! {
        _ = cancel.cancelled() => Err(err("cancelled")),
        _ = tokio::time::sleep(Duration::from_secs(limits.timeout_secs)) => Err(err("worker_timeout")),
        result = operation => result,
    };
    if result.is_err() {
        #[cfg(unix)]
        process_group.kill();
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    #[cfg(unix)]
    process_group.disarm();
    result
}
