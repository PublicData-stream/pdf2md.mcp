use crate::error::{LoadError, Result};
use crate::model::{Acquired, BrowserJob};
use serde::Deserialize;
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use tokio_util::sync::CancellationToken;

const MAX_IPC_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum WorkerResponse {
    Ok {
        acquired: Acquired,
    },
    Error {
        code: String,
        retry_after_secs: Option<u64>,
    },
}

/// Run one isolated browser process. The proxy must already be running and
/// enforce the job's origin and resolved-address policy.
pub async fn acquire(
    job: BrowserJob,
    worker_path: &Path,
    max_rss_bytes: u64,
    cancel: &CancellationToken,
) -> Result<Acquired> {
    let input = serde_json::to_vec(&job)
        .map_err(|_| LoadError::new("worker_protocol", "invalid browser job"))?;
    if input.len() as u64 > MAX_IPC_BYTES {
        return Err(LoadError::new(
            "worker_protocol",
            "browser job exceeds IPC limit",
        ));
    }
    let mut cmd = Command::new(worker_path);
    cmd.env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for name in ["PATH", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR"] {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    cmd.env("OBSCURA_FETCH_MAX_BODY_BYTES", job.max_bytes.to_string());
    let mut child = cmd
        .spawn()
        .map_err(|_| LoadError::new("worker_start", "browser worker could not start"))?;
    let pid = child
        .id()
        .ok_or_else(|| LoadError::new("worker_start", "browser worker has no process ID"))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let io = async move {
        stdin.write_all(&input).await?;
        drop(stdin);
        let mut output = Vec::new();
        stdout
            .take(MAX_IPC_BYTES + 1)
            .read_to_end(&mut output)
            .await?;
        Ok::<_, std::io::Error>(output)
    };
    tokio::pin!(io);
    let deadline = tokio::time::sleep(Duration::from_secs(job.timeout_secs));
    tokio::pin!(deadline);
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    let mut monitor_errors = 0;
    let output = loop {
        tokio::select! {
            _ = cancel.cancelled() => break Err(LoadError::new("cancelled", "browser job cancelled")),
            _ = &mut deadline => break Err(LoadError::transient("browser_timeout", "browser job deadline exceeded")),
            result = &mut io => break result.map_err(|_| LoadError::new("worker_protocol", "browser worker communication failed")),
            _ = interval.tick() => {
                match rss_bytes(pid).await {
                    Ok(bytes) if bytes > max_rss_bytes => break Err(LoadError::new("browser_memory_limit", "browser worker exceeded memory limit")),
                    Ok(_) => { monitor_errors = 0; },
                    Err(_) => {
                        // A process can be exiting while /proc no longer reports VmRSS.
                        // Tolerate brief races but fail closed if monitoring remains unavailable.
                        monitor_errors += 1;
                        if monitor_errors >= 3 && child.try_wait().ok().flatten().is_none() {
                            break Err(LoadError::new("browser_monitor", "browser worker memory could not be monitored"));
                        }
                    }
                }
            }
        }
    };
    let output = match output {
        Ok(output) => output,
        Err(err) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(err);
        }
    };
    let status = loop {
        tokio::select! {
            _ = cancel.cancelled() => { let _ = child.kill().await; let _ = child.wait().await; return Err(LoadError::new("cancelled", "browser job cancelled")); },
            _ = &mut deadline => { let _ = child.kill().await; let _ = child.wait().await; return Err(LoadError::transient("browser_timeout", "browser job deadline exceeded")); },
            status = child.wait() => break status.map_err(|_| LoadError::new("worker_protocol", "browser worker wait failed"))?,
            _ = interval.tick() => {
                if rss_bytes(pid).await.is_ok_and(|bytes| bytes > max_rss_bytes) {
                    let _ = child.kill().await; let _ = child.wait().await;
                    return Err(LoadError::new("browser_memory_limit", "browser worker exceeded memory limit"));
                }
            }
        }
    };
    if !status.success() || output.len() as u64 > MAX_IPC_BYTES {
        return Err(LoadError::new("worker_protocol", "browser worker failed"));
    }
    match serde_json::from_slice::<WorkerResponse>(&output)
        .map_err(|_| LoadError::new("worker_protocol", "invalid browser worker response"))?
    {
        WorkerResponse::Ok { acquired } => Ok(acquired),
        WorkerResponse::Error {
            code,
            retry_after_secs,
        } => {
            // Never forward worker-supplied text to logs or clients.
            let (code, message) = match code.as_str() {
                "http_429" => ("http_429", "upstream returned an unsuccessful HTTP status"),
                "http_500" => ("http_500", "upstream returned an unsuccessful HTTP status"),
                "http_502" => ("http_502", "upstream returned an unsuccessful HTTP status"),
                "http_503" => ("http_503", "upstream returned an unsuccessful HTTP status"),
                "http_504" => ("http_504", "upstream returned an unsuccessful HTTP status"),
                "invalid_proxy" => ("invalid_proxy", "invalid browser proxy"),
                "invalid_job" => ("invalid_job", "invalid browser job"),
                "upstream_limit" => ("upstream_limit", "upstream browser response limit exceeded"),
                "size_limit" => ("size_limit", "PDF exceeds configured byte limit"),
                "upstream_timeout" => ("upstream_timeout", "upstream browser request timed out"),
                "network_failed" => ("network_failed", "browser network request failed"),
                "pdf_not_found" => ("pdf_not_found", "matching PDF response was not found"),
                "storage_io" => ("storage_io", "filesystem operation failed"),
                _ => ("browser_failed", "browser acquisition failed"),
            };
            let mut error = if code == "upstream_timeout"
                || code == "network_failed"
                || code.starts_with("http_")
            {
                LoadError::transient(code, message)
            } else {
                LoadError::new(code, message)
            };
            error.retry_after_secs = retry_after_secs;
            Err(error)
        }
    }
}

async fn rss_bytes(pid: u32) -> std::io::Result<u64> {
    let status = tokio::fs::read_to_string(format!("/proc/{pid}/status")).await?;
    let kb = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing VmRSS"))?;
    Ok(kb.saturating_mul(1024))
}
