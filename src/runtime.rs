use crate::{
    browser,
    config::{Config, Mode, Source, resolve_cookies, resolve_steps},
    direct,
    error::{LoadError, Result},
    manual,
    model::{BrowserJob, Observation},
    policy::{BrowserProxy, NetworkPolicy, sanitized_url},
    storage::Store,
};
use futures_util::{StreamExt, stream};
use notify::{RecursiveMode, Watcher};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub async fn fetch(
    store: &Store,
    config: &Config,
    source: &Source,
    worker: &Path,
    cancel: &CancellationToken,
) -> Result<Observation> {
    fetch_inner(store, config, source, worker, cancel, None).await
}

pub async fn fetch_job(
    store: &Store,
    config: &Config,
    source: &Source,
    worker: &Path,
    cancel: &CancellationToken,
    job_id: &str,
) -> Result<Observation> {
    fetch_inner(store, config, source, worker, cancel, Some(job_id)).await
}

async fn fetch_inner(
    store: &Store,
    config: &Config,
    source: &Source,
    worker: &Path,
    cancel: &CancellationToken,
    job_id: Option<&str>,
) -> Result<Observation> {
    if cancel.is_cancelled() {
        return Err(LoadError::new("cancelled", "loading cancelled"));
    }
    let limits = source.limits(&config.limits);
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(limits.timeout_secs))
        .ok_or_else(|| LoadError::new("config_invalid", "timeout is too large"))?;
    let policy = NetworkPolicy::for_source(source)?;
    for retry in 0..3u32 {
        let attempt = uuid::Uuid::new_v4().to_string();
        let staged = store.staging_file()?;
        let result = async {
            let acquired = match source.mode {
                Mode::Https => tokio::select! {
                    _=cancel.cancelled()=>return Err(LoadError::new("cancelled","loading cancelled")),
                    result=tokio::time::timeout(deadline.saturating_duration_since(Instant::now()),direct::acquire(source,staged.path(),&policy,limits.max_bytes,deadline))=>result.unwrap_or_else(|_|Err(LoadError::new("run_timeout","loading deadline exceeded")))?,
                },
                Mode::Obscura | Mode::Browser => {
                    let proxy = BrowserProxy::start(policy.clone()).await?;
                    std::fs::remove_file(staged.path()).map_err(crate::error::io_error)?;
                    let cookies = resolve_cookies(&source.cookies)?;
                    let steps = resolve_steps(&source.steps)?;
                    let remaining = deadline.saturating_duration_since(Instant::now()).as_secs();
                    if remaining == 0 {
                        return Err(LoadError::new("run_timeout", "loading deadline exceeded"));
                    }
                    let job = BrowserJob {
                        url: source.url.clone(),
                        output: staged.path().to_owned(),
                        max_bytes: limits.max_bytes,
                        timeout_secs: remaining,
                        proxy_url: proxy.url.clone(),
                        allowed_origins: policy.origins(),
                        cookies,
                        steps,
                        response_url_glob: source
                            .response_url_glob
                            .clone()
                            .unwrap_or_else(|| "*".into()),
                        raw: matches!(source.mode, Mode::Obscura),
                    };
                    browser::acquire(job, worker, limits.worker_max_rss_mib * 1024 * 1024, cancel)
                        .await?
                }
            };
            if acquired.bytes > limits.max_bytes {
                return Err(LoadError::new(
                    "size_limit",
                    "PDF exceeds configured byte limit",
                ));
            }
            if cancel.is_cancelled() {
                return Err(LoadError::new("cancelled", "loading cancelled"));
            }
            if Instant::now() >= deadline {
                return Err(LoadError::new("run_timeout", "loading deadline exceeded"));
            }
            let url = sanitized_url(&acquired.final_url);
            if let Some(job_id) = job_id {
                store
                    .accept_before_job(
                        staged.path(),
                        &source.id,
                        source.mode.as_str(),
                        url.as_deref(),
                        &attempt,
                        deadline,
                        cancel,
                        job_id,
                    )
                    .await
            } else {
                store
                    .accept_before(
                        staged.path(),
                        &source.id,
                        source.mode.as_str(),
                        url.as_deref(),
                        &attempt,
                        deadline,
                        cancel,
                    )
                    .await
            }
        };
        // The browser supervisor must finish kill+wait before its proxy and staging file drop.
        let result = result.await;
        match result {
            Ok(observation) => return Ok(observation),
            Err(error) => {
                let url = sanitized_url(&source.url);
                store
                    .record_failure(
                        &source.id,
                        source.mode.as_str(),
                        url.as_deref(),
                        &attempt,
                        &error.code,
                    )
                    .await?;
                if !error.retryable || retry == 2 || cancel.is_cancelled() {
                    return Err(error);
                }
                let seconds = error
                    .retry_after_secs
                    .unwrap_or_else(|| (1u64 << retry) + rand::random_range(0..=1));
                let delay = Duration::from_secs(seconds);
                if delay >= deadline.saturating_duration_since(Instant::now()) {
                    return Err(error);
                }
                tokio::select! {_=cancel.cancelled()=>return Err(LoadError::new("cancelled","loading cancelled")),_=tokio::time::sleep(delay)=>{}}
            }
        }
    }
    unreachable!("bounded retry loop returns")
}

/// One daemon owns this Store; the filesystem lock also excludes standalone CLI writes.
pub async fn daemon<F: Fn(&Observation) + Sync>(
    store: &Store,
    config: &Config,
    worker: &Path,
    poll_remote: bool,
    cancel: &CancellationToken,
    emit: F,
) -> Result<()> {
    let emit = &emit;
    let (sender, mut events) = tokio::sync::mpsc::channel::<()>(1);
    let watch_failed = Arc::new(AtomicBool::new(false));
    let callback_failed = watch_failed.clone();
    let mut watcher =
        notify::recommended_watcher(move |event: notify::Result<notify::Event>| match event {
            Ok(event)
                if event.kind.is_create()
                    || event.kind.is_modify()
                    || event.kind.is_remove()
                    || event.need_rescan() =>
            {
                let _ = sender.try_send(());
            }
            Err(_) => {
                callback_failed.store(true, Ordering::Relaxed);
                let _ = sender.try_send(());
            }
            _ => {}
        })
        .map_err(|_| LoadError::new("watch_failed", "cannot initialize filesystem watcher"))?;
    watcher
        .watch(&store.root().join("pdfs"), RecursiveMode::Recursive)
        .map_err(|_| LoadError::new("watch_failed", "cannot watch manual inbox"))?;
    let mut last_scan = Instant::now()
        .checked_sub(Duration::from_secs(30))
        .unwrap_or_else(Instant::now);
    loop {
        if cancel.is_cancelled() {
            break;
        }
        if watch_failed.load(Ordering::Relaxed) {
            return Err(LoadError::new(
                "watch_failed",
                "filesystem watcher reported an error",
            ));
        }
        if last_scan.elapsed() >= Duration::from_secs(30) || events.try_recv().is_ok() {
            while events.try_recv().is_ok() {}
            match manual::scan(store, config.limits.max_bytes, cancel).await {
                Ok(results) => {
                    for result in results {
                        emit(&result)
                    }
                }
                Err(e) if e.code == "cancelled" => break,
                Err(e) => return Err(e),
            }
            last_scan = Instant::now();
        }
        if poll_remote {
            let now = chrono::Utc::now().timestamp();
            let mut due = Vec::new();
            for source in &config.sources {
                if source.interval_secs.is_some() {
                    let when = store.next_due(&source.id).await?.unwrap_or(0);
                    if when <= now {
                        due.push((when, source));
                    }
                }
            }
            due.sort_by_key(|(when, _)| *when);
            // Process only one admission window before reconciling the manual inbox again.
            let mut jobs = stream::iter(due.into_iter().take(config.limits.concurrency).map(
                |(_, source)| async move {
                    let result = fetch(store, config, source, worker, cancel).await;
                    let interval = source.interval_secs.expect("scheduled source");
                    let next = chrono::Utc::now()
                        .timestamp()
                        .saturating_add(i64::try_from(interval).unwrap_or(i64::MAX));
                    store.set_next_due(&source.id, next).await?;
                    match result {
                        Ok(obs) => emit(&obs),
                        Err(e) if e.code.starts_with("storage_") => return Err(e),
                        Err(_) => {
                            if let Some(obs) = store.history(Some(&source.id)).await?.last() {
                                emit(obs);
                            }
                        }
                    }
                    Ok(())
                },
            ))
            .buffer_unordered(config.limits.concurrency);
            let mut failure = None;
            while let Some(result) = jobs.next().await {
                if let Err(error) = result {
                    cancel.cancel();
                    failure.get_or_insert(error);
                }
            }
            if let Some(error) = failure {
                return Err(error);
            }
        }
        tokio::select! {
            _=cancel.cancelled()=>break,
            event=events.recv()=>{if event.is_none(){return Err(LoadError::new("watch_failed","filesystem watcher stopped"));}last_scan=Instant::now().checked_sub(Duration::from_secs(30)).unwrap_or_else(Instant::now);},
            _=tokio::time::sleep(Duration::from_secs(1))=>{},
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejected_sources_are_never_fetched() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let store = Store::open(d.path(), None).await.unwrap();
        let cfg = Config::default();
        let s = Source::one_off("https://127.0.0.1/secret".into(), Mode::Https);
        assert_eq!(
            fetch(
                &store,
                &cfg,
                &s,
                Path::new("no-worker"),
                &CancellationToken::new()
            )
            .await
            .unwrap_err()
            .code,
            "network_policy"
        );
        assert!(store.history(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn daemon_watches_manual_files_and_polls_only_opted_in_sources() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let worker = dir.path().join("fixture-worker");
        std::fs::write(
            &worker,
            r##"#!/usr/bin/env python3
import json,sys
j=json.load(sys.stdin)
b=b'%PDF-1.7\nfixture\n%%EOF\n'
with open(j['output'],'xb') as f: f.write(b)
json.dump({'status':'ok','acquired':{'bytes':len(b),'final_url':j['url']}},sys.stdout)
"##,
        )
        .unwrap();
        std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(&dir.path().join("data"), None).await.unwrap();
        let mut cfg = Config::default();
        let mut scheduled = Source::one_off("https://example.com/pdf".into(), Mode::Obscura);
        scheduled.id = "scheduled".into();
        scheduled.interval_secs = Some(1);
        let mut on_demand = scheduled.clone();
        on_demand.id = "on-demand".into();
        on_demand.interval_secs = None;
        cfg.sources = vec![scheduled, on_demand];
        cfg.validate().unwrap();
        let cancel = CancellationToken::new();
        let seen = std::sync::Mutex::new(Vec::new());
        let observer = async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            std::fs::write(
                store.root().join("pdfs/copied.pdf"),
                b"%PDF-1.7\nmanual\n%%EOF",
            )
            .unwrap();
            for _ in 0..100 {
                {
                    let seen = seen.lock().unwrap();
                    if seen.iter().any(|s: &String| s.starts_with("manual:"))
                        && seen.iter().filter(|s| s.as_str() == "scheduled").count() >= 2
                    {
                        cancel.cancel();
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            cancel.cancel();
            panic!("daemon did not register both manual and scheduled work");
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(
                daemon(&store, &cfg, &worker, true, &cancel, |o| seen
                    .lock()
                    .unwrap()
                    .push(o.source_id.clone())),
                observer
            )
        })
        .await
        .unwrap();
        result.unwrap();
        let history = store.history(None).await.unwrap();
        assert!(!history.iter().any(|o| o.source_id == "on-demand"));
        assert!(store.next_due("scheduled").await.unwrap().is_some());
        assert!(store.next_due("on-demand").await.unwrap().is_none());
        assert_eq!(
            std::fs::read_dir(store.root().join(".staging"))
                .unwrap()
                .count(),
            0
        );
    }
}
