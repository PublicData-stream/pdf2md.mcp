use super::*;
use tokio::task::JoinSet;

impl CallerService {
    /// Dispatch durable work fairly across eligible workspaces with host-wide limits.
    /// Shutdown cancels workers and awaits their supervisors; queued jobs remain durable.
    pub async fn run(
        self: &Arc<Self>,
        worker: &Path,
        conversion_worker: &Path,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let mut tasks: JoinSet<(PathBuf, String, Result<()>)> = JoinSet::new();
        let mut cursor = 0usize;
        let mut failure = None;
        loop {
            while let Some(result) = tasks.try_join_next() {
                match result {
                    Ok((path, id, result)) => {
                        self.running.lock().await.remove(&(path, id));
                        if let Err(error) = result {
                            failure.get_or_insert(error);
                            cancel.cancel();
                        }
                    }
                    Err(_) => {
                        failure.get_or_insert_with(|| {
                            LoadError::new("service_worker", "job task failed")
                        });
                        cancel.cancel();
                    }
                }
            }
            if cancel.is_cancelled() {
                break;
            }
            let workspaces = match self.registry.list().await {
                Ok(workspaces) => workspaces
                    .into_iter()
                    .filter(|info| self.eligible(info))
                    .collect::<Vec<_>>(),
                Err(error) => {
                    failure = Some(error);
                    cancel.cancel();
                    break;
                }
            };
            let mut admitted = false;
            let scan_result: Result<()> = async {
                let acquire_available = self.acquisitions.available_permits() > 0;
                let convert_available = self.conversions.available_permits() > 0;
                if !acquire_available && !convert_available {
                    return Ok(());
                }
                let start = cursor;
                'workspaces: for offset in 0..workspaces.len() {
                    if cancel.is_cancelled() {
                        break;
                    }
                    let index = (start + offset) % workspaces.len();
                    let path = self
                        .registry
                        .resolve_existing(&workspaces[index].id)
                        .await?;
                    let store = match self.store(path.clone()).await {
                        Ok(store) => store,
                        Err(error) if error.code == "service_busy" => continue,
                        Err(error) => return Err(error),
                    };
                    self.admit_schedules(&store).await?;
                    // One admission per workspace per pass bounds competition from a busy owner.
                    let mut queued = Vec::new();
                    if acquire_available {
                        queued.extend(store.queued_jobs_by_kind(false, 1).await?);
                    }
                    if convert_available {
                        queued.extend(store.queued_jobs_by_kind(true, 1).await?);
                    }
                    for job in queued {
                        let slots = if matches!(job.command, JobCommand::Convert { .. }) {
                            &self.conversions
                        } else {
                            &self.acquisitions
                        };
                        let Ok(permit) = slots.clone().try_acquire_owned() else {
                            continue;
                        };
                        let child = cancel.child_token();
                        let explicit = Arc::new(AtomicBool::new(false));
                        let mut running = self.running.lock().await;
                        if let Some(job) = store.claim_job(&job.id).await? {
                            running.insert(
                                (path.clone(), job.id.clone()),
                                RunningJob {
                                    cancel: child.clone(),
                                    explicit: explicit.clone(),
                                },
                            );
                            let service = self.clone();
                            let store = store.clone();
                            let path = path.clone();
                            let worker = worker.to_owned();
                            let conversion_worker = conversion_worker.to_owned();
                            let parent_cancel = cancel.clone();
                            tasks.spawn(async move {
                                let id = job.id.clone();
                                let _permit = permit;
                                let result = service
                                    .perform_job(
                                        &store,
                                        &job,
                                        (&worker, &conversion_worker),
                                        &child,
                                        &parent_cancel,
                                        &explicit,
                                    )
                                    .await;
                                (path, id, result)
                            });
                            admitted = true;
                            cursor = (index + 1) % workspaces.len();
                            break 'workspaces;
                        }
                    }
                }
                Ok(())
            }
            .await;
            if let Err(error) = scan_result {
                failure = Some(error);
                cancel.cancel();
                break;
            }
            // Always yield to cancellation, new admissions and completion. No workspace owns a task.
            if admitted {
                tokio::task::yield_now().await;
            }
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = self.wake.notified() => {},
                _ = tokio::time::sleep(Duration::from_millis(if admitted { 10 } else { 250 })) => {},
            }
        }
        cancel.cancel();
        for running in self.running.lock().await.values() {
            running.cancel.cancel();
        }
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((path, id, result)) => {
                    self.running.lock().await.remove(&(path, id));
                    if let Err(error) = result {
                        failure.get_or_insert(error);
                    }
                }
                Err(_) => {
                    failure
                        .get_or_insert_with(|| LoadError::new("service_worker", "job task failed"));
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn admit_schedules(&self, store: &Arc<Store>) -> Result<()> {
        if !store
            .schedules()
            .await?
            .iter()
            .any(|schedule| schedule.enabled && schedule.next_due <= chrono::Utc::now().timestamp())
        {
            return Ok(());
        }
        let _admission = self.admission.lock().await;
        let unit = if self.config.conversion.enabled { 2 } else { 1 };
        let local_remaining = self
            .config
            .http
            .per_workspace_jobs
            .saturating_sub(self.count_jobs(store).await?)
            / unit;
        if local_remaining == 0 {
            return Ok(());
        }
        let global_remaining = self
            .config
            .http
            .total_jobs
            .saturating_sub(self.total_jobs().await?)
            / unit;
        let limit = local_remaining.min(global_remaining);
        if limit > 0 {
            store
                .enqueue_due_schedules_bounded(self.config.http.per_workspace_jobs, limit)
                .await?;
        }
        Ok(())
    }

    async fn perform_job(
        &self,
        store: &Arc<Store>,
        job: &Job,
        workers: (&Path, &Path),
        cancel: &CancellationToken,
        shutdown: &CancellationToken,
        explicit: &AtomicBool,
    ) -> Result<()> {
        let (worker, conversion_worker) = workers;
        let result: Result<()> = match &job.command {
            JobCommand::AcquireHttps { url } => {
                let source = Source::one_off(url.clone(), Mode::Https);
                runtime::fetch_job(store, &self.config, &source, worker, cancel, &job.id)
                    .await
                    .map(|_| ())
            }
            JobCommand::FetchSource {
                source_id,
                fingerprint,
            } => {
                match self
                    .definitions
                    .get(source_id)
                    .filter(|definition| &definition.fingerprint == fingerprint)
                {
                    Some(definition) => runtime::fetch_job(
                        store,
                        &self.config,
                        &definition.source,
                        worker,
                        cancel,
                        &job.id,
                    )
                    .await
                    .map(|_| ()),
                    None => Err(LoadError::new(
                        "source_changed",
                        "operator source definition changed",
                    )),
                }
            }
            JobCommand::Convert { .. } => store
                .process_conversion(
                    &job.id,
                    &self.config.conversion.limits,
                    conversion_worker,
                    cancel,
                )
                .await
                .map(|_| ()),
        };
        if let Err(error) = result {
            let status = if error.code == "source_changed" {
                "interrupted"
            } else if cancel.is_cancelled() || error.code == "cancelled" {
                if shutdown.is_cancelled() && !explicit.load(Ordering::Acquire) {
                    "interrupted"
                } else {
                    "cancelled"
                }
            } else {
                "failed"
            };
            store.finish_job(&job.id, status, Some(&error.code)).await?;
            if error.code.starts_with("storage_") {
                return Err(error);
            }
        }
        if shutdown.is_cancelled()
            && !explicit.load(Ordering::Acquire)
            && matches!(job.command, JobCommand::Convert { .. })
        {
            store.interrupt_cancelled_conversion(&job.id).await?;
        }
        self.wake.notify_one();
        Ok(())
    }
}
