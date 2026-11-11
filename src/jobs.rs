use crate::{
    conversion::ConversionOptions,
    error::{LoadError, Result},
    storage::{Store, corrupt, db_error},
};
use serde::{Deserialize, Serialize};
use sqlx::{Any, Row, Transaction};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobCommand {
    AcquireHttps {
        url: String,
    },
    FetchSource {
        source_id: String,
        fingerprint: String,
    },
    Convert {
        document_id: String,
        options: ConversionOptions,
        force: bool,
    },
}
impl JobCommand {
    fn kind(&self) -> &'static str {
        match self {
            Self::AcquireHttps { .. } => "acquire_https",
            Self::FetchSource { .. } => "fetch_source",
            Self::Convert { .. } => "convert",
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub document_id: Option<String>,
    pub observation_id: Option<String>,
    pub conversion_id: Option<String>,
    pub error_code: Option<String>,
    pub retry_of: Option<String>,
    #[serde(skip)]
    pub command: JobCommand,
}
#[derive(Debug, Clone, Serialize)]
pub struct Schedule {
    pub source_id: String,
    pub enabled: bool,
    pub interval_secs: u64,
    pub next_due: i64,
    pub status: String,
    pub error_code: Option<String>,
    #[serde(skip)]
    pub fingerprint: String,
}
fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn row(r: sqlx::any::AnyRow) -> Result<Job> {
    let command: String = r.try_get("command").map_err(db_error)?;
    Ok(Job {
        id: r.try_get("id").map_err(db_error)?,
        kind: r.try_get("kind").map_err(db_error)?,
        status: r.try_get("status").map_err(db_error)?,
        created_at: r.try_get("created_at").map_err(db_error)?,
        started_at: r.try_get("started_at").map_err(db_error)?,
        finished_at: r.try_get("finished_at").map_err(db_error)?,
        document_id: r.try_get("document_id").map_err(db_error)?,
        observation_id: r.try_get("observation_id").map_err(db_error)?,
        conversion_id: r.try_get("conversion_id").map_err(db_error)?,
        error_code: r.try_get("error_code").map_err(db_error)?,
        retry_of: r.try_get("retry_of").map_err(db_error)?,
        command: serde_json::from_str(&command).map_err(|_| corrupt())?,
    })
}
const COLS: &str = "id,kind,command,status,created_at,started_at,finished_at,document_id,observation_id,conversion_id,error_code,(SELECT parent_id FROM api_job_retries links WHERE links.namespace=api_jobs.namespace AND links.job_id=api_jobs.id) AS retry_of";
pub(crate) async fn insert_job(
    tx: &mut Transaction<'_, Any>,
    ns: &str,
    id: &str,
    command: &JobCommand,
    key: Option<&str>,
) -> Result<()> {
    let data = serde_json::to_string(command).map_err(|_| corrupt())?;
    let (document, conversion) = match command {
        JobCommand::Convert { document_id, .. } => (Some(document_id.as_str()), Some(id)),
        _ => (None, None),
    };
    sqlx::query("INSERT INTO api_jobs(namespace,id,kind,command,status,created_at,document_id,conversion_id,idempotency_key) VALUES($1,$2,$3,$4,'queued',$5,$6,$7,$8)").bind(ns).bind(id).bind(command.kind()).bind(data).bind(now()).bind(document).bind(conversion).bind(key).execute(&mut **tx).await.map_err(db_error)?;
    Ok(())
}
pub(crate) async fn advance_schedule(
    tx: &mut Transaction<'_, Any>,
    namespace: &str,
    job_id: &str,
) -> Result<()> {
    let command: Option<String> =
        sqlx::query_scalar("SELECT command FROM api_jobs WHERE namespace=$1 AND id=$2")
            .bind(namespace)
            .bind(job_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
    if let Some(command) = command
        && let JobCommand::FetchSource {
            source_id,
            fingerprint,
        } = serde_json::from_str(&command).map_err(|_| corrupt())?
    {
        sqlx::query("UPDATE api_schedules SET next_due=$1+interval_secs WHERE namespace=$2 AND source_id=$3 AND fingerprint=$4 AND enabled=1").bind(chrono::Utc::now().timestamp()).bind(namespace).bind(source_id).bind(fingerprint).execute(&mut **tx).await.map_err(db_error)?;
    }
    Ok(())
}
impl Store {
    pub async fn enqueue_job(
        &self,
        command: &JobCommand,
        key: Option<&str>,
        workspace_cap: usize,
    ) -> Result<(Job, bool)> {
        self.enqueue_retry_job(command, key, workspace_cap, None)
            .await
    }
    pub async fn enqueue_retry_job(
        &self,
        command: &JobCommand,
        key: Option<&str>,
        workspace_cap: usize,
        retry_of: Option<&str>,
    ) -> Result<(Job, bool)> {
        if let JobCommand::Convert {
            document_id,
            options,
            ..
        } = command
        {
            self.open_document(document_id).await?;
            options.validate()?;
        }
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        if let Some(key) = key {
            let q = format!(
                "SELECT {COLS} FROM api_jobs WHERE namespace=$1 AND id=(SELECT job_id FROM api_idempotency WHERE namespace=$1 AND key=$2)"
            );
            if let Some(r) = sqlx::query(&q)
                .bind(&self.namespace)
                .bind(key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?
            {
                let existing = row(r)?;
                let original: String = sqlx::query_scalar(
                    "SELECT command FROM api_idempotency WHERE namespace=$1 AND key=$2",
                )
                .bind(&self.namespace)
                .bind(key)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_error)?;
                let original: serde_json::Value =
                    serde_json::from_str(&original).map_err(|_| corrupt())?;
                let original = if original.get("command").is_some() {
                    original
                } else {
                    serde_json::json!({"command":original,"retry_of":null})
                };
                let expected = serde_json::json!({"command":command,"retry_of":retry_of});
                if original != expected {
                    return Err(LoadError::new(
                        "idempotency_conflict",
                        "idempotency key already used for another command",
                    ));
                }
                return Ok((existing, false));
            }
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_jobs WHERE namespace=$1 AND status IN ('queued','running')",
        )
        .bind(&self.namespace)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        let mut created = true;
        let mut id = uuid::Uuid::new_v4().to_string();
        if let JobCommand::Convert {
            document_id,
            options,
            force,
        } = command
        {
            let profile = crate::conversion::profile_key(document_id, options)?;
            let existing: Option<String> = sqlx::query_scalar("SELECT id FROM conversion_attempts WHERE namespace=$1 AND profile_key=$2 AND (status IN ('pending','running') OR (status='succeeded' AND $3=0)) ORDER BY created_at DESC,id DESC LIMIT 1").bind(&self.namespace).bind(profile).bind(i32::from(*force)).fetch_optional(&mut *tx).await.map_err(db_error)?;
            if let Some(existing) = existing {
                if retry_of.is_some() {
                    return Err(LoadError::new(
                        "job_conflict",
                        "a matching conversion is already active",
                    ));
                }
                id = existing;
                created = false;
            } else {
                crate::conversion::store::insert(
                    &mut tx,
                    &self.namespace,
                    &id,
                    document_id,
                    options,
                    false,
                )
                .await?;
            }
        }
        if created && count >= i64::try_from(workspace_cap).unwrap_or(i64::MAX) {
            return Err(LoadError::new(
                "job_capacity",
                "workspace job capacity reached",
            ));
        }
        if created {
            insert_job(&mut tx, &self.namespace, &id, command, None).await?;
            if let Some(parent) = retry_of {
                sqlx::query(
                    "INSERT INTO api_job_retries(namespace,job_id,parent_id) VALUES($1,$2,$3)",
                )
                .bind(&self.namespace)
                .bind(&id)
                .bind(parent)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
            }
        }
        if let Some(key) = key {
            sqlx::query(
                "INSERT INTO api_idempotency(namespace,key,job_id,command) VALUES($1,$2,$3,$4)",
            )
            .bind(&self.namespace)
            .bind(key)
            .bind(&id)
            .bind(
                serde_json::to_string(&serde_json::json!({"command":command,"retry_of":retry_of}))
                    .map_err(|_| corrupt())?,
            )
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        }
        tx.commit().await.map_err(db_error)?;
        Ok((self.job(&id).await?, created))
    }
    pub async fn reusable_conversion(&self, command: &JobCommand) -> Result<Option<Job>> {
        let JobCommand::Convert {
            document_id,
            options,
            force,
        } = command
        else {
            return Ok(None);
        };
        let profile = crate::conversion::profile_key(document_id, options)?;
        let id:Option<String>=sqlx::query_scalar("SELECT id FROM conversion_attempts WHERE namespace=$1 AND profile_key=$2 AND (status IN ('pending','running') OR (status='succeeded' AND $3=0)) ORDER BY created_at DESC,id DESC LIMIT 1").bind(&self.namespace).bind(profile).bind(i32::from(*force)).fetch_optional(&self.pool).await.map_err(db_error)?;
        match id {
            Some(id) => Ok(Some(self.job(&id).await?)),
            None => Ok(None),
        }
    }
    pub async fn job_for_key(&self, key: &str) -> Result<Option<Job>> {
        let q = format!(
            "SELECT {COLS} FROM api_jobs WHERE namespace=$1 AND id=(SELECT job_id FROM api_idempotency WHERE namespace=$1 AND key=$2)"
        );
        sqlx::query(&q)
            .bind(&self.namespace)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?
            .map(row)
            .transpose()
    }
    pub async fn reconcile_sources(&self, sources: &[(String, String)]) -> Result<()> {
        for job in self.jobs().await? {
            if let JobCommand::FetchSource {
                source_id,
                fingerprint,
            } = &job.command
                && job.status == "queued"
                && !sources
                    .iter()
                    .any(|(id, hash)| id == source_id && hash == fingerprint)
            {
                sqlx::query("UPDATE api_jobs SET status='interrupted', finished_at=$1,error_code='config_changed' WHERE namespace=$2 AND id=$3 AND status='queued'").bind(now()).bind(&self.namespace).bind(&job.id).execute(&self.pool).await.map_err(db_error)?;
            }
        }
        for schedule in self.schedules().await? {
            if !sources
                .iter()
                .any(|(id, hash)| id == &schedule.source_id && hash == &schedule.fingerprint)
            {
                sqlx::query("UPDATE api_schedules SET enabled=0,status='paused',error_code='config_changed' WHERE namespace=$1 AND source_id=$2").bind(&self.namespace).bind(&schedule.source_id).execute(&self.pool).await.map_err(db_error)?;
            }
        }
        Ok(())
    }
    pub async fn pause_schedules(&self, code: &str) -> Result<()> {
        sqlx::query("UPDATE api_schedules SET enabled=0,status='paused',error_code=$1 WHERE namespace=$2 AND enabled=1").bind(code).bind(&self.namespace).execute(&self.pool).await.map_err(db_error)?;
        Ok(())
    }
    pub async fn active_job_counts(&self) -> Result<(usize, usize)> {
        let row = sqlx::query("SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN kind <> 'convert' THEN 1 ELSE 0 END),0) AS non_conversion FROM api_jobs WHERE namespace=$1 AND status IN ('queued','running')").bind(&self.namespace).fetch_one(&self.pool).await.map_err(db_error)?;
        let total: i64 = row.try_get("total").map_err(db_error)?;
        let non_conversion: i64 = row.try_get("non_conversion").map_err(db_error)?;
        Ok((
            usize::try_from(total).map_err(|_| corrupt())?,
            usize::try_from(non_conversion).map_err(|_| corrupt())?,
        ))
    }
    pub async fn queued_jobs(&self, limit: usize) -> Result<Vec<Job>> {
        let q = format!(
            "SELECT {COLS} FROM api_jobs WHERE namespace=$1 AND status='queued' ORDER BY created_at,id LIMIT $2"
        );
        sqlx::query(&q)
            .bind(&self.namespace)
            .bind(i64::try_from(limit).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(row)
            .collect()
    }
    pub async fn jobs(&self) -> Result<Vec<Job>> {
        let q = format!("SELECT {COLS} FROM api_jobs WHERE namespace=$1 ORDER BY created_at,id");
        sqlx::query(&q)
            .bind(&self.namespace)
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(row)
            .collect()
    }
    pub async fn jobs_page(&self, limit: usize, offset: usize) -> Result<Vec<Job>> {
        let q = format!(
            "SELECT {COLS} FROM api_jobs WHERE namespace=$1 ORDER BY created_at,id LIMIT $2 OFFSET $3"
        );
        sqlx::query(&q)
            .bind(&self.namespace)
            .bind(i64::try_from(limit).unwrap_or(i64::MAX))
            .bind(i64::try_from(offset).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(row)
            .collect()
    }
    pub async fn queued_jobs_by_kind(&self, conversion: bool, limit: usize) -> Result<Vec<Job>> {
        let kind = if conversion {
            "kind='convert'"
        } else {
            "kind<>'convert'"
        };
        let q = format!(
            "SELECT {COLS} FROM api_jobs WHERE namespace=$1 AND status='queued' AND {kind} ORDER BY created_at,id LIMIT $2"
        );
        sqlx::query(&q)
            .bind(&self.namespace)
            .bind(i64::try_from(limit).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(row)
            .collect()
    }
    pub(crate) async fn interrupt_cancelled_conversion(&self, id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        sqlx::query("UPDATE conversion_attempts SET status='interrupted',error_code='shutdown' WHERE namespace=$1 AND id=$2 AND status='cancelled' AND error_code='cancelled'").bind(&self.namespace).bind(id).execute(&mut *tx).await.map_err(db_error)?;
        sqlx::query("UPDATE api_jobs SET status='interrupted',error_code='shutdown' WHERE namespace=$1 AND id=$2 AND status='cancelled' AND error_code='cancelled'").bind(&self.namespace).bind(id).execute(&mut *tx).await.map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }
    pub async fn job(&self, id: &str) -> Result<Job> {
        let q = format!("SELECT {COLS} FROM api_jobs WHERE namespace=$1 AND id=$2");
        row(sqlx::query(&q)
            .bind(&self.namespace)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?
            .ok_or_else(|| LoadError::new("job_not_found", "job unavailable"))?)
    }
    pub async fn claim_job(&self, id: &str) -> Result<Option<Job>> {
        let n = sqlx::query("UPDATE api_jobs SET status='running',started_at=$1 WHERE namespace=$2 AND id=$3 AND status='queued'").bind(now()).bind(&self.namespace).bind(id).execute(&self.pool).await.map_err(db_error)?.rows_affected();
        if n == 0 {
            Ok(None)
        } else {
            Ok(Some(self.job(id).await?))
        }
    }
    pub async fn finish_job(&self, id: &str, status: &str, error: Option<&str>) -> Result<Job> {
        if !["succeeded", "failed", "cancelled", "interrupted"].contains(&status) {
            return Err(LoadError::new("job_status", "invalid terminal job status"));
        }
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let n = sqlx::query("UPDATE api_jobs SET status=$1,finished_at=$2,error_code=$3 WHERE namespace=$4 AND id=$5 AND status='running'").bind(status).bind(now()).bind(error).bind(&self.namespace).bind(id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
        if n != 0 && status != "succeeded" {
            sqlx::query("UPDATE conversion_attempts SET status=$1,finished_at=$2,error_code=$3 WHERE namespace=$4 AND id=$5 AND status='pending'").bind(status).bind(now()).bind(error).bind(&self.namespace).bind(id).execute(&mut *tx).await.map_err(db_error)?;
        }
        if n != 0 {
            advance_schedule(&mut tx, &self.namespace, id).await?;
        }
        tx.commit().await.map_err(db_error)?;
        self.job(id).await
    }
    pub async fn cancel_job(&self, id: &str) -> Result<Job> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let n = sqlx::query("UPDATE api_jobs SET status='cancelled',finished_at=$1,error_code='cancelled' WHERE namespace=$2 AND id=$3 AND status='queued'").bind(now()).bind(&self.namespace).bind(id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
        if n != 0 {
            sqlx::query("UPDATE conversion_attempts SET status='cancelled',finished_at=$1,error_code='cancelled' WHERE namespace=$2 AND id=$3 AND status='pending'").bind(now()).bind(&self.namespace).bind(id).execute(&mut *tx).await.map_err(db_error)?;
        }
        if n != 0 {
            advance_schedule(&mut tx, &self.namespace, id).await?;
        }
        tx.commit().await.map_err(db_error)?;
        self.job(id).await
    }
    pub async fn schedules(&self) -> Result<Vec<Schedule>> {
        let rows = sqlx::query("SELECT source_id,enabled,interval_secs,next_due,status,error_code,fingerprint FROM api_schedules WHERE namespace=$1 ORDER BY source_id").bind(&self.namespace).fetch_all(&self.pool).await.map_err(db_error)?;
        rows.into_iter()
            .map(|r| {
                let interval: i64 = r.try_get("interval_secs").map_err(db_error)?;
                Ok(Schedule {
                    source_id: r.try_get("source_id").map_err(db_error)?,
                    enabled: r.try_get::<i32, _>("enabled").map_err(db_error)? != 0,
                    interval_secs: u64::try_from(interval).map_err(|_| corrupt())?,
                    next_due: r.try_get("next_due").map_err(db_error)?,
                    status: r.try_get("status").map_err(db_error)?,
                    error_code: r.try_get("error_code").map_err(db_error)?,
                    fingerprint: r.try_get("fingerprint").map_err(db_error)?,
                })
            })
            .collect()
    }
    pub async fn set_schedule(
        &self,
        source_id: &str,
        enabled: bool,
        interval_secs: u64,
        fingerprint: &str,
    ) -> Result<()> {
        let interval = i64::try_from(interval_secs)
            .map_err(|_| LoadError::new("schedule_invalid", "invalid schedule interval"))?;
        if interval == 0 {
            return Err(LoadError::new(
                "schedule_invalid",
                "invalid schedule interval",
            ));
        }
        sqlx::query("INSERT INTO api_schedules(namespace,source_id,enabled,interval_secs,next_due,status,fingerprint) VALUES($1,$2,$3,$4,$5,'ready',$6) ON CONFLICT(namespace,source_id) DO UPDATE SET enabled=$3,interval_secs=$4,next_due=$5,status='ready',error_code=NULL,fingerprint=$6").bind(&self.namespace).bind(source_id).bind(i32::from(enabled)).bind(interval).bind(chrono::Utc::now().timestamp()).bind(fingerprint).execute(&self.pool).await.map_err(db_error)?;
        Ok(())
    }
    pub async fn enqueue_due_schedules(&self, workspace_cap: usize) -> Result<Vec<Job>> {
        self.enqueue_due_schedules_bounded(workspace_cap, usize::MAX)
            .await
    }
    pub async fn enqueue_due_schedules_bounded(
        &self,
        workspace_cap: usize,
        max_new: usize,
    ) -> Result<Vec<Job>> {
        let mut result = Vec::new();
        for schedule in self.schedules().await? {
            if result.len() >= max_new {
                break;
            }
            if !schedule.enabled || schedule.next_due > chrono::Utc::now().timestamp() {
                continue;
            }
            let mut tx = self.pool.begin().await.map_err(db_error)?;
            let command = JobCommand::FetchSource {
                source_id: schedule.source_id.clone(),
                fingerprint: schedule.fingerprint.clone(),
            };
            let serialized = serde_json::to_string(&command).map_err(|_| corrupt())?;
            let active:i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_jobs WHERE namespace=$1 AND command=$2 AND status IN ('queued','running')").bind(&self.namespace).bind(serialized).fetch_one(&mut *tx).await.map_err(db_error)?;
            let count:i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_jobs WHERE namespace=$1 AND status IN ('queued','running')").bind(&self.namespace).fetch_one(&mut *tx).await.map_err(db_error)?;
            if active == 0 && count >= i64::try_from(workspace_cap).unwrap_or(i64::MAX) {
                tx.rollback().await.map_err(db_error)?;
                continue;
            }
            let mut id = None;
            if active == 0 {
                let next = uuid::Uuid::new_v4().to_string();
                insert_job(&mut tx, &self.namespace, &next, &command, None).await?;
                id = Some(next);
            }
            sqlx::query("UPDATE api_schedules SET next_due=$1 WHERE namespace=$2 AND source_id=$3 AND enabled=1 AND next_due=$4").bind(chrono::Utc::now().timestamp().saturating_add(i64::try_from(schedule.interval_secs).unwrap_or(i64::MAX))).bind(&self.namespace).bind(&schedule.source_id).bind(schedule.next_due).execute(&mut *tx).await.map_err(db_error)?;
            tx.commit().await.map_err(db_error)?;
            if let Some(id) = id {
                result.push(self.job(&id).await?);
            }
        }
        Ok(result)
    }
}
