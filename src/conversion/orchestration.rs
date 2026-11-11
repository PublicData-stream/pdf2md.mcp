//! Trusted operator orchestration; pending records are the durable source of work.
use super::{ConversionAttempt, ConversionLimits};
use crate::{error::Result, storage::Store};
use futures_util::{StreamExt, stream};
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// Run pending jobs without holding a database transaction during parsing.
/// Acquisition continues independently; storage ownership stays with this Store.
pub async fn dispatch<F: Fn(&ConversionAttempt) + Sync>(
    store: &Store,
    limits: &ConversionLimits,
    worker: &Path,
    cancel: &CancellationToken,
    emit: F,
) -> Result<()> {
    limits.validate()?;
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        let pending = store.pending_conversions().await?;
        if pending.is_empty() {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
            }
            continue;
        }
        let mut jobs = stream::iter(
            pending
                .iter()
                .map(|attempt| store.process_conversion(&attempt.id, limits, worker, cancel)),
        )
        .buffer_unordered(limits.concurrency);
        let mut failure = None;
        while let Some(result) = jobs.next().await {
            match result {
                Ok(attempt) => emit(&attempt),
                Err(error) if error.code == "cancelled" && cancel.is_cancelled() => {}
                Err(error) => {
                    cancel.cancel();
                    failure.get_or_insert(error);
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
    }
}
