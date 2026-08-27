//! The single consumer that aggregates and persists telemetry drains.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use ironclaw_telemetry_contracts::observation::{
    CanonicalTenantId as TenantId, CollectorInstanceId, TelemetryObservation,
};
use tokio::{select, sync::mpsc};
use tokio_util::sync::CancellationToken;

use crate::{
    CollectorCoverage, TelemetryBatch, TelemetryRepository, aggregate_batch,
    buffered_recorder::{DiagnosticsState, TelemetryClock, classify_repository_error},
    floor_utc_hour,
};

pub(crate) struct WorkerConfig {
    pub(crate) max_batch_size: usize,
    pub(crate) max_wait: Duration,
    pub(crate) collector_instance_id: Option<CollectorInstanceId>,
}

#[derive(Debug)]
struct CoverageAccumulator {
    tenant_id: TenantId,
    window_start: DateTime<Utc>,
    accepted_observation_count: u64,
    queue_full_drop_count: u64,
    closed_drop_count: u64,
    invalid_drop_count: u64,
    write_failed_observation_count: u64,
    first_observed_at: DateTime<Utc>,
    last_observed_at: DateTime<Utc>,
}

impl CoverageAccumulator {
    fn from_observation(observation: &TelemetryObservation) -> Self {
        let occurred_at = observation.occurred_at();
        Self {
            tenant_id: observation.tenant_id().clone(),
            window_start: floor_utc_hour(occurred_at),
            accepted_observation_count: 1,
            queue_full_drop_count: 0,
            closed_drop_count: 0,
            invalid_drop_count: 0,
            write_failed_observation_count: 0,
            first_observed_at: occurred_at,
            last_observed_at: occurred_at,
        }
    }

    fn add_observation(&mut self, observation: &TelemetryObservation) -> Result<(), ()> {
        self.accepted_observation_count =
            self.accepted_observation_count.checked_add(1).ok_or(())?;
        self.first_observed_at = self.first_observed_at.min(observation.occurred_at());
        self.last_observed_at = self.last_observed_at.max(observation.occurred_at());
        Ok(())
    }

    fn add_invalid(&mut self, count: u64) -> Result<(), ()> {
        self.invalid_drop_count = self.invalid_drop_count.checked_add(count).ok_or(())?;
        Ok(())
    }

    fn add_write_failed(&mut self, count: u64) -> Result<(), ()> {
        self.write_failed_observation_count = self
            .write_failed_observation_count
            .checked_add(count)
            .ok_or(())?;
        Ok(())
    }

    fn to_record(
        &self,
        collector_instance_id: &CollectorInstanceId,
    ) -> Result<CollectorCoverage, crate::records::RecordError> {
        CollectorCoverage::new(
            self.tenant_id.clone(),
            self.window_start,
            collector_instance_id.clone(),
            self.accepted_observation_count,
            self.queue_full_drop_count,
            self.closed_drop_count,
            self.invalid_drop_count,
            self.write_failed_observation_count,
            self.first_observed_at,
            self.last_observed_at,
        )
    }
}

pub(crate) async fn run(
    config: WorkerConfig,
    mut receiver: mpsc::Receiver<TelemetryObservation>,
    repository: Arc<dyn TelemetryRepository>,
    clock: Arc<dyn TelemetryClock>,
    diagnostics: Arc<DiagnosticsState>,
    cancellation: CancellationToken,
) {
    let mut pending_coverage = BTreeMap::<(TenantId, DateTime<Utc>), CoverageAccumulator>::new();
    let mut shutting_down = false;
    loop {
        let Some(first) = receive_first(&mut receiver, &cancellation, shutting_down).await else {
            break;
        };
        let mut observations = vec![first];
        if !shutting_down {
            let deadline = tokio::time::sleep(config.max_wait);
            tokio::pin!(deadline);
            while observations.len() < config.max_batch_size {
                select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        shutting_down = true;
                        break;
                    }
                    _ = &mut deadline => break,
                    next = receiver.recv() => match next {
                        Some(observation) => observations.push(observation),
                        None => {
                            shutting_down = true;
                            break;
                        }
                    },
                }
            }
        } else {
            while observations.len() < config.max_batch_size {
                match receiver.try_recv() {
                    Ok(observation) => observations.push(observation),
                    Err(
                        mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected,
                    ) => break,
                }
            }
        }

        flush(
            &observations,
            &mut pending_coverage,
            config.collector_instance_id.as_ref(),
            repository.as_ref(),
            clock.as_ref(),
            diagnostics.as_ref(),
        )
        .await;

        if cancellation.is_cancelled() {
            shutting_down = true;
        }
        if shutting_down && receiver.is_empty() {
            break;
        }
    }
}

async fn receive_first(
    receiver: &mut mpsc::Receiver<TelemetryObservation>,
    cancellation: &CancellationToken,
    shutting_down: bool,
) -> Option<TelemetryObservation> {
    if shutting_down {
        return receiver.try_recv().ok();
    }
    select! {
        biased;
        _ = cancellation.cancelled() => receiver.try_recv().ok(),
        observation = receiver.recv() => observation,
    }
}

async fn flush(
    observations: &[TelemetryObservation],
    pending_coverage: &mut BTreeMap<(TenantId, DateTime<Utc>), CoverageAccumulator>,
    collector_instance_id: Option<&CollectorInstanceId>,
    repository: &dyn TelemetryRepository,
    clock: &dyn TelemetryClock,
    diagnostics: &DiagnosticsState,
) {
    for observation in observations {
        let key = (
            observation.tenant_id().clone(),
            floor_utc_hour(observation.occurred_at()),
        );
        if let Some(accumulator) = pending_coverage.get_mut(&key) {
            if accumulator.add_observation(observation).is_err() {
                diagnostics.add_invalid(observations.len());
                return;
            }
        } else {
            pending_coverage.insert(key, CoverageAccumulator::from_observation(observation));
        }
    }

    let aggregate = aggregate_batch(observations);
    let mut batch = match aggregate {
        Ok(batch) => batch,
        Err(_) => {
            diagnostics.add_invalid(observations.len());
            for key in observations.iter().map(|observation| {
                (
                    observation.tenant_id().clone(),
                    floor_utc_hour(observation.occurred_at()),
                )
            }) {
                if let Some(accumulator) = pending_coverage.get_mut(&key)
                    && accumulator.add_invalid(1).is_err()
                {
                    return;
                }
            }
            return;
        }
    };

    if let Some(collector_instance_id) = collector_instance_id {
        let mut coverage = Vec::with_capacity(pending_coverage.len());
        for accumulator in pending_coverage.values() {
            match accumulator.to_record(collector_instance_id) {
                Ok(row) => coverage.push(row),
                Err(_) => {
                    diagnostics.add_invalid(observations.len());
                    return;
                }
            }
        }
        batch = match TelemetryBatch::new(
            batch.activity().to_vec(),
            batch.model_usage().to_vec(),
            batch.run_failures().to_vec(),
            batch.automation_usage().to_vec(),
            batch.lifecycle_events().to_vec(),
            coverage,
        ) {
            Ok(batch) => batch,
            Err(_) => {
                diagnostics.add_invalid(observations.len());
                return;
            }
        };
    }

    let started = clock.now();
    if let Err(error) = repository.upsert_batch(&batch).await {
        let class = classify_repository_error(&error);
        diagnostics.record_repository_failure(class);
        diagnostics.add_write_failed(observations.len());
        for key in observations.iter().map(|observation| {
            (
                observation.tenant_id().clone(),
                floor_utc_hour(observation.occurred_at()),
            )
        }) {
            if let Some(accumulator) = pending_coverage.get_mut(&key)
                && accumulator.add_write_failed(1).is_err()
            {
                return;
            }
        }
        return;
    }
    let elapsed_ms = clock
        .now()
        .signed_duration_since(started)
        .num_milliseconds();
    diagnostics.record_flush(observations.len(), elapsed_ms.max(0) as u64);
    pending_coverage.clear();
}
