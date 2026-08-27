use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{DateTime, TimeZone, Utc};
use ironclaw_host_api::ids::{TenantId, UserId};
use ironclaw_telemetry::{
    BufferedRecorderConfig, BufferedTelemetryRecorder, CollectorCoverage, HourlyAutomationUsage,
    HourlyModelUsage, HourlyRunFailure, HourlyUserActivity, LifecycleEvent, RecordOutcome,
    TelemetryBatch, TelemetryClock, TelemetryPage, TelemetryRepository, TelemetryRepositoryError,
    TelemetryScanPageRequest, TelemetryWriteFailureClass,
};
use ironclaw_telemetry_contracts::observation::{
    AutomationKind, AutomationSettledObservation, EffectiveModelId, ModelCallCompletedObservation,
    ModelUsage, ObservationContext, OriginKind, ProviderId, RunOutcome, RunSettledObservation,
    TelemetryObservation,
};

const START: i64 = 1_756_200_000;

#[derive(Clone)]
struct FixedClock {
    now: Arc<Mutex<DateTime<Utc>>>,
}

impl FixedClock {
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            now: Arc::new(Mutex::new(now)),
        }
    }
}

impl TelemetryClock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        *self.now.lock().expect("clock lock")
    }
}

#[derive(Default)]
struct FakeRepository {
    state: Mutex<FakeRepositoryState>,
}

#[derive(Default)]
struct FakeRepositoryState {
    batches: Vec<TelemetryBatch>,
    failures_remaining: usize,
    active_writes: usize,
    max_active_writes: usize,
    write_started: Option<tokio::sync::oneshot::Sender<()>>,
    release_write: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl FakeRepository {
    fn batches(&self) -> Vec<TelemetryBatch> {
        self.state.lock().expect("repository lock").batches.clone()
    }

    fn fail_next(&self) {
        self.state
            .lock()
            .expect("repository lock")
            .failures_remaining += 1;
    }

    fn max_active_writes(&self) -> usize {
        self.state
            .lock()
            .expect("repository lock")
            .max_active_writes
    }

    fn block_next_write(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let mut state = self.state.lock().expect("repository lock");
        state.write_started = Some(started_tx);
        state.release_write = Some(release_rx);
        (started_rx, release_tx)
    }
}

#[async_trait::async_trait]
impl TelemetryRepository for FakeRepository {
    async fn migrate(&self) -> Result<(), TelemetryRepositoryError> {
        Ok(())
    }

    async fn upsert_batch(&self, batch: &TelemetryBatch) -> Result<(), TelemetryRepositoryError> {
        let (started, release, fail) = {
            let mut state = self.state.lock().expect("repository lock");
            state.active_writes += 1;
            state.max_active_writes = state.max_active_writes.max(state.active_writes);
            (
                state.write_started.take(),
                state.release_write.take(),
                if state.failures_remaining > 0 {
                    state.failures_remaining -= 1;
                    true
                } else {
                    false
                },
            )
        };
        if let Some(started) = started {
            let _ = started.send(());
        }
        if let Some(release) = release {
            let _ = release.await;
        }
        {
            let mut state = self.state.lock().expect("repository lock");
            state.active_writes -= 1;
            if !fail {
                state.batches.push(batch.clone());
            }
        }
        if fail {
            Err(TelemetryRepositoryError::StorageOperation {
                operation: "fake batch write",
                source: "injected failure".to_owned().into(),
            })
        } else {
            Ok(())
        }
    }

    async fn scan_activity_page(
        &self,
        _: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyUserActivity>, TelemetryRepositoryError> {
        Err(fake_scan_error())
    }

    async fn scan_model_page(
        &self,
        _: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyModelUsage>, TelemetryRepositoryError> {
        Err(fake_scan_error())
    }

    async fn scan_failure_page(
        &self,
        _: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyRunFailure>, TelemetryRepositoryError> {
        Err(fake_scan_error())
    }

    async fn scan_automation_page(
        &self,
        _: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyAutomationUsage>, TelemetryRepositoryError> {
        Err(fake_scan_error())
    }

    async fn scan_lifecycle_page(
        &self,
        _: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<LifecycleEvent>, TelemetryRepositoryError> {
        Err(fake_scan_error())
    }

    async fn scan_coverage_page(
        &self,
        _: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<CollectorCoverage>, TelemetryRepositoryError> {
        Err(fake_scan_error())
    }
}

fn fake_scan_error() -> TelemetryRepositoryError {
    TelemetryRepositoryError::StorageOperation {
        operation: "fake scan",
        source: "not used by recorder contract".to_owned().into(),
    }
}

fn timestamp(offset_seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(START + offset_seconds, 0)
        .single()
        .expect("valid timestamp")
}

fn context(offset_seconds: i64) -> ObservationContext {
    ObservationContext::new(
        TenantId::new("tenant-a").expect("tenant"),
        UserId::new("user-a").expect("user"),
        timestamp(offset_seconds),
    )
}

fn completed_run(offset_seconds: i64) -> TelemetryObservation {
    TelemetryObservation::RunSettled(
        RunSettledObservation::new(
            context(offset_seconds),
            OriginKind::Human,
            RunOutcome::Completed,
            25,
            Some(1),
            None,
        )
        .expect("run"),
    )
}

fn model_call(offset_seconds: i64) -> TelemetryObservation {
    TelemetryObservation::ModelCallCompleted(
        ModelCallCompletedObservation::new(
            context(offset_seconds),
            ProviderId::new("provider-a").expect("provider"),
            EffectiveModelId::new("model-a").expect("model"),
            Some(ModelUsage::new(3, 4, 5, 6)),
        )
        .expect("model call"),
    )
}

fn automation(offset_seconds: i64) -> TelemetryObservation {
    TelemetryObservation::AutomationSettled(
        AutomationSettledObservation::new(
            context(offset_seconds),
            ironclaw_telemetry_contracts::observation::AutomationId::new("automation-a")
                .expect("automation"),
            AutomationKind::Cron,
            RunOutcome::Completed,
        )
        .expect("automation"),
    )
}

fn config() -> BufferedRecorderConfig {
    BufferedRecorderConfig::default()
        .with_queue_capacity(16)
        .with_max_batch_size(512)
        .with_max_wait(Duration::from_secs(1))
        .with_shutdown_timeout(Duration::from_secs(5))
}

async fn wait_for_batches(repository: &FakeRepository, count: usize) {
    for _ in 0..100 {
        if repository.batches().len() >= count {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for {count} repository batches");
}

#[tokio::test(start_paused = true)]
async fn try_record_is_synchronous_and_queue_pressure_is_typed() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn(
        BufferedRecorderConfig::default().with_queue_capacity(1),
        repository.clone(),
        clock,
    );
    let first = recorder.try_record(completed_run(0));
    assert_eq!(first, RecordOutcome::Accepted);
    let second = recorder.try_record(completed_run(1));
    assert_eq!(second, RecordOutcome::DroppedQueueFull);
    assert_eq!(lifecycle.diagnostics().queue_full_drop_count(), 1);
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn five_hundred_twelve_items_trigger_one_aggregate_drain() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn(
        config().with_queue_capacity(600),
        repository.clone(),
        clock,
    );
    for offset in 0..512 {
        assert_eq!(
            recorder.try_record(completed_run(offset)),
            RecordOutcome::Accepted
        );
    }
    wait_for_batches(&repository, 1).await;
    assert_eq!(repository.batches()[0].activity()[0].run_count(), 512);
    assert_eq!(lifecycle.diagnostics().flushed_batch_count(), 1);
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn one_second_of_paused_time_triggers_a_nonempty_drain() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn(config(), repository.clone(), clock);
    assert_eq!(recorder.try_record(model_call(0)), RecordOutcome::Accepted);
    assert!(repository.batches().is_empty());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    wait_for_batches(&repository, 1).await;
    assert_eq!(
        repository.batches()[0].model_usage()[0].inference_count(),
        1
    );
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn repository_failure_drops_only_that_drain_and_later_drain_continues() {
    let repository = Arc::new(FakeRepository::default());
    repository.fail_next();
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn(config(), repository.clone(), clock);
    assert_eq!(
        recorder.try_record(completed_run(0)),
        RecordOutcome::Accepted
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..100 {
        if lifecycle.diagnostics().repository_failure_count() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(lifecycle.diagnostics().repository_failure_count(), 1);
    assert_eq!(
        lifecycle.diagnostics().last_failure_class(),
        Some(TelemetryWriteFailureClass::StorageOperation)
    );
    assert_eq!(recorder.try_record(model_call(2)), RecordOutcome::Accepted);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    wait_for_batches(&repository, 1).await;
    assert_eq!(
        repository.batches()[0].model_usage()[0].inference_count(),
        1
    );
    assert_eq!(lifecycle.diagnostics().write_failed_observation_count(), 1);
    let batches = repository.batches();
    let coverage = batches[0].collector_coverage();
    assert_eq!(coverage.len(), 1);
    assert_eq!(coverage[0].accepted_observation_count(), 2);
    assert_eq!(coverage[0].write_failed_observation_count(), 1);
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn drains_never_overlap_and_coverage_counters_carry_forward() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn(
        config().with_queue_capacity(4),
        repository.clone(),
        clock,
    );
    assert_eq!(
        recorder.try_record(completed_run(0)),
        RecordOutcome::Accepted
    );
    let (started, release) = repository.block_next_write();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    started.await.expect("write started");
    assert_eq!(recorder.try_record(model_call(2)), RecordOutcome::Accepted);
    assert_eq!(recorder.try_record(automation(3)), RecordOutcome::Accepted);
    let _ = release.send(());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    wait_for_batches(&repository, 2).await;
    assert_eq!(repository.max_active_writes(), 1);
    assert!(lifecycle.diagnostics().accepted_observation_count() >= 3);
    assert_eq!(
        repository.batches()[0].collector_coverage()[0].accepted_observation_count(),
        1
    );
    assert_eq!(
        repository.batches()[1].collector_coverage()[0].accepted_observation_count(),
        2
    );
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn shutdown_closes_intake_and_flushes_tail_within_budget() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn(config(), repository.clone(), clock);
    assert_eq!(
        recorder.try_record(completed_run(0)),
        RecordOutcome::Accepted
    );
    lifecycle.shutdown().await;
    assert_eq!(
        recorder.try_record(completed_run(1)),
        RecordOutcome::DroppedClosed
    );
    assert_eq!(repository.batches().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn shutdown_aborts_a_stalled_write_after_the_five_second_budget() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn(
        config().with_shutdown_timeout(Duration::from_secs(5)),
        repository.clone(),
        clock,
    );
    assert_eq!(
        recorder.try_record(completed_run(0)),
        RecordOutcome::Accepted
    );
    let (started, _release) = repository.block_next_write();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    started.await.expect("write started");
    let shutdown = lifecycle.shutdown();
    tokio::pin!(shutdown);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    shutdown.await;
    assert_eq!(
        recorder.try_record(completed_run(1)),
        RecordOutcome::DroppedClosed
    );
}

#[tokio::test(start_paused = true)]
async fn a_new_recorder_after_shutdown_has_an_independent_worker() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (old_recorder, old_lifecycle) =
        BufferedTelemetryRecorder::spawn(config(), repository.clone(), clock.clone());
    drop(old_recorder);
    drop(old_lifecycle);

    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn(config(), repository.clone(), clock);
    assert_eq!(recorder.try_record(model_call(0)), RecordOutcome::Accepted);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    wait_for_batches(&repository, 1).await;
    assert_eq!(
        repository.batches()[0].model_usage()[0].inference_count(),
        1
    );
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn invalid_aggregate_is_counted_without_a_repository_write() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn(config(), repository.clone(), clock);
    let huge = RunSettledObservation::new(
        context(0),
        OriginKind::Human,
        RunOutcome::Completed,
        i64::MAX as u64,
        None,
        None,
    )
    .expect("maximum duration");
    assert_eq!(
        recorder.try_record(TelemetryObservation::RunSettled(huge.clone())),
        RecordOutcome::Accepted
    );
    assert_eq!(
        recorder.try_record(TelemetryObservation::RunSettled(huge)),
        RecordOutcome::Accepted
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..100 {
        if lifecycle.diagnostics().invalid_observation_count() == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(lifecycle.diagnostics().invalid_observation_count(), 2);
    assert!(repository.batches().is_empty());
    lifecycle.shutdown().await;
}
