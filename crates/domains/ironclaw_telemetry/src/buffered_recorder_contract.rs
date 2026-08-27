use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::repository::{ScopedTelemetryBatch, TelemetryBatchSink};
use crate::{
    BatchApplyReport, BufferedRecorderConfig, BufferedTelemetryRecorder, RecordError,
    RecordOutcome, TelemetryBatch, TelemetryClock, TelemetryRepositoryError,
    TelemetryWriteFailureClass,
};
use chrono::{DateTime, TimeZone, Utc};
use ironclaw_host_api::{
    ids::{InvocationId, TenantId, UserId},
    resource::ResourceScope,
};
use ironclaw_telemetry_contracts::observation::{
    AutomationKind, AutomationSettledObservation, EffectiveModelId, LifecycleEventId,
    LifecycleEventKind, LifecycleSubjectKind, LifecycleTransitionObservation,
    ModelCallCompletedObservation, ModelUsage, ObservationContext, OriginKind, ProviderId,
    RunOutcome, RunSettledObservation, TelemetryObservation,
};
use ironclaw_telemetry_contracts::recorder::TelemetryRecorder;

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
    scopes: Vec<ironclaw_host_api::resource::ResourceScope>,
    failures_remaining: usize,
    always_fail: bool,
    commit_then_error: bool,
    next_error: Option<TelemetryRepositoryError>,
    fail_on_write: Option<usize>,
    write_count: usize,
    next_report: Option<BatchApplyReport>,
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

    fn set_fail_all(&self, fail: bool) {
        self.state.lock().expect("repository lock").always_fail = fail;
    }

    fn fail_next_with(&self, error: TelemetryRepositoryError) {
        self.state.lock().expect("repository lock").next_error = Some(error);
    }

    fn fail_on_write(&self, write_number: usize) {
        self.state.lock().expect("repository lock").fail_on_write = Some(write_number);
    }

    fn return_next_report(&self, report: BatchApplyReport) {
        self.state.lock().expect("repository lock").next_report = Some(report);
    }

    fn scopes(&self) -> Vec<ironclaw_host_api::resource::ResourceScope> {
        self.state.lock().expect("repository lock").scopes.clone()
    }

    fn fail_next_after_commit(&self) {
        let mut state = self.state.lock().expect("repository lock");
        state.failures_remaining += 1;
        state.commit_then_error = true;
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
impl TelemetryBatchSink for FakeRepository {
    async fn apply_batch(
        &self,
        batch: ScopedTelemetryBatch,
    ) -> Result<BatchApplyReport, TelemetryRepositoryError> {
        let (started, release, fail, committed_before_error, injected_error, report) = {
            let mut state = self.state.lock().expect("repository lock");
            state.write_count += 1;
            state.active_writes += 1;
            state.max_active_writes = state.max_active_writes.max(state.active_writes);
            let fail = state.next_error.is_some()
                || if state.always_fail {
                    true
                } else if state.failures_remaining > 0 {
                    state.failures_remaining -= 1;
                    true
                } else {
                    state.fail_on_write == Some(state.write_count)
                };
            let committed_before_error = fail && state.commit_then_error;
            if committed_before_error {
                state.commit_then_error = false;
            }
            (
                state.write_started.take(),
                state.release_write.take(),
                fail,
                committed_before_error,
                state.next_error.take(),
                state.next_report.take(),
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
            if !fail || committed_before_error {
                state.scopes.push(batch.scope().clone());
                state.batches.push(batch.batch().clone());
            }
        }
        if fail {
            Err(
                injected_error.unwrap_or(TelemetryRepositoryError::StorageOperation {
                    operation: "fake batch write",
                    source: "injected failure".to_owned().into(),
                }),
            )
        } else {
            Ok(report.unwrap_or_else(|| BatchApplyReport::complete(batch.batch().record_count())))
        }
    }
}

fn timestamp(offset_seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(START + offset_seconds, 0)
        .single()
        .expect("valid timestamp")
}

fn context(offset_seconds: i64) -> ObservationContext {
    ObservationContext::new(timestamp(offset_seconds))
}

fn scope() -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new("tenant-a").expect("tenant"),
        user_id: UserId::new("user-a").expect("user"),
        agent_id: None,
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

fn scope_for(index: u64) -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new(format!("tenant-{index}")).expect("tenant"),
        user_id: UserId::new(format!("user-{index}")).expect("user"),
        agent_id: None,
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
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

fn completed_run_for_tenant_hour(index: u64) -> (ResourceScope, TelemetryObservation) {
    let occurred_at = timestamp((index as i64) * 3_600);
    (
        scope_for(index),
        TelemetryObservation::RunSettled(
            RunSettledObservation::new(
                ObservationContext::new(occurred_at),
                OriginKind::Human,
                RunOutcome::Completed,
                1,
                None,
                None,
            )
            .expect("run"),
        ),
    )
}

trait TestRecorderCall {
    fn try_record(&self, observation: TelemetryObservation) -> RecordOutcome;
    fn try_record_scoped(
        &self,
        scope: ResourceScope,
        observation: TelemetryObservation,
    ) -> RecordOutcome;
}

impl<T: TelemetryRecorder + ?Sized> TestRecorderCall for Arc<T> {
    fn try_record(&self, observation: TelemetryObservation) -> RecordOutcome {
        self.try_record_scoped(scope(), observation)
    }

    fn try_record_scoped(
        &self,
        scope: ResourceScope,
        observation: TelemetryObservation,
    ) -> RecordOutcome {
        TelemetryRecorder::try_record(self.as_ref(), scope, observation)
    }
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
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn_with_sink(
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
async fn queue_full_drop_is_written_to_tenant_hour_coverage() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn_with_sink(
        config().with_queue_capacity(1),
        repository.clone(),
        clock,
    );
    assert_eq!(
        recorder.try_record(completed_run(0)),
        RecordOutcome::Accepted
    );
    assert_eq!(
        recorder.try_record(completed_run(1)),
        RecordOutcome::DroppedQueueFull
    );
    lifecycle.shutdown().await;
    let batches = repository.batches();
    assert_eq!(batches.len(), 1);
    assert_eq!(
        batches[0].collector_coverage()[0].queue_full_drop_count(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn coverage_only_commit_then_error_retains_a_loss_marker() {
    let repository = Arc::new(FakeRepository::default());
    repository.fail_next_after_commit();
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);

    lifecycle.close_intake();
    assert_eq!(
        recorder.try_record(completed_run(3599)),
        RecordOutcome::DroppedClosed
    );
    for _ in 0..100 {
        if lifecycle.diagnostics().repository_failure_count() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let attempted = repository.batches();
    assert_eq!(attempted.len(), 1);
    assert_eq!(attempted[0].collector_coverage()[0].closed_drop_count(), 1);
    assert_eq!(
        attempted[0].collector_coverage()[0].write_failed_observation_count(),
        0
    );

    lifecycle.shutdown().await;
    let batches = repository.batches();
    assert_eq!(batches.len(), 2);
    let marker = &batches[1].collector_coverage()[0];
    assert_eq!(marker.accepted_observation_count(), 0);
    assert_eq!(marker.queue_full_drop_count(), 0);
    assert_eq!(marker.closed_drop_count(), 0);
    assert_eq!(marker.invalid_drop_count(), 0);
    assert_eq!(marker.write_failed_observation_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn repeated_marker_failure_retains_a_fresh_marker_for_retry() {
    let repository = Arc::new(FakeRepository::default());
    repository.fail_next_after_commit();
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);

    lifecycle.close_intake();
    assert_eq!(
        recorder.try_record(completed_run(3599)),
        RecordOutcome::DroppedClosed
    );
    for _ in 0..100 {
        if lifecycle.diagnostics().repository_failure_count() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }

    repository.fail_next_after_commit();
    lifecycle.close_intake();
    for _ in 0..100 {
        if lifecycle.diagnostics().repository_failure_count() == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let failed_markers = repository.batches();
    assert_eq!(failed_markers.len(), 2);
    let first_attempt = &failed_markers[0].collector_coverage()[0];
    assert_eq!(first_attempt.accepted_observation_count(), 0);
    assert_eq!(first_attempt.queue_full_drop_count(), 0);
    assert_eq!(first_attempt.closed_drop_count(), 1);
    assert_eq!(first_attempt.invalid_drop_count(), 0);
    assert_eq!(first_attempt.write_failed_observation_count(), 0);
    let second_attempt = &failed_markers[1].collector_coverage()[0];
    assert_eq!(second_attempt.accepted_observation_count(), 0);
    assert_eq!(second_attempt.queue_full_drop_count(), 0);
    assert_eq!(second_attempt.closed_drop_count(), 0);
    assert_eq!(second_attempt.invalid_drop_count(), 0);
    assert_eq!(second_attempt.write_failed_observation_count(), 1);

    lifecycle.shutdown().await;
    assert_eq!(repository.batches().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn closed_drop_is_written_to_tenant_hour_coverage() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
    lifecycle.close_intake();
    assert_eq!(
        recorder.try_record(completed_run(0)),
        RecordOutcome::DroppedClosed
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    wait_for_batches(&repository, 1).await;
    assert_eq!(
        repository.batches()[0].collector_coverage()[0].closed_drop_count(),
        1
    );
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn five_hundred_twelve_items_trigger_one_aggregate_drain() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn_with_sink(
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
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
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
async fn continuous_queue_drop_notifications_do_not_starve_the_batch_deadline() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn_with_sink(
        config().with_queue_capacity(1),
        repository.clone(),
        clock,
    );
    assert_eq!(
        recorder.try_record(completed_run(0)),
        RecordOutcome::Accepted
    );
    let started = Arc::new(std::sync::Barrier::new(2));
    let stop = Arc::new(AtomicBool::new(false));
    let flood_recorder = Arc::clone(&recorder);
    let flood_started = Arc::clone(&started);
    let flood_stop = Arc::clone(&stop);
    let flood = std::thread::spawn(move || {
        flood_started.wait();
        while !flood_stop.load(Ordering::Acquire) {
            let _ = flood_recorder.try_record(completed_run(1));
            std::thread::yield_now();
        }
    });
    started.wait();
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    let flushed_at_deadline = !repository.batches().is_empty();
    stop.store(true, Ordering::Release);
    flood.join().expect("flood thread");
    assert!(flushed_at_deadline);
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn repository_failure_drops_only_that_drain_and_later_drain_continues() {
    let repository = Arc::new(FakeRepository::default());
    repository.fail_next();
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
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
    assert_eq!(coverage[0].accepted_observation_count(), 1);
    assert_eq!(coverage[0].write_failed_observation_count(), 1);
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn write_failure_coverage_counts_each_observation_in_a_tenant_hour() {
    let repository = Arc::new(FakeRepository::default());
    repository.fail_next();
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);

    assert_eq!(
        recorder.try_record(completed_run(0)),
        RecordOutcome::Accepted
    );
    assert_eq!(
        recorder.try_record(completed_run(1)),
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

    assert_eq!(
        recorder.try_record(completed_run(2)),
        RecordOutcome::Accepted
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..100 {
        if lifecycle.diagnostics().flushed_batch_count() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(lifecycle.diagnostics().flushed_batch_count(), 1);

    let batches = repository.batches();
    let coverage = &batches[0].collector_coverage()[0];
    assert_eq!(coverage.accepted_observation_count(), 1);
    assert_eq!(coverage.write_failed_observation_count(), 2);
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn partial_report_is_not_counted_as_a_successful_flush() {
    let repository = Arc::new(FakeRepository::default());
    repository.return_next_report(BatchApplyReport::from_counts(0, 1));
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);

    assert_eq!(
        recorder.try_record(completed_run(0)),
        RecordOutcome::Accepted
    );
    assert_eq!(
        recorder.try_record(completed_run(1)),
        RecordOutcome::Accepted
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..100 {
        if lifecycle.diagnostics().partial_batch_failure_count() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(lifecycle.diagnostics().partial_batch_failure_count(), 1);
    assert_eq!(lifecycle.diagnostics().flushed_batch_count(), 0);

    assert_eq!(
        recorder.try_record(completed_run(2)),
        RecordOutcome::Accepted
    );
    let diagnostics = lifecycle.shutdown().await;
    assert_eq!(diagnostics.flushed_batch_count(), 1);
    let batches = repository.batches();
    assert_eq!(batches.len(), 2);
    assert_eq!(
        batches[1].collector_coverage()[0].write_failed_observation_count(),
        2
    );
}

#[tokio::test(start_paused = true)]
async fn tenant_fan_out_stops_after_failure_and_preserves_queued_scopes() {
    let repository = Arc::new(FakeRepository::default());
    repository.fail_on_write(2);
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
    let (tenant_a_scope, tenant_a_observation) = completed_run_for_tenant_hour(0);
    let (tenant_b_scope, tenant_b_observation) = completed_run_for_tenant_hour(1);

    assert_eq!(
        recorder.try_record_scoped(tenant_a_scope.clone(), tenant_a_observation),
        RecordOutcome::Accepted
    );
    assert_eq!(
        recorder.try_record_scoped(tenant_b_scope.clone(), tenant_b_observation),
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
    assert_eq!(repository.scopes().len(), 1);
    assert_eq!(repository.scopes()[0], tenant_a_scope);
    assert_eq!(
        repository.batches()[0].activity()[0].tenant_id().as_str(),
        "tenant-0"
    );

    assert_eq!(
        recorder.try_record_scoped(tenant_b_scope.clone(), completed_run(2)),
        RecordOutcome::Accepted
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    lifecycle.close_intake();
    let diagnostics = lifecycle.shutdown().await;
    assert_eq!(
        diagnostics.flushed_batch_count(),
        1,
        "scopes={:?}",
        repository.scopes()
    );
    assert_eq!(
        repository.scopes().len(),
        2,
        "batches={:?}",
        repository.batches()
    );
    assert_eq!(repository.scopes()[1], tenant_b_scope);
    assert!(
        repository.batches()[1]
            .activity()
            .iter()
            .all(|row| row.tenant_id().as_str() == "tenant-1")
    );
    assert_eq!(
        repository.batches()[1]
            .collector_coverage()
            .iter()
            .map(|row| row.write_failed_observation_count())
            .sum::<u64>(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn commit_then_error_does_not_replay_attempted_coverage() {
    let repository = Arc::new(FakeRepository::default());
    repository.fail_next_after_commit();
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);

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
    assert_eq!(repository.batches().len(), 1);
    let attempted_batches = repository.batches();
    assert_eq!(
        attempted_batches[0].collector_coverage()[0].accepted_observation_count(),
        1
    );
    assert_eq!(
        attempted_batches[0].collector_coverage()[0].write_failed_observation_count(),
        0
    );

    assert_eq!(
        recorder.try_record(completed_run(1)),
        RecordOutcome::Accepted
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    wait_for_batches(&repository, 2).await;

    let batches = repository.batches();
    let retry_coverage = batches[1].collector_coverage();
    assert_eq!(retry_coverage.len(), 1);
    assert_eq!(retry_coverage[0].accepted_observation_count(), 1);
    assert_eq!(retry_coverage[0].queue_full_drop_count(), 0);
    assert_eq!(retry_coverage[0].closed_drop_count(), 0);
    assert_eq!(retry_coverage[0].invalid_drop_count(), 0);
    assert_eq!(retry_coverage[0].write_failed_observation_count(), 1);
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn pending_coverage_is_bounded_during_an_outage_and_later_drains_continue() {
    const OBSERVATIONS: usize = 8_193;
    let repository = Arc::new(FakeRepository::default());
    repository.set_fail_all(true);
    let (started, release) = repository.block_next_write();
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn_with_sink(
        config().with_queue_capacity(OBSERVATIONS),
        repository.clone(),
        clock,
    );
    let (tenant_scope, tenant_observation) = completed_run_for_tenant_hour(0);
    assert_eq!(
        recorder.try_record_scoped(tenant_scope, tenant_observation),
        RecordOutcome::Accepted
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    started.await.expect("write started");
    for index in 1..OBSERVATIONS {
        let (tenant_scope, tenant_observation) = completed_run_for_tenant_hour(index as u64);
        assert_eq!(
            recorder.try_record_scoped(tenant_scope, tenant_observation),
            RecordOutcome::Accepted
        );
    }
    let _ = release.send(());
    for _ in 0..100 {
        if lifecycle.diagnostics().repository_failure_count() >= 17 {
            break;
        }
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
    }
    let diagnostics = lifecycle.diagnostics();
    assert_eq!(
        diagnostics.accepted_observation_count(),
        OBSERVATIONS as u64
    );
    assert!(
        diagnostics.repository_failure_count() >= 17,
        "diagnostics={diagnostics:?}"
    );
    assert!(diagnostics.coverage_key_overflow_count() > 0);

    repository.set_fail_all(false);
    assert_eq!(
        recorder.try_record(completed_run(0)),
        RecordOutcome::Accepted
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..100 {
        if repository
            .batches()
            .iter()
            .any(|batch| !batch.activity().is_empty())
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        repository
            .batches()
            .iter()
            .any(|batch| !batch.activity().is_empty())
    );
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn drains_never_overlap_and_coverage_counters_carry_forward() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn_with_sink(
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
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
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
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn_with_sink(
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
    tokio::select! {
        biased;
        _ = &mut shutdown => panic!("stalled shutdown completed before its timeout"),
        _ = tokio::time::sleep(Duration::ZERO) => {}
    }
    let shutdown_started = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_secs(5)).await;
    shutdown.await;
    assert!(
        tokio::time::Instant::now().duration_since(shutdown_started) <= Duration::from_secs(5),
        "shutdown elapsed {:?}",
        tokio::time::Instant::now().duration_since(shutdown_started)
    );
    assert_eq!(
        recorder.try_record(completed_run(1)),
        RecordOutcome::DroppedClosed
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_timeout_accounts_for_queued_and_in_flight_observations() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn_with_sink(
        config()
            .with_queue_capacity(4)
            .with_shutdown_timeout(Duration::from_secs(5)),
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
    assert_eq!(
        recorder.try_record(completed_run(2)),
        RecordOutcome::Accepted
    );
    let shutdown = lifecycle.shutdown();
    tokio::pin!(shutdown);
    tokio::select! {
        biased;
        _ = &mut shutdown => panic!("stalled shutdown completed before its timeout"),
        _ = tokio::time::sleep(Duration::ZERO) => {}
    }
    let shutdown_started = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_secs(5)).await;
    let diagnostics = shutdown.await;
    assert!(
        tokio::time::Instant::now().duration_since(shutdown_started) <= Duration::from_secs(5),
        "shutdown elapsed {:?}",
        tokio::time::Instant::now().duration_since(shutdown_started)
    );
    assert_eq!(repository.batches().len(), 0);
    assert_eq!(diagnostics.shutdown_timeout_count(), 1);
    assert_eq!(diagnostics.shutdown_write_loss_count(), 2);
    assert_eq!(diagnostics.shutdown_abandoned_observation_count(), 2);
    assert_eq!(diagnostics.write_failed_observation_count(), 2);
    assert_eq!(
        diagnostics.last_failure_class(),
        Some(TelemetryWriteFailureClass::ShutdownTimeout)
    );
}

#[tokio::test(start_paused = true)]
async fn coverage_attribution_overflow_does_not_hide_global_shutdown_loss_count() {
    const OBSERVATIONS: usize = 8_193;
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn_with_sink(
        config().with_queue_capacity(OBSERVATIONS + 1),
        repository.clone(),
        clock,
    );
    let (started, _release) = repository.block_next_write();
    let (tenant_scope, tenant_observation) = completed_run_for_tenant_hour(0);
    assert_eq!(
        recorder.try_record_scoped(tenant_scope, tenant_observation),
        RecordOutcome::Accepted
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    started.await.expect("write started");
    for index in 1..OBSERVATIONS {
        let (tenant_scope, tenant_observation) = completed_run_for_tenant_hour(index as u64);
        assert_eq!(
            recorder.try_record_scoped(tenant_scope, tenant_observation),
            RecordOutcome::Accepted
        );
    }
    assert_eq!(
        lifecycle.diagnostics().accepted_observation_count(),
        OBSERVATIONS as u64
    );
    assert!(lifecycle.diagnostics().coverage_key_overflow_count() > 0);
    let shutdown = lifecycle.shutdown();
    tokio::pin!(shutdown);
    tokio::select! {
        biased;
        _ = &mut shutdown => panic!("stalled shutdown completed before its timeout"),
        _ = tokio::time::sleep(Duration::ZERO) => {}
    }
    let shutdown_started = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_secs(5)).await;
    let diagnostics = shutdown.await;
    assert!(
        tokio::time::Instant::now().duration_since(shutdown_started) <= Duration::from_secs(5),
        "shutdown elapsed {:?}",
        tokio::time::Instant::now().duration_since(shutdown_started)
    );
    assert_eq!(
        diagnostics.shutdown_abandoned_observation_count(),
        OBSERVATIONS as u64
    );
    assert_eq!(diagnostics.shutdown_write_loss_count(), OBSERVATIONS as u64);
    assert!(diagnostics.coverage_key_overflow_count() > 0);
}

#[tokio::test(start_paused = true)]
async fn invalid_timestamp_is_rejected_synchronously_and_covered() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
    let future = Utc
        .with_ymd_and_hms(10_000, 1, 1, 0, 0, 0)
        .single()
        .expect("chrono supports this bounded test timestamp");
    let observation = TelemetryObservation::RunSettled(
        RunSettledObservation::new(
            ObservationContext::new(future),
            OriginKind::Human,
            RunOutcome::Completed,
            1,
            None,
            None,
        )
        .expect("valid typed observation"),
    );
    assert_eq!(
        recorder.try_record(observation),
        RecordOutcome::DroppedInvalid
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    wait_for_batches(&repository, 1).await;
    let diagnostics = lifecycle.diagnostics();
    assert_eq!(diagnostics.invalid_observation_count(), 1);
    assert_eq!(
        repository.batches()[0].collector_coverage()[0].invalid_drop_count(),
        1
    );
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn close_and_send_are_linearized_without_persisting_closed_observations() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
    let recorder_for_thread = Arc::clone(&recorder);
    let sender = std::thread::spawn(move || recorder_for_thread.try_record(completed_run(2)));
    lifecycle.close_intake();
    let outcome = sender.join().expect("send thread");
    assert!(matches!(
        outcome,
        RecordOutcome::Accepted | RecordOutcome::DroppedClosed
    ));
    lifecycle.shutdown().await;
    let persisted_runs: u64 = repository
        .batches()
        .iter()
        .flat_map(|batch| batch.activity())
        .map(|row| row.run_count())
        .sum();
    assert_eq!(
        persisted_runs,
        u64::from(outcome == RecordOutcome::Accepted)
    );
}

#[tokio::test(start_paused = true)]
async fn a_new_recorder_after_shutdown_has_an_independent_worker() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (old_recorder, old_lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock.clone());
    drop(old_recorder);
    drop(old_lifecycle);

    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
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
async fn default_collector_ids_are_unique_per_recorder_instance() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));

    let (first_recorder, first_lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock.clone());
    first_lifecycle.close_intake();
    assert_eq!(
        first_recorder.try_record(completed_run(3599)),
        RecordOutcome::DroppedClosed
    );
    first_lifecycle.shutdown().await;

    let (second_recorder, second_lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
    second_lifecycle.close_intake();
    assert_eq!(
        second_recorder.try_record(completed_run(3599)),
        RecordOutcome::DroppedClosed
    );
    second_lifecycle.shutdown().await;

    let batches = repository.batches();
    assert_eq!(batches.len(), 2);
    let first_id = batches[0].collector_coverage()[0]
        .collector_instance_id()
        .as_str();
    let second_id = batches[1].collector_coverage()[0]
        .collector_instance_id()
        .as_str();
    assert_ne!(first_id, second_id);
    assert!(first_id.len() <= 128);
    assert!(second_id.len() <= 128);
}

#[tokio::test(start_paused = true)]
async fn direct_oversized_queue_configuration_is_clamped_at_spawn() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let direct_config = BufferedRecorderConfig {
        queue_capacity: 8_193,
        ..BufferedRecorderConfig::default()
    };
    assert_eq!(direct_config.effective_queue_capacity(), 8_192);
    let zero_config = BufferedRecorderConfig {
        queue_capacity: 0,
        ..BufferedRecorderConfig::default()
    };
    assert_eq!(zero_config.effective_queue_capacity(), 1);
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(direct_config, repository, clock);

    for offset in 0..8_192 {
        assert_eq!(
            recorder.try_record(completed_run(offset)),
            RecordOutcome::Accepted
        );
    }
    assert_eq!(
        recorder.try_record(completed_run(8_192)),
        RecordOutcome::DroppedQueueFull
    );
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn drop_only_coverage_uses_the_drop_timestamp_for_its_span() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
    lifecycle.close_intake();
    let dropped_at = timestamp(3_599);
    assert_eq!(
        recorder.try_record(completed_run(3_599)),
        RecordOutcome::DroppedClosed
    );
    lifecycle.shutdown().await;
    let batches = repository.batches();
    let coverage = &batches[0].collector_coverage()[0];
    assert_eq!(coverage.first_observed_at(), dropped_at);
    assert_eq!(coverage.last_observed_at(), dropped_at);
}

#[tokio::test(start_paused = true)]
async fn invalid_aggregate_is_counted_without_a_repository_write() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
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
    assert_eq!(
        lifecycle.diagnostics().last_failure_class(),
        Some(TelemetryWriteFailureClass::CounterOverflow)
    );
    assert_eq!(
        lifecycle
            .diagnostics()
            .failure_class_count(TelemetryWriteFailureClass::CounterOverflow),
        1
    );
    assert!(repository.batches().is_empty());
    lifecycle.shutdown().await;
    let batches = repository.batches();
    let coverage = batches[0].collector_coverage();
    assert_eq!(coverage[0].accepted_observation_count(), 2);
    assert_eq!(coverage[0].invalid_drop_count(), 2);
}

#[tokio::test(start_paused = true)]
async fn repository_record_failures_preserve_typed_diagnostics() {
    let repository = Arc::new(FakeRepository::default());
    repository.fail_next_with(TelemetryRepositoryError::Record(
        RecordError::InvalidWindowStart,
    ));
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
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
    let diagnostics = lifecycle.diagnostics();
    assert_eq!(
        diagnostics.last_failure_class(),
        Some(TelemetryWriteFailureClass::InvalidRecord)
    );
    assert_eq!(
        diagnostics.failure_class_count(TelemetryWriteFailureClass::InvalidRecord),
        1
    );
    lifecycle.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn system_scope_is_rejected_without_entering_a_global_bucket() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);

    assert_eq!(
        recorder.try_record_scoped(ResourceScope::system(), completed_run(0)),
        RecordOutcome::DroppedInvalid
    );
    assert_eq!(lifecycle.diagnostics().invalid_observation_count(), 1);
    lifecycle.shutdown().await;
    assert!(repository.batches().is_empty());
}

#[tokio::test(start_paused = true)]
async fn queued_scope_is_the_only_usage_attribution_source() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
    let mut trusted_scope = scope();
    trusted_scope.tenant_id = TenantId::new("tenant-b").expect("tenant");
    trusted_scope.user_id = UserId::new("user-b").expect("user");

    assert_eq!(
        recorder.try_record_scoped(trusted_scope, completed_run(0)),
        RecordOutcome::Accepted
    );
    lifecycle.shutdown().await;

    let batches = repository.batches();
    let activity = &batches[0].activity()[0];
    assert_eq!(activity.tenant_id().as_str(), "tenant-b");
    assert_eq!(activity.user_id().as_str(), "user-b");
}

#[tokio::test(start_paused = true)]
async fn lifecycle_subject_user_can_differ_from_scope_user() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
    let observation = TelemetryObservation::LifecycleTransition(
        LifecycleTransitionObservation::new(
            Some(UserId::new("subject-user").expect("subject user")),
            LifecycleEventId::new("event-a").expect("event"),
            LifecycleEventKind::MemberAdded,
            LifecycleSubjectKind::User,
            "subject-user",
            timestamp(0),
        )
        .expect("lifecycle observation"),
    );

    assert_eq!(
        recorder.try_record_scoped(scope(), observation),
        RecordOutcome::Accepted
    );
    lifecycle.shutdown().await;

    let batches = repository.batches();
    let event = &batches[0].lifecycle_events()[0];
    assert_eq!(event.tenant_id().as_str(), "tenant-a");
    assert_eq!(event.user_id().map(UserId::as_str), Some("subject-user"));
}

#[tokio::test(start_paused = true)]
async fn malformed_lifecycle_observation_does_not_poison_valid_usage() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn_with_sink(config(), repository.clone(), clock);
    let malformed = TelemetryObservation::LifecycleTransition(
        LifecycleTransitionObservation::new(
            None,
            LifecycleEventId::new("event-without-owner").expect("event"),
            LifecycleEventKind::RoutineCreated,
            LifecycleSubjectKind::Routine,
            "routine-a",
            timestamp(0),
        )
        .expect("structurally valid lifecycle observation"),
    );

    assert_eq!(
        recorder.try_record_scoped(scope(), malformed),
        RecordOutcome::DroppedInvalid
    );
    assert_eq!(
        recorder.try_record_scoped(scope(), completed_run(0)),
        RecordOutcome::Accepted
    );
    lifecycle.shutdown().await;

    let batches = repository.batches();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].activity().len(), 1);
    assert!(batches[0].lifecycle_events().is_empty());
}
