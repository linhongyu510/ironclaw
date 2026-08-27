use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, TimeZone, Utc};
use ironclaw_host_api::ids::{TenantId, UserId};
use ironclaw_telemetry::{
    BufferedRecorderConfig, BufferedTelemetryRecorder, CollectorCoverage, HourlyAutomationUsage,
    HourlyModelUsage, HourlyRunFailure, HourlyUserActivity, LifecycleEvent, RecordError,
    RecordOutcome, TelemetryBatch, TelemetryClock, TelemetryPage, TelemetryRepository,
    TelemetryRepositoryError, TelemetryScanPageRequest, TelemetryWriteFailureClass,
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
    always_fail: bool,
    next_error: Option<TelemetryRepositoryError>,
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
        let (started, release, fail, injected_error) = {
            let mut state = self.state.lock().expect("repository lock");
            state.active_writes += 1;
            state.max_active_writes = state.max_active_writes.max(state.active_writes);
            (
                state.write_started.take(),
                state.release_write.take(),
                state.next_error.is_some()
                    || if state.always_fail {
                        true
                    } else if state.failures_remaining > 0 {
                        state.failures_remaining -= 1;
                        true
                    } else {
                        false
                    },
                state.next_error.take(),
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
            Err(
                injected_error.unwrap_or(TelemetryRepositoryError::StorageOperation {
                    operation: "fake batch write",
                    source: "injected failure".to_owned().into(),
                }),
            )
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

fn completed_run_for_tenant_hour(index: u64) -> TelemetryObservation {
    let tenant = TenantId::new(format!("tenant-{index}")).expect("tenant");
    let user = UserId::new(format!("user-{index}")).expect("user");
    let occurred_at = timestamp((index as i64) * 3_600);
    TelemetryObservation::RunSettled(
        RunSettledObservation::new(
            ObservationContext::new(tenant, user, occurred_at),
            OriginKind::Human,
            RunOutcome::Completed,
            1,
            None,
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
async fn queue_full_drop_is_written_to_tenant_hour_coverage() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn(
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
async fn closed_drop_is_written_to_tenant_hour_coverage() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) =
        BufferedTelemetryRecorder::spawn(config(), repository.clone(), clock);
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
async fn continuous_queue_drop_notifications_do_not_starve_the_batch_deadline() {
    let repository = Arc::new(FakeRepository::default());
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn(
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
async fn pending_coverage_is_bounded_during_an_outage_and_later_drains_continue() {
    const OBSERVATIONS: usize = 8_193;
    let repository = Arc::new(FakeRepository::default());
    repository.set_fail_all(true);
    let clock = Arc::new(FixedClock::new(timestamp(0)));
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn(
        config().with_queue_capacity(OBSERVATIONS + 1),
        repository.clone(),
        clock,
    );
    for index in 0..OBSERVATIONS {
        assert_eq!(
            recorder.try_record(completed_run_for_tenant_hour(index as u64)),
            RecordOutcome::Accepted
        );
    }
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
    wait_for_batches(&repository, 1).await;
    assert!(!repository.batches()[0].activity().is_empty());
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
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn(
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
    let (recorder, lifecycle) = BufferedTelemetryRecorder::spawn(
        config().with_queue_capacity(OBSERVATIONS + 1),
        repository.clone(),
        clock,
    );
    let (started, _release) = repository.block_next_write();
    assert_eq!(
        recorder.try_record(completed_run_for_tenant_hour(0)),
        RecordOutcome::Accepted
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    started.await.expect("write started");
    for index in 1..OBSERVATIONS {
        assert_eq!(
            recorder.try_record(completed_run_for_tenant_hour(index as u64)),
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
        BufferedTelemetryRecorder::spawn(config(), repository.clone(), clock);
    let future = Utc
        .with_ymd_and_hms(10_000, 1, 1, 0, 0, 0)
        .single()
        .expect("chrono supports this bounded test timestamp");
    let observation = TelemetryObservation::RunSettled(
        RunSettledObservation::new(
            ObservationContext::new(
                TenantId::new("tenant-a").expect("tenant"),
                UserId::new("user-a").expect("user"),
                future,
            ),
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
        BufferedTelemetryRecorder::spawn(config(), repository.clone(), clock);
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
