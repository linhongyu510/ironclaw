//! Non-blocking producer port for the telemetry batch worker.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Datelike, Timelike, Utc};
use ironclaw_telemetry_contracts::{
    observation::{CollectorInstanceId, MAX_DURABLE_COUNTER, TelemetryObservation},
    recorder::{RecordOutcome, TelemetryRecorder},
};
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{floor_utc_hour, repository::TelemetryRepository, worker};

pub const DEFAULT_TELEMETRY_QUEUE_CAPACITY: usize = 8_192;
pub const DEFAULT_TELEMETRY_MAX_BATCH_SIZE: usize = 512;
pub const DEFAULT_TELEMETRY_MAX_WAIT: Duration = Duration::from_secs(1);
pub const DEFAULT_TELEMETRY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum distinct tenant/UTC-hour keys retained for count-only loss coverage.
///
/// Once this bound is reached, the global diagnostic still records the outcome,
/// but no unbounded producer-side state is allocated for a new key.
pub(crate) const MAX_COVERAGE_SIDE_KEYS: usize = 8_192;
const MAX_TELEMETRY_TIMESTAMP_YEAR: i32 = 9_999;

/// Configuration for the bounded telemetry collector.
#[derive(Debug, Clone)]
pub struct BufferedRecorderConfig {
    pub queue_capacity: usize,
    pub max_batch_size: usize,
    pub max_wait: Duration,
    pub shutdown_timeout: Duration,
    pub collector_instance_id: Option<CollectorInstanceId>,
}

impl Default for BufferedRecorderConfig {
    fn default() -> Self {
        Self {
            queue_capacity: DEFAULT_TELEMETRY_QUEUE_CAPACITY,
            max_batch_size: DEFAULT_TELEMETRY_MAX_BATCH_SIZE,
            max_wait: DEFAULT_TELEMETRY_MAX_WAIT,
            shutdown_timeout: DEFAULT_TELEMETRY_SHUTDOWN_TIMEOUT,
            collector_instance_id: None,
        }
    }
}

impl BufferedRecorderConfig {
    pub fn with_queue_capacity(mut self, queue_capacity: usize) -> Self {
        self.queue_capacity = queue_capacity.max(1);
        self
    }

    pub fn with_max_batch_size(mut self, max_batch_size: usize) -> Self {
        self.max_batch_size = max_batch_size.clamp(1, DEFAULT_TELEMETRY_MAX_BATCH_SIZE);
        self
    }

    pub fn with_max_wait(mut self, max_wait: Duration) -> Self {
        self.max_wait = if max_wait.is_zero() {
            Duration::from_millis(1)
        } else {
            max_wait.min(DEFAULT_TELEMETRY_MAX_WAIT)
        };
        self
    }

    pub fn with_shutdown_timeout(mut self, shutdown_timeout: Duration) -> Self {
        self.shutdown_timeout = if shutdown_timeout.is_zero() {
            Duration::from_millis(1)
        } else {
            shutdown_timeout.min(DEFAULT_TELEMETRY_SHUTDOWN_TIMEOUT)
        };
        self
    }

    pub fn with_collector_instance_id(
        mut self,
        collector_instance_id: CollectorInstanceId,
    ) -> Self {
        self.collector_instance_id = Some(collector_instance_id);
        self
    }
}

/// Clock used for coverage timestamps and count-only diagnostics.
pub trait TelemetryClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// Production wall clock implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemTelemetryClock;

impl TelemetryClock for SystemTelemetryClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Typed class for operational repository failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryWriteFailureClass {
    StorageAdmission,
    StoragePoolAdmission,
    StorageOperation,
    CounterOverflow,
    InvalidRecord,
    InvalidData,
    ShutdownTimeout,
    CollectorIdResolution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum FailureClassCode {
    StorageAdmission = 1,
    StoragePoolAdmission = 2,
    StorageOperation = 3,
    CounterOverflow = 4,
    InvalidRecord = 5,
    InvalidData = 6,
    ShutdownTimeout = 7,
    CollectorIdResolution = 8,
}

/// Count-only worker and queue diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryDiagnostics {
    accepted_observation_count: u64,
    queue_full_drop_count: u64,
    closed_drop_count: u64,
    invalid_observation_count: u64,
    write_failed_observation_count: u64,
    repository_failure_count: u64,
    flushed_batch_count: u64,
    flushed_observation_count: u64,
    last_batch_size: u64,
    last_flush_latency_ms: u64,
    last_failure_class: Option<TelemetryWriteFailureClass>,
    shutdown_timeout_count: u64,
    shutdown_write_loss_count: u64,
    shutdown_abandoned_observation_count: u64,
    coverage_key_overflow_count: u64,
    collector_id_resolution_failure_count: u64,
}

impl TelemetryDiagnostics {
    pub const fn accepted_observation_count(self) -> u64 {
        self.accepted_observation_count
    }
    pub const fn queue_full_drop_count(self) -> u64 {
        self.queue_full_drop_count
    }
    pub const fn closed_drop_count(self) -> u64 {
        self.closed_drop_count
    }
    pub const fn invalid_observation_count(self) -> u64 {
        self.invalid_observation_count
    }
    pub const fn write_failed_observation_count(self) -> u64 {
        self.write_failed_observation_count
    }
    pub const fn repository_failure_count(self) -> u64 {
        self.repository_failure_count
    }
    pub const fn flushed_batch_count(self) -> u64 {
        self.flushed_batch_count
    }
    pub const fn flushed_observation_count(self) -> u64 {
        self.flushed_observation_count
    }
    pub const fn last_batch_size(self) -> u64 {
        self.last_batch_size
    }
    pub const fn last_flush_latency_ms(self) -> u64 {
        self.last_flush_latency_ms
    }
    pub const fn last_failure_class(self) -> Option<TelemetryWriteFailureClass> {
        self.last_failure_class
    }
    pub const fn shutdown_timeout_count(self) -> u64 {
        self.shutdown_timeout_count
    }
    pub const fn shutdown_write_loss_count(self) -> u64 {
        self.shutdown_write_loss_count
    }
    pub const fn shutdown_abandoned_observation_count(self) -> u64 {
        self.shutdown_abandoned_observation_count
    }
    pub const fn coverage_key_overflow_count(self) -> u64 {
        self.coverage_key_overflow_count
    }
    pub const fn collector_id_resolution_failure_count(self) -> u64 {
        self.collector_id_resolution_failure_count
    }
}

pub(crate) struct DiagnosticsState {
    accepted_observation_count: AtomicU64,
    queue_full_drop_count: AtomicU64,
    closed_drop_count: AtomicU64,
    invalid_observation_count: AtomicU64,
    write_failed_observation_count: AtomicU64,
    repository_failure_count: AtomicU64,
    flushed_batch_count: AtomicU64,
    flushed_observation_count: AtomicU64,
    last_batch_size: AtomicU64,
    last_flush_latency_ms: AtomicU64,
    last_failure_class: AtomicU8,
    shutdown_timeout_count: AtomicU64,
    shutdown_write_loss_count: AtomicU64,
    shutdown_abandoned_observation_count: AtomicU64,
    coverage_key_overflow_count: AtomicU64,
    collector_id_resolution_failure_count: AtomicU64,
}

impl Default for DiagnosticsState {
    fn default() -> Self {
        Self {
            accepted_observation_count: AtomicU64::new(0),
            queue_full_drop_count: AtomicU64::new(0),
            closed_drop_count: AtomicU64::new(0),
            invalid_observation_count: AtomicU64::new(0),
            write_failed_observation_count: AtomicU64::new(0),
            repository_failure_count: AtomicU64::new(0),
            flushed_batch_count: AtomicU64::new(0),
            flushed_observation_count: AtomicU64::new(0),
            last_batch_size: AtomicU64::new(0),
            last_flush_latency_ms: AtomicU64::new(0),
            last_failure_class: AtomicU8::new(0),
            shutdown_timeout_count: AtomicU64::new(0),
            shutdown_write_loss_count: AtomicU64::new(0),
            shutdown_abandoned_observation_count: AtomicU64::new(0),
            coverage_key_overflow_count: AtomicU64::new(0),
            collector_id_resolution_failure_count: AtomicU64::new(0),
        }
    }
}

impl DiagnosticsState {
    pub(crate) fn snapshot(&self) -> TelemetryDiagnostics {
        let last_failure_class = match self.last_failure_class.load(Ordering::Relaxed) {
            1 => Some(TelemetryWriteFailureClass::StorageAdmission),
            2 => Some(TelemetryWriteFailureClass::StoragePoolAdmission),
            3 => Some(TelemetryWriteFailureClass::StorageOperation),
            4 => Some(TelemetryWriteFailureClass::CounterOverflow),
            5 => Some(TelemetryWriteFailureClass::InvalidRecord),
            6 => Some(TelemetryWriteFailureClass::InvalidData),
            7 => Some(TelemetryWriteFailureClass::ShutdownTimeout),
            8 => Some(TelemetryWriteFailureClass::CollectorIdResolution),
            _ => None,
        };
        TelemetryDiagnostics {
            accepted_observation_count: self.accepted_observation_count.load(Ordering::Relaxed),
            queue_full_drop_count: self.queue_full_drop_count.load(Ordering::Relaxed),
            closed_drop_count: self.closed_drop_count.load(Ordering::Relaxed),
            invalid_observation_count: self.invalid_observation_count.load(Ordering::Relaxed),
            write_failed_observation_count: self
                .write_failed_observation_count
                .load(Ordering::Relaxed),
            repository_failure_count: self.repository_failure_count.load(Ordering::Relaxed),
            flushed_batch_count: self.flushed_batch_count.load(Ordering::Relaxed),
            flushed_observation_count: self.flushed_observation_count.load(Ordering::Relaxed),
            last_batch_size: self.last_batch_size.load(Ordering::Relaxed),
            last_flush_latency_ms: self.last_flush_latency_ms.load(Ordering::Relaxed),
            last_failure_class,
            shutdown_timeout_count: self.shutdown_timeout_count.load(Ordering::Relaxed),
            shutdown_write_loss_count: self.shutdown_write_loss_count.load(Ordering::Relaxed),
            shutdown_abandoned_observation_count: self
                .shutdown_abandoned_observation_count
                .load(Ordering::Relaxed),
            coverage_key_overflow_count: self.coverage_key_overflow_count.load(Ordering::Relaxed),
            collector_id_resolution_failure_count: self
                .collector_id_resolution_failure_count
                .load(Ordering::Relaxed),
        }
    }

    pub(crate) fn increment_accepted(&self) {
        self.accepted_observation_count
            .fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn increment_queue_full(&self) {
        self.queue_full_drop_count.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn increment_closed(&self) {
        self.closed_drop_count.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn add_invalid(&self, count: usize) {
        self.invalid_observation_count
            .fetch_add(count as u64, Ordering::Relaxed);
    }
    pub(crate) fn add_write_failed(&self, count: usize) {
        self.write_failed_observation_count
            .fetch_add(count as u64, Ordering::Relaxed);
    }
    pub(crate) fn record_repository_failure(&self, class: FailureClassCode) {
        self.repository_failure_count
            .fetch_add(1, Ordering::Relaxed);
        self.last_failure_class
            .store(class as u8, Ordering::Relaxed);
    }
    pub(crate) fn record_flush(&self, batch_size: usize, latency_ms: u64) {
        self.flushed_batch_count.fetch_add(1, Ordering::Relaxed);
        self.flushed_observation_count
            .fetch_add(batch_size as u64, Ordering::Relaxed);
        self.last_batch_size
            .store(batch_size as u64, Ordering::Relaxed);
        self.last_flush_latency_ms
            .store(latency_ms, Ordering::Relaxed);
    }

    pub(crate) fn record_shutdown_timeout(&self, abandoned: u64) {
        self.shutdown_timeout_count.fetch_add(1, Ordering::Relaxed);
        self.shutdown_write_loss_count
            .fetch_add(abandoned, Ordering::Relaxed);
        self.shutdown_abandoned_observation_count
            .fetch_add(abandoned, Ordering::Relaxed);
        self.write_failed_observation_count
            .fetch_add(abandoned, Ordering::Relaxed);
        self.last_failure_class
            .store(FailureClassCode::ShutdownTimeout as u8, Ordering::Relaxed);
    }

    pub(crate) fn record_coverage_key_overflow(&self) {
        self.coverage_key_overflow_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_collector_id_resolution_failure(&self) {
        self.collector_id_resolution_failure_count
            .fetch_add(1, Ordering::Relaxed);
        self.last_failure_class.store(
            FailureClassCode::CollectorIdResolution as u8,
            Ordering::Relaxed,
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TenantHourKey {
    pub(crate) tenant_id: ironclaw_telemetry_contracts::observation::CanonicalTenantId,
    pub(crate) window_start: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CoverageSideDelta {
    pub(crate) accepted_pending: u64,
    pub(crate) queue_full_drop_count: u64,
    pub(crate) closed_drop_count: u64,
    pub(crate) invalid_drop_count: u64,
}

#[derive(Debug, Default)]
pub(crate) struct CoverageSideAccumulator {
    entries: BTreeMap<TenantHourKey, CoverageSideDelta>,
}

impl CoverageSideAccumulator {
    fn record(&mut self, key: TenantHourKey, update: impl FnOnce(&mut CoverageSideDelta)) -> bool {
        if let Some(delta) = self.entries.get_mut(&key) {
            update(delta);
            return true;
        }
        if self.entries.len() >= MAX_COVERAGE_SIDE_KEYS {
            return false;
        }
        let mut delta = CoverageSideDelta::default();
        update(&mut delta);
        self.entries.insert(key, delta);
        true
    }

    fn take_drop_deltas(&mut self) -> BTreeMap<TenantHourKey, CoverageSideDelta> {
        let mut drops = BTreeMap::new();
        self.entries.retain(|key, delta| {
            let drop_delta = CoverageSideDelta {
                accepted_pending: 0,
                queue_full_drop_count: delta.queue_full_drop_count,
                closed_drop_count: delta.closed_drop_count,
                invalid_drop_count: delta.invalid_drop_count,
            };
            if drop_delta.queue_full_drop_count != 0
                || drop_delta.closed_drop_count != 0
                || drop_delta.invalid_drop_count != 0
            {
                drops.insert(key.clone(), drop_delta);
                delta.queue_full_drop_count = 0;
                delta.closed_drop_count = 0;
                delta.invalid_drop_count = 0;
            }
            delta.accepted_pending != 0
                || delta.queue_full_drop_count != 0
                || delta.closed_drop_count != 0
                || delta.invalid_drop_count != 0
        });
        drops
    }

    fn account_observations(&mut self, keys: impl IntoIterator<Item = TenantHourKey>) {
        for key in keys {
            if let Some(delta) = self.entries.get_mut(&key) {
                delta.accepted_pending = delta.accepted_pending.saturating_sub(1);
            }
        }
        self.entries.retain(|_, delta| {
            delta.accepted_pending != 0
                || delta.queue_full_drop_count != 0
                || delta.closed_drop_count != 0
                || delta.invalid_drop_count != 0
        });
    }

    fn take_unpersisted(&mut self) -> BTreeMap<TenantHourKey, u64> {
        let mut abandoned = BTreeMap::new();
        for (key, delta) in &self.entries {
            if delta.accepted_pending != 0 {
                abandoned.insert(key.clone(), delta.accepted_pending);
            }
        }
        for delta in self.entries.values_mut() {
            delta.accepted_pending = 0;
        }
        self.entries.retain(|_, delta| {
            delta.queue_full_drop_count != 0
                || delta.closed_drop_count != 0
                || delta.invalid_drop_count != 0
        });
        abandoned
    }
}

struct IntakeState {
    sender: mpsc::Sender<TelemetryObservation>,
    closed: bool,
    coverage: CoverageSideAccumulator,
}

pub(crate) struct Intake {
    state: Mutex<IntakeState>,
    notify: Notify,
}

impl Intake {
    fn new(sender: mpsc::Sender<TelemetryObservation>) -> Self {
        Self {
            state: Mutex::new(IntakeState {
                sender,
                closed: false,
                coverage: CoverageSideAccumulator::default(),
            }),
            notify: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, IntakeState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub(crate) fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        drop(state);
        self.notify.notify_one();
    }

    pub(crate) fn notified(&self) -> impl std::future::Future<Output = ()> + '_ {
        self.notify.notified()
    }

    pub(crate) fn take_drop_deltas(&self) -> BTreeMap<TenantHourKey, CoverageSideDelta> {
        self.lock().coverage.take_drop_deltas()
    }

    pub(crate) fn account_observations(&self, keys: impl IntoIterator<Item = TenantHourKey>) {
        self.lock().coverage.account_observations(keys);
    }

    pub(crate) fn take_unpersisted(&self) -> BTreeMap<TenantHourKey, u64> {
        self.lock().coverage.take_unpersisted()
    }

    pub(crate) fn try_record(
        &self,
        observation: TelemetryObservation,
        key: TenantHourKey,
        diagnostics: &DiagnosticsState,
        preflight: Result<(), ()>,
    ) -> RecordOutcome {
        let mut state = self.lock();
        if state.closed {
            if !state.coverage.record(key, |delta| {
                delta.closed_drop_count = delta.closed_drop_count.saturating_add(1)
            }) {
                diagnostics.record_coverage_key_overflow();
            }
            diagnostics.increment_closed();
            drop(state);
            self.notify.notify_one();
            return RecordOutcome::DroppedClosed;
        }
        if preflight.is_err() {
            if !state.coverage.record(key, |delta| {
                delta.invalid_drop_count = delta.invalid_drop_count.saturating_add(1)
            }) {
                diagnostics.record_coverage_key_overflow();
            }
            diagnostics.add_invalid(1);
            drop(state);
            self.notify.notify_one();
            return RecordOutcome::DroppedInvalid;
        }
        let outcome = state.sender.try_send(observation);
        match outcome {
            Ok(()) => {
                if !state.coverage.record(key, |delta| {
                    delta.accepted_pending = delta.accepted_pending.saturating_add(1)
                }) {
                    diagnostics.record_coverage_key_overflow();
                }
                diagnostics.increment_accepted();
                RecordOutcome::Accepted
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                if !state.coverage.record(key, |delta| {
                    delta.queue_full_drop_count = delta.queue_full_drop_count.saturating_add(1)
                }) {
                    diagnostics.record_coverage_key_overflow();
                }
                diagnostics.increment_queue_full();
                drop(state);
                self.notify.notify_one();
                RecordOutcome::DroppedQueueFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                if !state.coverage.record(key, |delta| {
                    delta.closed_drop_count = delta.closed_drop_count.saturating_add(1)
                }) {
                    diagnostics.record_coverage_key_overflow();
                }
                diagnostics.increment_closed();
                drop(state);
                self.notify.notify_one();
                RecordOutcome::DroppedClosed
            }
        }
    }
}

/// Shared non-blocking telemetry recorder.
pub struct BufferedTelemetryRecorder;

impl BufferedTelemetryRecorder {
    pub fn spawn(
        config: BufferedRecorderConfig,
        repository: Arc<dyn TelemetryRepository>,
        clock: Arc<dyn TelemetryClock>,
    ) -> (Arc<dyn TelemetryRecorder>, BufferedTelemetryRecorderHandle) {
        let (sender, receiver) = mpsc::channel(config.queue_capacity.max(1));
        let cancellation = CancellationToken::new();
        let diagnostics = Arc::new(DiagnosticsState::default());
        let collector_instance_id =
            resolve_collector_instance_id(config.collector_instance_id, &diagnostics);
        let intake = Arc::new(Intake::new(sender));
        let join = tokio::spawn(worker::run(
            worker::WorkerConfig {
                max_batch_size: config
                    .max_batch_size
                    .clamp(1, DEFAULT_TELEMETRY_MAX_BATCH_SIZE),
                max_wait: if config.max_wait.is_zero() {
                    Duration::from_millis(1)
                } else {
                    config.max_wait.min(DEFAULT_TELEMETRY_MAX_WAIT)
                },
                collector_instance_id,
            },
            receiver,
            Arc::clone(&intake),
            Arc::clone(&repository),
            clock,
            Arc::clone(&diagnostics),
            cancellation.clone(),
        ));
        let recorder = Arc::new(Recorder {
            intake: Arc::clone(&intake),
            diagnostics: Arc::clone(&diagnostics),
        });
        let lifecycle = BufferedTelemetryRecorderHandle {
            cancellation,
            intake,
            diagnostics,
            join: Some(join),
            shutdown_timeout: if config.shutdown_timeout.is_zero() {
                Duration::from_millis(1)
            } else {
                config
                    .shutdown_timeout
                    .min(DEFAULT_TELEMETRY_SHUTDOWN_TIMEOUT)
            },
        };
        (recorder, lifecycle)
    }
}

fn resolve_collector_instance_id(
    configured: Option<CollectorInstanceId>,
    diagnostics: &DiagnosticsState,
) -> Option<CollectorInstanceId> {
    let candidate = match configured {
        Some(collector_instance_id) => Ok(collector_instance_id),
        None => CollectorInstanceId::new(format!("collector-{}", std::process::id())),
    };
    match candidate {
        Ok(collector_instance_id) => Some(collector_instance_id),
        Err(_error) => {
            diagnostics.record_collector_id_resolution_failure();
            match CollectorInstanceId::new("collector-fallback") {
                Ok(collector_instance_id) => Some(collector_instance_id),
                Err(_fallback_error) => {
                    diagnostics.record_collector_id_resolution_failure();
                    None
                }
            }
        }
    }
}

struct Recorder {
    intake: Arc<Intake>,
    diagnostics: Arc<DiagnosticsState>,
}

impl TelemetryRecorder for Recorder {
    fn try_record(&self, observation: TelemetryObservation) -> RecordOutcome {
        let key = TenantHourKey {
            tenant_id: observation.tenant_id().clone(),
            window_start: floor_utc_hour(observation.occurred_at()),
        };
        let preflight = preflight_observation(&observation);
        self.intake
            .try_record(observation, key, self.diagnostics.as_ref(), preflight)
    }
}

fn preflight_observation(observation: &TelemetryObservation) -> Result<(), ()> {
    let occurred_at = observation.occurred_at();
    if !(1..=MAX_TELEMETRY_TIMESTAMP_YEAR).contains(&occurred_at.year()) {
        return Err(());
    }
    let window_start = floor_utc_hour(occurred_at);
    if window_start > occurred_at
        || window_start.minute() != 0
        || window_start.second() != 0
        || window_start.nanosecond() != 0
    {
        return Err(());
    }
    match observation {
        TelemetryObservation::RunSettled(observation) => {
            if observation.duration_ms() > MAX_DURABLE_COUNTER
                || observation
                    .reported_tool_call_count()
                    .is_some_and(|count| count > MAX_DURABLE_COUNTER)
            {
                return Err(());
            }
        }
        TelemetryObservation::ModelCallCompleted(observation) => {
            if [
                observation.input_tokens(),
                observation.output_tokens(),
                observation.cache_read_input_tokens(),
                observation.cache_creation_input_tokens(),
            ]
            .into_iter()
            .any(|value| value > MAX_DURABLE_COUNTER)
            {
                return Err(());
            }
        }
        TelemetryObservation::AutomationSettled(_) => {}
        TelemetryObservation::LifecycleTransition(observation) => {
            if observation.user_id().is_none()
                && observation.subject_kind()
                    != ironclaw_telemetry_contracts::observation::LifecycleSubjectKind::Tenant
            {
                return Err(());
            }
        }
    }
    Ok(())
}

/// Lifecycle owner for the single telemetry consumer task.
pub struct BufferedTelemetryRecorderHandle {
    cancellation: CancellationToken,
    intake: Arc<Intake>,
    diagnostics: Arc<DiagnosticsState>,
    join: Option<tokio::task::JoinHandle<()>>,
    shutdown_timeout: Duration,
}

impl BufferedTelemetryRecorderHandle {
    pub fn diagnostics(&self) -> TelemetryDiagnostics {
        self.diagnostics.snapshot()
    }

    pub fn close_intake(&self) {
        self.intake.close();
    }

    pub async fn shutdown(mut self) -> TelemetryDiagnostics {
        self.intake.close();
        self.cancellation.cancel();
        if let Some(mut join) = self.join.take()
            && tokio::time::timeout(self.shutdown_timeout, &mut join)
                .await
                .is_err()
        {
            join.abort();
            let _ = join.await;
            let abandoned = self.intake.take_unpersisted().values().copied().sum();
            self.diagnostics.record_shutdown_timeout(abandoned);
        }
        self.diagnostics.snapshot()
    }
}

impl Drop for BufferedTelemetryRecorderHandle {
    fn drop(&mut self) {
        self.intake.close();
        self.cancellation.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

pub(crate) fn classify_repository_error(
    error: &crate::TelemetryRepositoryError,
) -> FailureClassCode {
    match error {
        crate::TelemetryRepositoryError::StorageAdmission { .. } => {
            FailureClassCode::StorageAdmission
        }
        crate::TelemetryRepositoryError::StoragePoolAdmission { .. } => {
            FailureClassCode::StoragePoolAdmission
        }
        crate::TelemetryRepositoryError::StorageOperation { .. } => {
            FailureClassCode::StorageOperation
        }
        crate::TelemetryRepositoryError::CounterOverflow { .. } => {
            FailureClassCode::CounterOverflow
        }
        crate::TelemetryRepositoryError::Record(_) => FailureClassCode::InvalidRecord,
        crate::TelemetryRepositoryError::InvalidScanRequest { .. }
        | crate::TelemetryRepositoryError::InvalidPageRequest { .. }
        | crate::TelemetryRepositoryError::InvalidCursor
        | crate::TelemetryRepositoryError::InvalidTimestamp { .. }
        | crate::TelemetryRepositoryError::InvalidPersistedField { .. }
        | crate::TelemetryRepositoryError::UnknownEnum { .. } => FailureClassCode::InvalidData,
    }
}
