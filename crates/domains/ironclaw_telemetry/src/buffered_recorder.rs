//! Non-blocking producer port for the telemetry batch worker.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use ironclaw_telemetry_contracts::{
    observation::{CollectorInstanceId, TelemetryObservation},
    recorder::{RecordOutcome, TelemetryRecorder},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{repository::TelemetryRepository, worker};

pub const DEFAULT_TELEMETRY_QUEUE_CAPACITY: usize = 8_192;
pub const DEFAULT_TELEMETRY_MAX_BATCH_SIZE: usize = 512;
pub const DEFAULT_TELEMETRY_MAX_WAIT: Duration = Duration::from_secs(1);
pub const DEFAULT_TELEMETRY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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
        let intake_closed = Arc::new(AtomicBool::new(false));
        let cancellation = CancellationToken::new();
        let diagnostics = Arc::new(DiagnosticsState::default());
        let collector_instance_id = config
            .collector_instance_id
            .or_else(|| CollectorInstanceId::new(format!("collector-{}", std::process::id())).ok());
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
            Arc::clone(&repository),
            clock,
            Arc::clone(&diagnostics),
            cancellation.clone(),
        ));
        let recorder = Arc::new(Recorder {
            sender,
            intake_closed: Arc::clone(&intake_closed),
            diagnostics: Arc::clone(&diagnostics),
        });
        let lifecycle = BufferedTelemetryRecorderHandle {
            cancellation,
            intake_closed,
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

struct Recorder {
    sender: mpsc::Sender<TelemetryObservation>,
    intake_closed: Arc<AtomicBool>,
    diagnostics: Arc<DiagnosticsState>,
}

impl TelemetryRecorder for Recorder {
    fn try_record(&self, observation: TelemetryObservation) -> RecordOutcome {
        let was_closed = self.intake_closed.load(Ordering::Acquire);
        let outcome = self.sender.try_send(observation);
        if was_closed {
            self.diagnostics.increment_closed();
            return RecordOutcome::DroppedClosed;
        }
        match outcome {
            Ok(()) => {
                self.diagnostics.increment_accepted();
                RecordOutcome::Accepted
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.diagnostics.increment_queue_full();
                RecordOutcome::DroppedQueueFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.diagnostics.increment_closed();
                RecordOutcome::DroppedClosed
            }
        }
    }
}

/// Lifecycle owner for the single telemetry consumer task.
pub struct BufferedTelemetryRecorderHandle {
    cancellation: CancellationToken,
    intake_closed: Arc<AtomicBool>,
    diagnostics: Arc<DiagnosticsState>,
    join: Option<tokio::task::JoinHandle<()>>,
    shutdown_timeout: Duration,
}

impl BufferedTelemetryRecorderHandle {
    pub fn diagnostics(&self) -> TelemetryDiagnostics {
        self.diagnostics.snapshot()
    }

    pub async fn shutdown(mut self) {
        self.intake_closed.store(true, Ordering::Release);
        self.cancellation.cancel();
        if let Some(mut join) = self.join.take()
            && tokio::time::timeout(self.shutdown_timeout, &mut join)
                .await
                .is_err()
        {
            join.abort();
        }
    }
}

impl Drop for BufferedTelemetryRecorderHandle {
    fn drop(&mut self) {
        self.intake_closed.store(true, Ordering::Release);
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
