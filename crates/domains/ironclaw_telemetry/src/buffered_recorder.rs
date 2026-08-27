//! Non-blocking producer port for the telemetry batch worker.

use std::{
    collections::BTreeMap,
    num::TryFromIntError,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Datelike, Timelike, Utc};
use ironclaw_telemetry_contracts::{
    observation::{
        CollectorInstanceId, MAX_DURABLE_COUNTER, ResourceScope, ScopedTelemetryObservation,
        TelemetryObservation,
    },
    recorder::{RecordOutcome, TelemetryRecorder},
};
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::repository::FilesystemTelemetryRepository;
use crate::{floor_utc_hour, repository::TelemetryBatchSink, worker};

pub const DEFAULT_TELEMETRY_QUEUE_CAPACITY: usize = 8_192;
pub(crate) const MAX_TELEMETRY_QUEUE_CAPACITY: usize = DEFAULT_TELEMETRY_QUEUE_CAPACITY;
pub const DEFAULT_TELEMETRY_MAX_BATCH_SIZE: usize = 512;
pub const DEFAULT_TELEMETRY_MAX_WAIT: Duration = Duration::from_secs(1);
pub const DEFAULT_TELEMETRY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum distinct tenant/UTC-hour keys retained for count-only loss coverage.
///
/// Once this bound is reached, the global diagnostic still records the outcome,
/// but no unbounded producer-side state is allocated for a new key.
pub(crate) const MAX_COVERAGE_SIDE_KEYS: usize = 8_192;
const MAX_TELEMETRY_TIMESTAMP_YEAR: i32 = 9_999;
const FAILURE_CLASS_COUNT: usize = 8;

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
        self.queue_capacity = queue_capacity.clamp(1, MAX_TELEMETRY_QUEUE_CAPACITY);
        self
    }

    /// Returns the queue capacity that `spawn` will use, including for callers
    /// that construct this public config by setting fields directly.
    pub const fn effective_queue_capacity(&self) -> usize {
        if self.queue_capacity == 0 {
            1
        } else if self.queue_capacity > MAX_TELEMETRY_QUEUE_CAPACITY {
            MAX_TELEMETRY_QUEUE_CAPACITY
        } else {
            self.queue_capacity
        }
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
#[repr(u8)]
pub enum TelemetryWriteFailureClass {
    StorageAdmission = 1,
    StoragePoolAdmission = 2,
    StorageOperation = 3,
    CounterOverflow = 4,
    InvalidRecord = 5,
    InvalidData = 6,
    ShutdownTimeout = 7,
    CollectorIdResolution = 8,
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

#[derive(Debug, Clone, Copy)]
pub(crate) enum PreflightError {
    SystemScope,
    MissingSubjectUserAttribution,
    InvalidTimestamp,
    InvalidWindowStart,
    CounterOutOfRange,
}

impl PreflightError {
    pub(crate) const fn failure_class(self) -> FailureClassCode {
        match self {
            Self::SystemScope
            | Self::MissingSubjectUserAttribution
            | Self::InvalidTimestamp
            | Self::InvalidWindowStart => FailureClassCode::InvalidRecord,
            Self::CounterOutOfRange => FailureClassCode::CounterOverflow,
        }
    }
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
    partial_batch_failure_count: u64,
    flushed_batch_count: u64,
    flushed_observation_count: u64,
    last_batch_size: u64,
    last_flush_latency_ms: u64,
    last_failure_class: Option<TelemetryWriteFailureClass>,
    failure_class_counts: [u64; FAILURE_CLASS_COUNT],
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
    pub const fn partial_batch_failure_count(self) -> u64 {
        self.partial_batch_failure_count
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
    pub const fn failure_class_count(self, class: TelemetryWriteFailureClass) -> u64 {
        let index = class as usize;
        if index == 0 || index > FAILURE_CLASS_COUNT {
            0
        } else {
            self.failure_class_counts[index - 1]
        }
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
    partial_batch_failure_count: AtomicU64,
    flushed_batch_count: AtomicU64,
    flushed_observation_count: AtomicU64,
    last_batch_size: AtomicU64,
    last_flush_latency_ms: AtomicU64,
    last_failure_class: AtomicU8,
    failure_class_counts: [AtomicU64; FAILURE_CLASS_COUNT],
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
            partial_batch_failure_count: AtomicU64::new(0),
            flushed_batch_count: AtomicU64::new(0),
            flushed_observation_count: AtomicU64::new(0),
            last_batch_size: AtomicU64::new(0),
            last_flush_latency_ms: AtomicU64::new(0),
            last_failure_class: AtomicU8::new(0),
            failure_class_counts: std::array::from_fn(|_| AtomicU64::new(0)),
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
            partial_batch_failure_count: self.partial_batch_failure_count.load(Ordering::Relaxed),
            flushed_batch_count: self.flushed_batch_count.load(Ordering::Relaxed),
            flushed_observation_count: self.flushed_observation_count.load(Ordering::Relaxed),
            last_batch_size: self.last_batch_size.load(Ordering::Relaxed),
            last_flush_latency_ms: self.last_flush_latency_ms.load(Ordering::Relaxed),
            last_failure_class,
            failure_class_counts: std::array::from_fn(|index| {
                self.failure_class_counts[index].load(Ordering::Relaxed)
            }),
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
        self.add_counter(&self.accepted_observation_count, 1);
    }
    pub(crate) fn increment_queue_full(&self) {
        self.add_counter(&self.queue_full_drop_count, 1);
    }
    pub(crate) fn increment_closed(&self) {
        self.add_counter(&self.closed_drop_count, 1);
    }
    pub(crate) fn add_invalid(&self, count: usize) {
        let Ok(count) = u64::try_from(count) else {
            self.record_counter_overflow();
            return;
        };
        self.add_counter(&self.invalid_observation_count, count);
    }
    pub(crate) fn add_write_failed(&self, count: usize) {
        let Ok(count) = u64::try_from(count) else {
            self.record_counter_overflow();
            return;
        };
        self.add_counter(&self.write_failed_observation_count, count);
    }
    pub(crate) fn record_repository_failure(&self, class: FailureClassCode) {
        self.add_counter(&self.repository_failure_count, 1);
        self.record_failure(class);
    }

    pub(crate) fn record_partial_batch_failure(&self) {
        self.add_counter(&self.partial_batch_failure_count, 1);
        self.record_failure(FailureClassCode::StorageOperation);
    }

    pub(crate) fn record_failure(&self, class: FailureClassCode) {
        let index = class as usize - 1;
        if checked_atomic_add(&self.failure_class_counts[index], 1).is_err()
            && class != FailureClassCode::CounterOverflow
        {
            self.record_counter_overflow();
        }
        self.last_failure_class
            .store(class as u8, Ordering::Relaxed);
    }
    pub(crate) fn record_flush(&self, batch_size: usize, latency_ms: u64) {
        self.add_counter(&self.flushed_batch_count, 1);
        let Ok(batch_size) = u64::try_from(batch_size) else {
            self.record_counter_overflow();
            return;
        };
        self.add_counter(&self.flushed_observation_count, batch_size);
        self.last_batch_size.store(batch_size, Ordering::Relaxed);
        self.last_flush_latency_ms
            .store(latency_ms, Ordering::Relaxed);
    }

    pub(crate) fn record_shutdown_timeout(&self, abandoned: u64) {
        self.add_counter(&self.shutdown_timeout_count, 1);
        self.add_counter(&self.shutdown_write_loss_count, abandoned);
        self.add_counter(&self.shutdown_abandoned_observation_count, abandoned);
        self.add_counter(&self.write_failed_observation_count, abandoned);
        self.record_failure(FailureClassCode::ShutdownTimeout);
    }

    pub(crate) fn record_coverage_key_overflow(&self) {
        self.add_counter(&self.coverage_key_overflow_count, 1);
    }

    pub(crate) fn record_collector_id_resolution_failure(
        &self,
        error: &ironclaw_telemetry_contracts::observation::BoundedIdentifierError,
    ) {
        self.add_counter(&self.collector_id_resolution_failure_count, 1);
        self.record_failure(classify_collector_id_error(error));
    }

    fn add_counter(&self, counter: &AtomicU64, amount: u64) {
        if checked_atomic_add(counter, amount).is_err() {
            self.record_counter_overflow();
        }
    }

    pub(crate) fn record_counter_overflow(&self) {
        let index = FailureClassCode::CounterOverflow as usize - 1;
        let _ = checked_atomic_add(&self.failure_class_counts[index], 1);
        self.last_failure_class
            .store(FailureClassCode::CounterOverflow as u8, Ordering::Relaxed);
    }
}

fn checked_atomic_add(counter: &AtomicU64, amount: u64) -> Result<u64, u64> {
    counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        current.checked_add(amount)
    })
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
    pub(crate) first_observed_at: Option<DateTime<Utc>>,
    pub(crate) last_observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Default)]
pub(crate) struct CoverageSideAccumulator {
    entries: BTreeMap<TenantHourKey, CoverageSideDelta>,
}

impl CoverageSideAccumulator {
    fn record(
        &mut self,
        key: TenantHourKey,
        occurred_at: DateTime<Utc>,
        update: impl FnOnce(&mut CoverageSideDelta) -> Result<(), ()>,
    ) -> Result<bool, ()> {
        if let Some(delta) = self.entries.get_mut(&key) {
            update(delta)?;
            delta.record_timestamp(occurred_at);
            return Ok(true);
        }
        if self.entries.len() >= MAX_COVERAGE_SIDE_KEYS {
            return Ok(false);
        }
        let mut delta = CoverageSideDelta::default();
        update(&mut delta)?;
        delta.record_timestamp(occurred_at);
        self.entries.insert(key, delta);
        Ok(true)
    }

    fn take_drop_deltas(&mut self) -> BTreeMap<TenantHourKey, CoverageSideDelta> {
        let mut drops = BTreeMap::new();
        self.entries.retain(|key, delta| {
            let drop_delta = CoverageSideDelta {
                accepted_pending: 0,
                queue_full_drop_count: delta.queue_full_drop_count,
                closed_drop_count: delta.closed_drop_count,
                invalid_drop_count: delta.invalid_drop_count,
                first_observed_at: delta.first_observed_at,
                last_observed_at: delta.last_observed_at,
            };
            if drop_delta.queue_full_drop_count != 0
                || drop_delta.closed_drop_count != 0
                || drop_delta.invalid_drop_count != 0
            {
                drops.insert(key.clone(), drop_delta);
                delta.queue_full_drop_count = 0;
                delta.closed_drop_count = 0;
                delta.invalid_drop_count = 0;
                delta.first_observed_at = None;
                delta.last_observed_at = None;
            }
            delta.accepted_pending != 0
                || delta.queue_full_drop_count != 0
                || delta.closed_drop_count != 0
                || delta.invalid_drop_count != 0
        });
        drops
    }

    fn account_observations(
        &mut self,
        keys: impl IntoIterator<Item = TenantHourKey>,
    ) -> Result<(), ()> {
        let mut requested = BTreeMap::<TenantHourKey, u64>::new();
        for key in keys {
            let entry = requested.entry(key).or_default();
            *entry = entry.checked_add(1).ok_or(())?;
        }
        for (key, count) in &requested {
            if let Some(delta) = self.entries.get(key)
                && delta.accepted_pending < *count
            {
                return Err(());
            }
        }
        for (key, count) in requested {
            if let Some(delta) = self.entries.get_mut(&key) {
                delta.accepted_pending -= count;
            }
        }
        self.entries.retain(|_, delta| {
            delta.accepted_pending != 0
                || delta.queue_full_drop_count != 0
                || delta.closed_drop_count != 0
                || delta.invalid_drop_count != 0
        });
        Ok(())
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

impl CoverageSideDelta {
    fn record_timestamp(&mut self, occurred_at: DateTime<Utc>) {
        self.first_observed_at = Some(match self.first_observed_at {
            Some(first) => first.min(occurred_at),
            None => occurred_at,
        });
        self.last_observed_at = Some(match self.last_observed_at {
            Some(last) => last.max(occurred_at),
            None => occurred_at,
        });
    }
}

struct IntakeState {
    sender: mpsc::Sender<ScopedTelemetryObservation>,
    closed: bool,
    coverage: CoverageSideAccumulator,
}

#[derive(Debug)]
pub(crate) enum IntakeAccountingError {
    KeyCountOverflow {
        count: usize,
        source: TryFromIntError,
    },
    PendingCountUnderflow {
        pending: u64,
        requested: u64,
    },
    CoveragePendingUnderflow,
}

impl IntakeAccountingError {
    pub(crate) const fn failure_class(&self) -> FailureClassCode {
        match self {
            Self::KeyCountOverflow { count, source } => {
                debug_assert!(*count > u64::MAX as usize);
                let _ = source;
                FailureClassCode::CounterOverflow
            }
            Self::PendingCountUnderflow { pending, requested } => {
                debug_assert!(*pending < *requested);
                FailureClassCode::CounterOverflow
            }
            Self::CoveragePendingUnderflow => FailureClassCode::CounterOverflow,
        }
    }
}

pub(crate) struct Intake {
    state: Mutex<IntakeState>,
    notify: Notify,
    pending_observation_count: AtomicU64,
}

fn record_coverage_event(
    state: &mut IntakeState,
    key: TenantHourKey,
    occurred_at: DateTime<Utc>,
    diagnostics: &DiagnosticsState,
    update: impl FnOnce(&mut CoverageSideDelta) -> Result<(), ()>,
) {
    match state.coverage.record(key, occurred_at, update) {
        Ok(true) => {}
        Ok(false) => diagnostics.record_coverage_key_overflow(),
        Err(()) => diagnostics.record_counter_overflow(),
    }
}

impl Intake {
    fn new(sender: mpsc::Sender<ScopedTelemetryObservation>) -> Self {
        Self {
            state: Mutex::new(IntakeState {
                sender,
                closed: false,
                coverage: CoverageSideAccumulator::default(),
            }),
            notify: Notify::new(),
            pending_observation_count: AtomicU64::new(0),
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

    pub(crate) fn account_observations(
        &self,
        keys: impl IntoIterator<Item = TenantHourKey>,
    ) -> Result<(), IntakeAccountingError> {
        let keys: Vec<_> = keys.into_iter().collect();
        let count = u64::try_from(keys.len()).map_err(|source| {
            IntakeAccountingError::KeyCountOverflow {
                count: keys.len(),
                source,
            }
        })?;
        let mut state = self.lock();
        if state.coverage.account_observations(keys.clone()).is_err() {
            return Err(IntakeAccountingError::CoveragePendingUnderflow);
        }
        match self.pending_observation_count.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |pending| pending.checked_sub(count),
        ) {
            Ok(_) => Ok(()),
            Err(pending) => Err(IntakeAccountingError::PendingCountUnderflow {
                pending,
                requested: count,
            }),
        }
    }

    pub(crate) fn take_unpersisted(&self) -> (BTreeMap<TenantHourKey, u64>, u64) {
        let mut state = self.lock();
        let unpersisted = state.coverage.take_unpersisted();
        let pending = self.pending_observation_count.swap(0, Ordering::AcqRel);
        (unpersisted, pending)
    }

    pub(crate) fn try_record(
        &self,
        observation: ScopedTelemetryObservation,
        key: TenantHourKey,
        diagnostics: &DiagnosticsState,
        preflight: Result<(), PreflightError>,
    ) -> RecordOutcome {
        let occurred_at = observation.occurred_at();
        let mut state = self.lock();
        if state.closed {
            record_coverage_event(&mut state, key, occurred_at, diagnostics, |delta| {
                delta.closed_drop_count = delta.closed_drop_count.checked_add(1).ok_or(())?;
                Ok(())
            });
            diagnostics.increment_closed();
            drop(state);
            self.notify.notify_one();
            return RecordOutcome::DroppedClosed;
        }
        if let Err(error) = preflight {
            record_coverage_event(&mut state, key, occurred_at, diagnostics, |delta| {
                delta.invalid_drop_count = delta.invalid_drop_count.checked_add(1).ok_or(())?;
                Ok(())
            });
            diagnostics.add_invalid(1);
            diagnostics.record_failure(error.failure_class());
            drop(state);
            self.notify.notify_one();
            return RecordOutcome::DroppedInvalid;
        }
        let outcome = state.sender.try_send(observation);
        match outcome {
            Ok(()) => {
                record_coverage_event(&mut state, key, occurred_at, diagnostics, |delta| {
                    delta.accepted_pending = delta.accepted_pending.checked_add(1).ok_or(())?;
                    Ok(())
                });
                if checked_atomic_add(&self.pending_observation_count, 1).is_err() {
                    diagnostics.record_counter_overflow();
                }
                diagnostics.increment_accepted();
                RecordOutcome::Accepted
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                record_coverage_event(&mut state, key, occurred_at, diagnostics, |delta| {
                    delta.queue_full_drop_count =
                        delta.queue_full_drop_count.checked_add(1).ok_or(())?;
                    Ok(())
                });
                diagnostics.increment_queue_full();
                drop(state);
                self.notify.notify_one();
                RecordOutcome::DroppedQueueFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                record_coverage_event(&mut state, key, occurred_at, diagnostics, |delta| {
                    delta.closed_drop_count = delta.closed_drop_count.checked_add(1).ok_or(())?;
                    Ok(())
                });
                diagnostics.increment_closed();
                drop(state);
                self.notify.notify_one();
                RecordOutcome::DroppedClosed
            }
        }
    }
}

/// Shared non-blocking telemetry recorder.
pub struct BufferedTelemetryRecorder {
    intake: Arc<Intake>,
    diagnostics: Arc<DiagnosticsState>,
}

impl BufferedTelemetryRecorder {
    pub fn spawn<F>(
        config: BufferedRecorderConfig,
        repository: Arc<FilesystemTelemetryRepository<F>>,
        clock: Arc<dyn TelemetryClock>,
    ) -> (
        Arc<BufferedTelemetryRecorder>,
        BufferedTelemetryRecorderHandle,
    )
    where
        F: ironclaw_filesystem::RootFilesystem + ?Sized + 'static,
    {
        Self::spawn_with_sink(config, repository, clock)
    }

    fn spawn_with_sink(
        config: BufferedRecorderConfig,
        repository: Arc<dyn TelemetryBatchSink>,
        clock: Arc<dyn TelemetryClock>,
    ) -> (
        Arc<BufferedTelemetryRecorder>,
        BufferedTelemetryRecorderHandle,
    ) {
        let (sender, receiver) = mpsc::channel(config.effective_queue_capacity());
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
        let recorder = Arc::new(BufferedTelemetryRecorder {
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
        None => CollectorInstanceId::new(format!("collector-{}", Uuid::new_v4())),
    };
    match candidate {
        Ok(collector_instance_id) => Some(collector_instance_id),
        Err(error) => {
            diagnostics.record_collector_id_resolution_failure(&error);
            match CollectorInstanceId::new("collector-fallback") {
                Ok(collector_instance_id) => Some(collector_instance_id),
                Err(fallback_error) => {
                    diagnostics.record_collector_id_resolution_failure(&fallback_error);
                    None
                }
            }
        }
    }
}

impl TelemetryRecorder for BufferedTelemetryRecorder {
    fn try_record(&self, scope: ResourceScope, observation: TelemetryObservation) -> RecordOutcome {
        let preflight = preflight_observation(&scope, &observation);
        if matches!(preflight, Err(PreflightError::SystemScope)) {
            let error = PreflightError::SystemScope;
            self.diagnostics.add_invalid(1);
            self.diagnostics.record_failure(error.failure_class());
            return RecordOutcome::DroppedInvalid;
        }
        let key = TenantHourKey {
            tenant_id: scope.tenant_id.clone(),
            window_start: floor_utc_hour(observation.occurred_at()),
        };
        self.intake.try_record(
            ScopedTelemetryObservation::new(scope, observation),
            key,
            self.diagnostics.as_ref(),
            preflight,
        )
    }
}

fn preflight_observation(
    scope: &ResourceScope,
    observation: &TelemetryObservation,
) -> Result<(), PreflightError> {
    if scope.is_system() {
        return Err(PreflightError::SystemScope);
    }
    let occurred_at = observation.occurred_at();
    if !(1..=MAX_TELEMETRY_TIMESTAMP_YEAR).contains(&occurred_at.year()) {
        return Err(PreflightError::InvalidTimestamp);
    }
    let window_start = floor_utc_hour(occurred_at);
    if window_start > occurred_at
        || window_start.minute() != 0
        || window_start.second() != 0
        || window_start.nanosecond() != 0
    {
        return Err(PreflightError::InvalidWindowStart);
    }
    match observation {
        TelemetryObservation::RunSettled(observation) => {
            if observation.duration_ms() > MAX_DURABLE_COUNTER
                || observation
                    .reported_tool_call_count()
                    .is_some_and(|count| count > MAX_DURABLE_COUNTER)
            {
                return Err(PreflightError::CounterOutOfRange);
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
                return Err(PreflightError::CounterOutOfRange);
            }
        }
        TelemetryObservation::AutomationSettled(_) => {}
        TelemetryObservation::LifecycleTransition(observation) => {
            if observation.subject_kind()
                != ironclaw_telemetry_contracts::observation::LifecycleSubjectKind::Tenant
                && observation.subject_user_id().is_none()
            {
                return Err(PreflightError::MissingSubjectUserAttribution);
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
            let (_, abandoned) = self.intake.take_unpersisted();
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

pub(crate) fn classify_aggregation_error(error: &crate::AggregationError) -> FailureClassCode {
    match error {
        crate::AggregationError::CounterOverflow { .. }
        | crate::AggregationError::CounterOutOfRange { .. } => FailureClassCode::CounterOverflow,
        crate::AggregationError::InvalidRecord(error) => classify_record_error(error),
    }
}

pub(crate) fn classify_record_error(error: &crate::RecordError) -> FailureClassCode {
    match error {
        crate::RecordError::CounterOutOfRange { .. }
        | crate::RecordError::TerminalCountOverflow => FailureClassCode::CounterOverflow,
        crate::RecordError::InvalidWindowStart
        | crate::RecordError::InvalidObservationRange
        | crate::RecordError::TerminalCountMismatch
        | crate::RecordError::ReportedToolCountExceedsRuns
        | crate::RecordError::ReportedUsageExceedsInferences
        | crate::RecordError::DuplicateRow { .. }
        | crate::RecordError::MissingUserAttribution => FailureClassCode::InvalidRecord,
    }
}

fn classify_collector_id_error(
    error: &ironclaw_telemetry_contracts::observation::BoundedIdentifierError,
) -> FailureClassCode {
    match error {
        ironclaw_telemetry_contracts::observation::BoundedIdentifierError::Empty { .. }
        | ironclaw_telemetry_contracts::observation::BoundedIdentifierError::TooLong { .. }
        | ironclaw_telemetry_contracts::observation::BoundedIdentifierError::ControlCharacters {
            ..
        } => FailureClassCode::CollectorIdResolution,
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
        crate::TelemetryRepositoryError::CounterConversion { .. } => {
            FailureClassCode::CounterOverflow
        }
        crate::TelemetryRepositoryError::Record(_) => FailureClassCode::InvalidRecord,
        crate::TelemetryRepositoryError::InvalidScanRequest { .. }
        | crate::TelemetryRepositoryError::InvalidPageRequest { .. }
        | crate::TelemetryRepositoryError::InvalidCursor
        | crate::TelemetryRepositoryError::InvalidCursorEncoding { .. }
        | crate::TelemetryRepositoryError::InvalidCursorLength { .. }
        | crate::TelemetryRepositoryError::InvalidTimestamp { .. }
        | crate::TelemetryRepositoryError::InvalidPersistedField { .. }
        | crate::TelemetryRepositoryError::UnknownEnum { .. } => FailureClassCode::InvalidData,
        crate::TelemetryRepositoryError::ScopeMismatch
        | crate::TelemetryRepositoryError::InvalidProjection
        | crate::TelemetryRepositoryError::Serialization { .. } => FailureClassCode::InvalidData,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_atomic_add_rejects_overflow_without_wrapping() {
        let counter = AtomicU64::new(u64::MAX);

        assert!(checked_atomic_add(&counter, 1).is_err());
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn diagnostic_counter_overflow_is_typed_and_loss_safe() {
        let diagnostics = DiagnosticsState::default();
        diagnostics
            .accepted_observation_count
            .store(u64::MAX, Ordering::Relaxed);

        diagnostics.increment_accepted();

        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.accepted_observation_count(), u64::MAX);
        assert_eq!(
            snapshot.failure_class_count(TelemetryWriteFailureClass::CounterOverflow),
            1
        );
        assert_eq!(
            snapshot.last_failure_class(),
            Some(TelemetryWriteFailureClass::CounterOverflow)
        );

        diagnostics.failure_class_counts[FailureClassCode::CounterOverflow as usize - 1]
            .store(u64::MAX, Ordering::Relaxed);
        diagnostics.record_counter_overflow();
        assert_eq!(
            diagnostics
                .snapshot()
                .failure_class_count(TelemetryWriteFailureClass::CounterOverflow),
            u64::MAX
        );
    }
}

// Keep worker fakes behind the crate-private sink seam. They need to observe
// the worker's exact call shape, but that seam is intentionally not a public
// repository selector.
#[cfg(test)]
#[path = "buffered_recorder_contract.rs"]
mod buffered_recorder_contract;
