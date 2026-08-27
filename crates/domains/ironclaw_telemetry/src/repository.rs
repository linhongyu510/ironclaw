use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Timelike, Utc};
use ironclaw_telemetry_contracts::observation::{
    AutomationKind, CanonicalTenantId as TenantId, CanonicalUserId as UserId, CollectorInstanceId,
    EffectiveModelId, FailureCategory, LifecycleEventId, LifecycleEventKind, LifecycleSubjectKind,
    MAX_TELEMETRY_IDENTIFIER_BYTES, OriginKind, ProviderId, SubjectId,
};

use crate::{
    CollectorCoverage, HourlyAutomationUsage, HourlyModelUsage, HourlyRunFailure,
    HourlyUserActivity, LifecycleEvent, TelemetryBatch, error::TelemetryRepositoryError,
};

pub const MAX_TELEMETRY_PAGE_SIZE: usize = 2_000;
/// Maximum UTF-8 byte length accepted for an opaque telemetry page cursor.
///
/// Cursors are parsed before they are used in backend query parameters. This
/// bound keeps malformed input from driving unbounded parser work or scratch
/// allocations while leaving ample room for the bounded cursor fields.
pub const MAX_TELEMETRY_CURSOR_BYTES: usize = 4_096;

/// Tenant and half-open time range shared by every export scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryScanRequest {
    tenant_id: TenantId,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    now: DateTime<Utc>,
    include_partial: bool,
    provider_id: Option<ProviderId>,
    effective_model_id: Option<EffectiveModelId>,
}

impl TelemetryScanRequest {
    pub fn new(
        tenant_id: TenantId,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Self, TelemetryRepositoryError> {
        let from = normalize_timestamp(from);
        let to = normalize_timestamp(to);
        let now = normalize_timestamp(now);
        if from >= to {
            return Err(TelemetryRepositoryError::InvalidScanRequest {
                reason: "from must be before to",
            });
        }
        Ok(Self {
            tenant_id,
            from,
            to,
            now,
            include_partial: false,
            provider_id: None,
            effective_model_id: None,
        })
    }

    pub fn with_include_partial(mut self, include_partial: bool) -> Self {
        self.include_partial = include_partial;
        self
    }

    pub fn with_provider_id(mut self, provider_id: Option<ProviderId>) -> Self {
        self.provider_id = provider_id;
        self
    }

    pub fn with_effective_model_id(mut self, model_id: Option<EffectiveModelId>) -> Self {
        self.effective_model_id = model_id;
        self
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn from(&self) -> DateTime<Utc> {
        self.from
    }

    pub fn to(&self) -> DateTime<Utc> {
        self.to
    }

    pub fn now(&self) -> DateTime<Utc> {
        self.now
    }

    pub fn include_partial(&self) -> bool {
        self.include_partial
    }

    pub fn provider_id(&self) -> Option<&ProviderId> {
        self.provider_id.as_ref()
    }

    pub fn effective_model_id(&self) -> Option<&EffectiveModelId> {
        self.effective_model_id.as_ref()
    }

    /// Return the effective upper bound. The open hour is excluded unless the
    /// caller explicitly opted into partial-hour data.
    pub fn effective_to(&self) -> DateTime<Utc> {
        if self.include_partial {
            self.to
        } else {
            self.to.min(crate::floor_utc_hour(self.now))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryScanPageRequest {
    range: TelemetryScanRequest,
    page_size: usize,
    after: Option<String>,
}

impl TelemetryScanPageRequest {
    pub fn new(
        range: TelemetryScanRequest,
        page_size: usize,
        after: Option<String>,
    ) -> Result<Self, TelemetryRepositoryError> {
        if page_size == 0 || page_size > MAX_TELEMETRY_PAGE_SIZE {
            return Err(TelemetryRepositoryError::InvalidPageRequest {
                reason: "page size must be between 1 and 2000",
            });
        }
        if after
            .as_deref()
            .is_some_and(|cursor| cursor.len() > MAX_TELEMETRY_CURSOR_BYTES)
        {
            return Err(TelemetryRepositoryError::InvalidPageRequest {
                reason: "cursor exceeds maximum length",
            });
        }
        Ok(Self {
            range,
            page_size,
            after,
        })
    }

    pub fn range(&self) -> &TelemetryScanRequest {
        &self.range
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    pub fn after(&self) -> Option<&str> {
        self.after.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryPage<T> {
    rows: Vec<T>,
    next_cursor: Option<String>,
}

impl<T> TelemetryPage<T> {
    pub(crate) fn new(rows: Vec<T>, next_cursor: Option<String>) -> Self {
        Self { rows, next_cursor }
    }

    pub fn rows(&self) -> &[T] {
        &self.rows
    }

    pub fn into_rows(self) -> Vec<T> {
        self.rows
    }

    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_deref()
    }
}

/// The persistence exception has two private SQL adapters behind one domain
/// contract. Both adapters must run the same repository conformance suite.
#[async_trait]
pub trait TelemetryRepository: Send + Sync {
    async fn migrate(&self) -> Result<(), TelemetryRepositoryError>;

    async fn upsert_batch(&self, batch: &TelemetryBatch) -> Result<(), TelemetryRepositoryError>;

    async fn scan_activity_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyUserActivity>, TelemetryRepositoryError>;

    async fn scan_model_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyModelUsage>, TelemetryRepositoryError>;

    async fn scan_failure_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyRunFailure>, TelemetryRepositoryError>;

    async fn scan_automation_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyAutomationUsage>, TelemetryRepositoryError>;

    async fn scan_lifecycle_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<LifecycleEvent>, TelemetryRepositoryError>;

    async fn scan_coverage_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<CollectorCoverage>, TelemetryRepositoryError>;
}

/// Internal admission seam shared by both SQL adapters. The production
/// implementation is a no-op; tests install a neutral counter to observe the
/// real handle/transaction path without naming either database driver.
pub(crate) trait AdmissionObserver: Send + Sync {
    fn acquired(&self);
    fn transaction_started(&self);
    fn released(&self);
}

#[derive(Default)]
pub(crate) struct NoopAdmissionObserver;

impl AdmissionObserver for NoopAdmissionObserver {
    fn acquired(&self) {}

    fn transaction_started(&self) {}

    fn released(&self) {}
}

pub(crate) struct AdmissionGuard {
    observer: std::sync::Arc<dyn AdmissionObserver>,
}

impl AdmissionGuard {
    pub(crate) fn transaction_started(&self) {
        self.observer.transaction_started();
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        self.observer.released();
    }
}

pub(crate) fn begin_admission(observer: &std::sync::Arc<dyn AdmissionObserver>) -> AdmissionGuard {
    observer.acquired();
    AdmissionGuard {
        observer: std::sync::Arc::clone(observer),
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdmissionStats {
    pub(crate) acquisitions: usize,
    pub(crate) transaction_starts: usize,
    pub(crate) releases: usize,
    pub(crate) max_active: usize,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct CountingAdmissionObserver {
    acquisitions: std::sync::atomic::AtomicUsize,
    transaction_starts: std::sync::atomic::AtomicUsize,
    releases: std::sync::atomic::AtomicUsize,
    active: std::sync::atomic::AtomicUsize,
    max_active: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl CountingAdmissionObserver {
    pub(crate) fn stats(&self) -> AdmissionStats {
        AdmissionStats {
            acquisitions: self.acquisitions.load(std::sync::atomic::Ordering::SeqCst),
            transaction_starts: self
                .transaction_starts
                .load(std::sync::atomic::Ordering::SeqCst),
            releases: self.releases.load(std::sync::atomic::Ordering::SeqCst),
            max_active: self.max_active.load(std::sync::atomic::Ordering::SeqCst),
        }
    }
}

#[cfg(test)]
impl AdmissionObserver for CountingAdmissionObserver {
    fn acquired(&self) {
        let active = self
            .active
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let mut observed = self.max_active.load(std::sync::atomic::Ordering::SeqCst);
        while active > observed {
            match self.max_active.compare_exchange(
                observed,
                active,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
        self.acquisitions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn transaction_started(&self) {
        self.transaction_starts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn released(&self) {
        self.releases
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.active
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(crate) fn assert_nonempty_batch_admission(stats: AdmissionStats) {
    assert_eq!(
        stats,
        AdmissionStats {
            acquisitions: 1,
            transaction_starts: 1,
            releases: 1,
            max_active: 1,
        }
    );
}

#[cfg(test)]
pub(crate) fn assert_empty_batch_admission(stats: AdmissionStats) {
    assert_eq!(
        stats,
        AdmissionStats {
            acquisitions: 0,
            transaction_starts: 0,
            releases: 0,
            max_active: 0,
        }
    );
}

pub(crate) fn timestamp_text(timestamp: DateTime<Utc>) -> String {
    normalize_timestamp(timestamp).to_rfc3339_opts(SecondsFormat::Micros, true)
}

pub(crate) fn normalize_timestamp(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    let micros = timestamp.nanosecond() / 1_000;
    match timestamp.with_nanosecond(micros * 1_000) {
        Some(normalized) => normalized,
        None => timestamp,
    }
}

pub(crate) fn parse_timestamp(
    value: &str,
    field: &'static str,
) -> Result<DateTime<Utc>, TelemetryRepositoryError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| normalize_timestamp(timestamp.with_timezone(&Utc)))
        .map_err(|source| TelemetryRepositoryError::InvalidTimestamp { field, source })
}

pub(crate) fn encode_cursor(timestamp: DateTime<Utc>, fields: &[&str]) -> String {
    let timestamp = timestamp_text(timestamp);
    let mut cursor = String::new();
    append_length_prefixed_segment(&mut cursor, &timestamp);
    for field in fields {
        append_length_prefixed_segment(&mut cursor, field);
    }
    cursor
}

fn append_length_prefixed_segment(cursor: &mut String, value: &str) {
    cursor.push_str(&value.len().to_string());
    cursor.push(':');
    cursor.push_str(value);
}

pub(crate) fn decode_cursor(
    cursor: &str,
    expected_fields: usize,
) -> Result<(DateTime<Utc>, Vec<String>), TelemetryRepositoryError> {
    if cursor.len() > MAX_TELEMETRY_CURSOR_BYTES {
        return Err(TelemetryRepositoryError::InvalidCursor);
    }
    let mut cursor = cursor.as_bytes();
    let timestamp = parse_length_prefixed_segment(&mut cursor)?;
    let timestamp = parse_timestamp(&timestamp, "cursor timestamp")?;
    let mut fields = Vec::with_capacity(expected_fields);
    while !cursor.is_empty() {
        fields.push(parse_length_prefixed_segment(&mut cursor)?);
    }
    if fields.len() != expected_fields {
        return Err(TelemetryRepositoryError::InvalidCursor);
    }
    Ok((timestamp, fields))
}

fn parse_length_prefixed_segment(cursor: &mut &[u8]) -> Result<String, TelemetryRepositoryError> {
    let colon = cursor
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(TelemetryRepositoryError::InvalidCursor)?;
    let length_text = std::str::from_utf8(&cursor[..colon])
        .map_err(TelemetryRepositoryError::invalid_cursor_encoding)?;
    let length = length_text.parse::<usize>().map_err(|source| {
        TelemetryRepositoryError::invalid_cursor_length(length_text.to_owned(), source)
    })?;
    if length == 0 || length > MAX_TELEMETRY_IDENTIFIER_BYTES * 2 {
        return Err(TelemetryRepositoryError::InvalidCursor);
    }
    let value_start = colon + 1;
    let value_end = value_start
        .checked_add(length)
        .ok_or(TelemetryRepositoryError::InvalidCursor)?;
    if value_end > cursor.len() {
        return Err(TelemetryRepositoryError::InvalidCursor);
    }
    let value = String::from_utf8(cursor[value_start..value_end].to_vec())
        .map_err(TelemetryRepositoryError::invalid_cursor_encoding)?;
    *cursor = &cursor[value_end..];
    Ok(value)
}

pub(crate) fn page_rows<T>(mut rows: Vec<T>, page_size: usize) -> (Vec<T>, bool) {
    let has_more = rows.len() > page_size;
    if has_more {
        rows.truncate(page_size);
    }
    (rows, has_more)
}

pub(crate) fn checked_counter_sum(
    current: i64,
    incoming: u64,
    family: &'static str,
) -> Result<(), TelemetryRepositoryError> {
    let current = counter_from_i64(current, family)?;
    let total = current
        .checked_add(incoming)
        .ok_or(TelemetryRepositoryError::CounterOverflow { family })?;
    if total > ironclaw_telemetry_contracts::observation::MAX_DURABLE_COUNTER {
        return Err(TelemetryRepositoryError::CounterOverflow { family });
    }
    Ok(())
}

pub(crate) fn counter_from_i64(
    value: i64,
    family: &'static str,
) -> Result<u64, TelemetryRepositoryError> {
    u64::try_from(value)
        .map_err(|source| TelemetryRepositoryError::counter_conversion(family, value, source))
}

pub(crate) fn batch_is_empty(batch: &TelemetryBatch) -> bool {
    batch.activity().is_empty()
        && batch.model_usage().is_empty()
        && batch.run_failures().is_empty()
        && batch.automation_usage().is_empty()
        && batch.lifecycle_events().is_empty()
        && batch.collector_coverage().is_empty()
}

pub(crate) fn decode_tenant_id(value: String) -> Result<TenantId, TelemetryRepositoryError> {
    TenantId::new(value.clone()).map_err(|source| {
        TelemetryRepositoryError::invalid_persisted_field("tenant_id", value, source)
    })
}

pub(crate) fn decode_user_id(value: String) -> Result<UserId, TelemetryRepositoryError> {
    UserId::new(value.clone()).map_err(|source| {
        TelemetryRepositoryError::invalid_persisted_field("user_id", value, source)
    })
}

pub(crate) fn decode_provider_id(value: String) -> Result<ProviderId, TelemetryRepositoryError> {
    ProviderId::new(value.clone()).map_err(|source| {
        TelemetryRepositoryError::invalid_persisted_field("provider_id", value, source)
    })
}

pub(crate) fn decode_model_id(value: String) -> Result<EffectiveModelId, TelemetryRepositoryError> {
    EffectiveModelId::new(value.clone()).map_err(|source| {
        TelemetryRepositoryError::invalid_persisted_field("effective_model_id", value, source)
    })
}

pub(crate) fn decode_failure_category(
    value: String,
) -> Result<FailureCategory, TelemetryRepositoryError> {
    FailureCategory::new(value.clone()).map_err(|source| {
        TelemetryRepositoryError::invalid_persisted_field("failure_category", value, source)
    })
}

pub(crate) fn decode_event_id(value: String) -> Result<LifecycleEventId, TelemetryRepositoryError> {
    LifecycleEventId::new(value.clone()).map_err(|source| {
        TelemetryRepositoryError::invalid_persisted_field("event_id", value, source)
    })
}

pub(crate) fn decode_subject_id(value: String) -> Result<SubjectId, TelemetryRepositoryError> {
    SubjectId::new(value.clone()).map_err(|source| {
        TelemetryRepositoryError::invalid_persisted_field("subject_id", value, source)
    })
}

pub(crate) fn decode_collector_id(
    value: String,
) -> Result<CollectorInstanceId, TelemetryRepositoryError> {
    CollectorInstanceId::new(value.clone()).map_err(|source| {
        TelemetryRepositoryError::invalid_persisted_field("collector_instance_id", value, source)
    })
}

pub(crate) fn origin_text(value: OriginKind) -> &'static str {
    match value {
        OriginKind::Human => "human",
        OriginKind::ParentAgent => "parent_agent",
        OriginKind::System => "system",
        OriginKind::Automation => "automation",
        OriginKind::Other => "other",
    }
}

pub(crate) fn parse_origin(value: &str) -> Result<OriginKind, TelemetryRepositoryError> {
    match value {
        "human" => Ok(OriginKind::Human),
        "parent_agent" => Ok(OriginKind::ParentAgent),
        "system" => Ok(OriginKind::System),
        "automation" => Ok(OriginKind::Automation),
        "other" => Ok(OriginKind::Other),
        value => Err(TelemetryRepositoryError::UnknownEnum {
            field: "origin_kind",
            value: value.to_owned(),
        }),
    }
}

pub(crate) fn automation_text(value: AutomationKind) -> &'static str {
    match value {
        AutomationKind::Cron => "cron",
        AutomationKind::Once => "once",
        AutomationKind::Manual => "manual",
    }
}

pub(crate) fn parse_automation(value: &str) -> Result<AutomationKind, TelemetryRepositoryError> {
    match value {
        "cron" => Ok(AutomationKind::Cron),
        "once" => Ok(AutomationKind::Once),
        "manual" => Ok(AutomationKind::Manual),
        value => Err(TelemetryRepositoryError::UnknownEnum {
            field: "automation_kind",
            value: value.to_owned(),
        }),
    }
}

pub(crate) fn lifecycle_event_text(value: LifecycleEventKind) -> &'static str {
    match value {
        LifecycleEventKind::MemberAdded => "member_added",
        LifecycleEventKind::MemberRemoved => "member_removed",
        LifecycleEventKind::RoutineCreated => "routine_created",
        LifecycleEventKind::RoutineEnabled => "routine_enabled",
        LifecycleEventKind::RoutineDisabled => "routine_disabled",
        LifecycleEventKind::RoutineDeleted => "routine_deleted",
    }
}

pub(crate) fn parse_event(value: &str) -> Result<LifecycleEventKind, TelemetryRepositoryError> {
    match value {
        "member_added" => Ok(LifecycleEventKind::MemberAdded),
        "member_removed" => Ok(LifecycleEventKind::MemberRemoved),
        "routine_created" => Ok(LifecycleEventKind::RoutineCreated),
        "routine_enabled" => Ok(LifecycleEventKind::RoutineEnabled),
        "routine_disabled" => Ok(LifecycleEventKind::RoutineDisabled),
        "routine_deleted" => Ok(LifecycleEventKind::RoutineDeleted),
        value => Err(TelemetryRepositoryError::UnknownEnum {
            field: "event_kind",
            value: value.to_owned(),
        }),
    }
}

pub(crate) fn lifecycle_subject_text(value: LifecycleSubjectKind) -> &'static str {
    match value {
        LifecycleSubjectKind::Tenant => "tenant",
        LifecycleSubjectKind::User => "user",
        LifecycleSubjectKind::Routine => "routine",
    }
}

pub(crate) fn parse_subject(value: &str) -> Result<LifecycleSubjectKind, TelemetryRepositoryError> {
    match value {
        "tenant" => Ok(LifecycleSubjectKind::Tenant),
        "user" => Ok(LifecycleSubjectKind::User),
        "routine" => Ok(LifecycleSubjectKind::Routine),
        value => Err(TelemetryRepositoryError::UnknownEnum {
            field: "subject_kind",
            value: value.to_owned(),
        }),
    }
}

#[cfg(test)]
pub(crate) fn assert_schema_v0_shape(migration: &str, postgres: bool) {
    let sql = migration.split_whitespace().collect::<Vec<_>>().join(" ");
    let timestamp_type = if postgres { "TIMESTAMPTZ" } else { "TEXT" };
    let integer_type = if postgres { "BIGINT" } else { "INTEGER" };
    let schema_version_type = if postgres { "SMALLINT" } else { "INTEGER" };
    let nullable_user = if postgres {
        "user_id TEXT NULL"
    } else {
        "user_id TEXT"
    };
    for (table, columns, primary_key) in [
        (
            "telemetry_hourly_user_activity_v0",
            format!(
                "tenant_id TEXT NOT NULL, window_start {timestamp_type} NOT NULL, user_id TEXT NOT NULL, origin_kind TEXT NOT NULL CHECK (origin_kind IN ('human','parent_agent','system','automation','other')), run_count {integer_type} NOT NULL CHECK (run_count >= 0), runs_with_reported_tool_calls_count {integer_type} NOT NULL CHECK (runs_with_reported_tool_calls_count >= 0), tool_count_reported_run_count {integer_type} NOT NULL CHECK (tool_count_reported_run_count >= 0), reported_tool_call_count {integer_type} NOT NULL CHECK (reported_tool_call_count >= 0), completed_count {integer_type} NOT NULL CHECK (completed_count >= 0), failed_count {integer_type} NOT NULL CHECK (failed_count >= 0), cancelled_count {integer_type} NOT NULL CHECK (cancelled_count >= 0), recovery_required_count {integer_type} NOT NULL CHECK (recovery_required_count >= 0), total_run_latency_ms {integer_type} NOT NULL CHECK (total_run_latency_ms >= 0), first_observed_at {timestamp_type} NOT NULL, last_observed_at {timestamp_type} NOT NULL, schema_version {schema_version_type} NOT NULL CHECK (schema_version = 0), updated_at {timestamp_type} NOT NULL, PRIMARY KEY (tenant_id, window_start, user_id, origin_kind), CHECK (completed_count + failed_count + cancelled_count + recovery_required_count = run_count), CHECK (runs_with_reported_tool_calls_count <= tool_count_reported_run_count), CHECK (tool_count_reported_run_count <= run_count)"
            ),
            "PRIMARY KEY (tenant_id, window_start, user_id, origin_kind)",
        ),
        (
            "telemetry_hourly_model_usage_v0",
            format!(
                "tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, window_start {timestamp_type} NOT NULL, provider_id TEXT NOT NULL, effective_model_id TEXT NOT NULL, inference_count {integer_type} NOT NULL CHECK (inference_count >= 0), usage_reported_count {integer_type} NOT NULL CHECK (usage_reported_count >= 0), input_tokens {integer_type} NOT NULL CHECK (input_tokens >= 0), output_tokens {integer_type} NOT NULL CHECK (output_tokens >= 0), cache_read_input_tokens {integer_type} NOT NULL CHECK (cache_read_input_tokens >= 0), cache_creation_input_tokens {integer_type} NOT NULL CHECK (cache_creation_input_tokens >= 0), first_observed_at {timestamp_type} NOT NULL, last_observed_at {timestamp_type} NOT NULL, schema_version {schema_version_type} NOT NULL CHECK (schema_version = 0), updated_at {timestamp_type} NOT NULL, PRIMARY KEY (tenant_id, user_id, window_start, provider_id, effective_model_id), CHECK (usage_reported_count <= inference_count)"
            ),
            "PRIMARY KEY (tenant_id, user_id, window_start, provider_id, effective_model_id)",
        ),
        (
            "telemetry_hourly_run_failures_v0",
            format!(
                "tenant_id TEXT NOT NULL, window_start {timestamp_type} NOT NULL, user_id TEXT NOT NULL, failure_category TEXT NOT NULL, failure_count {integer_type} NOT NULL CHECK (failure_count >= 0), first_observed_at {timestamp_type} NOT NULL, last_observed_at {timestamp_type} NOT NULL, schema_version {schema_version_type} NOT NULL CHECK (schema_version = 0), updated_at {timestamp_type} NOT NULL, PRIMARY KEY (tenant_id, window_start, user_id, failure_category)"
            ),
            "PRIMARY KEY (tenant_id, window_start, user_id, failure_category)",
        ),
        (
            "telemetry_hourly_automation_usage_v0",
            format!(
                "tenant_id TEXT NOT NULL, window_start {timestamp_type} NOT NULL, user_id TEXT NOT NULL, automation_kind TEXT NOT NULL CHECK (automation_kind IN ('cron','once','manual')), run_count {integer_type} NOT NULL CHECK (run_count >= 0), completed_count {integer_type} NOT NULL CHECK (completed_count >= 0), failed_count {integer_type} NOT NULL CHECK (failed_count >= 0), cancelled_count {integer_type} NOT NULL CHECK (cancelled_count >= 0), recovery_required_count {integer_type} NOT NULL CHECK (recovery_required_count >= 0), first_observed_at {timestamp_type} NOT NULL, last_observed_at {timestamp_type} NOT NULL, schema_version {schema_version_type} NOT NULL CHECK (schema_version = 0), updated_at {timestamp_type} NOT NULL, PRIMARY KEY (tenant_id, window_start, user_id, automation_kind), CHECK (completed_count + failed_count + cancelled_count + recovery_required_count = run_count)"
            ),
            "PRIMARY KEY (tenant_id, window_start, user_id, automation_kind)",
        ),
        (
            "telemetry_lifecycle_events_v0",
            format!(
                "tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, {nullable_user}, event_kind TEXT NOT NULL, subject_kind TEXT NOT NULL, subject_id TEXT NOT NULL, occurred_at {timestamp_type} NOT NULL, schema_version {schema_version_type} NOT NULL CHECK (schema_version = 0), PRIMARY KEY (tenant_id, event_id)"
            ),
            "PRIMARY KEY (tenant_id, event_id)",
        ),
        (
            "telemetry_collector_hourly_v0",
            format!(
                "tenant_id TEXT NOT NULL, window_start {timestamp_type} NOT NULL, collector_instance_id TEXT NOT NULL, accepted_observation_count {integer_type} NOT NULL CHECK (accepted_observation_count >= 0), queue_full_drop_count {integer_type} NOT NULL CHECK (queue_full_drop_count >= 0), closed_drop_count {integer_type} NOT NULL CHECK (closed_drop_count >= 0), invalid_drop_count {integer_type} NOT NULL CHECK (invalid_drop_count >= 0), write_failed_observation_count {integer_type} NOT NULL CHECK (write_failed_observation_count >= 0), first_observed_at {timestamp_type} NOT NULL, last_observed_at {timestamp_type} NOT NULL, schema_version {schema_version_type} NOT NULL CHECK (schema_version = 0), updated_at {timestamp_type} NOT NULL, PRIMARY KEY (tenant_id, window_start, collector_instance_id)"
            ),
            "PRIMARY KEY (tenant_id, window_start, collector_instance_id)",
        ),
    ] {
        let table_start = format!("CREATE TABLE IF NOT EXISTS {table} (");
        let table_body = sql
            .split_once(&table_start)
            .and_then(|(_, rest)| rest.split_once(");"))
            .map(|(body, _)| body.trim())
            .unwrap_or_else(|| panic!("missing or unterminated table {table}"));
        assert_eq!(
            table_body, columns,
            "table {table} must match the complete schema-v0 column, constraint, and key shape"
        );
        assert!(
            !table_body.contains(" DEFAULT "),
            "table {table} must not introduce a schema-v0 default"
        );
        assert!(
            table_body.contains(primary_key),
            "table {table} has the wrong primary key; expected {primary_key}"
        );
    }
    for (index, definition) in [
        (
            "telemetry_activity_tenant_user_time_v0",
            "CREATE INDEX IF NOT EXISTS telemetry_activity_tenant_user_time_v0 ON telemetry_hourly_user_activity_v0 (tenant_id, user_id, window_start)",
        ),
        (
            "telemetry_model_tenant_time_model_v0",
            "CREATE INDEX IF NOT EXISTS telemetry_model_tenant_time_model_v0 ON telemetry_hourly_model_usage_v0 (tenant_id, window_start, provider_id, effective_model_id)",
        ),
        (
            "telemetry_lifecycle_tenant_time_v0",
            "CREATE INDEX IF NOT EXISTS telemetry_lifecycle_tenant_time_v0 ON telemetry_lifecycle_events_v0 (tenant_id, occurred_at, event_id)",
        ),
        (
            "telemetry_lifecycle_subject_history_v0",
            "CREATE INDEX IF NOT EXISTS telemetry_lifecycle_subject_history_v0 ON telemetry_lifecycle_events_v0 (tenant_id, subject_kind, subject_id, occurred_at, event_id)",
        ),
    ] {
        assert!(
            sql.contains(definition),
            "index {index} does not match its tenant-leading shape"
        );
    }
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;

    use super::{decode_cursor, encode_cursor, timestamp_text};
    use crate::TelemetryRepositoryError;

    #[test]
    fn cursor_round_trip_accepts_identifier_delimiters() {
        let timestamp = DateTime::parse_from_rfc3339("2026-08-26T10:00:00.123456789Z")
            .expect("test timestamp")
            .with_timezone(&chrono::Utc);
        let cursor = encode_cursor(timestamp, &["user|one", "provider|two", "model|three"]);

        let (decoded_timestamp, fields) = decode_cursor(&cursor, 3).expect("cursor round trip");

        assert_eq!(
            timestamp_text(decoded_timestamp),
            "2026-08-26T10:00:00.123456Z"
        );
        assert_eq!(fields, ["user|one", "provider|two", "model|three"]);
    }

    #[test]
    fn timestamp_text_normalizes_to_postgres_precision() {
        let timestamp = DateTime::parse_from_rfc3339("2026-08-26T10:00:00.123456789Z")
            .expect("test timestamp")
            .with_timezone(&chrono::Utc);

        assert_eq!(timestamp_text(timestamp), "2026-08-26T10:00:00.123456Z");
    }

    #[test]
    fn persisted_decode_errors_preserve_field_causes() {
        let error = super::decode_tenant_id(String::new()).expect_err("empty tenant");
        assert!(matches!(
            error,
            TelemetryRepositoryError::InvalidPersistedField {
                field: "tenant_id",
                ..
            }
        ));
        assert_eq!(error.to_string(), "invalid persisted telemetry tenant_id");
        assert!(std::error::Error::source(&error).is_some());

        let error = super::parse_origin("not-a-real-origin").expect_err("unknown origin");
        assert!(matches!(
            error,
            TelemetryRepositoryError::UnknownEnum {
                field: "origin_kind",
                ..
            }
        ));
        assert_eq!(error.to_string(), "unknown persisted telemetry origin_kind");
    }

    #[test]
    fn cursor_timestamp_parse_preserves_source() {
        let error = decode_cursor("3:bad", 0).expect_err("invalid cursor timestamp");
        assert!(matches!(
            error,
            TelemetryRepositoryError::InvalidTimestamp {
                field: "cursor timestamp",
                ..
            }
        ));
        assert_eq!(
            error.to_string(),
            "invalid persisted telemetry timestamp in cursor timestamp"
        );
        assert!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<chrono::ParseError>())
                .is_some()
        );
    }

    #[test]
    fn cursor_length_parse_preserves_source() {
        let error = decode_cursor("x:payload", 0).expect_err("invalid cursor length");
        assert!(matches!(
            error,
            TelemetryRepositoryError::InvalidCursorLength { ref value, .. } if value == "x"
        ));
        assert_eq!(error.to_string(), "invalid telemetry page cursor length");
        assert!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<std::num::ParseIntError>())
                .is_some()
        );
    }

    #[test]
    fn cursor_payload_utf8_preserves_source() {
        let error = decode_cursor("1:\u{e9}", 1).expect_err("invalid cursor payload");
        assert!(matches!(
            error,
            TelemetryRepositoryError::InvalidCursorEncoding { .. }
        ));
        assert_eq!(error.to_string(), "invalid telemetry page cursor encoding");
        assert!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<std::string::FromUtf8Error>())
                .is_some()
        );
    }

    #[test]
    fn persisted_counter_conversion_preserves_source_and_value() {
        let error = super::checked_counter_sum(-1, 0, "persisted").expect_err("negative counter");
        assert!(matches!(
            error,
            TelemetryRepositoryError::CounterConversion {
                family: "persisted",
                value: -1,
                ..
            }
        ));
        assert_eq!(
            error.to_string(),
            "telemetry counter conversion failed for persisted row"
        );
        assert!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<std::num::TryFromIntError>())
                .is_some()
        );
    }
}
