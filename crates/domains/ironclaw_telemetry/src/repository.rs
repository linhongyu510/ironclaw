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
        if from >= to {
            return Err(TelemetryRepositoryError::InvalidScanRequest {
                reason: "from must be before to",
            });
        }
        Ok(Self {
            tenant_id,
            from: normalize_timestamp(from),
            to: normalize_timestamp(to),
            now: normalize_timestamp(now),
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
    let mut cursor = cursor.as_bytes();
    let timestamp = parse_length_prefixed_segment(&mut cursor)?;
    let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp)
        .map(|value| normalize_timestamp(value.with_timezone(&Utc)))
        .map_err(|_| TelemetryRepositoryError::InvalidCursor)?;
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
    let length = std::str::from_utf8(&cursor[..colon])
        .map_err(|_| TelemetryRepositoryError::InvalidCursor)?
        .parse::<usize>()
        .map_err(|_| TelemetryRepositoryError::InvalidCursor)?;
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
        .map_err(|_| TelemetryRepositoryError::InvalidCursor)?;
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
    let current =
        u64::try_from(current).map_err(|_| TelemetryRepositoryError::CounterOverflow { family })?;
    let total = current
        .checked_add(incoming)
        .ok_or(TelemetryRepositoryError::CounterOverflow { family })?;
    if total > ironclaw_telemetry_contracts::observation::MAX_DURABLE_COUNTER {
        return Err(TelemetryRepositoryError::CounterOverflow { family });
    }
    Ok(())
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
    let nullable_user = if postgres {
        "user_id TEXT NULL"
    } else {
        "user_id TEXT"
    };
    for (table, columns, primary_key) in [
        (
            "telemetry_hourly_user_activity_v0",
            format!(
                "tenant_id TEXT NOT NULL, window_start {timestamp_type} NOT NULL, user_id TEXT NOT NULL, origin_kind TEXT NOT NULL"
            ),
            "PRIMARY KEY (tenant_id, window_start, user_id, origin_kind)",
        ),
        (
            "telemetry_hourly_model_usage_v0",
            format!(
                "tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, window_start {timestamp_type} NOT NULL, provider_id TEXT NOT NULL, effective_model_id TEXT NOT NULL"
            ),
            "PRIMARY KEY (tenant_id, user_id, window_start, provider_id, effective_model_id)",
        ),
        (
            "telemetry_hourly_run_failures_v0",
            format!(
                "tenant_id TEXT NOT NULL, window_start {timestamp_type} NOT NULL, user_id TEXT NOT NULL, failure_category TEXT NOT NULL"
            ),
            "PRIMARY KEY (tenant_id, window_start, user_id, failure_category)",
        ),
        (
            "telemetry_hourly_automation_usage_v0",
            format!(
                "tenant_id TEXT NOT NULL, window_start {timestamp_type} NOT NULL, user_id TEXT NOT NULL, automation_kind TEXT NOT NULL"
            ),
            "PRIMARY KEY (tenant_id, window_start, user_id, automation_kind)",
        ),
        (
            "telemetry_lifecycle_events_v0",
            format!(
                "tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, {nullable_user}, event_kind TEXT NOT NULL, subject_kind TEXT NOT NULL, subject_id TEXT NOT NULL, occurred_at {timestamp_type} NOT NULL"
            ),
            "PRIMARY KEY (tenant_id, event_id)",
        ),
        (
            "telemetry_collector_hourly_v0",
            format!(
                "tenant_id TEXT NOT NULL, window_start {timestamp_type} NOT NULL, collector_instance_id TEXT NOT NULL"
            ),
            "PRIMARY KEY (tenant_id, window_start, collector_instance_id)",
        ),
    ] {
        let table_start = format!("CREATE TABLE IF NOT EXISTS {table} (");
        let table_body = sql
            .split_once(&table_start)
            .and_then(|(_, rest)| rest.split_once(");"))
            .map(|(body, _)| body)
            .unwrap_or_else(|| panic!("missing or unterminated table {table}"));
        assert!(
            table_body.contains(&columns),
            "table {table} is missing its leading columns: {columns}"
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
pub(crate) fn assert_single_batch_admission(source: &str, function: &str, acquisition: &str) {
    let rest = source
        .rsplit_once(&format!("async fn {function}"))
        .map(|(_, rest)| rest)
        .expect("batch function body");
    let body = if function == "transaction_batch" {
        rest.split_once("impl TelemetryRepository")
            .map(|(body, _)| body)
    } else {
        rest.split_once("async fn scan_").map(|(body, _)| body)
    }
    .expect("batch function body boundary");
    assert_eq!(
        body.matches(acquisition).count(),
        1,
        "batch must acquire exactly one admitted write handle"
    );
    assert!(!body.contains("join!"));
    assert!(!body.contains("spawn("));
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
        assert!(std::error::Error::source(&error).is_some());

        let error = super::parse_origin("not-a-real-origin").expect_err("unknown origin");
        assert!(matches!(
            error,
            TelemetryRepositoryError::UnknownEnum {
                field: "origin_kind",
                ..
            }
        ));
    }
}
