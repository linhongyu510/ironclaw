use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use ironclaw_telemetry_contracts::observation::{
    CanonicalTenantId as TenantId, EffectiveModelId, MAX_TELEMETRY_IDENTIFIER_BYTES, ProviderId,
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
    timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

pub(crate) fn parse_timestamp(
    value: &str,
    field: &'static str,
) -> Result<DateTime<Utc>, TelemetryRepositoryError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| TelemetryRepositoryError::InvalidTimestamp { field })
}

pub(crate) fn encode_cursor(timestamp: DateTime<Utc>, fields: &[&str]) -> String {
    let timestamp = timestamp_text(timestamp);
    let mut cursor = timestamp.len().to_string();
    cursor.push(':');
    cursor.push_str(&timestamp);
    for field in fields {
        cursor.push('|');
        cursor.push_str(&field.len().to_string());
        cursor.push(':');
        cursor.push_str(field);
    }
    cursor
}

pub(crate) fn decode_cursor(
    cursor: &str,
    expected_fields: usize,
) -> Result<(DateTime<Utc>, Vec<String>), TelemetryRepositoryError> {
    let mut segments = cursor.split('|');
    let timestamp = parse_length_prefixed_segment(segments.next())?;
    let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| TelemetryRepositoryError::InvalidCursor)?;
    let fields = segments
        .map(|segment| parse_length_prefixed_segment(Some(segment)))
        .collect::<Result<Vec<_>, _>>()?;
    if fields.len() != expected_fields {
        return Err(TelemetryRepositoryError::InvalidCursor);
    }
    Ok((timestamp, fields))
}

fn parse_length_prefixed_segment(
    segment: Option<&str>,
) -> Result<String, TelemetryRepositoryError> {
    let segment = segment.ok_or(TelemetryRepositoryError::InvalidCursor)?;
    let (length, value) = segment
        .split_once(':')
        .ok_or(TelemetryRepositoryError::InvalidCursor)?;
    let length = length
        .parse::<usize>()
        .map_err(|_| TelemetryRepositoryError::InvalidCursor)?;
    if value.len() != length || value.len() > MAX_TELEMETRY_IDENTIFIER_BYTES * 2 {
        return Err(TelemetryRepositoryError::InvalidCursor);
    }
    Ok(value.to_owned())
}

pub(crate) fn page_rows<T>(mut rows: Vec<T>, page_size: usize) -> (Vec<T>, bool) {
    let has_more = rows.len() > page_size;
    if has_more {
        rows.truncate(page_size);
    }
    (rows, has_more)
}
