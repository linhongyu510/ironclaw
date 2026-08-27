//! Tenant-scoped BI telemetry domain boundary.

pub mod aggregate;
mod error;
mod libsql;
mod postgres;
pub mod records;
pub mod repository;

pub use aggregate::{
    AggregationError, aggregate_batch, floor_utc_day, floor_utc_hour, floor_utc_month,
    floor_utc_year,
};
pub use error::TelemetryRepositoryError;
pub use records::{
    CollectorCoverage, HourlyAutomationUsage, HourlyModelUsage, HourlyRunFailure,
    HourlyUserActivity, LifecycleEvent, RecordError, TelemetryBatch, TelemetryBatchRowFamily,
};

/// Backend-neutral repository handle. Concrete database admission remains in
/// private adapters; callers provide an already-admitted handle through the
/// opaque conversion implemented by composition-owned database types.
#[derive(Clone)]
pub struct TelemetryRepositoryAdapter {
    inner: std::sync::Arc<dyn TelemetryRepository>,
}

impl TelemetryRepositoryAdapter {
    pub fn from_admitted<T>(admitted: T) -> Self
    where
        T: Into<Self>,
    {
        admitted.into()
    }
}

#[async_trait::async_trait]
impl TelemetryRepository for TelemetryRepositoryAdapter {
    async fn migrate(&self) -> Result<(), TelemetryRepositoryError> {
        self.inner.migrate().await
    }

    async fn upsert_batch(&self, batch: &TelemetryBatch) -> Result<(), TelemetryRepositoryError> {
        self.inner.upsert_batch(batch).await
    }

    async fn scan_activity_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyUserActivity>, TelemetryRepositoryError> {
        self.inner.scan_activity_page(request).await
    }

    async fn scan_model_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyModelUsage>, TelemetryRepositoryError> {
        self.inner.scan_model_page(request).await
    }

    async fn scan_failure_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyRunFailure>, TelemetryRepositoryError> {
        self.inner.scan_failure_page(request).await
    }

    async fn scan_automation_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyAutomationUsage>, TelemetryRepositoryError> {
        self.inner.scan_automation_page(request).await
    }

    async fn scan_lifecycle_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<LifecycleEvent>, TelemetryRepositoryError> {
        self.inner.scan_lifecycle_page(request).await
    }

    async fn scan_coverage_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<CollectorCoverage>, TelemetryRepositoryError> {
        self.inner.scan_coverage_page(request).await
    }
}
pub use repository::{
    MAX_TELEMETRY_PAGE_SIZE, TelemetryPage, TelemetryRepository, TelemetryScanPageRequest,
    TelemetryScanRequest,
};
