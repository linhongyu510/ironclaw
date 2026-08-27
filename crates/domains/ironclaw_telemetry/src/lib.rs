//! Tenant-scoped BI telemetry domain boundary.

pub mod aggregate;
mod error;
// Composition wiring lands in the follow-up task; keep the admitted SQL
// adapters private in this task without turning their intentionally dormant
// production surface into a warning.
#[allow(dead_code)]
mod libsql;
#[allow(dead_code)]
mod postgres;
pub mod records;
pub mod repository;

#[cfg(test)]
mod repository_contract_tests;

pub use aggregate::{
    AggregationError, aggregate_batch, floor_utc_day, floor_utc_hour, floor_utc_month,
    floor_utc_year,
};
pub use error::TelemetryRepositoryError;
pub use records::{
    CollectorCoverage, HourlyAutomationUsage, HourlyModelUsage, HourlyRunFailure,
    HourlyUserActivity, LifecycleEvent, RecordError, TelemetryBatch, TelemetryBatchRowFamily,
};

pub use repository::{
    MAX_TELEMETRY_PAGE_SIZE, TelemetryPage, TelemetryRepository, TelemetryScanPageRequest,
    TelemetryScanRequest,
};
