//! Tenant-scoped BI telemetry domain boundary.

pub mod aggregate;
pub mod error;
pub mod libsql;
pub mod postgres;
pub mod records;
pub mod repository;

pub use aggregate::{
    AggregationError, aggregate_batch, floor_utc_day, floor_utc_hour, floor_utc_month,
    floor_utc_year,
};
pub use error::TelemetryRepositoryError;
pub use libsql::LibSqlTelemetryRepository;
pub use postgres::PostgresTelemetryRepository;
pub use records::{
    CollectorCoverage, HourlyAutomationUsage, HourlyModelUsage, HourlyRunFailure,
    HourlyUserActivity, LifecycleEvent, RecordError, TelemetryBatch, TelemetryBatchRowFamily,
};
pub use repository::{
    MAX_TELEMETRY_PAGE_SIZE, TelemetryPage, TelemetryRepository, TelemetryScanPageRequest,
    TelemetryScanRequest,
};
