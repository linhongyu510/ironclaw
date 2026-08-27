//! Tenant-scoped BI telemetry domain boundary.

pub mod aggregate;
pub mod records;

pub use aggregate::{
    AggregationError, aggregate_batch, floor_utc_day, floor_utc_hour, floor_utc_month,
    floor_utc_year,
};
pub use records::{
    CollectorCoverage, HourlyAutomationUsage, HourlyModelUsage, HourlyRunFailure,
    HourlyUserActivity, LifecycleEvent, RecordError, TelemetryBatch, TelemetryBatchRowFamily,
};
