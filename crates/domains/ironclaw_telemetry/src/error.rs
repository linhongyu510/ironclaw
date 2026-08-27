use thiserror::Error;

/// Errors returned by the telemetry repositories. Backend sources remain
/// attached so callers can distinguish storage failure from invalid durable
/// data without exposing driver types in the repository contract.
#[derive(Debug, Error)]
pub enum TelemetryRepositoryError {
    #[error("invalid telemetry scan request: {reason}")]
    InvalidScanRequest { reason: &'static str },
    #[error("invalid telemetry page request: {reason}")]
    InvalidPageRequest { reason: &'static str },
    #[error("invalid telemetry page cursor")]
    InvalidCursor,
    #[error("invalid persisted telemetry timestamp in {field}")]
    InvalidTimestamp { field: &'static str },
    #[error("unknown persisted telemetry {field} value {value:?}")]
    UnknownEnum { field: &'static str, value: String },
    #[error("telemetry counter overflow for {family} row")]
    CounterOverflow { family: &'static str },
    #[error(transparent)]
    Record(#[from] crate::records::RecordError),
    #[error("libSQL runtime admission failed while {operation}")]
    LibSqlRuntime {
        operation: &'static str,
        #[source]
        source: ironclaw_libsql_runtime::LibSqlRuntimeError,
    },
    #[error("libSQL operation failed while {operation}")]
    LibSql {
        operation: &'static str,
        #[source]
        source: libsql::Error,
    },
    #[error("PostgreSQL pool admission failed while {operation}")]
    PostgresPool {
        operation: &'static str,
        #[source]
        source: deadpool_postgres::PoolError,
    },
    #[error("PostgreSQL operation failed while {operation}")]
    Postgres {
        operation: &'static str,
        #[source]
        source: tokio_postgres::Error,
    },
}
