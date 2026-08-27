use chrono::{DateTime, Utc};
use ironclaw_host_api::ids::TenantId;
use ironclaw_telemetry::{TelemetryRepositoryError, TelemetryScanRequest};

fn timestamp(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("test timestamp")
        .with_timezone(&Utc)
}

#[test]
fn repository_contract_rejects_inverted_ranges() {
    let result = TelemetryScanRequest::new(
        TenantId::new("tenant-a").expect("test tenant"),
        timestamp("2026-08-27T00:00:00Z"),
        timestamp("2026-08-26T00:00:00Z"),
        timestamp("2026-08-27T00:00:00Z"),
    );
    assert!(matches!(
        result,
        Err(TelemetryRepositoryError::InvalidScanRequest { .. })
    ));
}

#[test]
fn repository_contract_normalizes_timestamp_precision() {
    let range = TelemetryScanRequest::new(
        TenantId::new("tenant-a").expect("test tenant"),
        timestamp("2026-08-26T00:00:00.123456789Z"),
        timestamp("2026-08-27T00:00:00.987654321Z"),
        timestamp("2026-08-27T00:00:00.987654321Z"),
    )
    .expect("valid range");
    assert_eq!(range.from(), timestamp("2026-08-26T00:00:00.123456Z"));
    assert_eq!(range.to(), timestamp("2026-08-27T00:00:00.987654Z"));
}

#[test]
fn repository_contract_rejects_ranges_that_collapse_after_normalization() {
    let result = TelemetryScanRequest::new(
        TenantId::new("tenant-a").expect("test tenant"),
        timestamp("2026-08-26T00:00:00.123456001Z"),
        timestamp("2026-08-26T00:00:00.123456999Z"),
        timestamp("2026-08-27T00:00:00Z"),
    );

    assert!(matches!(
        result,
        Err(TelemetryRepositoryError::InvalidScanRequest { .. })
    ));
}

#[test]
fn repository_contract_rejects_oversized_opaque_cursors() {
    let range = TelemetryScanRequest::new(
        TenantId::new("tenant-a").expect("test tenant"),
        timestamp("2026-08-26T00:00:00Z"),
        timestamp("2026-08-27T00:00:00Z"),
        timestamp("2026-08-27T00:00:00Z"),
    )
    .expect("valid range");

    let result =
        ironclaw_telemetry::TelemetryScanPageRequest::new(range, 10, Some("x".repeat(4097)));

    assert!(matches!(
        result,
        Err(TelemetryRepositoryError::InvalidPageRequest { .. })
    ));
}

#[tokio::test]
async fn strict_repository_contract_requires_postgres_runtime() {
    use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};

    let image = testcontainers_modules::postgres::Postgres::default()
        .with_db_name("ironclaw_test")
        .with_user("postgres")
        .with_password("postgres")
        .with_tag("16-alpine");
    if let Err(error) = image.start().await {
        if std::env::var_os("IRONCLAW_REQUIRE_POSTGRES").is_some() {
            panic!("PostgreSQL is required but Docker could not start it: {error}");
        }
        eprintln!("skipping PostgreSQL runtime contract: {error}");
    }
}
