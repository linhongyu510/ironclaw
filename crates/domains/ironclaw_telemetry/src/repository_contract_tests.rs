use std::sync::Arc;

use crate::repository::{
    CountingAdmissionObserver, assert_empty_batch_admission, assert_nonempty_batch_admission,
};
use crate::{
    CollectorCoverage, HourlyAutomationUsage, HourlyModelUsage, HourlyRunFailure,
    HourlyUserActivity, LifecycleEvent, TelemetryBatch, TelemetryRepository,
    TelemetryRepositoryError, TelemetryScanPageRequest, TelemetryScanRequest,
};
use crate::{libsql::LibSqlTelemetryRepository, postgres::PostgresTelemetryRepository};
use chrono::{DateTime, Duration, TimeZone, Utc};
use ironclaw_host_api::ids::{TenantId, UserId};
use ironclaw_libsql_runtime::LibSqlRuntime;
use ironclaw_telemetry_contracts::observation::{
    AutomationKind, CollectorInstanceId, EffectiveModelId, FailureCategory, LifecycleEventId,
    LifecycleEventKind, LifecycleSubjectKind, MAX_DURABLE_COUNTER, OriginKind, ProviderId,
    SubjectId,
};

#[async_trait::async_trait]
trait MidTransactionFailureInjector: Send + Sync {
    async fn drop_lifecycle_table(&self);
    async fn corrupt_activity_user_id(&self);
    async fn corrupt_lifecycle_event_kind(&self);
}

#[async_trait::async_trait]
impl MidTransactionFailureInjector for Arc<libsql::Database> {
    async fn drop_lifecycle_table(&self) {
        let connection = self
            .connect()
            .unwrap_or_else(|error| panic!("libSQL fault-injection connection: {error}"));
        connection
            .execute("DROP TABLE telemetry_lifecycle_events_v0", ())
            .await
            .unwrap_or_else(|error| panic!("drop libSQL lifecycle table: {error}"));
    }

    async fn corrupt_activity_user_id(&self) {
        let connection = self
            .connect()
            .unwrap_or_else(|error| panic!("libSQL corruption connection: {error}"));
        connection
            .execute(
                "UPDATE telemetry_hourly_user_activity_v0 SET user_id='' WHERE tenant_id='tenant-a' AND user_id='user-a' AND origin_kind='human'",
                (),
            )
            .await
            .unwrap_or_else(|error| panic!("corrupt libSQL activity identifier: {error}"));
    }

    async fn corrupt_lifecycle_event_kind(&self) {
        let connection = self
            .connect()
            .unwrap_or_else(|error| panic!("libSQL enum corruption connection: {error}"));
        connection
            .execute(
                "UPDATE telemetry_lifecycle_events_v0 SET event_kind='not-a-real-event' WHERE tenant_id='tenant-a' AND event_id='event-a'",
                (),
            )
            .await
            .unwrap_or_else(|error| panic!("corrupt libSQL lifecycle enum: {error}"));
    }
}

#[async_trait::async_trait]
impl MidTransactionFailureInjector for deadpool_postgres::Pool {
    async fn drop_lifecycle_table(&self) {
        let client = self
            .get()
            .await
            .unwrap_or_else(|error| panic!("PostgreSQL fault-injection connection: {error}"));
        client
            .batch_execute("DROP TABLE telemetry_lifecycle_events_v0")
            .await
            .unwrap_or_else(|error| panic!("drop PostgreSQL lifecycle table: {error}"));
    }

    async fn corrupt_activity_user_id(&self) {
        let client = self
            .get()
            .await
            .unwrap_or_else(|error| panic!("PostgreSQL corruption connection: {error}"));
        client
            .execute(
                "UPDATE telemetry_hourly_user_activity_v0 SET user_id='' WHERE tenant_id='tenant-a' AND user_id='user-a' AND origin_kind='human'",
                &[],
            )
            .await
            .unwrap_or_else(|error| panic!("corrupt PostgreSQL activity identifier: {error}"));
    }

    async fn corrupt_lifecycle_event_kind(&self) {
        let client = self
            .get()
            .await
            .unwrap_or_else(|error| panic!("PostgreSQL enum corruption connection: {error}"));
        client
            .execute(
                "UPDATE telemetry_lifecycle_events_v0 SET event_kind='not-a-real-event' WHERE tenant_id='tenant-a' AND event_id='event-a'",
                &[],
            )
            .await
            .unwrap_or_else(|error| panic!("corrupt PostgreSQL lifecycle enum: {error}"));
    }
}

fn timestamp(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0)
        .single()
        .unwrap_or_else(|| panic!("valid test timestamp: {seconds}"))
}

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).unwrap_or_else(|error| panic!("valid test tenant: {error}"))
}

fn user(value: &str) -> UserId {
    UserId::new(value).unwrap_or_else(|error| panic!("valid test user: {error}"))
}

fn batch_at(tenant_id: &str, user_id: &str, hour: DateTime<Utc>) -> TelemetryBatch {
    let activity = HourlyUserActivity::new(
        tenant(tenant_id),
        hour,
        user(user_id),
        OriginKind::Human,
        1,
        1,
        1,
        2,
        1,
        0,
        0,
        0,
        25,
        hour + Duration::minutes(1) + Duration::nanoseconds(999),
        hour + Duration::minutes(2) + Duration::nanoseconds(999),
    )
    .unwrap_or_else(|error| panic!("valid activity row: {error}"));
    let model = HourlyModelUsage::new(
        tenant(tenant_id),
        user(user_id),
        hour,
        ProviderId::new("provider-a").unwrap_or_else(|error| panic!("provider: {error}")),
        EffectiveModelId::new("model-a").unwrap_or_else(|error| panic!("model: {error}")),
        1,
        1,
        3,
        4,
        5,
        6,
        hour + Duration::minutes(1) + Duration::nanoseconds(999),
        hour + Duration::minutes(2) + Duration::nanoseconds(999),
    )
    .unwrap_or_else(|error| panic!("valid model row: {error}"));
    let failure = HourlyRunFailure::new(
        tenant(tenant_id),
        hour,
        user(user_id),
        FailureCategory::new("provider_error").unwrap_or_else(|error| panic!("category: {error}")),
        1,
        hour + Duration::minutes(1),
        hour + Duration::minutes(1),
    )
    .unwrap_or_else(|error| panic!("valid failure row: {error}"));
    let automation = HourlyAutomationUsage::new(
        tenant(tenant_id),
        hour,
        user(user_id),
        AutomationKind::Cron,
        1,
        0,
        1,
        0,
        0,
        hour + Duration::minutes(1),
        hour + Duration::minutes(2),
    )
    .unwrap_or_else(|error| panic!("valid automation row: {error}"));
    let lifecycle = LifecycleEvent::new(
        tenant(tenant_id),
        LifecycleEventId::new("event-a").unwrap_or_else(|error| panic!("event id: {error}")),
        Some(user(user_id)),
        LifecycleEventKind::RoutineCreated,
        LifecycleSubjectKind::Routine,
        SubjectId::new("routine-a").unwrap_or_else(|error| panic!("subject id: {error}")),
        hour + Duration::minutes(3),
    )
    .unwrap_or_else(|error| panic!("valid lifecycle row: {error}"));
    let coverage = CollectorCoverage::new(
        tenant(tenant_id),
        hour,
        CollectorInstanceId::new("collector-a")
            .unwrap_or_else(|error| panic!("collector id: {error}")),
        1,
        0,
        0,
        0,
        0,
        hour + Duration::minutes(1),
        hour + Duration::minutes(2),
    )
    .unwrap_or_else(|error| panic!("valid coverage row: {error}"));
    TelemetryBatch::new(
        vec![activity],
        vec![model],
        vec![failure],
        vec![automation],
        vec![lifecycle],
        vec![coverage],
    )
    .unwrap_or_else(|error| panic!("valid telemetry batch: {error}"))
}

fn model_only_batch(
    tenant_id: &str,
    user_id: &str,
    hour: DateTime<Utc>,
    provider: &str,
    model: &str,
) -> TelemetryBatch {
    let row = HourlyModelUsage::new(
        tenant(tenant_id),
        user(user_id),
        hour,
        ProviderId::new(provider).unwrap_or_else(|error| panic!("provider: {error}")),
        EffectiveModelId::new(model).unwrap_or_else(|error| panic!("model: {error}")),
        1,
        0,
        10,
        20,
        0,
        0,
        hour + Duration::minutes(5),
        hour + Duration::minutes(6),
    )
    .unwrap_or_else(|error| panic!("valid model-only row: {error}"));
    TelemetryBatch::new(
        Vec::new(),
        vec![row],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("valid model-only batch: {error}"))
}

fn activity_only_batch(
    tenant_id: &str,
    user_id: &str,
    hour: DateTime<Utc>,
    origin: OriginKind,
) -> TelemetryBatch {
    let row = HourlyUserActivity::new(
        tenant(tenant_id),
        hour,
        user(user_id),
        origin,
        1,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        hour + Duration::minutes(1),
        hour + Duration::minutes(2),
    )
    .unwrap_or_else(|error| panic!("valid activity-only row: {error}"));
    TelemetryBatch::new(
        vec![row],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("valid activity-only batch: {error}"))
}

fn automation_only_batch(
    tenant_id: &str,
    user_id: &str,
    hour: DateTime<Utc>,
    kind: AutomationKind,
) -> TelemetryBatch {
    let row = HourlyAutomationUsage::new(
        tenant(tenant_id),
        hour,
        user(user_id),
        kind,
        1,
        1,
        0,
        0,
        0,
        hour + Duration::minutes(1),
        hour + Duration::minutes(2),
    )
    .unwrap_or_else(|error| panic!("valid automation-only row: {error}"));
    TelemetryBatch::new(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![row],
        Vec::new(),
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("valid automation-only batch: {error}"))
}

async fn assert_repository_contract<I>(
    repository: Arc<dyn TelemetryRepository>,
    failure_injector: &I,
    admission_observer: &CountingAdmissionObserver,
) where
    I: MidTransactionFailureInjector,
{
    repository
        .upsert_batch(&TelemetryBatch::default())
        .await
        .unwrap_or_else(|error| panic!("empty batch: {error}"));
    assert_empty_batch_admission(admission_observer.stats());

    repository
        .migrate()
        .await
        .unwrap_or_else(|error| panic!("first migration: {error}"));
    repository
        .migrate()
        .await
        .unwrap_or_else(|error| panic!("replayed migration: {error}"));

    let hour = timestamp(1_735_689_600);
    let batch = batch_at("tenant-a", "user-a", hour);
    repository
        .upsert_batch(&batch)
        .await
        .unwrap_or_else(|error| panic!("first batch: {error}"));
    assert_nonempty_batch_admission(admission_observer.stats());
    repository
        .upsert_batch(&batch)
        .await
        .unwrap_or_else(|error| panic!("additive replay batch: {error}"));

    let request = TelemetryScanRequest::new(
        tenant("tenant-a"),
        hour - Duration::hours(1),
        hour + Duration::hours(2),
        hour + Duration::hours(2),
    )
    .unwrap_or_else(|error| panic!("valid scan request: {error}"))
    .with_include_partial(true);
    let page = TelemetryScanPageRequest::new(request.clone(), 2, None)
        .unwrap_or_else(|error| panic!("valid page request: {error}"));
    let activity_page = repository
        .scan_activity_page(&page)
        .await
        .unwrap_or_else(|error| panic!("activity page: {error}"));
    assert_eq!(activity_page.rows().len(), 1);
    assert_eq!(activity_page.rows()[0].run_count(), 2);
    assert_eq!(activity_page.rows()[0].reported_tool_call_count(), 4);
    assert_eq!(
        activity_page.rows()[0].first_observed_at(),
        hour + Duration::minutes(1)
    );
    assert_eq!(
        activity_page.rows()[0].last_observed_at(),
        hour + Duration::minutes(2)
    );
    let model_page = repository
        .scan_model_page(&page)
        .await
        .unwrap_or_else(|error| panic!("model page: {error}"));
    assert_eq!(model_page.rows().len(), 1);
    assert_eq!(model_page.rows()[0].inference_count(), 2);
    assert_eq!(model_page.rows()[0].input_tokens(), 6);
    assert_eq!(
        model_page.rows()[0].first_observed_at(),
        hour + Duration::minutes(1)
    );
    assert_eq!(
        model_page.rows()[0].last_observed_at(),
        hour + Duration::minutes(2)
    );
    let failure_page = repository
        .scan_failure_page(&page)
        .await
        .unwrap_or_else(|error| panic!("failure page: {error}"));
    assert_eq!(failure_page.rows().len(), 1);
    assert_eq!(failure_page.rows()[0].failure_count(), 2);
    let automation_page = repository
        .scan_automation_page(&page)
        .await
        .unwrap_or_else(|error| panic!("automation page: {error}"));
    assert_eq!(automation_page.rows().len(), 1);
    assert_eq!(automation_page.rows()[0].run_count(), 2);
    assert_eq!(automation_page.rows()[0].failed_count(), 2);
    assert_eq!(
        repository
            .scan_lifecycle_page(&page)
            .await
            .unwrap_or_else(|error| panic!("lifecycle page: {error}"))
            .rows()
            .len(),
        1
    );
    let coverage_page = repository
        .scan_coverage_page(&page)
        .await
        .unwrap_or_else(|error| panic!("coverage page: {error}"));
    assert_eq!(coverage_page.rows().len(), 1);
    assert_eq!(coverage_page.rows()[0].accepted_observation_count(), 2);

    repository
        .upsert_batch(&activity_only_batch(
            "tenant-a",
            "user-a",
            hour,
            OriginKind::Automation,
        ))
        .await
        .unwrap_or_else(|error| panic!("second activity origin: {error}"));
    assert_eq!(
        repository
            .scan_activity_page(&page)
            .await
            .unwrap_or_else(|error| panic!("activity origin isolation: {error}"))
            .rows()
            .len(),
        2
    );

    repository
        .upsert_batch(&automation_only_batch(
            "tenant-a",
            "user-a",
            hour,
            AutomationKind::Once,
        ))
        .await
        .unwrap_or_else(|error| panic!("second automation kind: {error}"));
    assert_eq!(
        repository
            .scan_automation_page(&page)
            .await
            .unwrap_or_else(|error| panic!("automation kind isolation: {error}"))
            .rows()
            .len(),
        2
    );

    repository
        .upsert_batch(&model_only_batch(
            "tenant-a",
            "user-b",
            hour,
            "provider-b",
            "model-b",
        ))
        .await
        .unwrap_or_else(|error| panic!("second model dimension: {error}"));
    let provider_filtered = TelemetryScanPageRequest::new(
        request.clone().with_provider_id(Some(
            ProviderId::new("provider-b")
                .unwrap_or_else(|error| panic!("provider filter: {error}")),
        )),
        100,
        None,
    )
    .unwrap_or_else(|error| panic!("provider-filtered page: {error}"));
    let provider_rows = repository
        .scan_model_page(&provider_filtered)
        .await
        .unwrap_or_else(|error| panic!("provider-filtered scan: {error}"));
    assert_eq!(provider_rows.rows().len(), 1);
    assert_eq!(provider_rows.rows()[0].provider_id().as_str(), "provider-b");
    let model_filtered = TelemetryScanPageRequest::new(
        request.clone().with_effective_model_id(Some(
            EffectiveModelId::new("model-a")
                .unwrap_or_else(|error| panic!("model filter: {error}")),
        )),
        100,
        None,
    )
    .unwrap_or_else(|error| panic!("model-filtered page: {error}"));
    assert_eq!(
        repository
            .scan_model_page(&model_filtered)
            .await
            .unwrap_or_else(|error| panic!("model-filtered scan: {error}"))
            .rows()
            .len(),
        1
    );

    for user_id in ["user|cursor-a", "user|cursor-b", "user|cursor-c"] {
        repository
            .upsert_batch(&batch_at("tenant-a", user_id, hour + Duration::hours(1)))
            .await
            .unwrap_or_else(|error| panic!("pagination fixture: {error}"));
    }
    let cursor_range = TelemetryScanRequest::new(
        tenant("tenant-a"),
        hour + Duration::hours(1),
        hour + Duration::hours(2),
        hour + Duration::hours(2),
    )
    .unwrap_or_else(|error| panic!("cursor range: {error}"))
    .with_include_partial(true);
    let pagination_request = TelemetryScanPageRequest::new(cursor_range.clone(), 1, None)
        .unwrap_or_else(|error| panic!("pagination request: {error}"));
    let first = repository
        .scan_activity_page(&pagination_request)
        .await
        .unwrap_or_else(|error| panic!("first page: {error}"));
    assert_eq!(first.rows().len(), 1);
    assert!(first.next_cursor().is_some());
    let second_request = TelemetryScanPageRequest::new(
        request.clone(),
        1,
        first.next_cursor().map(ToOwned::to_owned),
    )
    .unwrap_or_else(|error| panic!("second pagination request: {error}"));
    let second = repository
        .scan_activity_page(&second_request)
        .await
        .unwrap_or_else(|error| panic!("second page: {error}"));
    assert_eq!(second.rows().len(), 1);
    assert_eq!(first.rows()[0].user_id().as_str(), "user|cursor-a");
    assert_eq!(second.rows()[0].user_id().as_str(), "user|cursor-b");
    let third_request =
        TelemetryScanPageRequest::new(cursor_range, 1, second.next_cursor().map(ToOwned::to_owned))
            .unwrap_or_else(|error| panic!("third pagination request: {error}"));
    let third = repository
        .scan_activity_page(&third_request)
        .await
        .unwrap_or_else(|error| panic!("third page: {error}"));
    assert_eq!(third.rows().len(), 1);
    assert_eq!(third.rows()[0].user_id().as_str(), "user|cursor-c");

    let other = batch_at("tenant-b", "user-a", hour);
    repository
        .upsert_batch(&other)
        .await
        .unwrap_or_else(|error| panic!("other tenant batch: {error}"));
    let tenant_a_page = repository
        .scan_activity_page(&page)
        .await
        .unwrap_or_else(|error| panic!("tenant isolation page: {error}"));
    assert!(
        tenant_a_page
            .rows()
            .iter()
            .all(|row| row.tenant_id().as_str() == "tenant-a")
    );

    let partial_request = TelemetryScanRequest::new(
        tenant("tenant-a"),
        hour,
        hour + Duration::hours(1),
        hour + Duration::minutes(30),
    )
    .unwrap_or_else(|error| panic!("partial scan request: {error}"));
    let excluded = TelemetryScanPageRequest::new(partial_request.clone(), 100, None)
        .unwrap_or_else(|error| panic!("excluded page request: {error}"));
    assert!(
        repository
            .scan_activity_page(&excluded)
            .await
            .unwrap_or_else(|error| panic!("default current-hour scan: {error}"))
            .rows()
            .is_empty()
    );
    let included =
        TelemetryScanPageRequest::new(partial_request.with_include_partial(true), 100, None)
            .unwrap_or_else(|error| panic!("included page request: {error}"));
    assert_eq!(
        repository
            .scan_activity_page(&included)
            .await
            .unwrap_or_else(|error| panic!("included current-hour scan: {error}"))
            .rows()
            .len(),
        2
    );

    let invalid_batch = batch_at("tenant-a", "user-b", hour);
    repository
        .upsert_batch(&invalid_batch)
        .await
        .unwrap_or_else(|error| panic!("second valid batch: {error}"));
    let overflow = TelemetryBatch::new(
        vec![
            HourlyUserActivity::new(
                tenant("tenant-a"),
                hour,
                user("user-c"),
                OriginKind::Human,
                MAX_DURABLE_COUNTER,
                MAX_DURABLE_COUNTER,
                MAX_DURABLE_COUNTER,
                MAX_DURABLE_COUNTER,
                MAX_DURABLE_COUNTER,
                0,
                0,
                0,
                MAX_DURABLE_COUNTER,
                hour,
                hour,
            )
            .unwrap_or_else(|error| panic!("max activity: {error}")),
        ],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("overflow batch shape: {error}"));
    let result = repository.upsert_batch(&overflow).await;
    assert!(result.is_ok(), "initial max row should fit: {result:?}");
    let before = repository
        .scan_activity_page(&included)
        .await
        .unwrap_or_else(|error| panic!("before rollback scan: {error}"))
        .rows()
        .len();
    let lifecycle = LifecycleEvent::new(
        tenant("tenant-a"),
        LifecycleEventId::new("event-rollback").unwrap_or_else(|error| panic!("event id: {error}")),
        Some(user("user-c")),
        LifecycleEventKind::RoutineEnabled,
        LifecycleSubjectKind::Routine,
        SubjectId::new("routine-rollback").unwrap_or_else(|error| panic!("subject id: {error}")),
        hour + Duration::minutes(4),
    )
    .unwrap_or_else(|error| panic!("rollback lifecycle row: {error}"));
    let mixed_overflow = TelemetryBatch::new(
        vec![
            HourlyUserActivity::new(
                tenant("tenant-a"),
                hour,
                user("user-c"),
                OriginKind::Human,
                MAX_DURABLE_COUNTER,
                MAX_DURABLE_COUNTER,
                MAX_DURABLE_COUNTER,
                MAX_DURABLE_COUNTER,
                MAX_DURABLE_COUNTER,
                0,
                0,
                0,
                MAX_DURABLE_COUNTER,
                hour,
                hour,
            )
            .unwrap_or_else(|error| panic!("max activity replay: {error}")),
        ],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![lifecycle],
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("mixed overflow batch: {error}"));
    let result = repository.upsert_batch(&mixed_overflow).await;
    assert!(result.is_err(), "mixed/overflow batch must roll back");
    let after = repository
        .scan_activity_page(&included)
        .await
        .unwrap_or_else(|error| panic!("after rollback scan: {error}"))
        .rows()
        .len();
    assert_eq!(before, after, "failed batch must not partially commit");
    let lifecycle_after = repository
        .scan_lifecycle_page(&included)
        .await
        .unwrap_or_else(|error| panic!("rollback lifecycle scan: {error}"));
    assert_eq!(
        lifecycle_after.rows().len(),
        1,
        "lifecycle write must roll back"
    );

    assert_database_error_rolls_back(Arc::clone(&repository), failure_injector).await;

    // The database-error injector drops and recreates the lifecycle table, so
    // restore a known row before exercising persisted-field decode failures.
    repository
        .upsert_batch(&batch_at("tenant-a", "user-a", timestamp(1_735_689_600)))
        .await
        .unwrap_or_else(|error| panic!("restore persisted corruption fixture: {error}"));
    failure_injector.corrupt_activity_user_id().await;
    let corrupted = repository
        .scan_activity_page(&page)
        .await
        .expect_err("corrupt persisted identifier must fail");
    assert!(matches!(
        corrupted,
        TelemetryRepositoryError::InvalidPersistedField {
            field: "user_id",
            ..
        }
    ));

    failure_injector.corrupt_lifecycle_event_kind().await;
    let corrupted = repository
        .scan_lifecycle_page(&page)
        .await
        .expect_err("corrupt persisted enum must fail");
    assert!(matches!(
        corrupted,
        TelemetryRepositoryError::UnknownEnum {
            field: "event_kind",
            ..
        }
    ));
}

async fn assert_database_error_rolls_back<I>(
    repository: Arc<dyn TelemetryRepository>,
    failure_injector: &I,
) where
    I: MidTransactionFailureInjector,
{
    let before = repository
        .scan_activity_page(
            &TelemetryScanPageRequest::new(
                TelemetryScanRequest::new(
                    tenant("tenant-a"),
                    timestamp(1_735_689_600),
                    timestamp(1_735_693_200),
                    timestamp(1_735_693_200),
                )
                .unwrap_or_else(|error| panic!("fault-injection range: {error}"))
                .with_include_partial(true),
                100,
                None,
            )
            .unwrap_or_else(|error| panic!("fault-injection page: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("fault-injection baseline scan: {error}"))
        .rows()
        .len();

    failure_injector.drop_lifecycle_table().await;
    let result = repository
        .upsert_batch(&batch_at(
            "tenant-a",
            "user-database-error",
            timestamp(1_735_689_600),
        ))
        .await;
    assert!(
        result.is_err(),
        "missing lifecycle table must fail the batch"
    );

    repository
        .migrate()
        .await
        .unwrap_or_else(|error| panic!("recreate lifecycle table: {error}"));
    let after = repository
        .scan_activity_page(
            &TelemetryScanPageRequest::new(
                TelemetryScanRequest::new(
                    tenant("tenant-a"),
                    timestamp(1_735_689_600),
                    timestamp(1_735_693_200),
                    timestamp(1_735_693_200),
                )
                .unwrap_or_else(|error| panic!("fault-injection post-range: {error}"))
                .with_include_partial(true),
                100,
                None,
            )
            .unwrap_or_else(|error| panic!("fault-injection post-page: {error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("fault-injection post-scan: {error}"))
        .rows()
        .len();
    assert_eq!(
        before, after,
        "database failure must roll back earlier writes"
    );
}

#[tokio::test]
async fn libsql_repository_contract() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let database = libsql::Builder::new_local(directory.path().join("telemetry.db"))
        .build()
        .await
        .unwrap_or_else(|error| panic!("libSQL database: {error}"));
    let database = Arc::new(database);
    let runtime = Arc::new(
        LibSqlRuntime::new(Arc::clone(&database))
            .unwrap_or_else(|error| panic!("libSQL runtime: {error}")),
    );
    let admission_probe = Arc::new(CountingAdmissionObserver::default());
    let repository = Arc::new(LibSqlTelemetryRepository::from_runtime_with_observer(
        Arc::clone(&runtime),
        admission_probe.clone(),
    ));
    assert_repository_contract(repository, &database, &admission_probe).await;
}

#[tokio::test]
async fn postgres_repository_contract() {
    let Some((container, pool)) = postgres_pool_or_skip().await else {
        return;
    };
    let admission_probe = Arc::new(CountingAdmissionObserver::default());
    let repository = Arc::new(PostgresTelemetryRepository::with_admission_observer(
        pool.clone(),
        admission_probe.clone(),
    ));
    assert_repository_contract(repository, &pool, &admission_probe).await;
    drop(container);
}

async fn postgres_pool_or_skip() -> Option<(
    testcontainers_modules::testcontainers::ContainerAsync<
        testcontainers_modules::postgres::Postgres,
    >,
    deadpool_postgres::Pool,
)> {
    use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};

    let image = testcontainers_modules::postgres::Postgres::default()
        .with_db_name("ironclaw_test")
        .with_user("postgres")
        .with_password("postgres")
        .with_tag("16-alpine");
    let container = match image.start().await {
        Ok(container) => container,
        Err(error) => {
            if std::env::var_os("IRONCLAW_REQUIRE_POSTGRES").is_some() {
                panic!("PostgreSQL is required but Docker could not start it: {error}");
            }
            eprintln!("skipping PostgreSQL telemetry contract: {error}");
            return None;
        }
    };
    let host_port = container
        .get_host_port_ipv4(5432)
        .await
        .unwrap_or_else(|error| panic!("PostgreSQL host port: {error}"));
    let config: tokio_postgres::Config = format!(
        "host=127.0.0.1 port={host_port} user=postgres password=postgres dbname=ironclaw_test"
    )
    .parse()
    .unwrap_or_else(|error| panic!("PostgreSQL test config: {error}"));
    let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
    let pool = deadpool_postgres::Pool::builder(manager)
        .max_size(4)
        .build()
        .unwrap_or_else(|error| panic!("PostgreSQL test pool: {error}"));
    if let Err(error) = pool.get().await {
        if std::env::var_os("IRONCLAW_REQUIRE_POSTGRES").is_some() {
            panic!("PostgreSQL is required but unavailable: {error}");
        }
        eprintln!("skipping PostgreSQL telemetry contract: {error}");
        return None;
    }
    Some((container, pool))
}
