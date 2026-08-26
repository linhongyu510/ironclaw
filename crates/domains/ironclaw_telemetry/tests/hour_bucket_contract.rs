use chrono::{DateTime, TimeZone, Utc};
use ironclaw_host_api::{
    ids::{TenantId, UserId},
    turn::SanitizedFailure,
};
use ironclaw_telemetry::records::{HourlyUserActivity, RecordError};
use ironclaw_telemetry::{
    AggregationError, aggregate_batch, floor_utc_day, floor_utc_hour, floor_utc_month,
    floor_utc_year,
};
use ironclaw_telemetry_contracts::observation::{
    AutomationId, AutomationKind, AutomationSettledObservation, EffectiveModelId, LifecycleEventId,
    LifecycleEventKind, LifecycleSubjectKind, LifecycleTransitionObservation,
    ModelCallCompletedObservation, ObservationContext, OriginKind, ProviderId, RunOutcome,
    RunSettledObservation, TelemetryObservation,
};

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("valid tenant")
}

fn user() -> UserId {
    UserId::new("user-a").expect("valid user")
}

fn at(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
        .expect("valid timestamp")
}

fn context(timestamp: DateTime<Utc>) -> ObservationContext {
    ObservationContext::new(tenant(), user(), timestamp)
}

fn completed_run(timestamp: DateTime<Utc>, duration_ms: u64) -> TelemetryObservation {
    TelemetryObservation::RunSettled(
        RunSettledObservation::new(
            context(timestamp),
            OriginKind::Human,
            RunOutcome::Completed,
            duration_ms,
            Some(0),
            None,
        )
        .expect("valid run observation"),
    )
}

#[test]
fn utc_floor_is_exact_at_hour_day_month_and_year_boundaries() {
    let timestamp = at(2026, 8, 26, 10, 23, 45);

    assert_eq!(floor_utc_hour(timestamp), at(2026, 8, 26, 10, 0, 0));
    assert_eq!(floor_utc_day(timestamp), at(2026, 8, 26, 0, 0, 0));
    assert_eq!(floor_utc_month(timestamp), at(2026, 8, 1, 0, 0, 0));
    assert_eq!(floor_utc_year(timestamp), at(2026, 1, 1, 0, 0, 0));
    assert_eq!(
        floor_utc_hour(at(2026, 8, 26, 10, 0, 0)),
        at(2026, 8, 26, 10, 0, 0)
    );
}

#[test]
fn utc_floor_does_not_reinterpret_dst_transitions() {
    let spring_transition = at(2026, 3, 8, 10, 30, 0);
    let fall_transition = at(2026, 11, 1, 8, 30, 0);

    assert_eq!(floor_utc_hour(spring_transition), at(2026, 3, 8, 10, 0, 0));
    assert_eq!(floor_utc_hour(fall_transition), at(2026, 11, 1, 8, 0, 0));
}

#[test]
fn aggregate_is_order_independent_and_reconciles_terminal_counts() {
    let failure = SanitizedFailure::new("model_unavailable").expect("sanitized category");
    let failed = TelemetryObservation::RunSettled(
        RunSettledObservation::new(
            context(at(2026, 8, 26, 10, 24, 0)),
            OriginKind::Human,
            RunOutcome::Failed,
            20,
            Some(3),
            Some(failure),
        )
        .expect("valid failed run"),
    );
    let model = TelemetryObservation::ModelCallCompleted(
        ModelCallCompletedObservation::new(
            context(at(2026, 8, 26, 10, 25, 0)),
            ProviderId::new("provider-a").expect("provider"),
            EffectiveModelId::new("model-a").expect("model"),
            None,
        )
        .expect("valid model call"),
    );
    let automation = TelemetryObservation::AutomationSettled(
        AutomationSettledObservation::new(
            context(at(2026, 8, 26, 10, 26, 0)),
            AutomationId::new("automation-a").expect("automation"),
            AutomationKind::Cron,
            RunOutcome::Cancelled,
        )
        .expect("valid automation"),
    );
    let lifecycle = TelemetryObservation::LifecycleTransition(
        LifecycleTransitionObservation::new(
            tenant(),
            Some(user()),
            LifecycleEventId::new("event-a").expect("event"),
            LifecycleEventKind::RoutineCreated,
            LifecycleSubjectKind::Routine,
            "routine-a".to_owned(),
            at(2026, 8, 26, 10, 27, 0),
        )
        .expect("valid lifecycle"),
    );
    let duplicate_lifecycle = lifecycle.clone();

    let ordered = vec![
        completed_run(at(2026, 8, 26, 10, 23, 0), 10),
        failed.clone(),
        model.clone(),
        automation.clone(),
        lifecycle.clone(),
        duplicate_lifecycle.clone(),
    ];
    let reversed = vec![
        duplicate_lifecycle,
        automation,
        model,
        lifecycle,
        failed,
        completed_run(at(2026, 8, 26, 10, 23, 0), 10),
    ];

    let first = aggregate_batch(&ordered).expect("ordered aggregate");
    let second = aggregate_batch(&reversed).expect("reversed aggregate");

    assert_eq!(first, second);
    assert_eq!(first.activity().len(), 1);
    let activity = &first.activity()[0];
    assert_eq!(activity.run_count(), 2);
    assert_eq!(activity.completed_count(), 1);
    assert_eq!(activity.failed_count(), 1);
    assert_eq!(activity.cancelled_count(), 0);
    assert_eq!(activity.recovery_required_count(), 0);
    assert_eq!(
        activity.completed_count()
            + activity.failed_count()
            + activity.cancelled_count()
            + activity.recovery_required_count(),
        activity.run_count()
    );
    assert_eq!(first.model_usage()[0].inference_count(), 1);
    assert_eq!(first.model_usage()[0].usage_reported_count(), 0);
    assert_eq!(first.lifecycle_events().len(), 1);
}

#[test]
fn aggregate_reports_checked_counter_overflow() {
    let observations = [
        completed_run(at(2026, 8, 26, 10, 0, 0), u64::MAX),
        completed_run(at(2026, 8, 26, 10, 1, 0), 1),
    ];

    assert!(matches!(
        aggregate_batch(&observations),
        Err(AggregationError::CounterOverflow { .. })
    ));
}

#[test]
fn hourly_activity_constructor_rejects_unreconciled_terminal_counts() {
    let timestamp = at(2026, 8, 26, 10, 0, 0);
    let result = HourlyUserActivity::new(
        tenant(),
        timestamp,
        user(),
        OriginKind::Human,
        2,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        10,
        timestamp,
        timestamp,
    );

    assert!(matches!(result, Err(RecordError::TerminalCountMismatch)));
}
