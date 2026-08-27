use chrono::{TimeZone, Utc};
use ironclaw_host_api::{
    ids::{InvocationId, TenantId, UserId},
    resource::ResourceScope,
    turn::SanitizedFailure,
};
use ironclaw_telemetry_contracts::observation::{
    AutomationId, AutomationKind, AutomationSettledObservation, BoundedIdentifierError,
    EffectiveModelId, FailureCategory, LifecycleEventId, LifecycleEventKind, LifecycleSubjectKind,
    LifecycleTransitionObservation, ModelCallCompletedObservation, ModelUsage, ObservationContext,
    ObservationError, OriginKind, ProviderId, RunOutcome, RunSettledObservation,
    TelemetryObservation,
};
use ironclaw_telemetry_contracts::recorder::{
    NoopTelemetryRecorder, RecordOutcome, TelemetryRecorder,
};

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("valid tenant")
}

fn user() -> UserId {
    UserId::new("user-a").expect("valid user")
}

fn occurred_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 26, 10, 23, 45)
        .single()
        .expect("valid timestamp")
}

fn context() -> ObservationContext {
    ObservationContext::new(occurred_at())
}

fn scope() -> ResourceScope {
    ResourceScope {
        tenant_id: tenant(),
        user_id: user(),
        agent_id: None,
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

#[test]
fn all_four_observation_variants_are_typed_and_constructible() {
    let run = RunSettledObservation::new(
        context(),
        OriginKind::Human,
        RunOutcome::Completed,
        42,
        Some(2),
        None,
    )
    .expect("valid run observation");
    let model = ModelCallCompletedObservation::new(
        context(),
        ProviderId::new("provider-a").expect("provider"),
        EffectiveModelId::new("model-a").expect("model"),
        Some(ModelUsage::new(10, 20, 3, 4)),
    )
    .expect("valid model observation");
    let automation = AutomationSettledObservation::new(
        context(),
        AutomationId::new("automation-a").expect("automation"),
        AutomationKind::Cron,
        RunOutcome::Failed,
    )
    .expect("valid automation observation");
    let lifecycle = LifecycleTransitionObservation::new(
        Some(user()),
        LifecycleEventId::new("event-a").expect("event"),
        LifecycleEventKind::MemberAdded,
        LifecycleSubjectKind::User,
        "user-a".to_owned(),
        occurred_at(),
    )
    .expect("valid lifecycle observation");

    let observations = [
        TelemetryObservation::RunSettled(run),
        TelemetryObservation::ModelCallCompleted(model),
        TelemetryObservation::AutomationSettled(automation),
        TelemetryObservation::LifecycleTransition(lifecycle),
    ];
    assert_eq!(observations.len(), 4);
}

#[test]
fn recorder_port_is_synchronous_and_has_distinct_loss_outcomes() {
    struct TestRecorder;

    impl TelemetryRecorder for TestRecorder {
        fn try_record(
            &self,
            _scope: ResourceScope,
            _observation: TelemetryObservation,
        ) -> RecordOutcome {
            RecordOutcome::Accepted
        }
    }

    let recorder = TestRecorder;
    let outcome = recorder.try_record(
        scope(),
        TelemetryObservation::RunSettled(
            RunSettledObservation::new(
                context(),
                OriginKind::Human,
                RunOutcome::Completed,
                0,
                None,
                None,
            )
            .expect("valid run observation"),
        ),
    );
    assert_eq!(outcome, RecordOutcome::Accepted);
    assert_ne!(
        RecordOutcome::DroppedQueueFull,
        RecordOutcome::DroppedClosed
    );
    assert_ne!(RecordOutcome::DroppedClosed, RecordOutcome::DroppedInvalid);
}

#[test]
fn lifecycle_subject_identity_is_optional_and_separate_from_scope() {
    let tenant_level_lifecycle = LifecycleTransitionObservation::new(
        None,
        LifecycleEventId::new("event-tenant").expect("event"),
        LifecycleEventKind::MemberAdded,
        LifecycleSubjectKind::Tenant,
        "tenant-a".to_owned(),
        occurred_at(),
    )
    .expect("tenant-level lifecycle may omit a subject user");
    assert!(tenant_level_lifecycle.subject_user_id().is_none());

    let subject_user = LifecycleTransitionObservation::new(
        Some(UserId::new("subject-user").expect("subject user")),
        LifecycleEventId::new("event-user").expect("event"),
        LifecycleEventKind::MemberAdded,
        LifecycleSubjectKind::User,
        "user-a".to_owned(),
        occurred_at(),
    )
    .expect("subject user is a separate bounded fact");
    assert_eq!(
        subject_user.subject_user_id().map(UserId::as_str),
        Some("subject-user")
    );
}

#[test]
fn recorder_receives_trusted_scope_separately_from_observation_facts() {
    struct CapturingRecorder(std::sync::Mutex<Option<ResourceScope>>);

    impl TelemetryRecorder for CapturingRecorder {
        fn try_record(
            &self,
            scope: ResourceScope,
            _observation: TelemetryObservation,
        ) -> RecordOutcome {
            *self.0.lock().expect("capture lock") = Some(scope);
            RecordOutcome::Accepted
        }
    }

    let recorder = CapturingRecorder(std::sync::Mutex::new(None));
    let expected_scope = scope();
    let outcome = recorder.try_record(
        expected_scope.clone(),
        TelemetryObservation::RunSettled(
            RunSettledObservation::new(
                context(),
                OriginKind::Human,
                RunOutcome::Completed,
                0,
                None,
                None,
            )
            .expect("valid run observation"),
        ),
    );

    assert_eq!(outcome, RecordOutcome::Accepted);
    assert_eq!(
        recorder.0.lock().expect("capture lock").as_ref(),
        Some(&expected_scope)
    );
}

#[test]
fn no_op_recorder_drops_without_observing_payload_fields() {
    let recorder = NoopTelemetryRecorder;
    let outcome = recorder.try_record(
        scope(),
        TelemetryObservation::RunSettled(
            RunSettledObservation::new(
                context(),
                OriginKind::Human,
                RunOutcome::Completed,
                0,
                None,
                None,
            )
            .expect("valid run observation"),
        ),
    );

    assert_eq!(outcome, RecordOutcome::DroppedClosed);
}

#[test]
fn identifiers_enforce_utf8_byte_limits() {
    let at_limit = "a".repeat(128);
    assert!(ProviderId::new(at_limit.clone()).is_ok());
    assert!(EffectiveModelId::new(format!("{at_limit}a")).is_err());

    let multibyte_at_limit = format!("{}é", "a".repeat(126));
    assert_eq!(multibyte_at_limit.len(), 128);
    assert!(AutomationId::new(multibyte_at_limit).is_ok());

    let too_long = format!("{}é", "a".repeat(127));
    assert_eq!(too_long.len(), 129);
    assert!(matches!(
        LifecycleEventId::new(too_long),
        Err(BoundedIdentifierError::TooLong { .. })
    ));
}

#[test]
fn failed_runs_require_only_the_sanitized_failure_category() {
    let failure = SanitizedFailure::new("model_unavailable").expect("sanitized category");
    assert!(
        RunSettledObservation::new(
            context(),
            OriginKind::Human,
            RunOutcome::Failed,
            42,
            None,
            Some(failure.clone()),
        )
        .is_ok()
    );
    assert!(matches!(
        RunSettledObservation::new(
            context(),
            OriginKind::Human,
            RunOutcome::Failed,
            42,
            None,
            None,
        ),
        Err(ObservationError::FailureRequired)
    ));
    assert!(matches!(
        RunSettledObservation::new(
            context(),
            OriginKind::Human,
            RunOutcome::Completed,
            42,
            None,
            Some(failure),
        ),
        Err(ObservationError::UnexpectedFailure)
    ));
}

#[test]
fn arbitrary_trusted_static_failure_categories_use_fallible_telemetry_conversion() {
    let failure = SanitizedFailure::from_trusted_static("arbitrary_failure_category");

    let category = FailureCategory::from_sanitized_failure(&failure)
        .expect("trusted-static categories are validated by telemetry");
    assert_eq!(category.as_str(), "arbitrary_failure_category");

    let observation = RunSettledObservation::new(
        context(),
        OriginKind::Human,
        RunOutcome::Failed,
        42,
        None,
        Some(failure),
    )
    .expect("arbitrary trusted-static category should remain supported");
    assert_eq!(
        observation.failure().map(FailureCategory::as_str),
        Some("arbitrary_failure_category")
    );
}

#[test]
fn missing_model_usage_keeps_inference_but_marks_usage_unreported() {
    let observation = ModelCallCompletedObservation::new(
        context(),
        ProviderId::new("provider-a").expect("provider"),
        EffectiveModelId::new("model-a").expect("model"),
        None,
    )
    .expect("valid model observation");

    assert_eq!(observation.inference_count(), 1);
    assert!(!observation.usage_reported());
    assert_eq!(observation.input_tokens(), 0);
    assert_eq!(observation.output_tokens(), 0);
    assert_eq!(observation.cache_read_input_tokens(), 0);
    assert_eq!(observation.cache_creation_input_tokens(), 0);
}

#[test]
fn durable_counter_values_above_signed_bigint_are_rejected() {
    let too_large = i64::MAX as u64 + 1;

    let run = RunSettledObservation::new(
        context(),
        OriginKind::Human,
        RunOutcome::Completed,
        too_large,
        None,
        None,
    );
    assert!(run.is_err());

    let model = ModelCallCompletedObservation::new(
        context(),
        ProviderId::new("provider-a").expect("provider"),
        EffectiveModelId::new("model-a").expect("model"),
        Some(ModelUsage::new(too_large, 0, 0, 0)),
    );
    assert!(model.is_err());
}
