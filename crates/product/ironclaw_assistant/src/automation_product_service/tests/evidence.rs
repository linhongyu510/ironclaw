use ironclaw_event_log::{DurableEventLog, InMemoryDurableEventLog, RuntimeEvent};
use ironclaw_event_projections::ReplayEventProjectionService;
use ironclaw_host_api::{
    ids::{ExtensionId, InvocationId},
    resource::ResourceScope,
    runtime::RuntimeKind,
};
use ironclaw_triggers::{TriggerRunEvidenceScope, TriggerRunEvidenceSource};

use super::*;

#[test]
fn deterministic_assessment_never_treats_missing_required_action_as_success() {
    let run = make_run_record(TriggerId::new(), TriggerRunHistoryStatus::Ok);
    let required = vec![CapabilityId::new("builtin.outbound_deliver").expect("capability id")];

    let assessment = super::super::assess_run(&run, &required, Some(&[]));

    assert_eq!(
        assessment.status,
        crate::RebornAutomationAssessmentStatus::Unverified
    );
    assert_eq!(assessment.capabilities.len(), 1);
    assert_eq!(
        assessment.capabilities[0].status,
        crate::RebornAutomationCapabilityEvidenceStatus::Missing
    );
}

#[tokio::test]
async fn automation_list_projects_displayed_run_evidence_despite_unrelated_saturation() {
    let repo = Arc::new(InMemoryTriggerRepository::default());
    let c = caller();
    let trigger_id = TriggerId::new();
    let capability_id = CapabilityId::new("builtin.outbound_deliver").expect("capability id");
    let mut record = make_record(
        trigger_id,
        &c,
        TriggerState::Scheduled,
        "Evidence-backed trigger",
        "* * * * *",
    );
    let spec = ironclaw_triggers::TriggerExecutionSpec {
        version: 1,
        goal: "Deliver the report".to_string(),
        success_criteria: vec!["The report is delivered".to_string()],
        output_instructions: "Confirm delivery".to_string(),
        no_result_text: "No report was available".to_string(),
        required_capability_ids: vec![capability_id.clone()],
        policy: TurnExecutionPolicy {
            allowed_capability_ids: Some(vec![capability_id.clone()]),
            required_skills: Vec::new(),
            result_delivery: ResultDeliveryPolicy::Deliver,
        },
    };
    record.prompt = spec.render_prompt();
    record.execution_spec = Some(spec);
    let fire_slot = record.next_run_at;
    let thread_id = ThreadId::new("01890f0f-test-7000-8000-0000000000bb").expect("valid thread id");
    let run_id = seed_accepted_run(&repo, record, thread_id.clone()).await;
    repo.clear_active_fire(ClearActiveFireRequest {
        tenant_id: c.tenant_id.clone(),
        trigger_id,
        fire_slot,
        run_id,
        status: TriggerRunHistoryStatus::Ok,
    })
    .await
    .expect("settle run");

    let log = Arc::new(InMemoryDurableEventLog::new());
    for _ in 0..ironclaw_event_projections::MAX_PROJECTION_PAGE_LIMIT {
        let unrelated_scope = ResourceScope {
            tenant_id: c.tenant_id.clone(),
            user_id: c.user_id.clone(),
            agent_id: Some(c.agent_id.clone()),
            project_id: c.project_id.clone(),
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        };
        let mut unrelated =
            RuntimeEvent::capability_activity_requested(unrelated_scope, capability_id.clone());
        unrelated.parent_invocation_id = Some(InvocationId::new());
        log.append(unrelated).await.expect("append unrelated");
    }
    let scope = ResourceScope {
        tenant_id: c.tenant_id.clone(),
        user_id: c.user_id.clone(),
        agent_id: Some(c.agent_id.clone()),
        project_id: c.project_id.clone(),
        mission_id: None,
        thread_id: Some(thread_id),
        invocation_id: InvocationId::new(),
    };
    let parent_run = InvocationId::from_uuid(run_id.as_uuid());
    let mut requested =
        RuntimeEvent::capability_activity_requested(scope.clone(), capability_id.clone());
    requested.parent_invocation_id = Some(parent_run);
    log.append(requested).await.expect("append requested");
    let mut succeeded = RuntimeEvent::capability_activity_succeeded(
        scope,
        capability_id,
        ExtensionId::new("builtin").expect("extension id"),
        RuntimeKind::FirstParty,
        32,
    );
    succeeded.parent_invocation_id = Some(parent_run);
    log.append(succeeded).await.expect("append succeeded");

    let service = service_over(repo).with_run_evidence(Arc::new(
        super::super::ProjectedTriggerRunEvidenceSource::new(Arc::new(
            ReplayEventProjectionService::new(log),
        )),
    ));
    let automations = service
        .list_automations(c, automation_list_request(10, 1))
        .await
        .expect("list automations");
    let assessment = automations[0].recent_runs[0]
        .assessment
        .as_ref()
        .expect("structured terminal run has assessment");

    assert_eq!(
        assessment.status,
        crate::RebornAutomationAssessmentStatus::AppearsSuccessful
    );
    assert_eq!(
        assessment.capabilities[0].status,
        crate::RebornAutomationCapabilityEvidenceStatus::Succeeded
    );
}

#[tokio::test]
async fn projected_run_evidence_fails_closed_when_selected_output_is_saturated() {
    let c = caller();
    let capability_id = CapabilityId::new("builtin.outbound_deliver").expect("capability id");
    let run_id = TurnRunId::new();
    let log = Arc::new(InMemoryDurableEventLog::new());
    for _ in 0..=ironclaw_event_projections::MAX_PROJECTION_PAGE_LIMIT {
        let scope = ResourceScope {
            tenant_id: c.tenant_id.clone(),
            user_id: c.user_id.clone(),
            agent_id: Some(c.agent_id.clone()),
            project_id: c.project_id.clone(),
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        };
        let mut requested =
            RuntimeEvent::capability_activity_requested(scope, capability_id.clone());
        requested.parent_invocation_id = Some(InvocationId::from_uuid(run_id.as_uuid()));
        log.append(requested).await.expect("append requested");
    }
    let source = super::super::ProjectedTriggerRunEvidenceSource::new(Arc::new(
        ReplayEventProjectionService::new(log),
    ));
    let evidence_scope = TriggerRunEvidenceScope {
        tenant_id: c.tenant_id,
        user_id: c.user_id,
        agent_id: Some(c.agent_id),
        project_id: c.project_id,
    };

    let result = source
        .list_capability_evidence(&evidence_scope, &[run_id])
        .await;

    assert!(
        matches!(
            result,
            Err(ironclaw_triggers::TriggerRunEvidenceError::Unavailable)
        ),
        "a saturated selected-run projection cannot prove that older evidence is absent"
    );
}
