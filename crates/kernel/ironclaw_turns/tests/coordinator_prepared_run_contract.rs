//! Pins for the coordinator's `prepare_turn` scope-binding reservation.
//!
//! `prepare_turn` mints a run id without side effects and records the scope it
//! was prepared under; `submit_turn` consumes that reservation and rejects a
//! cross-scope submission so a prepared id cannot inject lineage into a
//! different scope. Subagent spawn legitimately prepares an id in the parent
//! scope and submits under a child scope, which is exempted via
//! `parent_run_id`. These semantics were previously untested; the AgentExecution
//! seam (Phase 2) moves conversation submission behind a port that must keep
//! them byte-identical, so this file is part of that migration evidence.

use chrono::{TimeZone, Utc};
use ironclaw_host_api::ids::{AgentId, ProjectId, TenantId, ThreadId, UserId};
use ironclaw_turns::{
    AcceptedMessageRef, DefaultTurnCoordinator, GetRunStateRequest, IdempotencyKey,
    ReplyTargetBindingRef, RunProfileRequest, SourceBindingRef, SubmitTurnRequest,
    SubmitTurnResponse, TurnActor, TurnCapacityResource, TurnCoordinator, TurnError, TurnRunId,
    TurnScope, test_support::in_memory_agent_turn_process_system,
};
use std::sync::Arc;

fn scope_for_thread(thread: &str) -> TurnScope {
    TurnScope::new(
        TenantId::new("tenant-prepared-run").expect("tenant"),
        Some(AgentId::new("agent-prepared-run").expect("agent")),
        Some(ProjectId::new("project-prepared-run").expect("project")),
        ThreadId::new(thread).expect("thread"),
    )
}

fn submit_request(
    scope: TurnScope,
    requested_run_id: Option<TurnRunId>,
    parent_run_id: Option<TurnRunId>,
    idempotency_key: &str,
) -> SubmitTurnRequest {
    SubmitTurnRequest {
        scope,
        actor: TurnActor::new(UserId::new("user-prepared-run").expect("user")),
        accepted_message_ref: AcceptedMessageRef::new("message-prepared-run").expect("accepted"),
        source_binding_ref: SourceBindingRef::new("source-prepared-run").expect("source"),
        reply_target_binding_ref: ReplyTargetBindingRef::new("reply-prepared-run").expect("reply"),
        requested_run_profile: Some(RunProfileRequest::new("default").expect("profile")),
        requested_model: None,
        idempotency_key: IdempotencyKey::new(idempotency_key).expect("idempotency key"),
        received_at: Utc.with_ymd_and_hms(2026, 8, 13, 12, 0, 0).unwrap(),
        requested_run_id,
        parent_run_id,
        subagent_depth: 0,
        spawn_tree_root_run_id: None,
        product_context: None,
    }
}

#[tokio::test]
async fn prepared_run_id_is_consumed_on_first_submit_in_the_prepared_scope() {
    let processes = in_memory_agent_turn_process_system();
    let coordinator = DefaultTurnCoordinator::new(Arc::new(processes.runtime()));
    let scope = scope_for_thread("thread-prepared-same-scope");

    let prepared = coordinator
        .prepare_turn(scope.clone())
        .await
        .expect("prepare turn");

    let response = coordinator
        .submit_turn(submit_request(
            scope.clone(),
            Some(prepared),
            None,
            "idem-prepared-same-scope",
        ))
        .await
        .expect("submit under the prepared scope");
    let SubmitTurnResponse::Accepted { run_id, .. } = response;
    assert_eq!(run_id, prepared, "the prepared id must become the run id");

    let state = coordinator
        .get_run_state(GetRunStateRequest {
            scope,
            run_id: prepared,
        })
        .await
        .expect("run state for the admitted prepared run");
    assert_eq!(state.run_id, prepared);
}

#[tokio::test]
async fn prepared_run_id_rejects_cross_scope_submission_without_a_parent() {
    let processes = in_memory_agent_turn_process_system();
    let coordinator = DefaultTurnCoordinator::new(Arc::new(processes.runtime()));
    let prepared_scope = scope_for_thread("thread-prepared-origin");
    let foreign_scope = scope_for_thread("thread-prepared-foreign");

    let prepared = coordinator
        .prepare_turn(prepared_scope.clone())
        .await
        .expect("prepare turn");

    let error = coordinator
        .submit_turn(submit_request(
            foreign_scope.clone(),
            Some(prepared),
            None,
            "idem-prepared-cross-scope",
        ))
        .await
        .expect_err("cross-scope submission of a prepared id must be rejected");
    assert_eq!(error, TurnError::Unauthorized);

    // Nothing was admitted under either scope for the rejected id.
    for scope in [prepared_scope, foreign_scope.clone()] {
        let state = coordinator
            .get_run_state(GetRunStateRequest {
                scope,
                run_id: prepared,
            })
            .await;
        assert_eq!(
            state.expect_err("the rejected prepared id must not have been admitted"),
            TurnError::ScopeNotFound
        );
    }

    // The reservation is consumed by the FIRST submit attempt, even a rejected
    // one: a retry of the same wrong-scope submission is no longer caught by
    // the coordinator reservation check and falls through to the store, which
    // admits it as an ordinary run in the submitted scope. This pins the
    // documented consume-on-first-attempt semantics.
    let retried = coordinator
        .submit_turn(submit_request(
            foreign_scope,
            Some(prepared),
            None,
            "idem-prepared-cross-scope-retry",
        ))
        .await
        .expect("post-consumption retry falls back to store admission");
    let SubmitTurnResponse::Accepted { run_id, .. } = retried;
    assert_eq!(run_id, prepared);
}

#[tokio::test]
async fn prepared_run_id_cross_scope_submission_with_a_parent_is_exempt() {
    let processes = in_memory_agent_turn_process_system();
    let coordinator = DefaultTurnCoordinator::new(Arc::new(processes.runtime()));
    let parent_scope = scope_for_thread("thread-prepared-parent");
    let child_scope = scope_for_thread("thread-prepared-child");

    // Subagent spawn prepares the child id under the parent scope and submits
    // it under the child scope; `parent_run_id` marks the submission as a
    // child run, which skips the cross-scope rejection.
    let prepared = coordinator
        .prepare_turn(parent_scope.clone())
        .await
        .expect("prepare turn");
    let parent_run_id = TurnRunId::new();

    let response = coordinator
        .submit_turn(submit_request(
            child_scope,
            Some(prepared),
            Some(parent_run_id),
            "idem-prepared-child-exempt",
        ))
        .await
        .expect("child-run submission under a different scope is exempt");
    let SubmitTurnResponse::Accepted { run_id, .. } = response;
    assert_eq!(run_id, prepared);
}

#[tokio::test]
async fn abort_prepared_turn_releases_the_reservation() {
    let processes = in_memory_agent_turn_process_system();
    let coordinator = DefaultTurnCoordinator::new(Arc::new(processes.runtime()));
    let prepared_scope = scope_for_thread("thread-prepared-abort-origin");
    let other_scope = scope_for_thread("thread-prepared-abort-other");

    let prepared = coordinator
        .prepare_turn(prepared_scope)
        .await
        .expect("prepare turn");
    coordinator
        .abort_prepared_turn(prepared)
        .await
        .expect("abort prepared turn");

    // With the reservation released, the id is an ordinary requested run id:
    // submitting it under a different scope is no longer a cross-scope
    // violation of a live reservation.
    let response = coordinator
        .submit_turn(submit_request(
            other_scope,
            Some(prepared),
            None,
            "idem-prepared-after-abort",
        ))
        .await
        .expect("submission after abort is not bound to the prepared scope");
    let SubmitTurnResponse::Accepted { run_id, .. } = response;
    assert_eq!(run_id, prepared);
}

#[tokio::test]
async fn prepare_turn_reservations_are_capped() {
    let processes = in_memory_agent_turn_process_system();
    let coordinator = DefaultTurnCoordinator::new(Arc::new(processes.runtime()));
    let scope = scope_for_thread("thread-prepared-cap");

    // MAX_PREPARED_RUN_IDS reservations succeed; the next one fails closed
    // with the submit-turn capacity resource instead of growing unbounded.
    const PREPARED_RUN_ID_CAP: u64 = 4096;
    for _ in 0..PREPARED_RUN_ID_CAP {
        coordinator
            .prepare_turn(scope.clone())
            .await
            .expect("prepare within the reservation cap");
    }
    let error = coordinator
        .prepare_turn(scope)
        .await
        .expect_err("reservations beyond the cap must be rejected");
    assert_eq!(
        error,
        TurnError::CapacityExceeded {
            resource: TurnCapacityResource::SubmitTurn,
            cap: PREPARED_RUN_ID_CAP,
        }
    );
}
