//! Reborn integration test — mid-run queued-message steering (E-GATEWAY seam).
//!
//! Proves the queued-steering journey end-to-end through the real stack: a
//! message submitted while the thread's run is mid-model-call is accepted as
//! `DeferredBusy` and stored `Queued` (not rejected), the running loop drains
//! it as steering input, the transcript row flips `Queued` → `Submitted`, and
//! — the load-bearing assertion — the steering text reaches a subsequent
//! model request through the real prompt rebuild, shaping the final reply.
//!
//! The parked model call doubles as the end-of-turn race: the steering input
//! arrives while the run's FINAL scripted model call is in flight, so it is
//! only observable at the reply-only exit boundary. Without the follow-up
//! drain consuming `Steering` inputs (and without the drain-time ack that
//! makes the row model-visible before the next prompt build), the run would
//! complete with the message stranded or silently unseen.

#[allow(dead_code)]
#[path = "support/mod.rs"]
mod reborn_support;
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;

use std::time::Duration;

use ironclaw_product_contracts::inbound::ProductInboundAck;
use ironclaw_threads::MessageStatus;
use ironclaw_turns::TurnStatus;
use reborn_support::builder::RebornIntegrationHarness;
use reborn_support::reply::RebornScriptedReply;
use reborn_support::scripted_provider::ParkingModelGate;

/// The full mid-run steering journey:
///
/// 1. Turn A parks inside its (final) model call.
/// 2. Message B submitted on the busy thread → `DeferredBusy` ack, transcript
///    row `Queued` and bound to run A — never `RejectedBusy`.
/// 3. Release the park: run A's reply-only exit drains B as steering input,
///    forces one more model iteration, and completes.
/// 4. B's text appears in a model request (the real prompt rebuild carried
///    it), the final reply is the steered script entry, and B's transcript
///    row is `Submitted`, still bound to run A.
#[tokio::test]
async fn queued_steering_message_reaches_the_model_mid_run() {
    let gate = ParkingModelGate::new();
    let harness = RebornIntegrationHarness::test_default()
        .park_model(gate.clone())
        .script([
            RebornScriptedReply::text("first reply before steering"),
            RebornScriptedReply::text("steered reply"),
        ])
        .build()
        .await
        .expect("harness builds");

    let run_id = harness
        .submit_turn_async("start a long task")
        .await
        .expect("turn A submitted");
    tokio::time::timeout(Duration::from_secs(10), gate.wait_until_parked())
        .await
        .expect("model call parks before the timeout");

    // Submit B while A is mid-model-call: accepted and queued as steering.
    let ack = harness
        .submit_turn_ack("steer the task toward blue")
        .await
        .expect("busy submit does not error");
    let ProductInboundAck::DeferredBusy { active_run_id, .. } = ack else {
        panic!("expected DeferredBusy while the thread has an active run, got {ack:?}");
    };
    assert_eq!(
        active_run_id, run_id,
        "the deferred ack must name run A as the consuming run"
    );
    let queued = harness
        .user_message_record("steer the task toward blue")
        .await
        .expect("queued message persisted");
    assert_eq!(
        queued.status,
        MessageStatus::Queued,
        "the busy-thread message must be stored Queued, not RejectedBusy"
    );
    assert_eq!(
        queued.turn_run_id.as_deref(),
        Some(run_id.to_string().as_str()),
        "the Queued row must be bound to run A"
    );

    // Release the park: A's reply-only exit must drain B and keep iterating.
    gate.release();
    harness
        .wait_for_status(run_id, TurnStatus::Completed)
        .await
        .expect("run A completes after consuming the steering input");

    harness
        .assert_model_saw_user_message("steer the task toward blue")
        .await
        .expect("the steering text must reach a model request");
    harness
        .assert_reply_contains("steered reply")
        .await
        .expect("the final reply is the post-steering script entry");
    let consumed = harness
        .user_message_record("steer the task toward blue")
        .await
        .expect("steering message still in transcript");
    assert_eq!(
        consumed.status,
        MessageStatus::Submitted,
        "the consumed steering row must flip Queued → Submitted"
    );
    assert_eq!(
        consumed.turn_run_id.as_deref(),
        Some(run_id.to_string().as_str()),
        "the Submitted row keeps its binding to run A"
    );
}

/// Cancel-time queue reconciliation (conversation-binding rule 12): a run
/// cancelled before draining its steering queue has its still-queued messages
/// flipped `Queued` → `RejectedBusy` by the cancel-time reconciler and NEVER
/// auto-resubmitted — the user resends; the thread is free for the next turn.
///
/// This is the root-tier pin of the behavior `CancelReconcilingTurnCoordinator`
/// (wired in this harness exactly as in production composition) provides; the
/// composition-tier twin is
/// `deferred_busy_message_not_auto_submitted_after_run_cancellation`.
#[tokio::test]
async fn cancelled_run_flips_queued_steering_to_rejected_busy_without_resubmit() {
    let gate = ParkingModelGate::new();
    let harness = RebornIntegrationHarness::test_default()
        .park_model(gate.clone())
        .script([
            RebornScriptedReply::text("should never be finalized"),
            RebornScriptedReply::text("next turn done"),
        ])
        .build()
        .await
        .expect("harness builds");

    let run_id = harness
        .submit_turn_async("start a long task")
        .await
        .expect("turn A submitted");
    tokio::time::timeout(Duration::from_secs(10), gate.wait_until_parked())
        .await
        .expect("model call parks before the timeout");

    // Queue B behind the parked run.
    let ack = harness
        .submit_turn_ack("steer the doomed task")
        .await
        .expect("busy submit does not error");
    let ProductInboundAck::DeferredBusy { active_run_id, .. } = ack else {
        panic!("expected DeferredBusy while the thread has an active run, got {ack:?}");
    };
    assert_eq!(active_run_id, run_id);
    let queued = harness
        .user_message_record("steer the doomed task")
        .await
        .expect("queued message persisted");
    assert_eq!(queued.status, MessageStatus::Queued);

    // Cancel A while parked, then release so the loop observes the cancel.
    harness.cancel_run(run_id).await.expect("cancel accepted");
    gate.release();
    harness
        .wait_for_status(run_id, TurnStatus::Cancelled)
        .await
        .expect("parked run reaches Cancelled after cancel");

    // The queued row settles RejectedBusy — reconciled, never resubmitted.
    let reconciled = harness
        .user_message_record("steer the doomed task")
        .await
        .expect("reconciled message still in transcript");
    assert_eq!(
        reconciled.status,
        MessageStatus::RejectedBusy,
        "cancel-time reconciliation must flip the stranded row Queued → RejectedBusy"
    );

    // Never auto-resubmitted: the steering text must not have reached any
    // model request, and no run was minted for it.
    assert!(
        harness
            .assert_model_saw_user_message("steer the doomed task")
            .await
            .is_err(),
        "a reconciled steering message must never reach a model request"
    );

    // The thread is free: the next submission is accepted and completes.
    harness
        .submit_turn("do the next thing")
        .await
        .expect("next turn on the freed thread completes");
    harness
        .assert_reply_contains("next turn done")
        .await
        .expect("next turn's reply persisted");
}

/// The durable steering guarantee across a restart (review: High): a message
/// queued behind a run parked on a durable approval gate survives a full
/// planned-runtime restart over the same LibSQL store — the resumed run drains
/// the persisted input, the row flips `Queued` → `Submitted`, and the steering
/// text reaches the post-restart model request.
#[tokio::test]
async fn queued_steering_survives_runtime_restart() {
    use reborn_support::builder::StorageMode;
    use reborn_support::group::RebornIntegrationGroup;

    let group = RebornIntegrationGroup::builder()
        .storage(StorageMode::LibSql)
        .live_approvals()
        .await
        .expect("durable live-approvals group builds");
    let before_restart = group
        .thread("steering-restart")
        .script([
            RebornScriptedReply::tool_call(
                "builtin.write_file",
                serde_json::json!({
                    "path": "/workspace/steering-restart.txt",
                    "content": "written across restart"
                }),
            ),
            RebornScriptedReply::text("unreachable on the old runtime"),
        ])
        .build()
        .await
        .expect("pre-restart thread builds");
    let (run_id, gate_ref) = before_restart
        .submit_turn_until_blocked("start gated work")
        .await
        .expect("run parks on the durable approval gate");

    // Busy submit while parked: accepted, stored Queued, durably enqueued.
    let ack = before_restart
        .submit_turn_ack("steer the gated work toward blue")
        .await
        .expect("busy submit does not error");
    assert!(
        matches!(ack, ProductInboundAck::DeferredBusy { .. }),
        "expected DeferredBusy while parked on the gate, got {ack:?}"
    );
    let queued = before_restart
        .user_message_record("steer the gated work toward blue")
        .await
        .expect("queued row persisted");
    assert_eq!(queued.status, MessageStatus::Queued);

    // Restart the whole planned runtime over the same durable store.
    drop(before_restart);
    let restarted_group = group
        .restart_planned_runtime()
        .await
        .expect("planned runtime restarts over durable state");
    let after_restart = restarted_group
        .thread("steering-restart")
        .script([RebornScriptedReply::text("steered reply after restart")])
        .build()
        .await
        .expect("post-restart thread rebuilds the scope gateway");

    after_restart
        .approve_gate(run_id, &gate_ref)
        .await
        .expect("approval resolves after restart");
    after_restart
        .wait_for_status(run_id, TurnStatus::Completed)
        .await
        .expect("resumed run completes after draining the persisted steering input");

    after_restart
        .assert_model_saw_user_message("steer the gated work toward blue")
        .await
        .expect("the persisted steering text must reach a post-restart model request");
    let consumed = after_restart
        .user_message_record("steer the gated work toward blue")
        .await
        .expect("steering row still in transcript");
    assert_eq!(
        consumed.status,
        MessageStatus::Submitted,
        "the resumed run must flip the persisted row Queued → Submitted"
    );
}
