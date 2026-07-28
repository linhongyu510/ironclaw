//! Generated lifecycle sequences over a gated run (#6524 workstream 9).
//!
//! The hand-written gate tests each drive one path: approve, or deny, or
//! cancel. The transitions nobody writes by hand are the ones that go wrong —
//! resolving a gate twice, cancelling something already finished, approving a
//! run that was cancelled a moment earlier. Those are exactly the races a real
//! client produces by double-clicking or retrying.
//!
//! This enumerates every ordering of a small action alphabet rather than
//! sampling randomly. Enumeration is reproducible, and at this size it is also
//! complete, so a failure names the exact sequence instead of a seed. That is
//! the "representative equivalence classes rather than the full Cartesian
//! product" the workstream asks for: the alphabet is the equivalence class,
//! and short orderings of it cover the interesting adjacencies.
//!
//! Invariants asserted after EVERY transition, not just at the end:
//!   1. a terminal run never becomes non-terminal again — which covers
//!      re-parking a finished run, since every gate status is non-terminal;
//!   2. a cancelled run never later reports Completed;
//!   3. every sequence lands terminal.
//!
//! Actions are applied unconditionally rather than only when "legal": refusing
//! an action that no longer applies is the behaviour under test, so the run
//! must survive being approved after it was cancelled.
//!
//! An earlier draft carried a fourth assertion for "a finished run returned to
//! a gate". Its self-test showed invariant 1 always fires first, because a
//! gate status is never terminal — so it could not fail on its own and was
//! removed rather than left as reassuring dead weight.

#[allow(dead_code)]
#[path = "support/mod.rs"]
mod reborn_support;
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;

use ironclaw_turns::TurnStatus;
use reborn_support::group::RebornIntegrationGroup;
use reborn_support::reply::RebornScriptedReply;
use serde_json::json;

/// One dimension of workstream 9's lifecycle axis: what a client can do to a
/// run parked on an approval gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GateAction {
    Approve,
    Deny,
    Cancel,
    /// Resolve the same gate a second time with the same ref — the shape a
    /// double-clicked approve button produces.
    ApproveAgain,
}

const ALPHABET: [GateAction; 4] = [
    GateAction::Approve,
    GateAction::Deny,
    GateAction::Cancel,
    GateAction::ApproveAgain,
];

/// Every ordering of `ALPHABET` up to `max_len`, shortest first.
fn sequences(max_len: usize) -> Vec<Vec<GateAction>> {
    let mut out: Vec<Vec<GateAction>> = Vec::new();
    let mut frontier: Vec<Vec<GateAction>> = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in &frontier {
            for action in ALPHABET {
                let mut candidate = prefix.clone();
                candidate.push(action);
                next.push(candidate);
            }
        }
        out.extend(next.iter().cloned());
        frontier = next;
    }
    out
}

struct Observed {
    statuses: Vec<TurnStatus>,
}

impl Observed {
    fn record(&mut self, status: TurnStatus, sequence: &[GateAction], step: usize) {
        if let Some(previous) = self.statuses.last().copied() {
            // (1) terminal is absorbing.
            assert!(
                !previous.is_terminal() || status.is_terminal(),
                "{sequence:?} step {step}: {previous:?} -> {status:?} left a terminal state"
            );
        }
        // (2) cancellation is not silently overridden by a later completion.
        if self.statuses.contains(&TurnStatus::Cancelled) {
            assert_ne!(
                status,
                TurnStatus::Completed,
                "{sequence:?} step {step}: a cancelled run reported Completed"
            );
        }
        self.statuses.push(status);
    }
}

async fn run_sequence(sequence: &[GateAction]) {
    let group = RebornIntegrationGroup::live_approvals()
        .await
        .expect("live-approvals group builds");
    let thread = format!(
        "gen-gate-{}",
        sequence
            .iter()
            .map(|action| format!("{action:?}"))
            .collect::<Vec<_>>()
            .join("-")
            .to_lowercase()
    );
    let h = group
        .thread(thread)
        .script([
            RebornScriptedReply::tool_call(
                "builtin.write_file",
                json!({"path": "/workspace/generated.txt", "content": "generated"}),
            ),
            RebornScriptedReply::text("done"),
        ])
        .build()
        .await
        .expect("thread builds");

    let (run_id, gate_ref) = h
        .submit_turn_until_blocked("write the generated file")
        .await
        .expect("turn parks on the approval gate");

    let mut observed = Observed {
        statuses: Vec::new(),
    };
    let parked = h
        .run_state(run_id)
        .await
        .expect("parked run is readable")
        .status;
    observed.record(parked, sequence, 0);

    for (step, action) in sequence.iter().enumerate() {
        // Deliberately unconditional: refusing an action that no longer
        // applies is the contract being tested, so the harness result is
        // allowed to be an error. What must never happen is the run coming
        // back to life, which `record` checks below.
        match action {
            GateAction::Approve | GateAction::ApproveAgain => {
                let _ = h.approve_gate(run_id, &gate_ref).await;
            }
            GateAction::Deny => {
                let _ = h.deny_gate(run_id, &gate_ref).await;
            }
            GateAction::Cancel => {
                let _ = h.cancel_run(run_id).await;
            }
        }
        let status = h
            .run_state(run_id)
            .await
            .expect("run stays readable after every action")
            .status;
        observed.record(status, sequence, step + 1);
    }

    // (3) every sequence settles. Read through `wait_for_terminal` so a run
    // still converging is given the same grace the product gives it.
    let final_state = h
        .wait_for_terminal(run_id)
        .await
        .unwrap_or_else(|err| panic!("{sequence:?} never reached a terminal state: {err:?}"));
    assert!(
        final_state.status.is_terminal(),
        "{sequence:?} settled on {:?}",
        final_state.status
    );
}

#[tokio::test]
async fn generated_gate_sequences_preserve_lifecycle_invariants() {
    let sequences = sequences(2);
    assert!(
        sequences.len() >= ALPHABET.len(),
        "enumeration produced {} sequences; an empty or truncated list would \
         pass this test while checking nothing",
        sequences.len()
    );
    for sequence in sequences {
        run_sequence(&sequence).await;
    }
}

/// The invariant checker is itself checked.
///
/// The sequences above pass, which on its own is also what a checker that
/// asserts nothing would produce. These feed `Observed` the transitions the
/// product must never make and require it to reject them, so a future edit
/// that loosens `record` fails here rather than going quiet.
#[cfg(test)]
mod invariant_checker {
    use super::*;

    fn observed_with(statuses: &[TurnStatus]) -> Observed {
        let mut observed = Observed {
            statuses: Vec::new(),
        };
        for (index, status) in statuses.iter().enumerate() {
            observed.record(*status, &[GateAction::Cancel], index);
        }
        observed
    }

    #[test]
    #[should_panic(expected = "left a terminal state")]
    fn rejects_a_terminal_run_becoming_active_again() {
        observed_with(&[TurnStatus::Cancelled, TurnStatus::Running]);
    }

    /// Re-parking a finished run is rejected by invariant 1, not by a rule of
    /// its own: a gate status is never terminal, so leaving the terminal state
    /// is the thing that fires. Pinned so a future split into a separate
    /// assertion does not quietly create an unreachable one.
    #[test]
    #[should_panic(expected = "left a terminal state")]
    fn rejects_a_finished_run_returning_to_a_gate() {
        observed_with(&[TurnStatus::Completed, TurnStatus::BlockedApproval]);
    }

    #[test]
    #[should_panic(expected = "a cancelled run reported Completed")]
    fn rejects_a_cancelled_run_completing() {
        observed_with(&[TurnStatus::Cancelled, TurnStatus::Completed]);
    }

    #[test]
    fn accepts_an_ordinary_settling_sequence() {
        observed_with(&[
            TurnStatus::BlockedApproval,
            TurnStatus::Running,
            TurnStatus::Completed,
        ]);
    }
}
