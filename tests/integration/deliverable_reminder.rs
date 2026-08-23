//! Whole-turn coverage for the deliverable reminder.
//!
//! The failure being pinned: a run reasons well, answers in chat, and never
//! writes the file it was asked for. Benchmark run 410dfedf lost
//! `task_meeting_advisory_technical` (judge 0.89, no report) and
//! `task_meeting_tech_messaging` (judge 0.90, empty final response) that way.
//!
//! These tests drive the REAL loop through the harness: the real budget stage
//! computes consumption, the real driver host stats the REAL workspace file on
//! disk, and the assertion is made where it matters — on the outgoing model
//! request. Nothing here stubs the decision to fire.

#[allow(dead_code)]
#[path = "support/mod.rs"]
mod reborn_support;
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;

use std::num::NonZeroU32;

use reborn_support::builder::RebornIntegrationHarness;
use reborn_support::reply::RebornScriptedReply;
use serde_json::json;

const DELIVERABLE: &str = "/workspace/report.md";
/// A phrase unique to the 80% reminder text.
const APPROACHING_MARKER: &str = "A complete answer in chat is not the deliverable";
/// A phrase unique to the 90% reminder text.
const FINAL_MARKER: &str = "Writing them is the only thing left to do";

/// Ten iterations puts the 80% threshold at iteration 8 and 90% at iteration 9,
/// so a scripted run can sit on either side of both deliberately.
const ITERATION_LIMIT: u32 = 10;

fn busywork() -> RebornScriptedReply {
    RebornScriptedReply::tool_call("bash", json!({ "command": "printf 'working'" }))
}

/// Filler turns that carry the run from iteration 0 to iteration 8, where the
/// first threshold is crossed.
fn busywork_up_to_the_first_threshold() -> Vec<RebornScriptedReply> {
    (0..8).map(|_| busywork()).collect()
}

fn write_the_deliverable() -> RebornScriptedReply {
    RebornScriptedReply::tool_call(
        "write",
        json!({ "path": DELIVERABLE, "content": "# Report\n\nFindings.\n" }),
    )
}

/// (i) The request names a file, the budget passes 80%, the file is not there —
/// the next model request carries a reminder naming that exact path.
#[tokio::test]
async fn a_missing_deliverable_is_named_back_to_the_model_at_the_budget_threshold() {
    let mut script = busywork_up_to_the_first_threshold();
    script.push(RebornScriptedReply::text("here is my analysis"));

    let h = RebornIntegrationHarness::test_default()
        .with_coding_tools()
        .with_iteration_limit_for_test(NonZeroU32::new(ITERATION_LIMIT).expect("nonzero"))
        .script(script)
        .build()
        .await
        .expect("harness builds");

    h.submit_turn(&format!(
        "Review the notes and write the findings to {DELIVERABLE}"
    ))
    .await
    .expect("turn completes");

    h.assert_workspace_file_absent("report.md")
        .await
        .expect("the run never wrote the deliverable");
    h.assert_model_message_content_contains(DELIVERABLE)
        .await
        .expect("the reminder names the exact missing path");
    h.assert_model_message_content_contains(APPROACHING_MARKER)
        .await
        .expect("the 80% reminder reaches the model");
}

/// (ii) Once the file exists, the next threshold stays silent. The check is a
/// real stat, so writing the file genuinely retires the reminder.
#[tokio::test]
async fn writing_the_deliverable_stops_the_next_reminder() {
    let mut script = busywork_up_to_the_first_threshold();
    // Iteration 8 carries the 80% reminder; the model answers it by writing.
    script.push(write_the_deliverable());
    // Iteration 9 crosses 90% with the file now on disk.
    script.push(RebornScriptedReply::text("report written"));

    let h = RebornIntegrationHarness::test_default()
        .with_coding_tools()
        .with_iteration_limit_for_test(NonZeroU32::new(ITERATION_LIMIT).expect("nonzero"))
        .script(script)
        .build()
        .await
        .expect("harness builds");

    h.submit_turn(&format!(
        "Review the notes and write the findings to {DELIVERABLE}"
    ))
    .await
    .expect("turn completes");

    h.assert_workspace_file_contains("report.md", "Findings.")
        .await
        .expect("the deliverable really landed on disk");
    h.assert_model_message_content_contains(APPROACHING_MARKER)
        .await
        .expect("the 80% reminder still fired before the file existed");
    h.assert_no_model_message_content_contains(FINAL_MARKER)
        .await
        .expect("a produced deliverable must not be chased again at 90%");
}

/// (iii) The dormancy guarantee. No path in the request means no requirement,
/// so no reminder can ever appear — however long the run gets.
#[tokio::test]
async fn a_request_naming_no_file_never_sees_a_reminder() {
    let mut script = busywork_up_to_the_first_threshold();
    script.push(RebornScriptedReply::text("here is my analysis"));

    let h = RebornIntegrationHarness::test_default()
        .with_coding_tools()
        .with_iteration_limit_for_test(NonZeroU32::new(ITERATION_LIMIT).expect("nonzero"))
        .script(script)
        .build()
        .await
        .expect("harness builds");

    h.submit_turn("Review the notes and tell me what you find")
        .await
        .expect("turn completes");

    h.assert_no_model_message_content_contains(APPROACHING_MARKER)
        .await
        .expect("no deliverable was requested, so nothing may be chased");
    h.assert_no_model_message_content_contains(FINAL_MARKER)
        .await
        .expect("no deliverable was requested, so nothing may be chased");
    // Not asserted here: the absence of "/workspace" anywhere in the prompt.
    // The coding tool descriptions legitimately mention that mount, so the
    // meaningful claim is the one above — no REMINDER was produced.
    h.assert_no_model_message_content_contains("do not exist yet")
        .await
        .expect("no file is described to the model as missing");
}

/// (iv) Each threshold fires at most once. A run that stays past both
/// thresholds without producing the file gets exactly one reminder per level,
/// not one per iteration.
#[tokio::test]
async fn each_threshold_fires_at_most_once() {
    let mut script = busywork_up_to_the_first_threshold();
    // Iterations 8 and 9 both sit past a threshold with the file still missing.
    script.push(busywork());
    script.push(RebornScriptedReply::text("here is my analysis"));

    let h = RebornIntegrationHarness::test_default()
        .with_coding_tools()
        .with_iteration_limit_for_test(NonZeroU32::new(ITERATION_LIMIT).expect("nonzero"))
        .script(script)
        .build()
        .await
        .expect("harness builds");

    h.submit_turn(&format!(
        "Review the notes and write the findings to {DELIVERABLE}"
    ))
    .await
    .expect("turn completes");

    h.assert_workspace_file_absent("report.md")
        .await
        .expect("the run never wrote the deliverable");
    assert_eq!(
        h.count_model_requests_containing(APPROACHING_MARKER).await,
        1,
        "the 80% reminder must ride exactly one model request"
    );
    assert_eq!(
        h.count_model_requests_containing(FINAL_MARKER).await,
        1,
        "the 90% reminder must ride exactly one model request"
    );
}
