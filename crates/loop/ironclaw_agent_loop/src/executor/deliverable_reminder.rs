//! Budget-threshold reminders about file deliverables the run has not produced.
//!
//! The failure this addresses is narrow and repeatable: a run reasons well,
//! says "now I'll write the report", and ends without a file. Benchmark run
//! 410dfedf lost `task_meeting_advisory_technical` (judge 0.89) and
//! `task_meeting_tech_messaging` (judge 0.90) exactly that way.
//!
//! Everything here is deterministic. The requirement comes from paths the user
//! wrote out in the request ([`ironclaw_loop_contracts::deliverable`]); the
//! absence comes from a host stat; the timing comes from budget counters. No
//! model call decides whether to fire, and nothing here ever writes the file or
//! claims it exists.

use ironclaw_loop_contracts::{
    LoopInlineMessage, LoopInlineMessageBody, LoopInlineMessagePlacement, LoopInlineMessageRole,
    deliverable::DeliverablePath,
};

use crate::state::{DeliverableReminder, DeliverableReminderLevel};

use super::AgentLoopExecutorError;

const REMINDER_APPROACHING: &str =
    include_str!("../../prompts/deliverable_reminder_approaching.md");
const REMINDER_FINAL: &str = include_str!("../../prompts/deliverable_reminder_final.md");

/// Budget fraction at which the first reminder fires.
pub(super) const APPROACHING_THRESHOLD: f64 = 0.80;
/// Budget fraction at which the firmer, final reminder fires.
pub(super) const FINAL_THRESHOLD: f64 = 0.90;

/// The reminder level a given budget-consumed fraction warrants, if any.
pub(super) fn level_for_consumed(consumed: f64) -> Option<DeliverableReminderLevel> {
    if consumed >= FINAL_THRESHOLD {
        Some(DeliverableReminderLevel::Final)
    } else if consumed >= APPROACHING_THRESHOLD {
        Some(DeliverableReminderLevel::Approaching)
    } else {
        None
    }
}

/// Remaining wall clock as whole minutes, rounded to nearest.
///
/// Coarse on purpose: see [`DeliverableReminder::remaining_minutes`].
fn remaining_minutes(remaining_seconds: u64) -> u64 {
    (remaining_seconds + 30) / 60
}

/// The opening sentence, which states the deadline only when there IS one.
///
/// A run with no declared wall-clock budget still gets a reminder — the
/// threshold that fired it came from the iteration budget — but it gets no
/// invented number.
fn budget_status(remaining: Option<u64>) -> String {
    match remaining {
        Some(0) => "Less than a minute of this run's time budget remains.".to_string(),
        Some(1) => "About 1 minute of this run's time budget remains.".to_string(),
        Some(minutes) => format!("About {minutes} minutes of this run's time budget remain."),
        None => "This run is near the end of its budget.".to_string(),
    }
}

pub(super) fn build_reminder(
    level: DeliverableReminderLevel,
    missing: &[DeliverablePath],
    remaining_seconds: Option<u64>,
) -> DeliverableReminder {
    DeliverableReminder {
        level,
        missing_paths: missing
            .iter()
            .map(|path| path.as_str().to_string())
            .collect(),
        remaining_minutes: remaining_seconds.map(remaining_minutes),
    }
}

/// Render a scheduled reminder as a TAIL inline message.
///
/// Tail placement is deliberate: the leading system block stays byte-identical
/// so the cached prompt prefix survives, and the instruction lands next to the
/// work it is about.
pub(super) fn reminder_control_message(
    reminder: &DeliverableReminder,
) -> Result<LoopInlineMessage, AgentLoopExecutorError> {
    let template = match reminder.level {
        DeliverableReminderLevel::Approaching => REMINDER_APPROACHING,
        DeliverableReminderLevel::Final => REMINDER_FINAL,
    };
    let missing = reminder
        .missing_paths
        .iter()
        .map(|path| format!("- {path}"))
        .collect::<Vec<_>>()
        .join("\n");
    let body = template
        .trim()
        .replace(
            "{BUDGET_STATUS}",
            &budget_status(reminder.remaining_minutes),
        )
        .replace("{MISSING_PATHS}", &missing);
    let safe_body =
        LoopInlineMessageBody::new(body).map_err(|_| AgentLoopExecutorError::PlannerContract {
            detail: "deliverable-reminder control text was invalid",
        })?;
    Ok(LoopInlineMessage {
        role: LoopInlineMessageRole::User,
        safe_body,
        placement: LoopInlineMessagePlacement::Tail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> DeliverablePath {
        DeliverablePath::new(value).expect("valid deliverable path")
    }

    #[test]
    fn thresholds_select_the_matching_level() {
        assert_eq!(level_for_consumed(0.0), None);
        assert_eq!(level_for_consumed(0.79), None);
        assert_eq!(
            level_for_consumed(0.80),
            Some(DeliverableReminderLevel::Approaching)
        );
        assert_eq!(
            level_for_consumed(0.89),
            Some(DeliverableReminderLevel::Approaching)
        );
        assert_eq!(
            level_for_consumed(0.90),
            Some(DeliverableReminderLevel::Final)
        );
        assert_eq!(
            level_for_consumed(1.5),
            Some(DeliverableReminderLevel::Final)
        );
    }

    #[test]
    fn remaining_time_is_reported_in_whole_minutes() {
        assert_eq!(remaining_minutes(0), 0);
        assert_eq!(remaining_minutes(29), 0);
        assert_eq!(remaining_minutes(30), 1);
        assert_eq!(remaining_minutes(60), 1);
        assert_eq!(remaining_minutes(200), 3);
        assert_eq!(remaining_minutes(209), 3);
    }

    /// The no-deadline case is the one that must never invent a number: a run
    /// without a declared wall-clock budget is still reminded (the iteration
    /// threshold fired it), but the text says nothing about time.
    #[test]
    fn a_run_without_a_wall_clock_budget_gets_no_time_claim() {
        let reminder = build_reminder(
            DeliverableReminderLevel::Approaching,
            &[path("/workspace/report.md")],
            None,
        );
        assert_eq!(reminder.remaining_minutes, None);
        let body = reminder_control_message(&reminder)
            .expect("reminder renders")
            .safe_body
            .as_str()
            .to_string();
        assert!(body.contains("/workspace/report.md"), "{body}");
        assert!(body.contains("near the end of its budget"), "{body}");
        for invented in ["minute", "second", "hour", "%"] {
            assert!(
                !body.contains(invented),
                "a run with no declared deadline must not describe time ({invented:?}): {body}"
            );
        }
    }

    /// Singular/plural and the sub-minute floor all read as English.
    #[test]
    fn the_time_clause_is_coarse_and_grammatical() {
        assert_eq!(
            budget_status(Some(0)),
            "Less than a minute of this run's time budget remains."
        );
        assert_eq!(
            budget_status(Some(1)),
            "About 1 minute of this run's time budget remains."
        );
        assert_eq!(
            budget_status(Some(3)),
            "About 3 minutes of this run's time budget remain."
        );
    }

    /// The reminder names the exact missing paths and rides at the TAIL, and it
    /// states facts without declaring the task failed.
    #[test]
    fn the_message_names_the_missing_paths_at_the_tail() {
        let reminder = build_reminder(
            DeliverableReminderLevel::Approaching,
            &[path("/workspace/report.md"), path("/workspace/data.csv")],
            Some(185),
        );
        let message = reminder_control_message(&reminder).expect("reminder renders");
        assert_eq!(message.placement, LoopInlineMessagePlacement::Tail);
        let body = message.safe_body.as_str();
        assert!(body.contains("/workspace/report.md"), "{body}");
        assert!(body.contains("/workspace/data.csv"), "{body}");
        assert!(body.contains("About 3 minutes"), "{body}");
        assert!(!body.contains("{MISSING_PATHS}"), "{body}");
        assert!(!body.contains("{BUDGET_STATUS}"), "{body}");
        for forbidden in ["failed", "failure", "you have failed"] {
            assert!(
                !body.to_ascii_lowercase().contains(forbidden),
                "the reminder states facts, it does not declare failure: {body}"
            );
        }
    }

    #[test]
    fn the_final_level_renders_the_firmer_text() {
        let reminder = build_reminder(
            DeliverableReminderLevel::Final,
            &[path("/workspace/out.md")],
            Some(45),
        );
        let message = reminder_control_message(&reminder).expect("reminder renders");
        let body = message.safe_body.as_str();
        assert!(body.contains("/workspace/out.md"), "{body}");
        assert!(body.contains("About 1 minute"), "{body}");
        assert!(
            body.contains("only thing left to do"),
            "the final level must read more firmly than the first: {body}"
        );
    }
}
