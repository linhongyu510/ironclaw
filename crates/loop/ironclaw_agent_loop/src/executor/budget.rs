use async_trait::async_trait;
use ironclaw_loop_contracts::{LoopExit, LoopFailureKind};

use crate::state::{CheckpointKind, LoopExecutionState, TerminalWarningObservation};

use super::{
    AgentLoopExecutorError, CancelCheck, CheckpointStage, ExecutorStage, FailedExitDetails,
    StageContext, attach_failure_explanation, deliverable_reminder, failed_exit,
};

/// Consumed share of one budget axis. An absent or zero ceiling contributes
/// nothing rather than dividing by zero.
fn fraction(used: u64, limit: u64) -> f64 {
    if limit == 0 {
        return 0.0;
    }
    used as f64 / limit as f64
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct BudgetStage;

pub(super) struct BudgetInput {
    pub(super) state: LoopExecutionState,
}

#[derive(Debug)]
pub(super) enum BudgetStep {
    Continue { state: Box<LoopExecutionState> },
    Exit(LoopExit),
}

impl BudgetStage {
    /// Terminal budget exit: cancel-check, explained failure, final
    /// checkpoint, failed exit. Unlike the iteration backstop there is no
    /// model-visible warning iteration — an exhausted budget is a hard stop.
    async fn hard_budget_exit(
        &self,
        ctx: StageContext<'_>,
        state: LoopExecutionState,
        kind: LoopFailureKind,
    ) -> Result<BudgetStep, AgentLoopExecutorError> {
        let mut state = match CheckpointStage.cancel_if_requested(ctx, state).await? {
            CancelCheck::Continue(state) => *state,
            CancelCheck::Exit(exit) => return Ok(BudgetStep::Exit(exit)),
        };
        let explanation_message_ref = attach_failure_explanation(ctx, &mut state, kind).await?;
        let checked = CheckpointStage
            .write(ctx, state, CheckpointKind::Final)
            .await?;
        Ok(BudgetStep::Exit(failed_exit(
            ctx.host,
            checked.state,
            kind,
            Some(checked.checkpoint_id),
            FailedExitDetails {
                safe_summary: None,
                explanation_message_ref,
            },
        )?))
    }
}

#[async_trait]
impl ExecutorStage<BudgetInput> for BudgetStage {
    type Output = BudgetStep;

    async fn process(
        &self,
        ctx: StageContext<'_>,
        input: BudgetInput,
    ) -> Result<BudgetStep, AgentLoopExecutorError> {
        let mut state = input.state;

        // Resource budget ceilings from the resolved run profile (narrowed
        // per-run by declared `TurnLimits` at admission). Each is a hard
        // stop after a final checkpoint.
        let policy = ctx
            .host
            .run_context()
            .resolved_run_profile
            .resource_budget_policy
            .clone();

        let strategy_wall_clock = ctx
            .planner
            .budget()
            .wall_clock_limit(&state)
            .map(|duration| u32::try_from(duration.as_secs()).unwrap_or(u32::MAX));
        let wall_clock_limit_seconds = match (policy.max_wall_clock_seconds, strategy_wall_clock) {
            (Some(policy_cap), Some(strategy_cap)) => Some(policy_cap.min(strategy_cap)),
            (policy_cap, strategy_cap) => policy_cap.or(strategy_cap),
        };
        // Boundary check: the wall-clock ceiling is evaluated only on stage
        // entry (once per loop iteration), not continuously. A single
        // in-flight model or capability call that overruns the ceiling is
        // not interrupted mid-call — the run only stops once control returns
        // to this stage on the NEXT iteration. This is consistent with the
        // budget stage's enforcement granularity generally (a hard stop
        // after the next checkpoint boundary, not a preemptive cutoff).
        let mut wall_clock_elapsed_seconds: Option<u64> = None;
        // Declared budget minus elapsed, and ONLY when a wall-clock budget
        // exists. With no declared budget there is no deadline to report, and
        // the reminder must omit its time clause rather than invent a number.
        let mut wall_clock_remaining_seconds: Option<u64> = None;
        if let Some(limit_seconds) = wall_clock_limit_seconds {
            let now = chrono::Utc::now();
            // First pass arms the clock (initial state carries no timestamp
            // so it stays deterministic); older checkpoints without the
            // field re-arm from resume time instead of failing the run.
            let started_at = state.budget_ledger.arm_wall_clock(now);
            let elapsed = now.signed_duration_since(started_at).num_seconds();
            if elapsed >= i64::from(limit_seconds) {
                return self
                    .hard_budget_exit(ctx, state, LoopFailureKind::WallClockLimit)
                    .await;
            }
            let elapsed = u64::try_from(elapsed).unwrap_or(0);
            wall_clock_elapsed_seconds = Some(elapsed);
            wall_clock_remaining_seconds = Some(u64::from(limit_seconds).saturating_sub(elapsed));
        }

        if state.budget_ledger.model_calls_made() >= policy.max_model_calls {
            return self
                .hard_budget_exit(ctx, state, LoopFailureKind::ModelCallLimit)
                .await;
        }

        if state.budget_ledger.capability_invocations_made() >= policy.max_capability_invocations {
            return self
                .hard_budget_exit(ctx, state, LoopFailureKind::CapabilityInvocationLimit)
                .await;
        }

        let iteration_limit = ctx.planner.budget().iteration_limit(&state);

        // Deliverable reminder. Budget consumption is the MAX across the axes
        // that can actually stop this run, because whichever runs out first is
        // the one that matters. Dormant unless the host reports a required file
        // confirmed missing, so a run with no extracted deliverable never even
        // reaches the stat.
        let mut consumed = fraction(u64::from(state.iteration), u64::from(iteration_limit));
        consumed = consumed.max(fraction(
            u64::from(state.budget_ledger.model_calls_made()),
            u64::from(policy.max_model_calls),
        ));
        if let Some(elapsed) = wall_clock_elapsed_seconds
            && let Some(limit_seconds) = wall_clock_limit_seconds
        {
            consumed = consumed.max(fraction(elapsed, u64::from(limit_seconds)));
        }
        if let Some(level) = deliverable_reminder::level_for_consumed(consumed)
            && state.deliverable_reminder.can_fire(level)
        {
            let missing = ctx.host.missing_deliverables().await;
            if !missing.is_empty() {
                tracing::debug!(
                    component = "agent_loop",
                    operation = "deliverable_reminder",
                    ?level,
                    missing = missing.len(),
                    consumed,
                    "scheduling a deliverable reminder for the next model request"
                );
                state
                    .deliverable_reminder
                    .schedule(deliverable_reminder::build_reminder(
                        level,
                        &missing,
                        wall_clock_remaining_seconds,
                    ));
            }
        }

        if state.iteration < iteration_limit
            || state.terminal_warning_state.pending().is_some()
            || state.terminal_warning_state.active().is_some()
        {
            return Ok(BudgetStep::Continue {
                state: Box::new(state),
            });
        }

        if state
            .terminal_warning_state
            .schedule(TerminalWarningObservation::iteration_limit(iteration_limit))
        {
            return Ok(BudgetStep::Continue {
                state: Box::new(state),
            });
        }

        // The one model-visible final iteration was already consumed: preserve
        // the existing explained terminal failure.
        self.hard_budget_exit(ctx, state, LoopFailureKind::IterationLimit)
            .await
    }
}
