use std::sync::Arc;

use chrono::Utc;
use ironclaw_host_api::ids::AgentId;
use ironclaw_loop_contracts::{
    SystemInferenceIdentity, SystemInferencePort, SystemInferenceRequest, SystemInferenceTaskId,
    SystemPromptId, SystemPromptSource, SystemTaskKind,
};
use ironclaw_threads::{FinalizedAssistantMessageByRunRequest, SessionThreadService, ThreadScope};
use ironclaw_triggers::{
    TriggerFire, TriggerRepository, TriggerSemanticEvaluation, TriggerSemanticVerdict,
};
use ironclaw_turns::{TurnCoordinator, TurnRunId, TurnScope, TurnStatus};
use serde::Deserialize;

use super::{RunDeliverySettings, triggered_run_delivery_settings, wait_for_actionable_state};

const SYSTEM_PROMPT: &str = include_str!("prompts/semantic_evaluation.md");
const MAX_INPUT_TOKENS: u64 = 12_000;
const DEADLINE_MS: u64 = 30_000;
const MAX_MODEL_OUTPUT_BYTES: usize = 2_048;
const MAX_REASON_CHARS: usize = 500;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeOutput {
    satisfied: bool,
    reason: String,
}

/// Watches a structured trigger run to completion and stores one independent
/// semantic verdict. Delivery remains a separate post-submit consumer.
pub struct SemanticRunEvaluator {
    repository: Arc<dyn TriggerRepository>,
    turn_coordinator: Arc<dyn TurnCoordinator>,
    thread_service: Arc<dyn SessionThreadService>,
    inference: Arc<dyn Fn() -> Arc<dyn SystemInferencePort> + Send + Sync>,
    fallback_agent_id: AgentId,
    settings: RunDeliverySettings,
}

impl SemanticRunEvaluator {
    pub fn new(
        repository: Arc<dyn TriggerRepository>,
        turn_coordinator: Arc<dyn TurnCoordinator>,
        thread_service: Arc<dyn SessionThreadService>,
        inference: Arc<dyn Fn() -> Arc<dyn SystemInferencePort> + Send + Sync>,
        fallback_agent_id: AgentId,
    ) -> Self {
        Self {
            repository,
            turn_coordinator,
            thread_service,
            inference,
            fallback_agent_id,
            settings: triggered_run_delivery_settings(),
        }
    }

    pub async fn on_trigger_submitted(
        &self,
        fire: TriggerFire,
        run_id: TurnRunId,
        scope: TurnScope,
    ) {
        match wait_for_actionable_state(
            self.turn_coordinator.as_ref(),
            &scope,
            run_id,
            &self.settings,
            None,
        )
        .await
        {
            Ok(state) if state.status == TurnStatus::Completed => {}
            Ok(_) => return,
            Err(error) => {
                tracing::warn!(%run_id, %error, "semantic evaluation could not observe terminal run");
                return;
            }
        }
        let trigger = match self
            .repository
            .get_trigger(fire.identity.tenant_id.clone(), fire.identity.trigger_id)
            .await
        {
            Ok(Some(trigger)) => trigger,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%run_id, %error, "semantic evaluation could not load trigger");
                return;
            }
        };
        let Some(spec) = trigger.execution_spec else {
            return;
        };
        let claimed_at = Utc::now();
        match self
            .repository
            .claim_semantic_evaluation(
                fire.identity.tenant_id.clone(),
                fire.identity.trigger_id,
                fire.identity.fire_slot,
                run_id,
                claimed_at,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                tracing::warn!(%run_id, %error, "semantic evaluation claim failed");
                return;
            }
        }

        let thread_scope = ThreadScope {
            tenant_id: scope.tenant_id.clone(),
            agent_id: scope
                .agent_id
                .clone()
                .unwrap_or_else(|| self.fallback_agent_id.clone()),
            project_id: scope.project_id.clone(),
            owner_user_id: scope.explicit_owner_user_id().cloned(),
            mission_id: None,
        };
        let evaluation = match self
            .thread_service
            .finalized_assistant_message_by_run(FinalizedAssistantMessageByRunRequest {
                scope: thread_scope,
                thread_id: scope.thread_id.clone(),
                turn_run_id: run_id.to_string(),
            })
            .await
        {
            Ok(Some(message)) => match message.content.filter(|text| !text.trim().is_empty()) {
                Some(answer) => {
                    let inference = (self.inference)();
                    judge(
                        inference.as_ref(),
                        &spec.goal,
                        &spec.success_criteria,
                        &answer,
                    )
                    .await
                }
                None => failed("completed run had no usable final answer"),
            },
            Ok(None) => failed("completed run had no finalized assistant answer"),
            Err(_) => failed("final answer could not be read"),
        };

        if let Err(error) = self
            .repository
            .complete_semantic_evaluation(
                fire.identity.tenant_id,
                fire.identity.trigger_id,
                fire.identity.fire_slot,
                run_id,
                evaluation,
            )
            .await
        {
            tracing::warn!(%run_id, %error, "semantic evaluation could not be persisted");
        }
    }
}

async fn judge(
    inference: &dyn SystemInferencePort,
    goal: &str,
    criteria: &[String],
    answer: &str,
) -> TriggerSemanticEvaluation {
    let input = serde_json::json!({
        "goal": goal,
        "success_criteria": criteria,
        "answer": answer,
    })
    .to_string();
    let prompt_id = match SystemPromptId::new("automation_semantic_evaluation") {
        Ok(prompt_id) => prompt_id,
        Err(_) => return failed("semantic evaluator configuration was invalid"),
    };
    let request = SystemInferenceRequest {
        task_id: SystemInferenceTaskId::new(),
        identity: SystemInferenceIdentity {
            task_kind: SystemTaskKind::SemanticEvaluation,
            prompt_source: SystemPromptSource::Static { prompt_id },
            system_prompt: SYSTEM_PROMPT.to_string(),
        },
        input_text: input,
        max_input_tokens: MAX_INPUT_TOKENS,
        deadline_ms: DEADLINE_MS,
    };
    let response = match inference.call_system_inference(request).await {
        Ok(response) => response,
        Err(_) => return failed("semantic evaluation model call failed"),
    };
    if response.output_text.len() > MAX_MODEL_OUTPUT_BYTES {
        return failed("semantic evaluation output was invalid");
    }
    let parsed: JudgeOutput = match serde_json::from_str(&response.output_text) {
        Ok(parsed) => parsed,
        Err(_) => return failed("semantic evaluation output was invalid"),
    };
    let reason = sanitize_reason(&parsed.reason);
    if reason.is_empty() {
        return failed("semantic evaluation output was invalid");
    }
    TriggerSemanticEvaluation {
        verdict: if parsed.satisfied {
            TriggerSemanticVerdict::Satisfied
        } else {
            TriggerSemanticVerdict::Unsatisfied
        },
        reason,
        evaluated_at: Utc::now(),
    }
}

fn failed(reason: &'static str) -> TriggerSemanticEvaluation {
    TriggerSemanticEvaluation {
        verdict: TriggerSemanticVerdict::EvaluationFailed,
        reason: reason.to_string(),
        evaluated_at: Utc::now(),
    }
}

fn sanitize_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_REASON_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ironclaw_loop_contracts::{LoopSafeSummary, SystemInferenceError, SystemInferenceResponse};

    use super::*;

    struct StubInference(Result<String, SystemInferenceError>);

    #[async_trait]
    impl SystemInferencePort for StubInference {
        async fn call_system_inference(
            &self,
            request: SystemInferenceRequest,
        ) -> Result<SystemInferenceResponse, SystemInferenceError> {
            self.0
                .as_ref()
                .map(|output| SystemInferenceResponse {
                    task_id: request.task_id,
                    output_text: output.clone(),
                    elapsed_ms: 1,
                })
                .map_err(Clone::clone)
        }
    }

    async fn verdict_for(result: Result<&str, SystemInferenceError>) -> TriggerSemanticVerdict {
        let inference = StubInference(result.map(str::to_string));
        judge(
            &inference,
            "Produce a report",
            &["Include the total".to_string()],
            "The total is 42",
        )
        .await
        .verdict
    }

    #[tokio::test]
    async fn judge_maps_satisfied_unsatisfied_and_model_failure() {
        assert_eq!(
            verdict_for(Ok(r#"{"satisfied":true,"reason":"The total is present."}"#)).await,
            TriggerSemanticVerdict::Satisfied
        );
        assert_eq!(
            verdict_for(Ok(
                r#"{"satisfied":false,"reason":"The total is missing."}"#
            ))
            .await,
            TriggerSemanticVerdict::Unsatisfied
        );
        assert_eq!(
            verdict_for(Err(SystemInferenceError::Failed {
                safe_summary: LoopSafeSummary::new("judge unavailable").expect("safe summary"),
            }))
            .await,
            TriggerSemanticVerdict::EvaluationFailed
        );
    }

    #[tokio::test]
    async fn judge_rejects_non_json_and_sanitizes_bounded_reason() {
        assert_eq!(
            verdict_for(Ok("satisfied")).await,
            TriggerSemanticVerdict::EvaluationFailed
        );
        let long_reason = format!("{}\n", "x".repeat(MAX_REASON_CHARS + 20));
        let inference = StubInference(Ok(format!(
            "{{\"satisfied\":true,\"reason\":{}}}",
            serde_json::to_string(&long_reason).expect("serialize reason")
        )));
        let evaluation = judge(
            &inference,
            "Produce a report",
            &["Include the total".to_string()],
            "The total is 42",
        )
        .await;
        assert_eq!(evaluation.reason.chars().count(), MAX_REASON_CHARS);
        assert!(!evaluation.reason.chars().any(char::is_control));
    }
}
