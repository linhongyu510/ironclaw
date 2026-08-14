use std::sync::{Arc, Weak};
use std::time::Duration;

use chrono::Utc;
use futures::{StreamExt, stream};
use ironclaw_host_api::ids::AgentId;
use ironclaw_loop_contracts::{
    SystemInferenceIdentity, SystemInferencePort, SystemInferenceRequest, SystemInferenceTaskId,
    SystemPromptId, SystemPromptSource, SystemTaskKind,
};
use ironclaw_threads::{FinalizedAssistantMessageByRunRequest, SessionThreadService, ThreadScope};
use ironclaw_triggers::{
    ClaimTriggerSemanticEvaluationRequest, PendingTriggerSemanticEvaluation, TriggerFire,
    TriggerRepository, TriggerSemanticEvaluation, TriggerSemanticEvaluationClaimId,
    TriggerSemanticVerdict,
};
use ironclaw_turns::{TurnRunId, TurnScope};
use serde::Deserialize;
use tokio::sync::Notify;

const SYSTEM_PROMPT: &str = include_str!("prompts/semantic_evaluation.md");
const MAX_INPUT_TOKENS: u64 = 12_000;
const DEADLINE_MS: u64 = 30_000;
const MAX_REASON_CHARS: usize = 500;
// A non-BMP scalar may arrive as a UTF-16 surrogate pair (`\uXXXX\uXXXX`),
// which takes twelve JSON bytes. Leave a small fixed allowance for the object
// keys, boolean, punctuation, and quotes around the maximum valid reason.
const MAX_MODEL_OUTPUT_BYTES: usize = MAX_REASON_CHARS * 12 + 64;
const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);
const RECONCILE_BATCH_SIZE: usize = 64;
const MAX_CONCURRENT_EVALUATIONS: usize = 8;
const CLAIM_LEASE: chrono::Duration = chrono::Duration::minutes(2);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeOutput {
    satisfied: bool,
    reason: String,
}

/// Reconciles completed structured trigger runs into independent semantic
/// verdicts. Delivery remains a separate post-submit consumer.
pub struct SemanticRunEvaluator {
    worker: Arc<SemanticEvaluationWorker>,
}

struct SemanticEvaluationWorker {
    repository: Arc<dyn TriggerRepository>,
    thread_service: Arc<dyn SessionThreadService>,
    inference: Arc<dyn Fn() -> Arc<dyn SystemInferencePort> + Send + Sync>,
    fallback_agent_id: AgentId,
    wake: Notify,
}

impl SemanticRunEvaluator {
    pub fn new(
        repository: Arc<dyn TriggerRepository>,
        thread_service: Arc<dyn SessionThreadService>,
        inference: Arc<dyn Fn() -> Arc<dyn SystemInferencePort> + Send + Sync>,
        fallback_agent_id: AgentId,
    ) -> Self {
        let worker = Arc::new(SemanticEvaluationWorker {
            repository,
            thread_service,
            inference,
            fallback_agent_id,
            wake: Notify::new(),
        });
        spawn_reconciler(Arc::downgrade(&worker));
        Self { worker }
    }

    pub async fn on_trigger_submitted(
        &self,
        _fire: TriggerFire,
        _run_id: TurnRunId,
        _scope: TurnScope,
    ) {
        // Accepted-fire callbacks are deliberately constant-time. Completed
        // structured runs are discovered from durable storage by one bounded
        // reconciler, so bursts cannot create one long-lived watcher per run.
        self.worker.wake.notify_one();
    }
}

fn spawn_reconciler(worker: Weak<SemanticEvaluationWorker>) {
    tokio::spawn(async move {
        loop {
            let Some(current) = worker.upgrade() else {
                return;
            };
            current.reconcile_once().await;
            tokio::select! {
                _ = current.wake.notified() => {}
                _ = tokio::time::sleep(RECONCILE_INTERVAL) => {}
            }
        }
    });
}

impl SemanticEvaluationWorker {
    async fn reconcile_once(&self) {
        let candidates = match self
            .repository
            .list_pending_semantic_evaluations(RECONCILE_BATCH_SIZE)
            .await
        {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::warn!(%error, "semantic evaluation reconciliation query failed");
                return;
            }
        };
        stream::iter(candidates)
            .for_each_concurrent(MAX_CONCURRENT_EVALUATIONS, |candidate| {
                self.evaluate(candidate)
            })
            .await;
    }

    async fn evaluate(&self, candidate: PendingTriggerSemanticEvaluation) {
        let thread_scope = ThreadScope {
            tenant_id: candidate.tenant_id.clone(),
            agent_id: candidate
                .agent_id
                .clone()
                .unwrap_or_else(|| self.fallback_agent_id.clone()),
            project_id: candidate.project_id.clone(),
            owner_user_id: Some(candidate.creator_user_id.clone()),
            mission_id: None,
        };
        let answer = match self
            .thread_service
            .finalized_assistant_message_by_run(FinalizedAssistantMessageByRunRequest {
                scope: thread_scope,
                thread_id: candidate.thread_id.clone(),
                turn_run_id: candidate.run_id.to_string(),
            })
            .await
        {
            Ok(Some(message)) => message.content.filter(|text| !text.trim().is_empty()),
            Ok(None) => {
                tracing::warn!(run_id = %candidate.run_id, "semantic evaluation final answer is not visible yet");
                return;
            }
            Err(error) => {
                tracing::warn!(run_id = %candidate.run_id, %error, "semantic evaluation could not read final answer");
                return;
            }
        };
        let claimed_at = Utc::now();
        let claim_id = TriggerSemanticEvaluationClaimId::new();
        match self
            .repository
            .claim_semantic_evaluation(ClaimTriggerSemanticEvaluationRequest {
                tenant_id: candidate.tenant_id.clone(),
                trigger_id: candidate.trigger_id,
                fire_slot: candidate.fire_slot,
                run_id: candidate.run_id,
                claim_id,
                claimed_at,
                stale_before: claimed_at - CLAIM_LEASE,
            })
            .await
        {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                tracing::warn!(run_id = %candidate.run_id, %error, "semantic evaluation claim failed");
                return;
            }
        }
        let evaluation = match answer {
            Some(answer) => {
                let inference = (self.inference)();
                judge(
                    inference.as_ref(),
                    &candidate.execution_spec.goal,
                    &candidate.execution_spec.success_criteria,
                    &answer,
                )
                .await
            }
            None => failed("completed run had no usable final answer"),
        };

        for attempt in 1..=3 {
            match self
                .repository
                .complete_semantic_evaluation(
                    candidate.tenant_id.clone(),
                    candidate.trigger_id,
                    candidate.fire_slot,
                    candidate.run_id,
                    claim_id,
                    evaluation.clone(),
                )
                .await
            {
                Ok(true) => {
                    tracing::info!(run_id = %candidate.run_id, "semantic evaluation persisted");
                    return;
                }
                Ok(false) => {
                    tracing::warn!(run_id = %candidate.run_id, "semantic evaluation claim was no longer owned at completion");
                    return;
                }
                Err(error) if attempt < 3 => {
                    tracing::warn!(run_id = %candidate.run_id, attempt, %error, "semantic evaluation persistence failed; retrying");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => {
                    tracing::warn!(run_id = %candidate.run_id, %error, "semantic evaluation could not be persisted; lease remains recoverable");
                }
            }
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

    #[tokio::test]
    async fn judge_accepts_maximum_reason_encoded_as_escaped_non_bmp_unicode() {
        let escaped_reason = "\\ud83d\\ude80".repeat(MAX_REASON_CHARS);
        let inference = StubInference(Ok(format!(
            "{{\"satisfied\":true,\"reason\":\"{escaped_reason}\"}}"
        )));

        let evaluation = judge(
            &inference,
            "Produce a report",
            &["Include the total".to_string()],
            "The total is 42",
        )
        .await;

        assert_eq!(evaluation.verdict, TriggerSemanticVerdict::Satisfied);
        assert_eq!(evaluation.reason.chars().count(), MAX_REASON_CHARS);
        assert!(evaluation.reason.chars().all(|character| character == '🚀'));
    }
}
