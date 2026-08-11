//! ProductSurface commands for automation suggestion cards (#7038):
//! `suggestions.get` / `suggestions.generate`. Follows the
//! `automation_product_service.rs` precedent — the descriptor constants and
//! dispatch-arm hookup live in `reborn_services.rs` (minimal registration
//! only, per the module's size charter); the actual generate flow (CAS
//! claim, hidden thread create, synthetic first message submit) lives here.

use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_host_api::ids::ThreadId;
use ironclaw_host_api::turn::{
    AcceptedMessageRef, IdempotencyKey, ReplyTargetBindingRef, RunProfileRequest, SourceBindingRef,
    SubmitTurnResponse, TurnActor, TurnScope,
};
use ironclaw_product_contracts::surface::ProductSurfaceError;
use ironclaw_suggestions::{
    RunLiveness, SuggestionsStore, SuggestionsView, derive_suggestions_view,
};
use ironclaw_threads::{
    AcceptInboundMessageRequest, EnsureThreadRequest, MessageContent, SessionThreadService,
    ThreadScope,
};
use ironclaw_turns::{GetRunStateRequest, SubmitTurnRequest, TurnCoordinator, TurnError};
use uuid::Uuid;

use crate::{ProductAgentBoundCaller, SuggestionsProductService};

/// Synthetic first message (spec §6): fixed template, not user-authored.
const SUGGESTION_GENERATION_PROMPT: &str = include_str!("../prompts/suggestion_generation.md");

/// The derived GET/POST response IS the domain crate's wire view — one
/// schema struct across the tool input, the stored doc, and this HTTP
/// response (spec §4), so no separate DTO is declared here.
pub type RebornSuggestionsResponse = SuggestionsView;

pub const SUGGESTIONS_VIEW_ID: &str = "suggestions";
pub const SUGGESTIONS_GENERATE_COMMAND_ID: &str = "suggestions.generate";
/// Mirrors `ironclaw_turn_runner::planned_driver_factory::SUGGESTION_GENERATION_RUN_PROFILE_ID`
/// as a literal — see the call site's comment for why it is not imported.
const SUGGESTION_GENERATION_RUN_PROFILE_ID: &str = "suggestion_generation";

/// Product command input for `suggestions.generate` — takes no fields; kept
/// as a named type (rather than reusing `EmptyProductCommandInput` directly
/// in the trait signature) so the wire shape has a name of its own if a
/// future field is added.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RebornSuggestionsGenerateRequest {}

pub struct RebornSuggestionsProductService {
    store: SuggestionsStore,
    thread_service: Arc<dyn SessionThreadService>,
    turn_coordinator: Arc<dyn TurnCoordinator>,
}

impl RebornSuggestionsProductService {
    pub fn new(
        store: SuggestionsStore,
        thread_service: Arc<dyn SessionThreadService>,
        turn_coordinator: Arc<dyn TurnCoordinator>,
    ) -> Self {
        Self {
            store,
            thread_service,
            turn_coordinator,
        }
    }

    async fn run_liveness(
        &self,
        scope: &TurnScope,
        run_id: ironclaw_host_api::turn::TurnRunId,
    ) -> RunLiveness {
        match self
            .turn_coordinator
            .get_run_state(GetRunStateRequest {
                scope: scope.clone(),
                run_id,
            })
            .await
        {
            Ok(state) if state.status.keeps_active_lock() => RunLiveness::Live,
            Ok(_) => RunLiveness::Terminal,
            // A backend error is treated as Missing (fail toward `failed`,
            // never toward a permanently stuck `running` — see the domain
            // crate's `derive_suggestions_view` doc comment).
            Err(_) => RunLiveness::Missing,
        }
    }
}

#[async_trait]
impl SuggestionsProductService for RebornSuggestionsProductService {
    async fn get_suggestions(
        &self,
        caller: ProductAgentBoundCaller,
    ) -> Result<RebornSuggestionsResponse, ProductSurfaceError> {
        let doc = self
            .store
            .read_doc(&caller.tenant_id, &caller.user_id)
            .await
            .map_err(ProductSurfaceError::internal_from)?
            .unwrap_or_else(ironclaw_suggestions::SuggestionsDoc::empty);
        let liveness = match &doc.active_job {
            Some(active_job) => {
                let scope = turn_scope(&caller, active_job.thread_id.clone());
                Some(self.run_liveness(&scope, active_job.run_id).await)
            }
            None => None,
        };
        Ok(derive_suggestions_view(&doc, liveness))
    }

    async fn generate_suggestions(
        &self,
        caller: ProductAgentBoundCaller,
    ) -> Result<RebornSuggestionsResponse, ProductSurfaceError> {
        self.generate_suggestions_with_thread_id(caller, fresh_suggestion_generation_thread_id())
            .await
    }
}

impl RebornSuggestionsProductService {
    /// Test-only entry point that lets an integration test pre-mint the
    /// hidden thread's id, so it can register a scripted model gateway for
    /// the exact resolved `TurnScope` before calling this (the same reason
    /// the trusted-trigger submit path grew its own `new_for_test`
    /// constructor: the production method mints its own id internally, so a
    /// caller has no other way to know it ahead of the real
    /// `TurnCoordinator::submit_turn` call). Zero bytes in production
    /// builds.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn generate_suggestions_for_test(
        &self,
        caller: ProductAgentBoundCaller,
        thread_id: ThreadId,
    ) -> Result<RebornSuggestionsResponse, ProductSurfaceError> {
        self.generate_suggestions_with_thread_id(caller, thread_id)
            .await
    }

    async fn generate_suggestions_with_thread_id(
        &self,
        caller: ProductAgentBoundCaller,
        thread_id: ThreadId,
    ) -> Result<RebornSuggestionsResponse, ProductSurfaceError> {
        // Resolve current state once: a live claim dedupes (no second loop);
        // a dead claim is cleared before a fresh one is attempted (spec §5
        // crash-recovery path — "subsequent POST claims cleanly").
        if let Some(doc) = self
            .store
            .read_doc(&caller.tenant_id, &caller.user_id)
            .await
            .map_err(ProductSurfaceError::internal_from)?
            && let Some(active_job) = &doc.active_job
        {
            let scope = turn_scope(&caller, active_job.thread_id.clone());
            match self.run_liveness(&scope, active_job.run_id).await {
                RunLiveness::Live => {
                    return Ok(derive_suggestions_view(&doc, Some(RunLiveness::Live)));
                }
                RunLiveness::Terminal | RunLiveness::Missing => {
                    self.store
                            .record_failure(
                                &caller.tenant_id,
                                &caller.user_id,
                                active_job.job_id,
                                "generation run ended without a live claim; superseded by a new request".to_string(),
                            )
                            .await
                            .map_err(ProductSurfaceError::internal_from)?;
                }
            }
        }

        let run_id = ironclaw_host_api::turn::TurnRunId::new();
        let claim = self
            .store
            .claim_active_job(
                &caller.tenant_id,
                &caller.user_id,
                thread_id.clone(),
                run_id,
            )
            .await
            .map_err(ProductSurfaceError::internal_from)?;

        let job_id = match claim {
            ironclaw_suggestions::ClaimOutcome::Claimed { job_id } => job_id,
            ironclaw_suggestions::ClaimOutcome::AlreadyClaimed { .. } => {
                // Lost a concurrent race after the pre-check above — dedupe
                // onto whichever claim just won (spec §4: both racers must
                // observe the same job_id / one loop).
                let doc = self
                    .store
                    .read_doc(&caller.tenant_id, &caller.user_id)
                    .await
                    .map_err(ProductSurfaceError::internal_from)?
                    .unwrap_or_else(ironclaw_suggestions::SuggestionsDoc::empty);
                return Ok(derive_suggestions_view(&doc, Some(RunLiveness::Live)));
            }
        };

        match self
            .submit_generation_turn(&caller, thread_id, run_id, job_id)
            .await
        {
            Ok(accepted_run_id) => {
                // The coordinator is free to mint its own run id rather than
                // honor `requested_run_id` verbatim (it only enforces a
                // scope match against a PRIOR `prepare_turn` reservation,
                // which this flow never makes) — reconcile the doc's
                // `active_job.run_id` to whatever id actually got accepted so
                // liveness polling (`run_liveness`) checks the real run,
                // not a placeholder that never exists.
                if accepted_run_id != run_id {
                    self.store
                        .update_active_job_run_id(
                            &caller.tenant_id,
                            &caller.user_id,
                            job_id,
                            accepted_run_id,
                        )
                        .await
                        .map_err(ProductSurfaceError::internal_from)?;
                }
                let doc = self
                    .store
                    .read_doc(&caller.tenant_id, &caller.user_id)
                    .await
                    .map_err(ProductSurfaceError::internal_from)?
                    .unwrap_or_else(ironclaw_suggestions::SuggestionsDoc::empty);
                Ok(derive_suggestions_view(&doc, Some(RunLiveness::Live)))
            }
            Err(error) => {
                // Release the claim so the next POST can retry cleanly
                // instead of waiting for the crash-recovery liveness path.
                let _ = self
                    .store
                    .record_failure(
                        &caller.tenant_id,
                        &caller.user_id,
                        job_id,
                        format!("failed to start suggestion generation: {error}"),
                    )
                    .await;
                Err(ProductSurfaceError::internal_from(error))
            }
        }
    }
}

impl RebornSuggestionsProductService {
    async fn submit_generation_turn(
        &self,
        caller: &ProductAgentBoundCaller,
        thread_id: ThreadId,
        run_id: ironclaw_host_api::turn::TurnRunId,
        job_id: Uuid,
    ) -> Result<ironclaw_host_api::turn::TurnRunId, TurnError> {
        let scope = turn_scope(caller, thread_id.clone());
        let thread_scope = ThreadScope {
            tenant_id: caller.tenant_id.clone(),
            agent_id: caller.agent_id.clone(),
            project_id: caller.project_id.clone(),
            owner_user_id: Some(caller.user_id.clone()),
            mission_id: None,
        };
        self.thread_service
            .ensure_thread(EnsureThreadRequest {
                scope: thread_scope.clone(),
                thread_id: Some(thread_id.clone()),
                created_by_actor_id: caller.user_id.as_str().to_string(),
                title: None,
                metadata_json: Some(crate::suggestion_generation_thread_metadata_json(job_id)),
            })
            .await
            .map_err(|error| TurnError::Unavailable {
                reason: format!("suggestion-generation thread ensure failed: {error}"),
            })?;

        let binding_ref = format!("suggestion-generation:{job_id}");
        let accepted = self
            .thread_service
            .accept_inbound_message(AcceptInboundMessageRequest {
                scope: thread_scope.clone(),
                thread_id: thread_id.clone(),
                actor_id: caller.user_id.as_str().to_string(),
                source_binding_id: Some(binding_ref.clone()),
                reply_target_binding_id: Some(binding_ref.clone()),
                external_event_id: Some(binding_ref.clone()),
                content: MessageContent::text(SUGGESTION_GENERATION_PROMPT.to_string()),
            })
            .await
            .map_err(|error| TurnError::Unavailable {
                reason: format!("suggestion-generation prompt record failed: {error}"),
            })?;

        let actor = TurnActor::new(caller.user_id.clone());
        let owner = scope.product_owner(&actor);
        let product_context = ironclaw_turns::product_context::resolve_web_ui(owner);
        let request_id = binding_ref;
        let response =
            self.turn_coordinator
                .submit_turn(SubmitTurnRequest {
                    requested_model: None,
                    scope,
                    actor,
                    accepted_message_ref: AcceptedMessageRef::new(request_id.clone()).map_err(
                        |_| TurnError::InvalidRequest {
                            reason: "invalid accepted message ref".to_string(),
                        },
                    )?,
                    source_binding_ref: SourceBindingRef::new(request_id.clone()).map_err(
                        |_| TurnError::InvalidRequest {
                            reason: "invalid source binding ref".to_string(),
                        },
                    )?,
                    reply_target_binding_ref: ReplyTargetBindingRef::new(request_id.clone())
                        .map_err(|_| TurnError::InvalidRequest {
                            reason: "invalid reply target binding ref".to_string(),
                        })?,
                    requested_run_profile: Some(
                        // Literal, not imported: `ironclaw_turn_runner` (loop
                        // layer) is dev-only from this product-layer crate.
                        // Pinned against
                        // `ironclaw_turn_runner::planned_driver_factory::SUGGESTION_GENERATION_RUN_PROFILE_ID`
                        // by the suggestion-generation integration test.
                        RunProfileRequest::new(SUGGESTION_GENERATION_RUN_PROFILE_ID).map_err(
                            |_| TurnError::InvalidRequest {
                                reason: "invalid suggestion-generation run profile id".to_string(),
                            },
                        )?,
                    ),
                    idempotency_key: IdempotencyKey::new(request_id).map_err(|_| {
                        TurnError::InvalidRequest {
                            reason: "invalid idempotency key".to_string(),
                        }
                    })?,
                    received_at: chrono::Utc::now(),
                    requested_run_id: Some(run_id),
                    parent_run_id: None,
                    subagent_depth: 0,
                    spawn_tree_root_run_id: None,
                    product_context: Some(product_context),
                })
                .await?;

        let SubmitTurnResponse::Accepted {
            turn_id: accepted_turn_id,
            run_id: accepted_run_id,
            ..
        } = response;

        // Required follow-up (mirrors `mark_message_submitted_or_replay` in
        // the ordinary WebUI submit path): links the accepted message to its
        // turn/run and transitions it Accepted -> Submitted. Without this the
        // message never carries a `turn_run_id`, and the executor's reply
        // pipeline has nothing to attach the finalized assistant message to.
        self.thread_service
            .mark_message_submitted(
                &thread_scope,
                &thread_id,
                accepted.message_id,
                accepted_turn_id.to_string(),
                accepted_run_id.to_string(),
            )
            .await
            .map_err(|error| TurnError::Unavailable {
                reason: format!("suggestion-generation mark-submitted failed: {error}"),
            })?;

        Ok(accepted_run_id)
    }
}

fn turn_scope(caller: &ProductAgentBoundCaller, thread_id: ThreadId) -> TurnScope {
    TurnScope::new_with_owner(
        caller.tenant_id.clone(),
        Some(caller.agent_id.clone()),
        caller.project_id.clone(),
        thread_id,
        Some(caller.user_id.clone()),
    )
}

fn fresh_suggestion_generation_thread_id() -> ThreadId {
    // Random per generation — a fresh hidden thread every run (spec §5:
    // "Regeneration overwrites the doc but creates a NEW hidden thread; old
    // transcripts remain").
    ThreadId::new(format!("suggestion-gen-{}", Uuid::new_v4()))
        .unwrap_or_else(|_| unreachable!("uuid-suffixed thread id is always valid"))
}
