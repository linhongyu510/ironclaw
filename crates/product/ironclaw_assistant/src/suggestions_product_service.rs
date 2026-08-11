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
    AcceptedMessageRef, IdempotencyKey, ReplyTargetBindingRef, RunProfileId, RunProfileRequest,
    SourceBindingRef, SubmitTurnResponse, TurnActor, TurnScope,
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

/// Minimum age an `active_job` must reach before a concurrent caller's
/// crash-recovery pre-check is allowed to treat it as dead and supersede it.
///
/// THIS IS A MITIGATION FOR A GAP, NOT A COMPLETE DESIGN ON ITS OWN. The
/// real fix is `SuggestionGenerationFinalizerSink`
/// (`ironclaw_composition::suggestions`) — the spec §6 "turn finalizer" —
/// which clears `active_job` the moment its own run's `TurnEventSink` event
/// fires, so a `Terminal`/`Missing` claim a reader observes is (almost
/// always) already a genuinely stale one, not a run that just completed
/// normally without calling `render_suggestions` (a plain successful
/// completion and a crash both resolve to the same `RunLiveness`, and
/// without the finalizer clearing the claim on ITS OWN terminal transition,
/// nothing else does until some other request's pre-check happens to poll).
///
/// The finalizer does not make this constant unnecessary, because it does
/// not close the window atomically with the status transition itself: the
/// run's `TurnStatus` becomes `Terminal`-observable (via
/// `TurnCoordinator::get_run_state`, what `run_liveness` below reads) at
/// commit time, and the finalizer's `TurnEventSink::publish` fires
/// separately, on its own schedule, afterward — a concurrent pre-check that
/// lands in that gap still sees `active_job` set with `Terminal`/`Missing`
/// liveness and nothing else protecting it. This constant is what protects
/// that residual gap: a claim younger than this is treated as still-forming
/// regardless of what the coordinator currently reports, so every racer
/// within the window converges on returning the SAME (first) claim instead
/// of racing to replace it. A claim older than this remains recoverable
/// exactly as before.
///
/// Failure mode if the finalizer is ever removed, disabled, or fails
/// unnoticed (its own errors are best-effort/swallowed at `debug!`, matching
/// every sibling `TurnEventSink`): this constant reverts to being the ONLY
/// protection, and claim formation exceeding it under real load (a busy CI
/// box, GC pause, or thread-starved host) reopens the double-claim race this
/// whole mechanism exists to close — found via a full-suite-load integration
/// test failure (`concurrent_generate_calls_converge_on_one_claim`) that a
/// filtered/isolated run of the same test never reproduced. Do not raise
/// this value to "fix" a flake without first checking the finalizer is
/// actually wired and firing.
const MIN_CLAIM_AGE_BEFORE_RECLAIM: chrono::Duration = chrono::Duration::milliseconds(500);

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

    /// Read the current doc (or the empty default) and derive its view
    /// under the assumption the caller already knows a claim is live — the
    /// shared tail of both the dedupe-onto-the-winner path and the
    /// just-accepted-a-turn path in `generate_suggestions_with_thread_id`.
    async fn read_live_view(
        &self,
        caller: &ProductAgentBoundCaller,
    ) -> Result<RebornSuggestionsResponse, ProductSurfaceError> {
        let doc = self
            .store
            .read_doc(&caller.tenant_id, &caller.user_id)
            .await
            .map_err(ProductSurfaceError::internal_from)?
            .unwrap_or_else(ironclaw_suggestions::SuggestionsDoc::empty);
        Ok(derive_suggestions_view(&doc, Some(RunLiveness::Live)))
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
            Err(error) => {
                tracing::debug!(
                    %error,
                    %run_id,
                    "suggestion-generation run liveness lookup failed; treating as Missing"
                );
                RunLiveness::Missing
            }
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
        self.generate_suggestions_with_thread_id(caller, fresh_suggestion_generation_thread_id()?)
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
            let claim_age = chrono::Utc::now() - active_job.started_at;
            if claim_age < MIN_CLAIM_AGE_BEFORE_RECLAIM {
                // Too young to safely tell "genuinely dead" apart from "another
                // concurrent racer's claim still forming" — converge on it
                // rather than risk a second racer independently reclaiming the
                // same slot (see MIN_CLAIM_AGE_BEFORE_RECLAIM's doc comment).
                return Ok(derive_suggestions_view(&doc, Some(RunLiveness::Live)));
            }
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
                return self.read_live_view(&caller).await;
            }
        };

        match self
            .submit_generation_turn(&caller, thread_id, run_id, job_id)
            .await
        {
            SubmitGenerationOutcome::Accepted(accepted_run_id) => {
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
                self.read_live_view(&caller).await
            }
            SubmitGenerationOutcome::AcceptedButUnlinked {
                accepted_run_id,
                error,
            } => {
                // submit_turn already accepted this run — it may still
                // execute and later call the rendering tool. Releasing the
                // claim here (as the NotAccepted arm does) would let a
                // concurrent caller submit a second generation while this
                // one is in flight, reintroducing the exact race this claim
                // exists to prevent. Retain the claim; only reconcile the
                // run id so liveness polling still tracks the real run.
                if accepted_run_id != run_id {
                    // silent-ok: best-effort reconciliation; if this write
                    // fails the claim still reflects the placeholder run_id,
                    // and MIN_CLAIM_AGE_BEFORE_RECLAIM / the finalizer sink
                    // remain the backstop once the run goes terminal.
                    if let Err(reconcile_error) = self
                        .store
                        .update_active_job_run_id(
                            &caller.tenant_id,
                            &caller.user_id,
                            job_id,
                            accepted_run_id,
                        )
                        .await
                    {
                        tracing::debug!(
                            %reconcile_error,
                            %job_id,
                            "failed to reconcile accepted-but-unlinked suggestion-generation run id"
                        );
                    }
                }
                tracing::error!(
                    %error,
                    %job_id,
                    %accepted_run_id,
                    "suggestion-generation run accepted but post-accept linking failed; \
                     claim retained for the in-flight run"
                );
                Err(ProductSurfaceError::internal_from(error))
            }
            SubmitGenerationOutcome::NotAccepted(error) => {
                // No run was ever accepted — safe to release the claim so
                // the next POST can retry cleanly instead of waiting for the
                // crash-recovery liveness path.
                // silent-ok: best-effort claim release; if this write itself
                // fails, the crash-recovery liveness path (run_liveness +
                // MIN_CLAIM_AGE_BEFORE_RECLAIM) still clears the stale claim.
                if let Err(release_error) = self
                    .store
                    .record_failure(
                        &caller.tenant_id,
                        &caller.user_id,
                        job_id,
                        format!("failed to start suggestion generation: {error}"),
                    )
                    .await
                {
                    tracing::debug!(
                        %release_error,
                        %job_id,
                        "failed to release suggestion-generation claim after submit failure"
                    );
                }
                Err(ProductSurfaceError::internal_from(error))
            }
        }
    }
}

/// Outcome of attempting to submit a suggestion-generation turn, distinguishing
/// whether a run was actually accepted before the failure — the caller must
/// only release the CAS claim in the [`NotAccepted`](Self::NotAccepted) case;
/// releasing it after [`AcceptedButUnlinked`](Self::AcceptedButUnlinked) would
/// let a concurrent caller submit a second run while the accepted one is
/// still executing.
enum SubmitGenerationOutcome {
    /// `submit_turn` and the post-accept linking (`mark_message_submitted`)
    /// both succeeded.
    Accepted(ironclaw_host_api::turn::TurnRunId),
    /// `submit_turn` accepted the run, but `mark_message_submitted` failed
    /// afterward. The run may still execute; the claim must be retained.
    AcceptedButUnlinked {
        accepted_run_id: ironclaw_host_api::turn::TurnRunId,
        error: TurnError,
    },
    /// No run was accepted (failure occurred at or before `submit_turn`).
    /// Safe to release the claim.
    NotAccepted(TurnError),
}

impl RebornSuggestionsProductService {
    async fn submit_generation_turn(
        &self,
        caller: &ProductAgentBoundCaller,
        thread_id: ThreadId,
        run_id: ironclaw_host_api::turn::TurnRunId,
        job_id: Uuid,
    ) -> SubmitGenerationOutcome {
        match self
            .submit_generation_turn_inner(caller, thread_id, run_id, job_id)
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => SubmitGenerationOutcome::NotAccepted(error),
        }
    }

    async fn submit_generation_turn_inner(
        &self,
        caller: &ProductAgentBoundCaller,
        thread_id: ThreadId,
        run_id: ironclaw_host_api::turn::TurnRunId,
        job_id: Uuid,
    ) -> Result<SubmitGenerationOutcome, TurnError> {
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
        let response = self
            .turn_coordinator
            .submit_turn(SubmitTurnRequest {
                requested_model: None,
                scope,
                actor,
                accepted_message_ref: AcceptedMessageRef::new(request_id.clone()).map_err(|e| {
                    TurnError::InvalidRequest {
                        reason: format!("invalid accepted message ref: {e}"),
                    }
                })?,
                source_binding_ref: SourceBindingRef::new(request_id.clone()).map_err(|e| {
                    TurnError::InvalidRequest {
                        reason: format!("invalid source binding ref: {e}"),
                    }
                })?,
                reply_target_binding_ref: ReplyTargetBindingRef::new(request_id.clone()).map_err(
                    |e| TurnError::InvalidRequest {
                        reason: format!("invalid reply target binding ref: {e}"),
                    },
                )?,
                requested_run_profile: Some(
                    RunProfileRequest::new(RunProfileId::suggestion_generation().as_str())
                        .map_err(|e| TurnError::InvalidRequest {
                            reason: format!("invalid suggestion-generation run profile id: {e}"),
                        })?,
                ),
                idempotency_key: IdempotencyKey::new(request_id).map_err(|e| {
                    TurnError::InvalidRequest {
                        reason: format!("invalid idempotency key: {e}"),
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
        //
        // `submit_turn` above has already accepted this run — a failure here
        // must NOT be reported the same way as a pre-accept failure (see
        // `SubmitGenerationOutcome`): the run may still execute.
        match self
            .thread_service
            .mark_message_submitted(
                &thread_scope,
                &thread_id,
                accepted.message_id,
                accepted_turn_id.to_string(),
                accepted_run_id.to_string(),
            )
            .await
        {
            Ok(_) => Ok(SubmitGenerationOutcome::Accepted(accepted_run_id)),
            Err(error) => Ok(SubmitGenerationOutcome::AcceptedButUnlinked {
                accepted_run_id,
                error: TurnError::Unavailable {
                    reason: format!("suggestion-generation mark-submitted failed: {error}"),
                },
            }),
        }
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

fn fresh_suggestion_generation_thread_id() -> Result<ThreadId, ProductSurfaceError> {
    // Random per generation — a fresh hidden thread every run (spec §5:
    // "Regeneration overwrites the doc but creates a NEW hidden thread; old
    // transcripts remain"). The literal prefix and UUID text always satisfy
    // `ThreadId`'s validation, so the error arm is unreachable in practice —
    // surfaced rather than panicked so production carries no panic path.
    ThreadId::new(format!("suggestion-gen-{}", Uuid::new_v4()))
        .map_err(ProductSurfaceError::internal_from)
}
