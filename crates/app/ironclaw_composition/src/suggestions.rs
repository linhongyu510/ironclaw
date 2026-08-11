//! Composition-owned bridge between the kernel-layer `render_suggestions`
//! tool (`ironclaw_host_runtime`) and the product-layer `SuggestionsStore`
//! (`ironclaw_suggestions`, mirrored at the domain layer so both sides can
//! reach it) — the same hook-injection shape `TriggerCreateHook` uses so a
//! kernel tool can reach a store one layer above it (#7038).
//!
//! Also owns [`SuggestionGenerationFinalizerSink`] — the spec §6 "turn
//! finalizer", initially left unwired and then built here in response to
//! review: the piece that makes a terminal `active_job` unambiguous by
//! clearing it the moment the run actually ends, so
//! `suggestions_product_service.rs`'s `MIN_CLAIM_AGE_BEFORE_RECLAIM` timer
//! only has to cover the narrow residual gap between a run's status
//! becoming visible and this sink firing — not stand in for the whole
//! "crashed vs finished without calling `render_suggestions`" distinction.

use async_trait::async_trait;
use ironclaw_host_api::resource::ResourceScope;
use ironclaw_host_runtime::{RenderSuggestionsHook, RenderSuggestionsHookError};
use ironclaw_suggestions::{SuggestionCard, SuggestionsStore, SuggestionsStoreError};
use ironclaw_turns::{TurnError, TurnEventKind, TurnEventSink, TurnLifecycleEvent};

pub(crate) struct StoreBackedRenderSuggestionsHook {
    store: SuggestionsStore,
}

impl StoreBackedRenderSuggestionsHook {
    pub(crate) fn new(store: SuggestionsStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl RenderSuggestionsHook for StoreBackedRenderSuggestionsHook {
    async fn record_cards(
        &self,
        scope: &ResourceScope,
        cards: Vec<SuggestionCard>,
    ) -> Result<(), RenderSuggestionsHookError> {
        let job_id = self
            .store
            .read_doc(&scope.tenant_id, &scope.user_id)
            .await
            .map_err(store_error)?
            .and_then(|doc| doc.active_job.map(|active_job| active_job.job_id))
            .ok_or(RenderSuggestionsHookError::NoActiveJob)?;
        self.store
            .record_result(&scope.tenant_id, &scope.user_id, job_id, cards)
            .await
            .map_err(store_error)
    }
}

fn store_error(error: SuggestionsStoreError) -> RenderSuggestionsHookError {
    RenderSuggestionsHookError::Backend {
        reason: error.to_string(),
    }
}

/// The spec §6 turn finalizer: fires on every terminal transition of every
/// run in the process (the same shared seam `TraceCaptureTurnEventSink` and
/// `SkillLearningTurnEventSink` use — see their composition in `runtime.rs`),
/// and clears a suggestion-generation `active_job` the moment ITS OWN run
/// goes terminal without ever calling `render_suggestions` — a crashed run
/// and a run that simply replied with prose both land here identically.
///
/// Scoping needs no run-profile check: `TurnLifecycleEvent` carries no
/// profile field, but `ActiveJob.run_id` already pins the exact run a claim
/// is waiting on (`SuggestionsStore::claim_active_job`), and
/// `record_failure`'s existing stale-job guard
/// (`apply_job_outcome`'s `job_id` match) is already a no-op for every event
/// that isn't the one specific run change this claim is watching — including
/// events from ordinary chat turns, and a `Completed` event that arrives
/// after `render_suggestions` already cleared the claim itself.
///
/// With this wired, a terminal `active_job` is a fact the next reader can
/// trust immediately: `RunLiveness::Terminal`/`Missing` in
/// `suggestions_product_service.rs`'s crash-recovery pre-check now only
/// describes a claim genuinely abandoned before ever reaching this sink
/// (e.g. the process crashed before the run's lifecycle event committed) —
/// `MIN_CLAIM_AGE_BEFORE_RECLAIM` stays as a narrow mitigation for exactly
/// that residual gap, not the primary correctness mechanism.
pub(crate) struct SuggestionGenerationFinalizerSink {
    store: SuggestionsStore,
}

impl SuggestionGenerationFinalizerSink {
    pub(crate) fn new(store: SuggestionsStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl TurnEventSink for SuggestionGenerationFinalizerSink {
    async fn publish(&self, event: TurnLifecycleEvent) -> Result<(), TurnError> {
        // Cheap filter only, same shape as every sibling `TurnEventSink`
        // (`trace_capture.rs`, `skill_learning.rs`): the actual store I/O is
        // spawned below so this fan-out (which fires on EVERY turn's
        // terminal transition, not just suggestion-generation ones) never
        // adds synchronous latency to an unrelated turn's completion path.
        if !matches!(
            event.kind,
            TurnEventKind::Completed | TurnEventKind::Failed | TurnEventKind::Cancelled
        ) {
            return Ok(());
        }
        let Some(user_id) = event
            .owner_user_id
            .clone()
            .or_else(|| event.scope.thread_owner.explicit_owner_user_id().cloned())
        else {
            return Ok(());
        };
        let store = self.store.clone();
        let tenant_id = event.scope.tenant_id.clone();
        let run_id = event.run_id;
        let status = event.status;
        tokio::spawn(async move {
            finalize_claim_if_owned(&store, &tenant_id, &user_id, run_id, status).await;
        });
        Ok(())
    }
}

/// The actual finalize work, extracted so it can be spawned off the fast
/// `publish` path (see [`SuggestionGenerationFinalizerSink::publish`]) while
/// staying directly callable — synchronously, no spawn-completion race — from
/// tests.
async fn finalize_claim_if_owned(
    store: &SuggestionsStore,
    tenant_id: &ironclaw_host_api::ids::TenantId,
    user_id: &ironclaw_host_api::ids::UserId,
    run_id: ironclaw_host_api::turn::TurnRunId,
    status: ironclaw_host_api::turn::TurnStatus,
) {
    let doc = match store.read_doc(tenant_id, user_id).await {
        Ok(doc) => doc,
        // Best-effort: a backend hiccup here must never fail the turn
        // commit. The claim is still recoverable via
        // `MIN_CLAIM_AGE_BEFORE_RECLAIM` on the next request if this
        // specific finalize is lost.
        Err(error) => {
            tracing::debug!(
                %error,
                %tenant_id,
                %run_id,
                "suggestion-generation finalizer: read_doc failed, deferring to the claim-age mitigation"
            );
            return;
        }
    };
    let Some(active_job) = doc.and_then(|doc| doc.active_job) else {
        return;
    };
    if active_job.run_id != run_id {
        // Not the run this claim is waiting on — either an unrelated chat
        // turn, or a stale event for a claim already superseded.
        return;
    }
    if let Err(error) = store
        .record_failure(
            tenant_id,
            user_id,
            active_job.job_id,
            format!(
                "generation run ended ({}) without calling render_suggestions",
                status.as_str()
            ),
        )
        .await
    {
        tracing::debug!(
            %error,
            %tenant_id,
            %run_id,
            "suggestion-generation finalizer: record_failure failed, deferring to the claim-age mitigation"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_filesystem::InMemoryBackend;
    use ironclaw_host_api::ids::{InvocationId, TenantId, ThreadId, UserId};
    use ironclaw_host_api::turn::TurnRunId;
    use ironclaw_suggestions::ClaimOutcome;
    use std::sync::Arc;
    use uuid::Uuid;

    fn scope(tenant: &str, user: &str) -> ResourceScope {
        ResourceScope {
            tenant_id: TenantId::new(tenant).unwrap(),
            user_id: UserId::new(user).unwrap(),
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: Some(ThreadId::new("t1").unwrap()),
            invocation_id: InvocationId::new(),
        }
    }

    fn card() -> SuggestionCard {
        SuggestionCard {
            id: Uuid::new_v4(),
            title: "Triage inbox".to_string(),
            description: "do the thing".to_string(),
            extension_id: None,
            requires_connection: false,
            suggested_prompt: "go triage".to_string(),
            category: "email".to_string(),
        }
    }

    #[tokio::test]
    async fn records_cards_against_the_active_claim() {
        let store = SuggestionsStore::new(Arc::new(InMemoryBackend::default()));
        let scope = scope("t", "u");
        let ClaimOutcome::Claimed { .. } = store
            .claim_active_job(
                &scope.tenant_id,
                &scope.user_id,
                ThreadId::new("t1").unwrap(),
                TurnRunId::new(),
            )
            .await
            .unwrap()
        else {
            panic!("expected claim");
        };

        let hook = StoreBackedRenderSuggestionsHook::new(store.clone());
        hook.record_cards(&scope, vec![card()]).await.unwrap();

        let doc = store
            .read_doc(&scope.tenant_id, &scope.user_id)
            .await
            .unwrap()
            .unwrap();
        assert!(doc.active_job.is_none());
        assert_eq!(doc.last_result.unwrap().cards.len(), 1);
    }

    #[tokio::test]
    async fn no_active_claim_is_reported_as_no_active_job() {
        let store = SuggestionsStore::new(Arc::new(InMemoryBackend::default()));
        let scope = scope("t", "u");
        let hook = StoreBackedRenderSuggestionsHook::new(store);

        let error = hook.record_cards(&scope, vec![card()]).await.unwrap_err();

        assert_eq!(error, RenderSuggestionsHookError::NoActiveJob);
    }

    #[tokio::test]
    async fn cards_do_not_leak_across_tenants() {
        let store = SuggestionsStore::new(Arc::new(InMemoryBackend::default()));
        let a = scope("tenant-a", "user-a");
        let b = scope("tenant-b", "user-b");
        store
            .claim_active_job(
                &a.tenant_id,
                &a.user_id,
                ThreadId::new("t1").unwrap(),
                TurnRunId::new(),
            )
            .await
            .unwrap();

        let hook = StoreBackedRenderSuggestionsHook::new(store.clone());
        let error = hook.record_cards(&b, vec![card()]).await.unwrap_err();

        assert_eq!(error, RenderSuggestionsHookError::NoActiveJob);
    }

    // --- SuggestionGenerationFinalizerSink ---------------------------------

    fn terminal_event(
        kind: TurnEventKind,
        tenant: &str,
        user: &str,
        run_id: ironclaw_host_api::turn::TurnRunId,
    ) -> TurnLifecycleEvent {
        let owner_user_id = Some(UserId::new(user).expect("test owner user id is valid"));
        TurnLifecycleEvent {
            cursor: ironclaw_turns::EventCursor::default(),
            scope: ironclaw_host_api::turn::TurnScope::new_with_owner(
                TenantId::new(tenant).expect("tenant"),
                None,
                None,
                ThreadId::new("finalizer-test-thread").expect("thread id"),
                owner_user_id.clone(),
            ),
            occurred_at: None,
            owner_user_id,
            run_id,
            status: match kind {
                TurnEventKind::Failed => ironclaw_host_api::turn::TurnStatus::Failed,
                TurnEventKind::Cancelled => ironclaw_host_api::turn::TurnStatus::Cancelled,
                _ => ironclaw_host_api::turn::TurnStatus::Completed,
            },
            kind,
            blocked_gate: None,
            sanitized_reason: None,
            detail: None,
            retryable: None,
        }
    }

    #[tokio::test]
    async fn finalizer_clears_active_job_when_its_own_run_goes_terminal() {
        let store = SuggestionsStore::new(Arc::new(InMemoryBackend::default()));
        let run_id = TurnRunId::new();
        let ClaimOutcome::Claimed { job_id } = store
            .claim_active_job(
                &TenantId::new("t").unwrap(),
                &UserId::new("u").unwrap(),
                ThreadId::new("t1").unwrap(),
                run_id,
            )
            .await
            .unwrap()
        else {
            panic!("expected claim");
        };

        // Calls the extracted finalize work directly (not through
        // `publish`, which now spawns it) so the assertion below doesn't
        // race a background task.
        finalize_claim_if_owned(
            &store,
            &TenantId::new("t").unwrap(),
            &UserId::new("u").unwrap(),
            run_id,
            ironclaw_host_api::turn::TurnStatus::Failed,
        )
        .await;

        let doc = store
            .read_doc(&TenantId::new("t").unwrap(), &UserId::new("u").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(doc.active_job.is_none());
        assert!(doc.last_error.unwrap().message.contains("failed"));
        let _ = job_id;
    }

    #[tokio::test]
    async fn finalizer_ignores_a_terminal_event_for_a_different_run() {
        let store = SuggestionsStore::new(Arc::new(InMemoryBackend::default()));
        let claimed_run_id = TurnRunId::new();
        let unrelated_run_id = TurnRunId::new();
        store
            .claim_active_job(
                &TenantId::new("t").unwrap(),
                &UserId::new("u").unwrap(),
                ThreadId::new("t1").unwrap(),
                claimed_run_id,
            )
            .await
            .unwrap();

        // An ordinary chat turn (or any other unrelated run) reaching this
        // sink must never touch a claim it doesn't own.
        finalize_claim_if_owned(
            &store,
            &TenantId::new("t").unwrap(),
            &UserId::new("u").unwrap(),
            unrelated_run_id,
            ironclaw_host_api::turn::TurnStatus::Completed,
        )
        .await;

        let doc = store
            .read_doc(&TenantId::new("t").unwrap(), &UserId::new("u").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(doc.active_job.unwrap().run_id, claimed_run_id);
    }

    #[tokio::test]
    async fn finalizer_is_a_noop_when_render_suggestions_already_cleared_the_claim() {
        let store = SuggestionsStore::new(Arc::new(InMemoryBackend::default()));
        let run_id = TurnRunId::new();
        let ClaimOutcome::Claimed { job_id } = store
            .claim_active_job(
                &TenantId::new("t").unwrap(),
                &UserId::new("u").unwrap(),
                ThreadId::new("t1").unwrap(),
                run_id,
            )
            .await
            .unwrap()
        else {
            panic!("expected claim");
        };
        store
            .record_result(
                &TenantId::new("t").unwrap(),
                &UserId::new("u").unwrap(),
                job_id,
                vec![card()],
            )
            .await
            .unwrap();

        // The run's Completed event arrives AFTER render_suggestions already
        // recorded the result and cleared active_job — the finalizer must not
        // clobber the successful result with a synthetic failure.
        finalize_claim_if_owned(
            &store,
            &TenantId::new("t").unwrap(),
            &UserId::new("u").unwrap(),
            run_id,
            ironclaw_host_api::turn::TurnStatus::Completed,
        )
        .await;

        let doc = store
            .read_doc(&TenantId::new("t").unwrap(), &UserId::new("u").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(doc.active_job.is_none());
        assert!(doc.last_error.is_none());
        assert_eq!(doc.last_result.unwrap().cards.len(), 1);
    }

    #[tokio::test]
    async fn finalizer_ignores_non_terminal_event_kinds() {
        let store = SuggestionsStore::new(Arc::new(InMemoryBackend::default()));
        let run_id = TurnRunId::new();
        store
            .claim_active_job(
                &TenantId::new("t").unwrap(),
                &UserId::new("u").unwrap(),
                ThreadId::new("t1").unwrap(),
                run_id,
            )
            .await
            .unwrap();

        let sink = SuggestionGenerationFinalizerSink::new(store.clone());
        sink.publish(terminal_event(TurnEventKind::Submitted, "t", "u", run_id))
            .await
            .unwrap();

        let doc = store
            .read_doc(&TenantId::new("t").unwrap(), &UserId::new("u").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(
            doc.active_job.is_some(),
            "a non-terminal event must never touch the claim"
        );
    }

    /// Test-through-the-caller proof (not just `finalize_claim_if_owned` in
    /// isolation): `publish` itself must actually spawn and complete the
    /// finalize work, matching the sibling `TraceCaptureTurnEventSink`'s own
    /// "capture task is detached; poll briefly" pattern.
    #[tokio::test]
    async fn publish_spawns_the_finalize_work_and_it_completes() {
        let store = SuggestionsStore::new(Arc::new(InMemoryBackend::default()));
        let run_id = TurnRunId::new();
        store
            .claim_active_job(
                &TenantId::new("t").unwrap(),
                &UserId::new("u").unwrap(),
                ThreadId::new("t1").unwrap(),
                run_id,
            )
            .await
            .unwrap();

        let sink = SuggestionGenerationFinalizerSink::new(store.clone());
        sink.publish(terminal_event(TurnEventKind::Failed, "t", "u", run_id))
            .await
            .unwrap();

        // The finalize work is detached; poll briefly for it to land.
        let mut doc = None;
        for _ in 0..100 {
            let current = store
                .read_doc(&TenantId::new("t").unwrap(), &UserId::new("u").unwrap())
                .await
                .unwrap();
            if current.as_ref().is_some_and(|doc| doc.active_job.is_none()) {
                doc = current;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let doc = doc.expect("spawned finalize work clears active_job within the poll window");
        assert!(doc.last_error.unwrap().message.contains("failed"));
    }
}
