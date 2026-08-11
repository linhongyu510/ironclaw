//! Composition-owned bridge between the kernel-layer `render_suggestions`
//! tool (`ironclaw_host_runtime`) and the product-layer `SuggestionsStore`
//! (`ironclaw_suggestions`, mirrored at the domain layer so both sides can
//! reach it) — the same hook-injection shape `TriggerCreateHook` uses so a
//! kernel tool can reach a store one layer above it (#7038).
//!
//! The spec §6 "turn finalizer" that shares this feature's seam —
//! `SuggestionGenerationFinalizerSink`, which clears a terminal
//! `active_job` the moment its own run ends — is real behavior, not
//! service-graph assembly, so it lives in `ironclaw_assistant`
//! (`ironclaw_assistant::SuggestionGenerationFinalizerSink`) beside
//! `suggestions_product_service.rs`, which it exists to unblock. This file
//! only constructs and registers it (see `runtime.rs`).

use async_trait::async_trait;
use ironclaw_host_api::{ids::RunId, resource::ResourceScope, turn::TurnRunId};
use ironclaw_host_runtime::{RenderSuggestionsHook, RenderSuggestionsHookError};
use ironclaw_suggestions::{SuggestionCard, SuggestionsStore, SuggestionsStoreError};

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
        run_id: Option<RunId>,
        cards: Vec<SuggestionCard>,
    ) -> Result<(), RenderSuggestionsHookError> {
        let active_job = self
            .store
            .read_doc(&scope.tenant_id, &scope.user_id)
            .await
            .map_err(store_error)?
            .and_then(|doc| doc.active_job)
            .ok_or(RenderSuggestionsHookError::NoActiveJob)?;
        // Bind to the job the CALLING run itself claimed, not to whichever
        // job happens to be active right now (#7498): a superseded run's
        // `render_suggestions` call landing after a newer claim replaced the
        // slot must not be recorded against that newer claim. `run_id` is
        // the dispatch-stamped identity of the acting loop run (forwarded
        // from `FirstPartyCapabilityRequest::run_id`, not model-supplied),
        // so it is safe to trust as the caller's own run.
        {
            // Fail closed: a call that cannot name its run cannot prove it owns
            // the claim, so it must not record against it. The production
            // dispatch always stamps `run_id` (verified by making this arm
            // reject and watching the full suggestion-cards integration suite
            // stay green), so this is a guard, not a live branch.
            let Some(run_id) = run_id else {
                return Err(RenderSuggestionsHookError::NoActiveJob);
            };
            let calling_run_id = TurnRunId::from_uuid(run_id.as_uuid());
            if active_job.run_id != calling_run_id {
                return Err(RenderSuggestionsHookError::NoActiveJob);
            }
        }
        self.store
            .record_result(&scope.tenant_id, &scope.user_id, active_job.job_id, cards)
            .await
            .map_err(store_error)
    }
}

fn store_error(error: SuggestionsStoreError) -> RenderSuggestionsHookError {
    RenderSuggestionsHookError::Backend {
        reason: error.to_string(),
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
        let run_id = TurnRunId::new();
        let ClaimOutcome::Claimed { .. } = store
            .claim_active_job(
                &scope.tenant_id,
                &scope.user_id,
                ThreadId::new("t1").unwrap(),
                run_id,
            )
            .await
            .unwrap()
        else {
            panic!("expected claim");
        };

        let hook = StoreBackedRenderSuggestionsHook::new(store.clone());
        hook.record_cards(
            &scope,
            Some(RunId::from_uuid(run_id.as_uuid())),
            vec![card()],
        )
        .await
        .unwrap();

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

        let error = hook
            .record_cards(&scope, None, vec![card()])
            .await
            .unwrap_err();

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
        let error = hook.record_cards(&b, None, vec![card()]).await.unwrap_err();

        assert_eq!(error, RenderSuggestionsHookError::NoActiveJob);
    }

    /// Regression for #7498's documented race: `RenderSuggestionsHook` used
    /// to resolve `job_id` by re-reading whichever `active_job` was CURRENTLY
    /// active rather than checking the acting run's own claim, so a
    /// superseded run's late `render_suggestions` call could be recorded
    /// against — and clear — a newer claim's slot. This pins the fix: the
    /// hook must bind to the job the CALLING run itself claimed.
    #[tokio::test]
    async fn stale_run_render_suggestions_call_does_not_overwrite_a_newer_claim() {
        let store = SuggestionsStore::new(Arc::new(InMemoryBackend::default()));
        let scope = scope("t", "u");
        let thread_id = ThreadId::new("t1").unwrap();

        // Run A claims the job, then is later judged dead (crash-recovery
        // path in `suggestions_product_service.rs`) and its claim cleared.
        let run_a = TurnRunId::new();
        let ClaimOutcome::Claimed { job_id: job_a } = store
            .claim_active_job(&scope.tenant_id, &scope.user_id, thread_id.clone(), run_a)
            .await
            .unwrap()
        else {
            panic!("expected claim");
        };
        store
            .record_failure(
                &scope.tenant_id,
                &scope.user_id,
                job_a,
                "run A superseded".to_string(),
            )
            .await
            .unwrap();

        // A fresh request claims a new job (run B) for the same caller.
        let run_b = TurnRunId::new();
        let ClaimOutcome::Claimed { job_id: job_b } = store
            .claim_active_job(&scope.tenant_id, &scope.user_id, thread_id, run_b)
            .await
            .unwrap()
        else {
            panic!("expected claim");
        };

        // Run A's `render_suggestions` tool call lands late — it must not be
        // recorded against job B's still-active slot.
        let hook = StoreBackedRenderSuggestionsHook::new(store.clone());
        let error = hook
            .record_cards(
                &scope,
                Some(RunId::from_uuid(run_a.as_uuid())),
                vec![card()],
            )
            .await
            .unwrap_err();
        assert_eq!(error, RenderSuggestionsHookError::NoActiveJob);

        let doc = store
            .read_doc(&scope.tenant_id, &scope.user_id)
            .await
            .unwrap()
            .unwrap();
        // Job B's claim must still be active and untouched by run A's stale
        // cards.
        assert_eq!(doc.active_job.unwrap().job_id, job_b);
        assert!(doc.last_result.is_none());
    }
}
