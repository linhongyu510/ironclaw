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
use ironclaw_host_api::resource::ResourceScope;
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
}
