//! Suggestion-generation (#7038) test-support seam: drives the REAL
//! `RebornSuggestionsProductService` (not a fake) over the harness's shared
//! `coordinator`/thread service, so a generated run carries the genuine
//! `suggestion_generation` run profile and lands in the same turn store/
//! scheduler as any other turn. Mirrors `triggered_submit.rs`'s shape for the
//! trigger domain.

#![allow(dead_code)]

use std::sync::Arc;

use ironclaw_assistant::{
    ProductAgentBoundCaller, RebornSuggestionsProductService, RebornSuggestionsResponse,
    SuggestionsProductService,
};
use ironclaw_filesystem::{InMemoryBackend, ScopedFilesystem};
use ironclaw_host_api::ids::ThreadId;
use ironclaw_host_api::mount::{MountGrant, MountPermissions, MountView};
use ironclaw_host_api::path::{MountAlias, VirtualPath};
use ironclaw_host_api::resource::ResourceScope;
use ironclaw_host_api::turn::TurnScope;
use ironclaw_llm::testing::provider_chain_over;
use ironclaw_llm::{LlmProvider, SessionConfig, create_session_manager};
use ironclaw_loop_contracts::ModelProfileId;
use ironclaw_loop_host::{HostManagedModelGateway, LlmModelProfilePolicy, LlmProviderModelGateway};
use ironclaw_suggestions::SuggestionsStore;

use super::builder::{INTERACTIVE_MODEL_PROFILE, RebornIntegrationHarness};
use super::reply::RebornScriptedReply;
use super::scripted_provider::{SCRIPTED_MODEL_NAME, scripted_trace_llm};
use crate::support::trace_llm::TraceLlm;

type HarnessResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

impl RebornIntegrationHarness {
    /// Caller matching this harness's own resolved binding — every scenario
    /// in this file is single-user, so the harness's own tenant/user/agent
    /// scope is also the suggestion-generation caller's scope.
    pub(crate) fn suggestions_caller(&self) -> ProductAgentBoundCaller {
        ProductAgentBoundCaller::new(
            self.binding.tenant_id.clone(),
            self.binding.actor_user_id.clone(),
            self.binding
                .agent_id
                .clone()
                .expect("harness binding carries an agent id"),
            self.binding.project_id.clone(),
        )
    }

    /// The `TurnScope` a suggestion-generation run for `thread_id` resolves
    /// to under this harness's binding — computed the same way
    /// `RebornSuggestionsProductService` computes it internally, so a test
    /// can register a scripted gateway for the EXACT scope before submitting
    /// (avoiding the routing-miss sentinel race `triggered_submit.rs`
    /// documents).
    pub(crate) fn suggestions_turn_scope(&self, thread_id: ThreadId) -> TurnScope {
        TurnScope::new_with_owner(
            self.binding.tenant_id.clone(),
            self.binding.agent_id.clone(),
            self.binding.project_id.clone(),
            thread_id,
            Some(self.binding.actor_user_id.clone()),
        )
    }

    /// Registers a scripted model gateway for the suggestion-generation scope
    /// at `thread_id`, over the real decorator chain (`provider_chain_over` →
    /// `LlmProviderModelGateway`, same one-fake-at-the-vendor-SDK-seam shape
    /// `triggered_submit.rs` uses). Must be called before the generate call
    /// that will submit under this `thread_id`.
    pub(crate) async fn register_suggestions_scripted_gateway(
        &self,
        thread_id: ThreadId,
        replies: impl IntoIterator<Item = RebornScriptedReply>,
    ) -> HarnessResult<()> {
        let scope = self.suggestions_turn_scope(thread_id.clone());
        let scripted_llm: Arc<TraceLlm> = Arc::new(scripted_trace_llm(replies));
        let raw: Arc<dyn LlmProvider> = scripted_llm;
        let session = create_session_manager(SessionConfig {
            session_path: self
                ._shared
                .turn_root
                .path()
                .join(format!("{}.suggestions.session.json", thread_id.as_str())),
            ..SessionConfig::default()
        })
        .await;
        let llm_config = ironclaw_llm::testing::nearai_test_config(SCRIPTED_MODEL_NAME);
        let provider = provider_chain_over(raw, &llm_config, session).await?;
        let model_profile_id = ModelProfileId::new(INTERACTIVE_MODEL_PROFILE)
            .map_err(|reason| format!("invalid model profile id: {reason}"))?;
        let policy = LlmModelProfilePolicy::new().allow_model_profile(model_profile_id, None);
        let gateway: Arc<dyn HostManagedModelGateway> =
            Arc::new(LlmProviderModelGateway::new(provider, policy));
        self.register_scope_gateway_for_test(scope, gateway);
        Ok(())
    }
}

/// Builds the REAL `RebornSuggestionsProductService` over the harness's
/// shared thread service/turn coordinator (the identical wiring
/// `product_surface.rs` composes in production, minus the composition-time
/// filesystem selection — an independent in-memory mount, since the doc
/// store's own persistence is exercised directly by `ironclaw_suggestions`'s
/// crate-tier tests; this seam is about the turn/capability-profile/tool
/// wiring around it).
pub(crate) fn suggestions_service_for_harness(
    harness: &RebornIntegrationHarness,
) -> RebornSuggestionsProductService<InMemoryBackend> {
    RebornSuggestionsProductService::new(
        SuggestionsStore::new(scoped_suggestions_fs()),
        harness.thread_harness.service.clone(),
        harness.coordinator.clone(),
    )
}

/// `/suggestions` mount grant over a fresh in-memory backend, the same shape
/// production wiring grants via `PER_USER_ALIASES` in `ironclaw_composition`.
pub(crate) fn scoped_suggestions_fs() -> Arc<ScopedFilesystem<InMemoryBackend>> {
    Arc::new(ScopedFilesystem::new(
        Arc::new(InMemoryBackend::default()),
        |scope: &ResourceScope| {
            MountView::new(vec![MountGrant::new(
                MountAlias::new("/suggestions")?,
                VirtualPath::new(format!(
                    "/tenants/{}/users/{}/suggestions",
                    scope.tenant_id, scope.user_id
                ))?,
                MountPermissions::read_write_list_delete(),
            )])
        },
    ))
}

/// Fresh, distinctive suggestion-generation thread id for a scenario.
pub(crate) fn suggestions_thread_id(label: &str) -> ThreadId {
    ThreadId::new(format!("suggestion-gen-test-{label}"))
        .unwrap_or_else(|error| panic!("invalid suggestion-generation test thread id: {error}"))
}

/// Poll the store-backed derived view until `predicate` holds or the
/// deadline elapses. Suggestion-generation runs execute asynchronously (the
/// scheduler picks the run up after `submit_turn` returns `Accepted`), so
/// scenarios that need the run's terminal effect (`last_result`/`last_error`
/// written) must poll rather than read once immediately after generating.
pub(crate) async fn wait_for_suggestions_view(
    service: &RebornSuggestionsProductService<InMemoryBackend>,
    caller: ProductAgentBoundCaller,
    predicate: impl Fn(&RebornSuggestionsResponse) -> bool,
) -> HarnessResult<RebornSuggestionsResponse> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let view = service.get_suggestions(caller.clone()).await?;
        if predicate(&view) {
            return Ok(view);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for suggestions view predicate; last view: {view:?}"
            )
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
