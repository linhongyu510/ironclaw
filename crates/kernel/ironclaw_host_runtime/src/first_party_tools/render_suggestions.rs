//! `render_suggestions` (#7038): the forced structured-output tool the
//! suggestion-generation loop must call to finish. Registered ONLY into the
//! suggestion-generation capability surface profile (see
//! `ironclaw_turn_runner::planned_driver_factory::SUGGESTION_GENERATION_CAPABILITY_SURFACE_PROFILE_ID`
//! and `runtime.rs`'s allow-list).
//!
//! `SuggestionCard` lives in the `ironclaw_suggestions` domain crate (below
//! this kernel-layer crate) so the schema struct is the single source of
//! truth across the tool input, the stored doc, and the HTTP response (spec
//! §4). The actual store write happens behind [`RenderSuggestionsHook`] —
//! `ironclaw_assistant` (product layer) implements it over
//! `SuggestionsStore`, the same hook-injection shape `TriggerCreateHook`
//! uses to let a kernel-layer tool reach a product-owned side effect.

use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_extension_registry::{CapabilityManifest, ExtensionError};
use ironclaw_host_api::{
    capability::{EffectKind, PermissionMode},
    dispatch::{DispatchInputIssue, DispatchInputIssueCode, RuntimeDispatchErrorKind},
    error::HostApiError,
    ids::CapabilityId,
    resource::{ResourceScope, ResourceUsage},
};
use ironclaw_suggestions::SuggestionCard;
use serde::Deserialize;
use serde_json::json;

use crate::{
    FirstPartyCapabilityError, FirstPartyCapabilityHandler, FirstPartyCapabilityRegistry,
    FirstPartyCapabilityRequest, FirstPartyCapabilityResult,
};

use super::{first_party_capability_manifest, resource_profile};

pub const RENDER_SUGGESTIONS_CAPABILITY_ID: &str = "builtin.render_suggestions";

const MIN_CARDS: usize = 1;
const MAX_CARDS: usize = 8;

const DESCRIPTION: &str = "Finish this suggestion-generation run by submitting the automation suggestion cards you decided on. This is the ONLY way to finish: a reply without calling this tool is recorded as a failed generation. Call it exactly once with your final list of 3 to 6 cards.";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenderSuggestionsInput {
    cards: Vec<SuggestionCard>,
}

/// Product-owned side effect: record the validated cards against the
/// caller's suggestions doc. Implemented in `ironclaw_assistant` over
/// `SuggestionsStore` and injected by composition — this kernel-layer crate
/// never depends on the product-layer store directly.
#[async_trait]
pub trait RenderSuggestionsHook: Send + Sync {
    async fn record_cards(
        &self,
        scope: &ResourceScope,
        cards: Vec<SuggestionCard>,
    ) -> Result<(), RenderSuggestionsHookError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderSuggestionsHookError {
    /// No claimed generation job for this caller — nothing to record
    /// against (e.g. a stale/expired run calling in after being superseded).
    NoActiveJob,
    Backend {
        reason: String,
    },
}

pub(super) fn manifest() -> Result<CapabilityManifest, ExtensionError> {
    first_party_capability_manifest(
        RENDER_SUGGESTIONS_CAPABILITY_ID,
        DESCRIPTION,
        vec![EffectKind::DispatchCapability],
        PermissionMode::Allow,
        resource_profile(),
    )
}

pub(super) fn insert_handler(
    registry: &mut FirstPartyCapabilityRegistry,
    hook: Arc<dyn RenderSuggestionsHook>,
) -> Result<(), HostApiError> {
    registry.insert_handler(
        CapabilityId::new(RENDER_SUGGESTIONS_CAPABILITY_ID)?,
        Arc::new(RenderSuggestionsHandler { hook }),
    );
    Ok(())
}

struct RenderSuggestionsHandler {
    hook: Arc<dyn RenderSuggestionsHook>,
}

#[async_trait]
impl FirstPartyCapabilityHandler for RenderSuggestionsHandler {
    async fn dispatch(
        &self,
        request: FirstPartyCapabilityRequest,
    ) -> Result<FirstPartyCapabilityResult, FirstPartyCapabilityError> {
        let input: RenderSuggestionsInput =
            serde_json::from_value(request.input).map_err(|error| {
                tracing::debug!(%error, "render_suggestions input failed schema decoding");
                super::input_error()
            })?;
        if input.cards.len() < MIN_CARDS || input.cards.len() > MAX_CARDS {
            return Err(FirstPartyCapabilityError::invalid_input_issues(
                "render_suggestions input failed validation",
                vec![
                    DispatchInputIssue::new("cards", DispatchInputIssueCode::InvalidValue)
                        .expected("between 1 and 8 suggestion cards"),
                ],
            ));
        }
        let card_count = input.cards.len();
        self.hook
            .record_cards(&request.scope, input.cards)
            .await
            .map_err(map_hook_error)?;
        Ok(FirstPartyCapabilityResult::new(
            json!({ "recorded": true, "card_count": card_count }),
            ResourceUsage::default(),
        ))
    }
}

/// Fail-closed default installed by the base registry (mirrors
/// `UnavailableModelChannelDelivery`): composition must call
/// `register_render_suggestions_first_party_handler` with the real
/// product-backed hook, or every call fails with `Backend`.
pub(super) struct UnavailableRenderSuggestionsHook;

#[async_trait]
impl RenderSuggestionsHook for UnavailableRenderSuggestionsHook {
    async fn record_cards(
        &self,
        _scope: &ResourceScope,
        _cards: Vec<SuggestionCard>,
    ) -> Result<(), RenderSuggestionsHookError> {
        Err(RenderSuggestionsHookError::Backend {
            reason: "render_suggestions hook is not wired".to_string(),
        })
    }
}

fn map_hook_error(error: RenderSuggestionsHookError) -> FirstPartyCapabilityError {
    match error {
        RenderSuggestionsHookError::NoActiveJob => FirstPartyCapabilityError::with_safe_summary(
            RuntimeDispatchErrorKind::OperationFailed,
            "no suggestion-generation job is currently claimed for this caller",
        ),
        RenderSuggestionsHookError::Backend { .. } => {
            FirstPartyCapabilityError::new(RuntimeDispatchErrorKind::Backend)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ironclaw_host_api::{
        dispatch::DispatchFailureDetail,
        ids::{InvocationId, RunId, TenantId, ThreadId, UserId},
        resource::ResourceEstimate,
    };
    use serde_json::{Value, json};
    use uuid::Uuid;

    use crate::{FirstPartyCapabilityRequest, HostProcessPort, InvocationServices};

    use super::*;

    struct FakeHook {
        result: Result<(), RenderSuggestionsHookError>,
        seen: Mutex<Vec<Vec<SuggestionCard>>>,
    }

    impl FakeHook {
        fn new(result: Result<(), RenderSuggestionsHookError>) -> Self {
            Self {
                result,
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl RenderSuggestionsHook for FakeHook {
        async fn record_cards(
            &self,
            _scope: &ResourceScope,
            cards: Vec<SuggestionCard>,
        ) -> Result<(), RenderSuggestionsHookError> {
            self.seen.lock().unwrap().push(cards);
            self.result.clone()
        }
    }

    fn sample_scope() -> ResourceScope {
        ResourceScope {
            tenant_id: TenantId::new("tenant-render-suggestions").unwrap(),
            user_id: UserId::new("user-render-suggestions").unwrap(),
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: Some(ThreadId::new("thread-render-suggestions").unwrap()),
            invocation_id: InvocationId::new(),
        }
    }

    fn sample_request(input: Value) -> FirstPartyCapabilityRequest {
        FirstPartyCapabilityRequest {
            capability_id: CapabilityId::new(RENDER_SUGGESTIONS_CAPABILITY_ID).unwrap(),
            scope: sample_scope(),
            authenticated_actor_user_id: None,
            run_id: Some(RunId::new()),
            origin: None,
            estimate: ResourceEstimate::default(),
            mounts: None,
            services: InvocationServices {
                filesystem: Arc::new(ironclaw_filesystem::InMemoryBackend::new()),
                runtime_http_egress: None,
                tool_call_http_egress: None,
                runtime_secret_material_stager: None,
                process: Arc::new(HostProcessPort::new()),
                secret_store: None,
                audit_sink: None,
                unsafe_raw_diagnostics_allowed: false,
                post_edit_check: None,
            },
            input,
        }
    }

    fn card(title: &str) -> Value {
        json!({
            "id": Uuid::new_v4(),
            "title": title,
            "description": "do the thing",
            "requires_connection": false,
            "suggested_prompt": "go do the thing",
            "category": "email",
        })
    }

    #[tokio::test]
    async fn valid_cards_are_recorded_and_reported() {
        let hook = Arc::new(FakeHook::new(Ok(())));
        let handler = RenderSuggestionsHandler { hook: hook.clone() };

        let result = handler
            .dispatch(sample_request(
                json!({ "cards": [card("Triage inbox"), card("Summarize mentions")] }),
            ))
            .await
            .expect("valid cards succeed");

        assert_eq!(result.output["recorded"], json!(true));
        assert_eq!(result.output["card_count"], json!(2));
        assert_eq!(hook.seen.lock().unwrap().len(), 1);
        assert_eq!(hook.seen.lock().unwrap()[0].len(), 2);
    }

    #[tokio::test]
    async fn empty_card_list_is_rejected_before_the_hook() {
        let hook = Arc::new(FakeHook::new(Ok(())));
        let handler = RenderSuggestionsHandler { hook: hook.clone() };

        let error = handler
            .dispatch(sample_request(json!({ "cards": [] })))
            .await
            .expect_err("empty card list must fail");

        assert_eq!(error.kind(), Some(RuntimeDispatchErrorKind::InputEncode));
        let FirstPartyCapabilityError::Dispatch { detail, .. } = &error else {
            panic!("expected Dispatch variant");
        };
        let Some(DispatchFailureDetail::InvalidInput { issues }) = detail.as_deref() else {
            panic!("expected InvalidInput detail, got {detail:?}");
        };
        assert!(issues.iter().any(|issue| issue.path == "cards"));
        assert!(hook.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn too_many_cards_is_rejected_before_the_hook() {
        let hook = Arc::new(FakeHook::new(Ok(())));
        let handler = RenderSuggestionsHandler { hook: hook.clone() };
        let cards: Vec<Value> = (0..9).map(|i| card(&format!("card {i}"))).collect();

        let error = handler
            .dispatch(sample_request(json!({ "cards": cards })))
            .await
            .expect_err("more than 8 cards must fail");

        assert_eq!(error.kind(), Some(RuntimeDispatchErrorKind::InputEncode));
        assert!(hook.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn no_active_job_maps_to_operation_failed() {
        let hook = Arc::new(FakeHook::new(Err(RenderSuggestionsHookError::NoActiveJob)));
        let handler = RenderSuggestionsHandler { hook };

        let error = handler
            .dispatch(sample_request(json!({ "cards": [card("Triage inbox")] })))
            .await
            .expect_err("no active job must fail");

        assert_eq!(
            error.kind(),
            Some(RuntimeDispatchErrorKind::OperationFailed)
        );
    }

    #[tokio::test]
    async fn backend_error_maps_to_backend_kind() {
        let hook = Arc::new(FakeHook::new(Err(RenderSuggestionsHookError::Backend {
            reason: "store unavailable".to_string(),
        })));
        let handler = RenderSuggestionsHandler { hook };

        let error = handler
            .dispatch(sample_request(json!({ "cards": [card("Triage inbox")] })))
            .await
            .expect_err("backend error must fail");

        assert_eq!(error.kind(), Some(RuntimeDispatchErrorKind::Backend));
    }
}
