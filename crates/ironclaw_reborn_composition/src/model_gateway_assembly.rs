use std::sync::Arc;

use ironclaw_extension_host::skill_learning::SkillLearnedNotifier;
use ironclaw_host_api::ids::UserId;
use ironclaw_product::projection::LiveProjectionPublisher;
use ironclaw_turns::{TurnRunId, TurnScope};

use crate::runtime::RebornRuntimeError;

/// [`SkillLearnedNotifier`] over the runtime's live projection publisher —
/// emits a `SkillActivation` projection item rendered as a chat bubble.
///
/// The adapter lives here, not beside the port. `LiveProjectionPublisher` is
/// one of `ironclaw_product`'s *concrete* types, and naming it was the whole
/// of `ironclaw_extension_host::skill_learning`'s `ironclaw_product`
/// dependency — the last one that file carried, and the one that would have
/// blocked the crate's `products` → `loops` re-layer. The port's own doc always
/// said "composition implements it over the projection publisher"; this makes
/// that true (PROPOSAL §6.8.2 shed list, CHECKLIST WS2 strays row).
///
/// It sits in this module because composition's other skill-learning assembly
/// piece — `build_skill_learning_provider` below — already does. It is
/// deliberately *not* a crate-root `skill_learning` module: the whole module is
/// what #6616/#6691 moved out of composition, and
/// `reborn_composition_boundaries.rs` holds it out.
pub(crate) struct LiveSkillLearnedNotifier {
    publisher: Arc<LiveProjectionPublisher>,
}

impl LiveSkillLearnedNotifier {
    pub(crate) fn new(publisher: Arc<LiveProjectionPublisher>) -> Self {
        Self { publisher }
    }
}

impl SkillLearnedNotifier for LiveSkillLearnedNotifier {
    fn notify(
        &self,
        owner: &UserId,
        scope: &TurnScope,
        run_id: TurnRunId,
        skill_name: &str,
        feedback: &str,
    ) {
        self.publisher
            .publish_skill_learned(Some(owner), scope, run_id, skill_name, feedback);
    }
}

pub(crate) async fn build_production_model_gateway(
    provider_factory: Option<ironclaw_operator::RebornProviderFactory>,
) -> Result<
    (
        Arc<dyn ironclaw_loop_host::HostManagedModelGateway>,
        Option<ironclaw_loop_host::StaticModelCostTable>,
        Option<RebornLlmReloadParts>,
    ),
    RebornRuntimeError,
> {
    let LlmGatewayBundle {
        gateway, reload, ..
    } = build_placeholder_llm_gateway(provider_factory).await?;
    Ok((gateway, None, Some(reload)))
}

pub(crate) async fn build_skill_learning_provider(
    config: &ironclaw_llm::LlmConfig,
) -> Option<(Arc<dyn ironclaw_llm::LlmProvider>, String)> {
    let model = std::env::var("IRONCLAW_SKILL_LEARNING_MODEL")
        .ok()
        .filter(|model| !model.trim().is_empty())?;
    if !matches!(config.backend.as_str(), "nearai" | "near_ai" | "near") {
        tracing::debug!(
            backend = %config.backend,
            "skill-learning: learning model is only wired for the nearai backend; skill learning disabled"
        );
        return None;
    }
    let mut nearai = config.nearai.clone();
    nearai.model = model.clone();
    let session = ironclaw_llm::create_session_manager(config.session.clone()).await;
    match ironclaw_llm::create_llm_provider_with_config(
        &nearai,
        session,
        config.request_timeout_secs,
    ) {
        Ok(provider) => Some((provider, model)),
        Err(error) => {
            tracing::debug!(%error, "skill-learning: could not build the learning provider; skill learning disabled");
            None
        }
    }
}

pub(crate) struct LlmGatewayBundle {
    pub(crate) gateway: Arc<dyn ironclaw_loop_host::HostManagedModelGateway>,
    pub(crate) reload: RebornLlmReloadParts,
}

pub(crate) struct RebornLlmReloadParts {
    pub(crate) reload_handle: Arc<ironclaw_llm::LlmReloadHandle>,
    pub(crate) session: Arc<ironclaw_llm::SessionManager>,
    pub(crate) nearai_login_states:
        Arc<ironclaw_operator::llm_admin::llm_config_service::NearAiLoginStateStore>,
}

async fn build_placeholder_llm_gateway(
    provider_factory: Option<ironclaw_operator::RebornProviderFactory>,
) -> Result<LlmGatewayBundle, RebornRuntimeError> {
    let session =
        ironclaw_llm::create_session_manager(ironclaw_llm::SessionConfig::default()).await;
    let raw: Arc<dyn ironclaw_llm::LlmProvider> = Arc::new(PlaceholderLlmProvider);
    wrap_swappable_gateway(raw, session, provider_factory)
}

/// Apply instrumentation outside the swappable provider so it survives reloads.
pub(crate) fn wrap_swappable_gateway(
    raw: Arc<dyn ironclaw_llm::LlmProvider>,
    session: Arc<ironclaw_llm::SessionManager>,
    provider_factory: Option<ironclaw_operator::RebornProviderFactory>,
) -> Result<LlmGatewayBundle, RebornRuntimeError> {
    use ironclaw_llm::{LlmProvider, LlmReloadHandle, SwappableLlmProvider};
    use ironclaw_loop_contracts::ModelProfileId;
    use ironclaw_runner::model_gateway::{LlmModelProfilePolicy, LlmProviderModelGateway};

    let swappable = Arc::new(SwappableLlmProvider::new(raw));
    let reload_handle = Arc::new(LlmReloadHandle::new(Arc::clone(&swappable), None));
    let swappable_provider: Arc<dyn LlmProvider> = swappable;
    let provider: Arc<dyn LlmProvider> = match provider_factory {
        Some(factory) => factory(Arc::clone(&swappable_provider)),
        None => swappable_provider,
    };

    let model_profile_id = ModelProfileId::new("interactive_model").map_err(|reason| {
        RebornRuntimeError::LlmProvider(format!("invalid interactive model profile id: {reason}"))
    })?;
    let policy = LlmModelProfilePolicy::new().allow_model_profile(model_profile_id, None);
    let gateway = LlmProviderModelGateway::new(provider, policy);
    Ok(LlmGatewayBundle {
        gateway: Arc::new(gateway),
        reload: RebornLlmReloadParts {
            reload_handle,
            session,
            nearai_login_states: Arc::new(
                ironclaw_operator::llm_admin::llm_config_service::NearAiLoginStateStore::new(),
            ),
        },
    })
}

#[derive(Debug)]
struct PlaceholderLlmProvider;

#[async_trait::async_trait]
impl ironclaw_llm::LlmProvider for PlaceholderLlmProvider {
    fn model_name(&self) -> &str {
        "unconfigured"
    }

    fn cost_per_token(&self) -> (rust_decimal::Decimal, rust_decimal::Decimal) {
        (rust_decimal::Decimal::ZERO, rust_decimal::Decimal::ZERO)
    }

    async fn complete(
        &self,
        _request: ironclaw_llm::CompletionRequest,
    ) -> Result<ironclaw_llm::CompletionResponse, ironclaw_llm::LlmError> {
        Err(placeholder_unconfigured_error())
    }

    async fn complete_with_tools(
        &self,
        _request: ironclaw_llm::ToolCompletionRequest,
    ) -> Result<ironclaw_llm::ToolCompletionResponse, ironclaw_llm::LlmError> {
        Err(placeholder_unconfigured_error())
    }
}

fn placeholder_unconfigured_error() -> ironclaw_llm::LlmError {
    ironclaw_llm::LlmError::RequestFailed {
        provider: ironclaw_llm::UNCONFIGURED_PROVIDER_ID.to_string(),
        reason: "no LLM provider is configured yet; choose one in Settings → Inference".to_string(),
    }
}
