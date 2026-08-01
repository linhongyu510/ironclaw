//! Product's half of the LLM configuration surface.
//!
//! The port itself — `LlmConfigService`, `ActiveModelReader`, and their request
//! and response DTOs — is declared in
//! `ironclaw_product_contracts::llm_config`, because its implementation is
//! `ironclaw_operator`'s and a port belongs at the boundary its implementor
//! compiles against (PROPOSAL §6.1.3, §6.9.2; CHECKLIST WS5 operator row).
//!
//! What stays here is what product owns: the frozen `llm_config` view
//! descriptor, the fail-closed error for "no service wired", and the
//! `RebornServices` wiring that calls through the port.

use ironclaw_product_contracts::llm_config::{
    LlmConfigServiceError, LlmConfigSnapshot, SetActiveLlmRequest, UpsertLlmProviderRequest,
};
use ironclaw_product_contracts::views::{RebornViewDescriptor, RebornViewProvider};

use ironclaw_product_contracts::surface::{
    ProductSurfaceCaller, ProductSurfaceError, ProductSurfaceErrorCode, ProductSurfaceErrorKind,
    ProductSurfaceValidationCode,
};

use super::{ProductCapabilityInvoker, RebornServices};

pub const LLM_CONFIG_VIEW: RebornViewDescriptor = RebornViewDescriptor {
    id: "llm_config",
    paginated: false,
};

/// Project the port error onto the surface error.
///
/// The status table is **not** repeated here: it is defined once, beside the
/// error, as `impl From<LlmConfigServiceError> for ProductSurfaceError` in
/// `ironclaw_product_contracts::llm_config`. This wrapper survives only so the
/// call sites keep reading as `.map_err(map_llm_config_error)`; deleting it in
/// favour of `ProductSurfaceError::from` is a pure rename.
pub(super) fn map_llm_config_error(error: LlmConfigServiceError) -> ProductSurfaceError {
    ProductSurfaceError::from(error)
}

/// Error returned when an LLM-config method is invoked but no service is wired.
pub(super) fn llm_config_unavailable() -> ProductSurfaceError {
    ProductSurfaceError::from_status_kind(
        ProductSurfaceErrorCode::Unavailable,
        ProductSurfaceErrorKind::ServiceUnavailable,
        503,
        false,
    )
}

impl<I, V> RebornServices<I, V>
where
    I: ProductCapabilityInvoker + Clone + 'static,
    V: RebornViewProvider + Clone + 'static,
{
    pub(super) async fn invoke_llm_provider_upsert(
        &self,
        caller: ProductSurfaceCaller,
        request: UpsertLlmProviderRequest,
    ) -> Result<(), ProductSurfaceError> {
        let service = self
            .llm_config
            .as_ref()
            .ok_or_else(llm_config_unavailable)?;
        super::validate_llm_base_url(request.base_url.as_deref())?;
        service
            .upsert_provider(caller, request)
            .await
            .map_err(map_llm_config_error)?;
        Ok(())
    }

    pub(super) async fn invoke_llm_provider_delete(
        &self,
        caller: ProductSurfaceCaller,
        input: serde_json::Value,
    ) -> Result<(), ProductSurfaceError> {
        let service = self
            .llm_config
            .as_ref()
            .ok_or_else(llm_config_unavailable)?;
        let provider_id = input
            .as_object()
            .and_then(|object| object.get("provider_id"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| llm_config_input_error("provider_id"))?
            .to_string();
        service
            .delete_provider(caller, provider_id)
            .await
            .map_err(map_llm_config_error)?;
        Ok(())
    }

    pub(super) async fn invoke_llm_active_set(
        &self,
        caller: ProductSurfaceCaller,
        input: serde_json::Value,
    ) -> Result<(), ProductSurfaceError> {
        let service = self
            .llm_config
            .as_ref()
            .ok_or_else(llm_config_unavailable)?;
        let request: SetActiveLlmRequest =
            serde_json::from_value(input).map_err(|_| llm_config_input_error("input"))?;
        service
            .set_active(caller, request)
            .await
            .map_err(map_llm_config_error)?;
        Ok(())
    }

    pub(super) async fn build_llm_config_view(
        &self,
        caller: ProductSurfaceCaller,
    ) -> Result<LlmConfigSnapshot, ProductSurfaceError> {
        let service = self
            .llm_config
            .as_ref()
            .ok_or_else(llm_config_unavailable)?;
        service.snapshot(caller).await.map_err(map_llm_config_error)
    }
}

fn llm_config_input_error(field: &'static str) -> ProductSurfaceError {
    ProductSurfaceError::validation(field, ProductSurfaceValidationCode::InvalidValue)
}
