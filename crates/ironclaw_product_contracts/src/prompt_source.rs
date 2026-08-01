//! The gate-prompt enrichment ports (PROPOSAL §6.1.3).
//!
//! When a run parks on an approval or auth gate, the delivery path and the
//! projection layer both render a prompt. *What* is being approved, and *which
//! challenge* an auth gate is waiting on, are read models owned outside
//! product — the approval-request store and the pairing/auth engines — so both
//! arrive through ports. `ironclaw_extension_host` implements both over its
//! pairing registry and the approvals store.
//!
//! Never here: prompt *rendering* (product owns the view constructor), the
//! challenge engine, or any implementation of these ports.

use async_trait::async_trait;
use ironclaw_extension_contracts::auth_prompt::AuthPromptView;
use ironclaw_host_api::decision::RuntimeCredentialAuthRequirement;
use ironclaw_host_api::ids::{InvocationId, UserId};
use ironclaw_host_api::product_adapter_error::ProductAdapterError;
use ironclaw_host_api::turn::{TurnGateRef, TurnRunId, TurnScope};

use crate::outbound::ApprovalPromptContextView;

/// Inputs for resolving a blocked-auth run's prompt view. One request shape
/// for every renderer (delivery path, projection layer); the challenge
/// provider is a separate argument, not request data.
pub struct BlockedAuthPromptRequest<'a> {
    pub fallback_owner_user_id: &'a UserId,
    pub scope: &'a TurnScope,
    pub run_id: TurnRunId,
    pub gate_ref: &'a str,
    /// Invocation the blocked capability ran under, when the renderer has it
    /// (the projection layer does; the delivery path renders without one).
    pub invocation_id: Option<InvocationId>,
    pub body: String,
    pub credential_requirements: &'a [RuntimeCredentialAuthRequirement],
}

/// Approval-gate context enrichment: resolves WHAT is being approved
/// (tool/action/reason) for a gate ref — the same source the WebUI gate
/// projection reads. Implemented over the approval request store; `None`
/// results degrade prompts to generic wording.
#[async_trait]
pub trait ApprovalPromptContextSource: Send + Sync {
    async fn approval_prompt_context(
        &self,
        gate_ref: &TurnGateRef,
        owner_user_id: &UserId,
        scope: &TurnScope,
    ) -> Option<ApprovalPromptContextView>;
}

/// Auth-prompt enrichment: resolves the challenge (OAuth authorization URL
/// vs manual credential entry) for a run blocked on auth. Implemented over the
/// auth engine and the host-issued pairing registry.
#[async_trait]
pub trait BlockedAuthPromptSource: Send + Sync {
    async fn auth_prompt_for_blocked_run(
        &self,
        request: BlockedAuthPromptRequest<'_>,
    ) -> Result<AuthPromptView, ProductAdapterError>;
}
