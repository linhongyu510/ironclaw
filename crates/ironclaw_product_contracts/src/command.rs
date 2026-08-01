//! The authority-bearing command context and the actor-role admission port
//! (PROPOSAL §6.1.3).
//!
//! [`ProductCommandContext`] is what a channel host hands the product surface
//! when an inbound message turns out to be a command: the verified claim, the
//! external refs it arrived on, and the action identity it is deduplicated by.
//! It crosses the boundary in both directions — product builds it from an
//! envelope, and `ironclaw_extension_host` reads it to resolve the bound
//! user's admin role through [`CommandActorRoleResolver`].
//!
//! Never here: the command grammar (`ProductCommand` and the declared command
//! inventory stay with product's frozen surface), admission policy, or any
//! resolver implementation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ironclaw_extension_contracts::channel_adapter::ProductTriggerReason;
use ironclaw_extension_contracts::external::{ExternalActorRef, ExternalConversationRef};
use ironclaw_host_api::product_adapter::{
    AdapterInstallationId, ProductAdapterId, VerifiedAuthClaim,
};
use serde::Serialize;

use crate::action::{ActionFingerprintKey, ProductActionId};
use crate::admin_users::AdminUserRole;
use crate::inbound::{ProductInboundEnvelope, ProductInboundPayload};
use crate::surface::{ProductSurfaceError, ProductSurfaceErrorCode};

/// Authority-bearing command dispatch context built by the workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductCommandContext {
    pub action_id: ProductActionId,
    pub fingerprint: ActionFingerprintKey,
    /// Exact raw inbound command token, verbatim from the payload.
    pub requested_command: String,
    pub adapter_id: ProductAdapterId,
    pub installation_id: AdapterInstallationId,
    pub external_actor_ref: ExternalActorRef,
    pub external_conversation_ref: ExternalConversationRef,
    pub auth_claim: VerifiedAuthClaim,
    pub trigger: ProductTriggerReason,
    pub received_at: DateTime<Utc>,
}

impl ProductCommandContext {
    pub fn from_envelope(
        envelope: &ProductInboundEnvelope,
        action_id: ProductActionId,
        fingerprint: ActionFingerprintKey,
    ) -> Result<Self, ProductSurfaceError> {
        let ProductInboundPayload::Command(command) = envelope.payload() else {
            return Err(ProductSurfaceError::from_status(
                ProductSurfaceErrorCode::InvalidRequest,
                400,
                false,
            ));
        };
        Ok(Self {
            action_id,
            fingerprint,
            requested_command: command.command.clone(),
            adapter_id: envelope.adapter_id().clone(),
            installation_id: envelope.installation_id().clone(),
            external_actor_ref: envelope.external_actor_ref().clone(),
            external_conversation_ref: envelope.external_conversation_ref().clone(),
            auth_claim: envelope.auth_claim().clone(),
            trigger: command.trigger,
            received_at: envelope.received_at(),
        })
    }
}

/// Resolves the admin-boundary role of the ACTIVE bound user behind an
/// inbound channel actor. `Ok(None)` means unbound actor, missing record, or
/// suspended account — all treated as not-admin (fail closed). `Err` means
/// transient resolution failure; the command fails retryable rather than
/// silently degrading to member or admin treatment.
#[async_trait]
pub trait CommandActorRoleResolver: Send + Sync {
    async fn actor_role(
        &self,
        context: &ProductCommandContext,
    ) -> Result<Option<AdminUserRole>, ProductSurfaceError>;
}
