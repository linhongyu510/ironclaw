//! Delivery-resolution ports (PROPOSAL §6.1.3).
//!
//! The outbound delivery coordinator is product-tier *semantics* and stays in
//! `ironclaw_product`. What crosses the product boundary is the pair of ports
//! it reads through: "which channel extension is active right now" and "what
//! opaque vendor reply context did that extension attach to the originating
//! inbound message". Both are implemented **below** product by
//! `ironclaw_extension_host`, which owns the active snapshot and the
//! reply-context store — so defining them here is what lets the extension host
//! satisfy the coordinator without depending on it.
//!
//! Never here: the coordinator, delivery attempt persistence, retry policy, or
//! any implementation of these ports.

use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_extension_contracts::channel_adapter::ChannelAdapter;
use ironclaw_extension_contracts::tool_adapter::RestrictedEgress;

/// One channel's delivery half, resolved from a single active-snapshot read
/// (generation-pinned: an in-flight delivery keeps these `Arc`s across an
/// upgrade).
#[derive(Clone)]
pub struct ResolvedChannelDelivery {
    pub extension_id: String,
    pub installation_id: String,
    pub adapter: Arc<dyn ChannelAdapter>,
    /// Policy-enforced egress built from the same snapshot read.
    pub egress: Arc<dyn RestrictedEgress>,
}

/// Resolver port: the coordinator's view of the active extension set.
/// Defined here (the coordinator is the consumer); implemented over the
/// extension host's snapshot.
pub trait ChannelDeliveryResolver: Send + Sync {
    fn resolve_channel_delivery(&self, extension_id: &str) -> Option<ResolvedChannelDelivery>;
}

/// Read half of the host-side `reply_context` storage (ING-11): the opaque
/// vendor context an adapter attached to the originating inbound message,
/// handed back at delivery time.
#[async_trait]
pub trait DeliveryReplyContextSource: Send + Sync {
    async fn reply_context(
        &self,
        extension_id: &str,
        installation_id: &str,
        conversation_fingerprint: &str,
    ) -> Option<Vec<u8>>;
}
