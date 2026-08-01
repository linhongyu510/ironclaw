//! The operator tool-catalog port (PROPOSAL §6.1.3).
//!
//! The operator/settings surface lists the capabilities a caller may see and
//! set per-tool permissions on them. What tools exist is an extension-host
//! question (it owns the active snapshot), so the catalog is a port defined at
//! the product boundary and implemented below it — the same inversion as
//! [`crate::delivery`].
//!
//! Never here: permission policy, override storage, or any catalog
//! implementation.

use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_host_api::{
    capability::{EffectKind, PermissionMode},
    ids::{CapabilityId, ExtensionId, UserId},
};

/// One tool as the operator surface sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebornOperatorToolInfo {
    pub capability_id: CapabilityId,
    pub provider: ExtensionId,
    pub description: Arc<str>,
    pub default_permission: PermissionMode,
    pub effects: Arc<[EffectKind]>,
}

#[async_trait]
pub trait RebornOperatorToolCatalog: Send + Sync {
    /// Tools visible to `caller` in the operator/settings surface (#5459 P1).
    ///
    /// The settings/tools routes are authenticated-caller routes (not
    /// operator-gated), so a member reads this catalog. It MUST therefore be
    /// filtered by installation owner exactly like the model capability
    /// surface: tenant-shared tools for everyone, user-private tools only for
    /// their owner. An unfiltered catalog would disclose another user's
    /// private install (its capability id, description, effects) — the leak
    /// this parameter closes.
    async fn list_operator_tools(&self, caller: &UserId) -> Vec<RebornOperatorToolInfo>;
}
