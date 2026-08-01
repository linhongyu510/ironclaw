//! The generic product-view conduit's descriptor types and provider port
//! (PROPOSAL §6.1.3).
//!
//! Product features register a read-only view instead of growing
//! `ProductSurface` with a feature-specific query method. The *inventory* of
//! concrete views is product's frozen surface and stays there; the descriptor,
//! the page envelope, and the port a view provider implements are boundary
//! vocabulary, because providers legitimately sit outside product — the
//! admin-configuration view is implemented by `ironclaw_extension_host`.
//!
//! Never here: any concrete view id, any provider implementation, or the
//! typed `ProductView` declaration wrapper (that carries product's frozen
//! request/response DTOs and stays with them).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::surface::{ProductSurfaceCaller, ProductSurfaceError};

/// Stable metadata for one read-only product view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebornViewDescriptor {
    pub id: &'static str,
    pub paginated: bool,
}

/// One registered, read-only product view invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornViewQuery {
    pub view_id: String,
    pub params: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// One page returned by the generic product view conduit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornViewPage {
    pub payload: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// One composition-supplied implementation behind the generic view conduit.
///
/// Product features register descriptors and providers instead of growing
/// `ProductSurface` with feature-specific read methods.
#[async_trait]
pub trait RebornViewProvider: Send + Sync {
    fn descriptor(&self) -> RebornViewDescriptor;

    async fn query(
        &self,
        caller: ProductSurfaceCaller,
        params: serde_json::Value,
        cursor: Option<String>,
    ) -> Result<RebornViewPage, ProductSurfaceError>;
}
