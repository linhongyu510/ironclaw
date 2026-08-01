//! The package-lifecycle product service port (PROPOSAL §6.1.3).
//!
//! [`crate::package_lifecycle`] owns the lifecycle *values*; this module owns
//! the service that answers in them. The split matters because the only
//! production implementation lives **below** product, in
//! `ironclaw_extension_host` — it is the crate that may write lifecycle state —
//! while product and every transport call it through this port.
//!
//! Never here: any lifecycle authority, install policy, or service
//! implementation (including the unsupported-runtime fallback, which is
//! product's).

use async_trait::async_trait;
use ironclaw_host_api::ids::{AgentId, ProjectId, TenantId, UserId};
use serde::Serialize;

use crate::command::ProductCommandContext;
use crate::package_lifecycle::{
    LifecyclePackageRef, LifecycleProductAction, LifecycleProductResponse,
};
use crate::surface::{ProductSurfaceError, ProductSurfaceErrorCode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LifecycleProductSurfaceContext {
    pub tenant_id: TenantId,
    pub user_id: UserId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<ProjectId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum LifecycleProductContext {
    Command(Box<ProductCommandContext>),
    Surface(LifecycleProductSurfaceContext),
}

#[async_trait]
pub trait LifecycleProductService: Send + Sync {
    async fn execute(
        &self,
        context: LifecycleProductContext,
        action: LifecycleProductAction,
    ) -> Result<LifecycleProductResponse, ProductSurfaceError>;

    async fn project_package(
        &self,
        context: LifecycleProductContext,
        package_ref: LifecyclePackageRef,
    ) -> Result<LifecycleProductResponse, ProductSurfaceError>;

    /// Import a standalone extension from an uploaded bundle (zip bytes) — the
    /// WebUI "Install Tool" path. Default is unavailable; only the local runtime
    /// service implements it.
    async fn import_extension_bundle(
        &self,
        _context: LifecycleProductContext,
        _bundle: Vec<u8>,
    ) -> Result<LifecycleProductResponse, ProductSurfaceError> {
        Err(ProductSurfaceError::from_status(
            ProductSurfaceErrorCode::InvalidRequest,
            400,
            false,
        ))
    }

    /// Redacted activation error for each installed extension whose activation
    /// failed, keyed by extension id — sourced from the durable installation
    /// record's typed `last_error`. The extensions-list service threads this
    /// into `RebornExtensionInfo::activation_error` so a failed extension shows
    /// *why* it failed instead of collapsing to a bare `installed`/`failed`
    /// state with no reason.
    ///
    /// Default: none. A service that does not surface durable installation
    /// errors reports no reason and the wire's `activation_error` stays absent;
    /// the production extension-host service overrides this to read the
    /// installation records' `last_error`.
    async fn installed_activation_errors(
        &self,
        _context: LifecycleProductContext,
    ) -> Result<std::collections::HashMap<String, String>, ProductSurfaceError> {
        Ok(std::collections::HashMap::new())
    }
}
