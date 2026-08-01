//! The per-extension channel-config port (PROPOSAL §6.1.3).
//!
//! `[channel.config]` declares operator-supplied configuration for a channel
//! extension. The product setup service routes submitted values through this
//! port and derives config completeness from the field status it returns; the
//! implementation is the extension host's, because it owns the durable
//! installation store and the scoped secret store the values land in.
//!
//! The field DTO itself is manifest vocabulary and already lives in
//! [`crate::package_lifecycle::ChannelConfigField`]; this module adds only the
//! port.

use async_trait::async_trait;
use ironclaw_host_api::ids::ExtensionId;

use crate::package_lifecycle::ChannelConfigField;
use crate::surface::ProductSurfaceError;

/// The generic channel-config configure port: per-extension operator config
/// declared by the extension manifest's channel-config fields. The extension
/// host implements it over the durable installation store and the scoped
/// secret store; the setup service routes submitted values through it and
/// derives config completeness from the field status.
#[async_trait]
pub trait ChannelConfigProductService: Send + Sync {
    /// Per-field presence for the extension's declared channel config.
    /// Empty when the extension declares none (or is not installed yet).
    async fn field_status(
        &self,
        extension_id: &ExtensionId,
    ) -> Result<Vec<ChannelConfigField>, ProductSurfaceError>;

    /// Validate submitted `(handle, value)` pairs against the installed
    /// manifest's declared fields and persist them (non-secret values
    /// durably per installation, secret values into the scoped secret
    /// store). Saving while the extension is active re-runs its activation
    /// with the new values.
    async fn save_values(
        &self,
        extension_id: &ExtensionId,
        values: Vec<(String, String)>,
    ) -> Result<(), ProductSurfaceError>;
}
