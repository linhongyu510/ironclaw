//! IronHub catalog client for IronClaw Reborn.
//!
//! IronHub is IronClaw's own package registry (`hub.ironclaw.com`): an
//! Ed25519-signed catalog of installable tools and skills. This crate is the
//! host side of that one concrete registry — vendor-scoped by charter, the
//! same way each concrete extension crate is scoped to its product:
//!
//! - **catalog** ([`catalog`], [`model`]): fetch the signed catalog over the
//!   runtime egress port, verify it against deployment-supplied keys, cache it,
//!   and classify entries (provenance tiers, unverified-acknowledgement gates,
//!   pinned private origins).
//! - **lifecycle** ([`service`], [`package`]): download digest-verified
//!   artifacts, persist a redacted immutable install receipt, report installed
//!   status, and drive explicit digest-pinned updates through
//!   `ironclaw_extension_host`'s lifecycle manager or the scoped
//!   skill-management port. Updates require fresh acknowledgement when tool
//!   authority or skill instructions change and compensate to the prior
//!   package on failure; there is no background auto-update path.
//! - **tool surface** ([`capabilities`], [`render`]): the
//!   `builtin.ironhub_search` / `_info` / `_status` / `_install` / `_update`
//!   model-callable capabilities.
//! - **deep-link install** ([`agent_link`], [`link_service`]): the
//!   HMAC-shared-key register/deliver flow behind
//!   `ironclaw_product::IronhubLinkService`; link state persists through
//!   `RootFilesystem`.
//!
//! The *generic* registry seam stays in `ironclaw_extension_host`
//! (`registry_extension_package`, `parse_imported_manifest`,
//! `ManifestSource::RegistryInstalled`): a second catalog source would reuse
//! that seam, not this client. Host authority lives here, not in
//! `ironclaw_extension_host` (whose charter excludes egress and shared-key
//! secrets); composition supplies the manifest URL, verify keys, shared key,
//! and runtime ports.

#![warn(unreachable_pub)]

mod agent_link;
mod artifact_hosts;
mod catalog;
mod link_service;
mod model;
mod package;
mod render;
mod service;

#[cfg(test)]
mod tests;

pub use agent_link::{IronhubSharedKey, IronhubSharedKeyError};
pub use artifact_hosts::artifact_network_policy;
pub const IRONHUB_SEARCH_CAPABILITY_ID: &str = "builtin.ironhub_search";
pub const IRONHUB_INFO_CAPABILITY_ID: &str = "builtin.ironhub_info";
pub const IRONHUB_STATUS_CAPABILITY_ID: &str = "builtin.ironhub_status";
pub const IRONHUB_INSTALL_CAPABILITY_ID: &str = "builtin.ironhub_install";
pub const IRONHUB_UPDATE_CAPABILITY_ID: &str = "builtin.ironhub_update";
pub use link_service::{
    IronhubLinkBuildError, IronhubLinkStateError, IronhubLinkStateStore, RebornIronhubLinkService,
};
pub use model::{
    IronHubCommand, IronHubCommandError, IronHubEntryKind, IronHubEntrySummary,
    IronHubInstallOptions, IronHubInstallationSummary, IronHubPhase, IronHubProvenance,
    IronHubResponse, IronHubUpdateOptions,
};
pub use render::render_reborn_ironhub_response;
pub use service::{
    IronhubManifestUrl, RebornIronHubRuntime, execute_reborn_ironhub_command,
    execute_reborn_ironhub_service_command, validated_manifest_url,
};

#[cfg(test)]
mod public_surface_tests {
    use super::*;

    #[test]
    fn capability_ids_are_stable_at_the_crate_root() {
        assert_eq!(IRONHUB_SEARCH_CAPABILITY_ID, "builtin.ironhub_search");
        assert_eq!(IRONHUB_INFO_CAPABILITY_ID, "builtin.ironhub_info");
        assert_eq!(IRONHUB_STATUS_CAPABILITY_ID, "builtin.ironhub_status");
        assert_eq!(IRONHUB_INSTALL_CAPABILITY_ID, "builtin.ironhub_install");
        assert_eq!(IRONHUB_UPDATE_CAPABILITY_ID, "builtin.ironhub_update");
    }
}
