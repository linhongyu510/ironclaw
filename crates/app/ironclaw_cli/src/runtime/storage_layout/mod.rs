//! Bounded, offline adoption for the profile-stable Reborn durable layout.
//!
//! This is deliberately a single state machine for this one filesystem
//! transition. It does not discover arbitrary roots, infer workspace owners,
//! or serve as a generic migration framework.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use ironclaw_composition::LegacySkillSnapshotSource;
use ironclaw_config::{
    DeploymentSecurityEnvelope, DurableStateKind, LayoutManifest, LayoutRequirement,
    ProfileTransitionAdmission, RebornHome, RebornStoragePaths, TenancyModel, WorkspaceAccessFloor,
};
use ironclaw_host_api::ids::{TenantId, TenantUserWorkspaceKey, UserId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

mod admission;
mod adoption;
mod filesystem;
mod locks;
mod model;

pub(crate) use admission::{
    admit_startup_layout, ensure_ready_layout, inspect_ready_layout,
    ready_legacy_skill_snapshot_source, ready_memory_provider_app_id,
};
pub(crate) use adoption::{
    adopt_layout_with_store_verification, automatically_adopt_layout_with_store_verification,
    validate_adopt_options,
};
pub(crate) use model::{
    AdoptOptions, CanonicalStoreVerification, StartupAdoptionAuthority, StartupLayoutAdmission,
    WorkspaceImportOptions, prepare_automatic_adoption,
};

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
