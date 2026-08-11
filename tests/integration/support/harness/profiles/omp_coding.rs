//! omp coding tools profiles (issue #7392 slice 3 registration seam).
//!
//! Grants the five omp capability ids
//! (`builtin.read`/`builtin.write`/`builtin.edit`/`builtin.glob`/
//! `builtin.grep`) over a read-write workspace mount, with the composed runtime wired to the
//! omp-extended built-in package + handlers
//! (`HostRuntimeHarnessOptions::with_omp_coding_tools`). The approval arm mirrors
//! `file_tools_requiring_approval`: auto-approve OFF and no runtime policy,
//! so a scripted `write` raises a real `BlockedApproval` gate.

use ironclaw_host_api::{capability::EffectKind, ids::CapabilityId, mount::MountPermissions};
use ironclaw_host_runtime::{
    OMP_EDIT_CAPABILITY_ID, OMP_GLOB_CAPABILITY_ID, OMP_GREP_CAPABILITY_ID, OMP_READ_CAPABILITY_ID,
    OMP_WRITE_CAPABILITY_ID,
};

use super::super::options::{HostRuntimeHarnessOptions, ToolsProfile};
use super::super::{HarnessResult, HostRuntimeCapabilityHarness, workspace_mounts};

fn omp_coding_tools_with_runtime_policy(
    runtime_policy: Option<ironclaw_host_api::runtime_policy::EffectiveRuntimePolicy>,
) -> HarnessResult<ToolsProfile> {
    Ok(ToolsProfile {
        // The temporary benchmark arm advertises only the five omp coding
        // capabilities so the comparison measures their contract directly.
        capability_ids: vec![
            CapabilityId::new(OMP_READ_CAPABILITY_ID)?,
            CapabilityId::new(OMP_WRITE_CAPABILITY_ID)?,
            CapabilityId::new(OMP_EDIT_CAPABILITY_ID)?,
            CapabilityId::new(OMP_GLOB_CAPABILITY_ID)?,
            CapabilityId::new(OMP_GREP_CAPABILITY_ID)?,
        ],
        effect_kinds: vec![
            EffectKind::ReadFilesystem,
            EffectKind::WriteFilesystem,
            EffectKind::DeleteFilesystem,
        ],
        options: HostRuntimeHarnessOptions::new(
            workspace_mounts(MountPermissions::read_write_list_delete())?,
            runtime_policy,
        )
        .with_omp_coding_tools(),
        ..ToolsProfile::new("reborn-e2e-omp-coding", "reborn-e2e-omp-coding-user")?
    })
}

pub(crate) fn omp_coding_tools_profile() -> HarnessResult<ToolsProfile> {
    Ok(omp_coding_tools_with_runtime_policy(Some(
        ironclaw_composition::standalone_unrestricted_runtime_policy(true)?,
    ))?
    .with_auto_approve_default(true))
}

pub(crate) async fn omp_coding_tools() -> HarnessResult<HostRuntimeCapabilityHarness> {
    omp_coding_tools_profile()?.build().await
}

/// Same omp surface with auto-approve OFF and no runtime policy — mirrors
/// `file_tools_requiring_approval_profile` so a scripted omp `write` raises
/// a real approval gate through the ordinary gate path.
pub(crate) fn omp_coding_tools_requiring_approval_profile() -> HarnessResult<ToolsProfile> {
    Ok(omp_coding_tools_with_runtime_policy(None)?.with_auto_approve_default(false))
}
