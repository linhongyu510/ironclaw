//! omp coding tools profiles (issue #7392 slice 3 registration seam).
//!
//! Grants the five omp capability ids
//! (`builtin.read`/`builtin.write`/`builtin.edit`/`builtin.glob`/
//! `builtin.grep`) PLUS the four old coding ids the omp package leaves
//! untouched (`builtin.read_file`/`builtin.write_file`/`builtin.list_dir`/
//! `builtin.apply_patch` — the omp package only replaces `builtin.glob`/
//! `builtin.grep`, whose canonical ids the omp engines reuse), over a
//! read-write workspace mount, with the composed runtime wired to the
//! omp-extended built-in package + handlers
//! (`HostRuntimeHarnessOptions::with_omp_coding_tools`). Granting the old
//! ids keeps BOTH surfaces model-visible: the surface policy filter would
//! otherwise drop the old coding tools from the advertised definitions even
//! though they stay registered in the package. The approval arm mirrors
//! `file_tools_requiring_approval`: auto-approve OFF and no runtime policy,
//! so a scripted `write` raises a real `BlockedApproval` gate.

use ironclaw_host_api::{capability::EffectKind, ids::CapabilityId, mount::MountPermissions};
use ironclaw_host_runtime::{
    APPLY_PATCH_CAPABILITY_ID, LIST_DIR_CAPABILITY_ID, OMP_EDIT_CAPABILITY_ID,
    OMP_GLOB_CAPABILITY_ID, OMP_GREP_CAPABILITY_ID, OMP_READ_CAPABILITY_ID,
    OMP_WRITE_CAPABILITY_ID, READ_FILE_CAPABILITY_ID, WRITE_FILE_CAPABILITY_ID,
};

use super::super::options::{HostRuntimeHarnessOptions, ToolsProfile};
use super::super::{HarnessResult, HostRuntimeCapabilityHarness, workspace_mounts};

fn omp_coding_tools_with_runtime_policy(
    runtime_policy: Option<ironclaw_host_api::runtime_policy::EffectiveRuntimePolicy>,
) -> HarnessResult<ToolsProfile> {
    Ok(ToolsProfile {
        // Both surfaces coexist on the model-visible surface (the benchmark
        // arm keeps the old coding tools registered): the five omp
        // capability ids AND the four old coding ids they leave untouched
        // (`read_file`/`write_file`/`list_dir`/`apply_patch` — the omp
        // package only REPLACES `builtin.glob`/`builtin.grep`, whose
        // canonical ids the omp engines reuse).
        capability_ids: vec![
            CapabilityId::new(OMP_READ_CAPABILITY_ID)?,
            CapabilityId::new(OMP_WRITE_CAPABILITY_ID)?,
            CapabilityId::new(OMP_EDIT_CAPABILITY_ID)?,
            CapabilityId::new(OMP_GLOB_CAPABILITY_ID)?,
            CapabilityId::new(OMP_GREP_CAPABILITY_ID)?,
            CapabilityId::new(READ_FILE_CAPABILITY_ID)?,
            CapabilityId::new(WRITE_FILE_CAPABILITY_ID)?,
            CapabilityId::new(LIST_DIR_CAPABILITY_ID)?,
            CapabilityId::new(APPLY_PATCH_CAPABILITY_ID)?,
        ],
        effect_kinds: vec![EffectKind::ReadFilesystem, EffectKind::WriteFilesystem],
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

pub(crate) async fn omp_coding_tools_requiring_approval()
-> HarnessResult<HostRuntimeCapabilityHarness> {
    omp_coding_tools_requiring_approval_profile()?.build().await
}
