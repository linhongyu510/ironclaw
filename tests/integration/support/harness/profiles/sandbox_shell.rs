//! Minimal integration-harness profile for a real sandboxed shell turn.

use super::super::options::{HostRuntimeHarnessOptions, ToolsProfile};
use super::super::{HarnessResult, HostRuntimeCapabilityHarness};
use ironclaw_host_api::{
    capability::EffectKind,
    ids::{AgentId, CapabilityId, TenantId, TenantUserWorkspaceKey, UserId},
    mount::{MountGrant, MountPermissions, MountView},
    path::{MountAlias, VirtualPath},
};
use ironclaw_host_runtime::SHELL_CAPABILITY_ID;

pub(crate) async fn sandbox_shell_tools() -> HarnessResult<HostRuntimeCapabilityHarness> {
    let runtime_policy =
        ironclaw_composition::hosted_single_tenant_volume_sandboxed_runtime_policy()?;
    let tenant_id = TenantId::new("tenant-itest")?;
    let user_id = UserId::new("host-user")?;
    let options = HostRuntimeHarnessOptions::new(
        caller_workspace_mounts(&tenant_id, &user_id)?,
        Some(runtime_policy),
    )
    .with_local_runtime_identity(tenant_id, AgentId::new("sandbox-shell-agent")?)
    .with_sandboxed_shell()
    .with_workspace_scoped_per_caller()
    .with_durable_capability_io();

    ToolsProfile {
        capability_ids: vec![CapabilityId::new(SHELL_CAPABILITY_ID)?],
        effect_kinds: vec![
            EffectKind::DispatchCapability,
            EffectKind::ExecuteCode,
            EffectKind::SpawnProcess,
            EffectKind::Network,
        ],
        options,
        auto_approve_default: Some(true),
        ..ToolsProfile::new("reborn-e2e-sandbox-shell-tools", user_id.as_str())?
    }
    .build()
    .await
}

fn caller_workspace_mounts(tenant_id: &TenantId, user_id: &UserId) -> HarnessResult<MountView> {
    let key = TenantUserWorkspaceKey::from_tenant_user(tenant_id, user_id);
    Ok(MountView::new(vec![MountGrant::new(
        MountAlias::new("/workspace")?,
        VirtualPath::new(format!(
            "/projects/workspace/users/{}",
            key.digest_segment()
        ))?,
        MountPermissions {
            execute: true,
            ..MountPermissions::read_write_list_delete()
        },
    )])?)
}
