//! `sandbox_shell` domain tools profile (`sandbox_shell_tools`) — W6 phase 2.
//!
//! Unlike `core_builtin`'s `core_builtin_tools()` (which hand-assembles a
//! `HostRuntime` via the local-development helper and never calls
//! `build_runtime`), this profile flows through
//! `HostRuntimeCapabilityHarness::new_with_options` / `ToolsProfile::build()`
//! with `HostRuntimeHarnessOptions::with_sandboxed_shell()` set — the ONLY
//! harness path that reaches the real `HostedSingleTenantVolumeSandboxed`
//! composition profile and, through it, a real `UserSandbox` Docker
//! process-port binding (`user_sandbox_process_binding`, wired in
//! `harness/mod.rs::new_with_options`). See
//! `tests/integration/reborn_sandbox_shell_turn.rs` for the driving test.
//!
//! Docker-gated: the CALLER must check `docker_gate::docker_available()` /
//! `docker_gate::docker_image_available()` itself before invoking
//! `sandbox_shell_tools` — this profile does not skip on a missing daemon; it
//! fails the Docker connect (surfaced as a build error).

use super::super::options::{HostRuntimeHarnessOptions, ToolsProfile};
use super::super::{HarnessResult, HostRuntimeCapabilityHarness, workspace_mounts};
use ironclaw_host_api::{
    capability::EffectKind,
    ids::{AgentId, CapabilityId, TenantId, UserId},
    mount::MountPermissions,
};
use ironclaw_host_runtime::SHELL_CAPABILITY_ID;

/// Fixed literal: unlike `tenant_id`/`user_id` (which the caller mints fresh
/// per test via `sandbox_shell_identity` so containers/workspaces never
/// collide across concurrent runs), `agent_id` does not feed the
/// `RebornSandboxUserKey` container-identity digest
/// (`ironclaw_host_runtime::RebornSandboxUserKey::from_tenant_user` hashes
/// only `{tenant_id, user_id}`), so a shared literal is safe here.
const SANDBOX_SHELL_AGENT_ID: &str = "sandbox-shell-agent";

pub(crate) fn sandbox_shell_tools_profile(
    tenant_id: TenantId,
    user_id: UserId,
) -> HarnessResult<ToolsProfile> {
    let runtime_policy =
        ironclaw_reborn_composition::hosted_single_tenant_volume_sandboxed_runtime_policy()?;
    let options = HostRuntimeHarnessOptions::new(
        workspace_mounts(MountPermissions::read_write_list_delete())?,
        Some(runtime_policy),
    )
    .with_local_runtime_identity(tenant_id, AgentId::new(SANDBOX_SHELL_AGENT_ID)?)
    .with_sandboxed_shell()
    .with_durable_capability_io();
    Ok(ToolsProfile {
        // `builtin.shell` on the surface so a scripted shell call routes
        // through the real `UserSandbox` process port — mirrors
        // `core_builtin_tools_capability_ids`'s shell entry, but this is the
        // ONLY capability this profile grants (a minimal, sandbox-only
        // surface, not the whole core-builtin set).
        capability_ids: vec![CapabilityId::new(SHELL_CAPABILITY_ID)?],
        effect_kinds: vec![
            EffectKind::DispatchCapability,
            EffectKind::ExecuteCode,
            EffectKind::SpawnProcess,
        ],
        options,
        auto_approve_default: Some(true),
        ..ToolsProfile::new("reborn-e2e-sandbox-shell-tools", user_id.as_str())?
    })
}

pub(crate) async fn sandbox_shell_tools(
    tenant_id: TenantId,
    user_id: UserId,
) -> HarnessResult<HostRuntimeCapabilityHarness> {
    sandbox_shell_tools_profile(tenant_id, user_id)?
        .build()
        .await
}
