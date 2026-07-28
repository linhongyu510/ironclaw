//! `sandbox_shell` domain tools profile (`sandbox_shell_tools`) — W6 phase 2.
//!
//! Unlike `core_builtin`'s `core_builtin_tools()` (which hand-assembles a
//! `HostRuntime` via `local_dev_host_runtime_with_http_egress` and never calls
//! `build_runtime`), this profile flows through
//! `HostRuntimeCapabilityHarness::new_with_options` / `ToolsProfile::build()`
//! with `HostRuntimeHarnessOptions::with_sandboxed_shell()` set — the ONLY
//! harness path that reaches the real `HostedSingleTenantVolumeSandboxed`
//! composition profile and, through it, a real `TenantSandbox` Docker
//! process-port binding (`tenant_sandbox_process_binding`, wired in
//! `harness/mod.rs::new_with_options`). See
//! `tests/integration/reborn_sandbox_shell_turn.rs` for the driving test.
//!
//! Docker-gated: the CALLER must check `docker_gate::docker_available()` /
//! `docker_gate::docker_image_available()` itself before invoking
//! `sandbox_shell_tools` — this profile does not skip on a missing daemon; it
//! fails the Docker connect (surfaced as a build error).

use ironclaw_host_api::{AgentId, CapabilityId, EffectKind, MountPermissions, TenantId, UserId};
use ironclaw_host_runtime::SHELL_CAPABILITY_ID;

use super::super::options::{HostRuntimeHarnessOptions, ToolsProfile};
use super::super::{
    HarnessResult, HostRuntimeCapabilityHarness, wildcard_test_policy, workspace_mounts,
};

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
    .with_sandboxed_shell();
    Ok(ToolsProfile {
        // `builtin.shell` on the surface so a scripted shell call routes
        // through the real `TenantSandbox` process port — mirrors
        // `core_builtin_tools_capability_ids`'s shell entry, but this is the
        // ONLY capability this profile grants (a minimal, sandbox-only
        // surface, not the whole core-builtin set).
        capability_ids: vec![CapabilityId::new(SHELL_CAPABILITY_ID)?],
        effect_kinds: vec![
            EffectKind::DispatchCapability,
            EffectKind::ExecuteCode,
            EffectKind::SpawnProcess,
            EffectKind::Network,
        ],
        options,
        // Granting `EffectKind::Network` above puts a network-obligation
        // check on the dispatch path (`validate_network_policy_metadata`,
        // `crates/ironclaw_host_runtime/src/obligations.rs`), which fails
        // closed with `CapabilityObligationFailureKind::Network` unless the
        // capability's authorized `NetworkPolicy.allowed_targets` is
        // non-empty. `builtin.shell` makes no direct HTTP calls of its own
        // (the sandbox's OWN egress allowlist, wired via
        // `tenant_sandbox_process_binding`'s egress proxy, is what actually
        // mediates the container's network access) — this is just satisfying
        // that unrelated ceiling-metadata check, so a wildcard policy is
        // correct here (unlike `core_builtin_tools`'s `http_test_policy()`,
        // which narrows `builtin.http`'s OWN outbound targets).
        network_policy_override: Some(wildcard_test_policy()),
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
