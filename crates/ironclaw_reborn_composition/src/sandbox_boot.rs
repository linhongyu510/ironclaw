//! Boot-time construction of the `TenantSandbox` process-port binding for
//! composition profiles that request it (today: only
//! `hosted-single-tenant-volume-sandboxed`).
//!
//! This is the one place composition reaches into
//! `ironclaw_host_runtime`'s sandbox transport to produce a
//! [`RebornRuntimeProcessBinding`]. Callers above composition — notably the
//! `ironclaw` CLI binary crate — enter Reborn only through this crate's
//! public surface and must never depend on `ironclaw_host_runtime` directly
//! (enforced by
//! `ironclaw_architecture::reborn_cli_binary_crate_stays_separate_from_v1_root`),
//! so the Docker connect + transport construction lives here rather than at
//! the CLI boot-input assembly call site.

use std::path::PathBuf;
use std::sync::Arc;

use ironclaw_host_runtime::{
    ConnectionAttributionResolver, RebornSandboxConfig, RebornScopedSandboxCommandTransport,
    SandboxActivityRegistry,
};

use crate::RebornBuildError;
use crate::input::RebornRuntimeProcessBinding;

/// Connect to the Docker daemon and build a `TenantSandbox` process-port
/// binding rooted at `sandbox_workspaces_root`. Fails closed: any Docker
/// connect failure returns `Err`, never a silent
/// `RebornRuntimeProcessBinding::none()` fallback (which would mean running
/// sandbox-profile shell commands unsandboxed on the host) — see
/// `docs/safety-and-sandbox.md`.
///
/// Network egress: this call ALWAYS spawns and owns its own
/// [`ironclaw_host_runtime::EgressAllowlistProxy`] (fail-closed: a bind
/// failure here fails this call, never a silent `--network none` downgrade
/// masquerading as "configured") and points the sandboxed container's
/// `http_proxy`/`https_proxy` env at its freshly bound port via the Docker
/// host-gateway address (see `RebornSandboxConfig::with_network_broker_port`).
/// There is deliberately no operator-pointed external-proxy override: this
/// in-process proxy is what enforces the egress allowlist, TLS interception,
/// and credential swap
/// (`ironclaw_host_runtime::sandbox_process::egress_proxy`) — an env knob
/// that let a caller substitute a different proxy (or none) would be a way
/// to silently disable all three. The returned [`TenantSandboxBinding::
/// egress_proxy`] is always `Some`; the caller
/// (`RebornHostBindings::with_sandbox_egress_proxy_handle`) threads that SAME
/// instance onward so `SandboxRuntimeBindings` owns its shutdown, rather
/// than this function orphaning a second one.
pub async fn tenant_sandbox_process_binding(
    sandbox_workspaces_root: PathBuf,
) -> Result<TenantSandboxBinding, RebornBuildError> {
    let egress_proxy = crate::sandbox_egress_proxy_task::spawn_sandbox_egress_proxy().await?;
    let broker_port = egress_proxy.local_addr.port();
    // Threads the SAME CA the egress proxy's `TlsInterceptConfig` mints
    // leaf certificates from into every container this config launches
    // (`RebornSandboxConfig::with_ca_bundle_pem`'s doc) — W5's CA
    // trust-distribution wiring. A mismatched or missing bundle here would
    // make every bound-host CONNECT fail certificate verification inside
    // the container.
    let config = RebornSandboxConfig::new(sandbox_workspaces_root)
        .with_network_broker_port(broker_port)
        .with_ca_bundle_pem(egress_proxy.ca_bundle_pem().to_string());
    let activity = Arc::new(SandboxActivityRegistry::new());
    // W17/W6: one shared attribution resolver, wired into BOTH this
    // transport and (via `TenantSandboxBinding::attribution`, threaded
    // through `RebornHostBindings::with_sandbox_attribution_resolver` and
    // `SandboxRuntimeBindings::build`) the reaper — see
    // `ConnectionAttributionResolver::for_sandbox_egress`'s doc for why a
    // second, independently constructed resolver would defeat W17's
    // invalidation wiring. A second `Docker` connect (separate from the
    // transport's own `connect`, which does not expose its handle) — the
    // same "reconnect per component" shape `sandbox_reaper_task::
    // spawn_sandbox_reaper` already uses for the reaper's own connect.
    let attribution_docker = ironclaw_host_runtime::connect_docker_with_retry()
        .await
        .map_err(|error| RebornBuildError::InvalidConfig {
            reason: format!(
                "tenant-sandbox attribution resolver requires a reachable Docker daemon: {error}"
            ),
        })?;
    let attribution = Arc::new(ConnectionAttributionResolver::for_sandbox_egress(
        attribution_docker,
    ));
    let transport = RebornScopedSandboxCommandTransport::connect(config)
        .await
        .map_err(|error| RebornBuildError::InvalidConfig {
            reason: format!(
                "tenant-sandbox process backend requires a reachable Docker daemon: {error}"
            ),
        })?
        .with_activity_registry(Arc::clone(&activity))
        .with_attribution_resolver(Arc::clone(&attribution));
    let process_port = Arc::new(transport.into_process_port());
    Ok(TenantSandboxBinding {
        binding: RebornRuntimeProcessBinding::tenant_sandbox(process_port),
        activity,
        attribution,
        egress_proxy: Some(egress_proxy),
    })
}

/// Return value of [`tenant_sandbox_process_binding`]: the process-port
/// binding plus the SAME [`SandboxActivityRegistry`] instance the exec
/// transport now writes activity into, so a caller that also spawns
/// `SandboxReaper` (via `sandbox_composition`/`factory.rs`) reads the exact
/// timestamps the transport is recording — never a second, independently
/// constructed registry.
pub struct TenantSandboxBinding {
    pub binding: RebornRuntimeProcessBinding,
    pub activity: Arc<SandboxActivityRegistry>,
    /// The SAME attribution-cache resolver this call wired into the exec
    /// transport (`with_attribution_resolver` above) — the caller threads
    /// this onward (`RebornHostBindings::with_sandbox_attribution_resolver`)
    /// so `SandboxRuntimeBindings::build` wires the reaper to the identical
    /// instance rather than a second, independently constructed resolver
    /// with a disjoint cache.
    pub attribution: Arc<ConnectionAttributionResolver>,
    /// Always `Some`: this call always spawns and owns its own
    /// egress-allowlist proxy (see the function doc — there is no longer an
    /// operator-pointed-external-proxy path that could leave this `None`).
    /// The caller threads this onward
    /// (`RebornHostBindings::with_sandbox_egress_proxy_handle`) so
    /// `SandboxRuntimeBindings::build` takes ownership of the SAME instance
    /// rather than spawning a second one — one bound proxy per
    /// sandboxed-profile boot, one owner for its shutdown. Kept as `Option`
    /// (rather than a required field) only because `SandboxProfileBindingInputs`
    /// / direct test construction elsewhere still models "no pre-spawned
    /// proxy" as a distinct, legitimate shape.
    pub egress_proxy: Option<crate::sandbox_composition::SandboxEgressProxyRuntimeHandle>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RED (pre-fix): today, a caller that supplies `default_broker_port:
    /// Some(_)` (as an operator-pointed proxy would) takes the
    /// `Some(port) => (Some(port), None)` branch and
    /// `tenant_sandbox_process_binding` never spawns our in-process
    /// allowlist/TLS-intercept proxy at all — `egress_proxy` comes back
    /// `None`. That means the sandboxed container gets no allowlist
    /// enforcement, no TLS interception, and no credential swap: a silent
    /// way to disable three security controls. This pins the fix: the
    /// sandbox profile ALWAYS gets our in-process proxy, so
    /// `egress_proxy` must always be `Some`. `tenant_sandbox_process_binding`
    /// no longer even accepts a caller-supplied broker port/env override
    /// that could route the container around it — this now just proves the
    /// production call always yields a spawned proxy. Docker-gated (SKIP
    /// without a daemon) like this crate's other
    /// `tenant_sandbox_process_binding` tests, since the function also
    /// connects to Docker for the exec transport and attribution resolver.
    #[tokio::test]
    async fn sandbox_profile_always_gets_the_in_process_egress_proxy() {
        if !matches!(
            ironclaw_host_runtime::sandbox_docker_readiness().await,
            ironclaw_host_runtime::SandboxDockerReadiness::Ready
        ) {
            eprintln!(
                "SKIP: no docker daemon reachable — sandbox_profile_always_gets_the_in_process_egress_proxy requires a real Docker daemon (CI/hosted Docker lane only)"
            );
            return;
        }

        let workspace_dir = tempfile::tempdir().expect("tempdir creates");
        let binding = tenant_sandbox_process_binding(workspace_dir.path().to_path_buf())
            .await
            .expect("tenant sandbox process binding builds against a reachable Docker daemon");

        assert!(
            binding.egress_proxy.is_some(),
            "the sandbox profile must always spawn and own its in-process egress proxy — \
             a None here means the container's egress went unenforced"
        );
    }
}
