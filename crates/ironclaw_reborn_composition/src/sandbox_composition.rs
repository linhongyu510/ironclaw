//! Single composition seam for every sandboxed-profile runtime background
//! task and shared handle. `factory.rs` gets exactly one construction call
//! site (`SandboxRuntimeBindings::build`, inside `build_local_runtime`) and
//! `runtime.rs` gets exactly one shutdown call
//! (`SandboxRuntimeBindings::shutdown_all`) for the whole family — the
//! per-user activity registry (Task A2), the reaper handle (already built;
//! Task A5 flips its wiring to use the activity registry), and Phase C's
//! egress-proxy daemon handle all live behind this one struct instead of
//! `factory.rs` growing a new field and a new shutdown block per sandbox
//! subsystem.

use std::sync::Arc;
use std::time::Duration;

use ironclaw_host_api::UserId;
use ironclaw_host_runtime::{ConnectionAttributionResolver, SandboxActivityRegistry};
use ironclaw_resources::ResourceGovernor;

use crate::RebornBuildError;
use crate::input::RebornLocalRuntimeIdentity;

/// Owned handle to a spawned [`ironclaw_host_runtime::BoundEgressAllowlistProxy::serve`]
/// task. Declared canonically here (not in `sandbox_egress_proxy_task.rs`)
/// so `SandboxRuntimeBindings`'s shape is stable across Phase A/Phase C —
/// `sandbox_egress_proxy_task::spawn_sandbox_egress_proxy` constructs one via
/// [`SandboxEgressProxyRuntimeHandle::new`] and returns it.
///
/// `pub` (not `pub(crate)`): `tenant_sandbox_process_binding` (`sandbox_boot.rs`) spawns the
/// production instance and hands it back on `TenantSandboxBinding` so the
/// assembling binary (`ironclaw_reborn_cli`) can thread it, opaquely, into
/// `RebornProductionBuildContext` for `SandboxRuntimeBindings::build` to take ownership
/// of later — the same round-trip-through-the-binary shape
/// `SandboxActivityRegistry` already uses. Its fields and methods stay
/// `pub(crate)`, so the binary can only move the value along, never
/// construct or drive one itself.
pub struct SandboxEgressProxyRuntimeHandle {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
    pub(crate) local_addr: std::net::SocketAddr,
    /// PEM container trust bundle (system roots + this proxy instance's
    /// sandbox CA public root certificate — no private key material; see
    /// `ironclaw_host_runtime::SandboxEgressProxyBinding::ca_bundle_pem`'s
    /// doc). `tenant_sandbox_process_binding` (`sandbox_boot.rs`) threads
    /// this into `RebornSandboxConfig::with_ca_bundle_pem` so every sandbox
    /// container trusts the exact CA this proxy instance mints leaf
    /// certificates from.
    ca_bundle_pem: String,
    /// Test-support only: whether the underlying `BoundEgressAllowlistProxy`
    /// had TLS interception wired in when `spawn_sandbox_egress_proxy`
    /// built it. See `BoundEgressAllowlistProxy::tls_intercept_is_active`'s
    /// doc for the production call site this mirrors.
    #[cfg(any(test, feature = "test-support"))]
    tls_intercept_active: bool,
}

impl SandboxEgressProxyRuntimeHandle {
    pub(crate) fn new(
        shutdown_tx: tokio::sync::watch::Sender<bool>,
        handle: tokio::task::JoinHandle<()>,
        local_addr: std::net::SocketAddr,
        ca_bundle_pem: String,
    ) -> Self {
        Self {
            shutdown_tx,
            handle,
            local_addr,
            ca_bundle_pem,
            #[cfg(any(test, feature = "test-support"))]
            tls_intercept_active: false,
        }
    }

    /// The container trust bundle this proxy instance's CA backs — see the
    /// field doc. `tenant_sandbox_process_binding` is the one production
    /// reader.
    pub(crate) fn ca_bundle_pem(&self) -> &str {
        &self.ca_bundle_pem
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn with_tls_intercept_active(mut self, active: bool) -> Self {
        self.tls_intercept_active = active;
        self
    }

    /// Test-support only: see the field doc above.
    #[cfg(any(test, feature = "test-support"))]
    pub fn tls_intercept_active(&self) -> bool {
        self.tls_intercept_active
    }

    /// Signals the proxy's accept loop to stop and awaits the task,
    /// aborting it if it has not stopped within `timeout`. Mirrors
    /// `SandboxReaperRuntimeHandle::shutdown` exactly.
    pub(crate) async fn shutdown(self, timeout: Duration) {
        let _ = self.shutdown_tx.send(true);
        let mut handle = self.handle;
        match tokio::time::timeout(timeout, &mut handle).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::debug!(?error, "sandbox egress proxy task join failed");
            }
            Err(_) => {
                tracing::debug!(
                    ?timeout,
                    "sandbox egress proxy did not stop before shutdown timeout; aborting"
                );
                handle.abort();
                if let Err(error) = handle.await
                    && error.is_panic()
                {
                    tracing::debug!(?error, "aborted sandbox egress proxy task panicked");
                }
            }
        }
    }
}

/// Inputs `build` needs out of `build_local_runtime`'s local scope. A
/// struct (not four positional params) so Task A6 can add
/// `owner_user_id` and Task A5 can source `activity` from
/// `sandbox_boot`'s returned binding without another signature churn at
/// every call site.
pub(crate) struct SandboxProfileBindingInputs<'a> {
    pub(crate) is_sandboxed_profile: bool,
    pub(crate) local_runtime_identity: Option<&'a RebornLocalRuntimeIdentity>,
    pub(crate) resource_governor: Arc<dyn ResourceGovernor>,
    /// The activity registry the transport (`sandbox_boot::tenant_sandbox_process_binding`)
    /// already constructed and injected into the exec transport — the reaper
    /// must observe the SAME instance, never a second independently
    /// constructed registry, or its idle/activity reads would never match
    /// what the transport records.
    pub(crate) activity: Arc<SandboxActivityRegistry>,
    /// The SAME attribution resolver `tenant_sandbox_process_binding`
    /// already wired into the exec transport
    /// (`TenantSandboxBinding::attribution`), so the reaper's teardown
    /// paths invalidate the identical cache the transport reads from
    /// instead of a second, disjoint one. `None` only for callers that
    /// never went through `tenant_sandbox_process_binding` (e.g. a direct
    /// test construction of `SandboxProfileBindingInputs`).
    pub(crate) attribution: Option<Arc<ConnectionAttributionResolver>>,
    /// Task A6: the sandbox concurrency ceiling is scoped per-user (not
    /// per-tenant), so one user cannot starve every other user in the
    /// tenant.
    pub(crate) owner_user_id: UserId,
    /// An egress-allowlist proxy `tenant_sandbox_process_binding` already
    /// spawned (and pointed the sandbox container's network broker at)
    /// before `build` ever runs — see `sandbox_boot::TenantSandboxBinding::egress_proxy`.
    /// When `Some`, `build` takes ownership of this SAME instance rather
    /// than spawning a second, orphaned proxy; when `None` (e.g. a direct
    /// test construction of `SandboxProfileBindingInputs`, or a future
    /// caller that never pre-spawned one), `build` spawns its own.
    pub(crate) egress_proxy: Option<SandboxEgressProxyRuntimeHandle>,
}

pub(crate) struct SandboxRuntimeBindings {
    pub(crate) reaper: Option<crate::sandbox_reaper_task::SandboxReaperRuntimeHandle>,
    pub(crate) egress_proxy: Option<SandboxEgressProxyRuntimeHandle>,
}

impl SandboxRuntimeBindings {
    /// The non-sandboxed-profile / production-build-context case: no
    /// background tasks.
    pub(crate) fn none() -> Self {
        Self {
            reaper: None,
            egress_proxy: None,
        }
    }

    /// Builds the sandboxed profile's runtime bindings: applies the
    /// per-user concurrency ceiling and spawns the orphan-container reaper.
    /// Moved verbatim out of `build_local_runtime`'s inline
    /// `if is_sandboxed_profile` block (D3-2/D4-1) — behavior-preserving,
    /// this task only relocates the wiring behind one seam. Non-sandboxed
    /// profiles get `Self::none()` immediately, without touching the
    /// governor or spawning anything.
    pub(crate) async fn build(
        inputs: SandboxProfileBindingInputs<'_>,
    ) -> Result<Self, RebornBuildError> {
        if !inputs.is_sandboxed_profile {
            return Ok(Self::none());
        }

        let sandbox_tenant_id =
            crate::sandbox_quota::resolve_local_runtime_tenant_id(inputs.local_runtime_identity)?;
        crate::sandbox_quota::apply_sandbox_user_ceiling(
            &inputs.resource_governor,
            sandbox_tenant_id,
            inputs.owner_user_id,
            crate::sandbox_quota::sandbox_max_concurrent_from_env(),
        )
        .map_err(|error| RebornBuildError::InvalidConfig {
            reason: format!("sandbox user concurrency ceiling could not be set: {error}"),
        })?;

        // D4-1: spawn the orphan-container reaper. Fails this build closed
        // (via `?`) if Docker is unreachable — without a reaper the
        // two-stage orphan sweep never runs and per-user sandbox containers
        // accumulate unbounded, so this now matches the egress proxy's
        // fail-closed posture immediately below rather than degrading
        // silently to `None`. Shares `inputs.activity` with the exec
        // transport (Task A5) so both observe the same per-user
        // last-activity timestamps.
        let reaper = crate::sandbox_reaper_task::spawn_sandbox_reaper(
            Arc::clone(&inputs.activity),
            inputs.attribution.clone(),
        )
        .await?;

        // Phase C: an unbindable egress proxy means sandboxed shell egress
        // would have no enforcement, so spawn failure here also fails this
        // build closed rather than degrading to `None`. Reuse the proxy
        // `tenant_sandbox_process_binding` already spawned (and pointed the
        // container at) when the caller supplied one, rather than binding a
        // second, orphaned proxy nobody shuts down.
        let egress_proxy = match inputs.egress_proxy {
            Some(handle) => Some(handle),
            None => Some(crate::sandbox_egress_proxy_task::spawn_sandbox_egress_proxy().await?),
        };

        Ok(Self {
            reaper: Some(reaper),
            egress_proxy,
        })
    }

    /// The one shutdown call site for every sandbox background task.
    /// `RebornRuntime::shutdown` calls this unconditionally (the struct
    /// is always present on `RebornRuntimeStores`, never `Option` at that
    /// level — `none()` just means every field inside is empty, so this
    /// is a cheap no-op for non-sandboxed profiles).
    pub(crate) async fn shutdown_all(self, timeout: Duration) {
        if let Some(reaper) = self.reaper {
            reaper.shutdown(timeout).await;
        }
        if let Some(egress_proxy) = self.egress_proxy {
            egress_proxy.shutdown(timeout).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_host_api::{InvocationId, ResourceEstimate, ResourceScope, UserId};
    use ironclaw_resources::InMemoryResourceGovernor;

    fn governor() -> Arc<dyn ironclaw_resources::ResourceGovernor> {
        Arc::new(InMemoryResourceGovernor::new())
    }

    /// True iff `SandboxRuntimeBindings::build`'s reaper spawn will be able
    /// to reach a Docker daemon. Reuses
    /// `ironclaw_host_runtime::sandbox_docker_readiness` (the same one-shot
    /// connect attempt `connect_docker_with_retry` retries) rather than
    /// shelling out to the `docker` CLI directly — the CLI honors
    /// `DOCKER_HOST`, not this crate's `IRONCLAW_REBORN_DOCKER_HOST`
    /// override, so a CLI-only probe would report "reachable" even while
    /// `sandboxed_profile_fails_closed_when_docker_unreachable`'s sibling
    /// test has that override pointed at a nonexistent socket.
    async fn docker_available() -> bool {
        matches!(
            ironclaw_host_runtime::sandbox_docker_readiness().await,
            ironclaw_host_runtime::SandboxDockerReadiness::Ready
        )
    }

    #[tokio::test]
    async fn non_sandboxed_profile_yields_inert_bindings_with_no_reaper() {
        let bindings = SandboxRuntimeBindings::build(SandboxProfileBindingInputs {
            is_sandboxed_profile: false,
            local_runtime_identity: None,
            resource_governor: governor(),
            activity: Arc::new(SandboxActivityRegistry::new()),
            attribution: None,
            owner_user_id: UserId::new("probe-user").unwrap(),
            egress_proxy: None,
        })
        .await
        .expect("non-sandboxed profile never fails to build inert bindings");

        assert!(bindings.reaper.is_none());
        assert!(bindings.egress_proxy.is_none());
        bindings.shutdown_all(Duration::from_secs(1)).await;
    }

    /// Plain `#[test]` + `block_on`, not `#[tokio::test]`, and guarded by
    /// `lock_env()`: the reaper spawn this now depends on reads the
    /// process-global `IRONCLAW_REBORN_DOCKER_HOST` runtime-env overlay, and
    /// `sandboxed_profile_fails_closed_when_docker_unreachable` (below)
    /// mutates that same overlay under the same guard — without sharing it,
    /// cargo's default parallel test execution could interleave the two and
    /// make this test observe the other's override. See
    /// `sandbox_reaper_task::tests::docker_unreachable_fails_the_spawn_closed`
    /// for why the guard must not be held across an `.await` in an outer
    /// async fn.
    ///
    /// `SandboxRuntimeBindings::build` now fails closed (D4-1) when the
    /// reaper can't connect to Docker, which makes this call-site test
    /// genuinely Docker-dependent — `cargo test -p ironclaw_reborn_composition
    /// --lib` is a plain, non-docker-gated lane, so a runner without a
    /// reachable daemon must SKIP rather than fail. The per-user-ceiling
    /// assertion itself (`apply_sandbox_user_ceiling`) is Docker-free and
    /// already has direct, dedicated coverage in
    /// `sandbox_quota::tests::ceiling_denies_the_second_concurrent_reservation_from_any_user_in_the_tenant`
    /// — reasserting it here via a bypassed, Docker-free `build()` path would
    /// just duplicate that coverage while still needing to fake the reaper,
    /// so a visible runtime skip (matching
    /// `ironclaw_host_runtime`'s `docker_gate` convention) is the correct
    /// shape for this call-site test, not a Docker-free rewrite.
    #[test]
    fn sandboxed_profile_applies_the_user_ceiling() {
        let _guard = ironclaw_common::env_helpers::lock_env();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime for test");

        if !runtime.block_on(docker_available()) {
            eprintln!(
                "SKIP: no docker daemon reachable — sandboxed_profile_applies_the_user_ceiling requires a real Docker daemon for SandboxRuntimeBindings::build's reaper spawn (CI/hosted Docker lane only)"
            );
            return;
        }
        let governor = governor();
        let owner_user_id = UserId::new("probe-user").unwrap();

        let bindings = runtime
            .block_on(SandboxRuntimeBindings::build(SandboxProfileBindingInputs {
                is_sandboxed_profile: true,
                local_runtime_identity: None,
                resource_governor: Arc::clone(&governor),
                activity: Arc::new(SandboxActivityRegistry::new()),
                attribution: None,
                owner_user_id: owner_user_id.clone(),
                egress_proxy: None,
            }))
            .expect(
                "sandboxed profile build succeeds against this machine's reachable Docker daemon",
            );

        // The ceiling is live once the build succeeds (which now requires a
        // reachable Docker daemon for the reaper spawn — see
        // `sandboxed_profile_fails_closed_when_docker_unreachable` for the
        // fail-closed path when the daemon is not reachable).
        let tenant_id = crate::sandbox_quota::resolve_local_runtime_tenant_id(None).unwrap();
        let scope = ResourceScope {
            tenant_id,
            user_id: owner_user_id,
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        };
        let first = governor
            .reserve(scope, ResourceEstimate::default().set_concurrency_slots(1))
            .expect("first reservation is within the default ceiling");
        drop(first);

        assert!(bindings.reaper.is_some());
        runtime.block_on(bindings.shutdown_all(Duration::from_secs(1)));
    }

    /// Call-site coverage for the fail-closed posture pinned at the helper
    /// level by `sandbox_reaper_task::tests::docker_unreachable_fails_the_spawn_closed`:
    /// on the sandboxed profile, a reaper-spawn failure must fail
    /// `SandboxRuntimeBindings::build` itself, not just the helper in
    /// isolation. Forces the unreachable condition deterministically via
    /// `IRONCLAW_REBORN_DOCKER_HOST` (this machine has a real daemon
    /// running). Plain `#[test]` + `block_on`, not `#[tokio::test]`, so the
    /// `lock_env()` guard is never held across an `.await` in an outer
    /// async fn.
    #[test]
    fn sandboxed_profile_fails_closed_when_docker_unreachable() {
        let _guard = ironclaw_common::env_helpers::lock_env();
        ironclaw_common::env_helpers::set_runtime_env(
            "IRONCLAW_REBORN_DOCKER_HOST",
            "/nonexistent/ironclaw-w3-reaper-composition-test-docker.sock",
        );

        let owner_user_id = UserId::new("probe-user").unwrap();
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime for test")
            .block_on(SandboxRuntimeBindings::build(SandboxProfileBindingInputs {
                is_sandboxed_profile: true,
                local_runtime_identity: None,
                resource_governor: governor(),
                activity: Arc::new(SandboxActivityRegistry::new()),
                attribution: None,
                owner_user_id,
                egress_proxy: None,
            }));

        ironclaw_common::env_helpers::remove_runtime_env("IRONCLAW_REBORN_DOCKER_HOST");

        match result {
            Err(RebornBuildError::InvalidConfig { reason }) => {
                assert!(
                    reason.contains("reaper"),
                    "expected reason to name the reaper, got: {reason}"
                );
            }
            Ok(_) => panic!("expected build to fail closed when Docker is unreachable"),
            Err(other) => panic!("expected InvalidConfig, got other RebornBuildError: {other:?}"),
        }
    }

    #[test]
    fn none_constructor_produces_no_handles() {
        let bindings = SandboxRuntimeBindings::none();
        assert!(bindings.reaper.is_none());
        assert!(bindings.egress_proxy.is_none());
    }

    /// The landing gate for W6 phase 2's connection-attribution wiring
    /// (design doc, W17 note): `ConnectionAttributionResolver::for_sandbox_egress`,
    /// `RebornScopedSandboxCommandTransport::with_attribution_resolver`, and
    /// `SandboxReaper::with_attribution_resolver` all existed before this
    /// test with zero production callers — `invalidate()`'s call sites in
    /// `reaper.rs`/`exec_transport.rs` compiled clean and looked wired, but
    /// fired never, because nothing ever populated the `Option<Arc<...>>`
    /// they read. Verifying "call sites exist" is not the same as verifying
    /// the control can fire; this test drives the actual PRODUCTION
    /// constructors — `sandbox_boot::tenant_sandbox_process_binding` (the
    /// exec-transport side) and `SandboxRuntimeBindings::build` /
    /// `sandbox_reaper_task::spawn_sandbox_reaper` (the reaper side) — and
    /// asserts the reaper ends up holding the SAME resolver instance the
    /// transport was wired with, not a second independently constructed one
    /// (which would defeat W17's whole point: invalidating on the transport
    /// side would leave the reaper's copy of the cache stale).
    ///
    /// Docker-gated like `sandboxed_profile_applies_the_user_ceiling`
    /// (`tenant_sandbox_process_binding` requires a reachable daemon).
    #[tokio::test]
    async fn sandbox_attribution_reaches_both_production_consumers() {
        if !docker_available().await {
            eprintln!(
                "SKIP: no docker daemon reachable — sandbox_attribution_reaches_both_production_consumers requires a real Docker daemon (CI/hosted Docker lane only)"
            );
            return;
        }

        // Bound for the whole test (not a bare temporary) — the sandbox
        // config keeps referencing this path after construction, so the
        // directory must outlive the `tenant_sandbox_process_binding` call.
        let workspace_dir = tempfile::tempdir().expect("tempdir creates");
        let tenant_sandbox = crate::sandbox_boot::tenant_sandbox_process_binding(
            workspace_dir.path().to_path_buf(),
        )
        .await
        .expect(
            "tenant sandbox process binding builds against this machine's reachable Docker daemon",
        );

        let bindings = SandboxRuntimeBindings::build(SandboxProfileBindingInputs {
            is_sandboxed_profile: true,
            local_runtime_identity: None,
            resource_governor: governor(),
            activity: Arc::clone(&tenant_sandbox.activity),
            // The SAME instance `tenant_sandbox_process_binding` already
            // wired into the exec transport — exactly what
            // `RebornHostBindings::with_sandbox_attribution_resolver` /
            // `RebornProductionBuildContext::sandbox_attribution` thread
            // through production's `factory.rs` in the real boot path.
            attribution: Some(Arc::clone(&tenant_sandbox.attribution)),
            owner_user_id: UserId::new("attribution-probe-user").unwrap(),
            egress_proxy: tenant_sandbox.egress_proxy,
        })
        .await
        .expect("sandboxed profile build succeeds against a reachable Docker daemon");

        let reaper_handle = bindings
            .reaper
            .as_ref()
            .expect("sandboxed profile always spawns a reaper");
        let reaper_attribution = reaper_handle
            .reaper
            .as_ref()
            .expect("spawn_sandbox_reaper always retains a test-support handle to the reaper")
            .attribution_for_test();

        assert!(
            reaper_attribution.is_some(),
            "REGRESSION: the reaper's attribution resolver is None after production \
             construction — with_attribution_resolver has no effective production caller"
        );
        assert!(
            Arc::ptr_eq(&tenant_sandbox.attribution, &reaper_attribution.unwrap()),
            "the reaper must share the SAME resolver instance the exec transport was wired \
             with, not a second, independently constructed one"
        );

        bindings.shutdown_all(Duration::from_secs(1)).await;
    }
}
