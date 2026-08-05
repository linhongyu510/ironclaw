//! Single lifecycle seam for every sandboxed-profile runtime background
//! task and shared handle. `factory.rs` gets exactly one construction call
//! site (`SandboxRuntimeBindings::build`, inside `build_local_runtime`) and
//! `runtime.rs` gets exactly one shutdown call
//! (`SandboxRuntimeBindings::shutdown_all`). PR1 owns only the local Docker
//! orphan reaper; transport-managed providers own their own lifecycle.

use std::sync::Arc;
use std::time::Duration;

use ironclaw_host_api::ids::UserId;
use ironclaw_resources::ResourceGovernor;

use crate::RebornBuildError;
use crate::input::RebornLocalRuntimeIdentity;

/// Inputs `build` needs out of `build_local_runtime`'s local scope. A
/// struct (not four positional params) so Task A6 can add
/// `owner_user_id` and Task A5 can source `activity` from
/// `sandbox::factory`'s returned binding without another signature churn at
/// every call site.
pub(crate) struct SandboxProfileBindingInputs<'a> {
    pub(crate) is_sandboxed_profile: bool,
    pub(crate) bundle: Option<crate::sandbox::UserSandboxRuntimeBundle>,
    pub(crate) local_runtime_identity: Option<&'a RebornLocalRuntimeIdentity>,
    pub(crate) resource_governor: Arc<dyn ResourceGovernor>,
    /// Task A6: the sandbox concurrency ceiling is scoped per-user (not
    /// per-tenant), so one user cannot starve every other user in the
    /// tenant.
    pub(crate) owner_user_id: UserId,
}

pub(crate) struct SandboxRuntimeBindings {
    pub(crate) reaper: Option<crate::sandbox::SandboxReaperRuntimeHandle>,
}

impl SandboxRuntimeBindings {
    /// The non-sandboxed-profile / production-build-context case: no
    /// background tasks.
    pub(crate) fn none() -> Self {
        Self { reaper: None }
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

        let bundle = inputs
            .bundle
            .ok_or_else(|| RebornBuildError::InvalidConfig {
                reason: "sandbox profile requires one complete sandbox runtime bundle".to_string(),
            })?;
        let lifecycle = bundle.into_lifecycle();

        let sandbox_tenant_id =
            crate::sandbox::resolve_local_runtime_tenant_id(inputs.local_runtime_identity)?;
        crate::sandbox::apply_sandbox_user_ceiling(
            &inputs.resource_governor,
            sandbox_tenant_id,
            inputs.owner_user_id,
            crate::sandbox::sandbox_max_concurrent_from_env(),
        )
        .map_err(|error| RebornBuildError::InvalidConfig {
            reason: format!("sandbox user concurrency ceiling could not be set: {error}"),
        })?;

        let crate::sandbox::UserSandboxLifecycle::HostManaged { activity } = lifecycle else {
            return Ok(Self::none());
        };

        // D4-1: spawn the orphan-container reaper. Fails this build closed
        // (via `?`) if Docker is unreachable — without a reaper the
        // two-stage orphan sweep never runs and per-user sandbox containers
        // accumulate unbounded, so this now matches the egress proxy's
        // fail-closed posture immediately below rather than degrading
        // silently to `None`. Shares `inputs.activity` with the exec
        // transport (Task A5) so both observe the same per-user
        // last-activity timestamps.
        let reaper = crate::sandbox::spawn_sandbox_reaper(activity).await?;

        Ok(Self {
            reaper: Some(reaper),
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_host_api::{
        ids::{InvocationId, UserId},
        resource::{ResourceEstimate, ResourceScope},
    };
    use ironclaw_resources::InMemoryResourceGovernor;

    fn governor() -> Arc<dyn ironclaw_resources::ResourceGovernor> {
        Arc::new(InMemoryResourceGovernor::new())
    }

    fn managed_bundle_for_test() -> crate::sandbox::UserSandboxRuntimeBundle {
        let config = ironclaw_host_runtime::RailwayPreviewSandboxConfig::new(
            "sandbox-test-project",
            "sandbox-test-environment",
        )
        .expect("static Railway test configuration is valid");
        crate::sandbox::UserSandboxFactory::railway_preview(config)
    }

    fn local_bundle_for_test() -> crate::sandbox::UserSandboxRuntimeBundle {
        let process_port = managed_bundle_for_test()
            .process_port_for_test()
            .expect("test bundle exposes its process port");
        crate::sandbox::UserSandboxFactory::recording_for_test(
            process_port,
            std::path::PathBuf::from("sandbox-test-workspaces"),
        )
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
            bundle: None,
            local_runtime_identity: None,
            resource_governor: governor(),
            owner_user_id: UserId::new("probe-user").unwrap(),
        })
        .await
        .expect("non-sandboxed profile never fails to build inert bindings");

        assert!(bindings.reaper.is_none());
        bindings.shutdown_all(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn transport_managed_sandbox_applies_quota_without_host_services() {
        let bindings = SandboxRuntimeBindings::build(SandboxProfileBindingInputs {
            is_sandboxed_profile: true,
            bundle: Some(managed_bundle_for_test()),
            local_runtime_identity: None,
            resource_governor: governor(),
            owner_user_id: UserId::new("railway-preview-user").unwrap(),
        })
        .await
        .expect("transport-managed sandbox needs no local Docker background services");

        assert!(bindings.reaper.is_none());
    }

    /// Plain `#[test]` + `block_on`, not `#[tokio::test]`, and guarded by
    /// `lock_env()`: the reaper spawn this now depends on reads the
    /// process-global `IRONCLAW_REBORN_DOCKER_HOST` runtime-env overlay, and
    /// `sandboxed_profile_fails_closed_when_docker_unreachable` (below)
    /// mutates that same overlay under the same guard — without sharing it,
    /// cargo's default parallel test execution could interleave the two and
    /// make this test observe the other's override. See
    /// `sandbox::reaper::tests::docker_unreachable_fails_the_spawn_closed`
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
                bundle: Some(local_bundle_for_test()),
                local_runtime_identity: None,
                resource_governor: Arc::clone(&governor),
                owner_user_id: owner_user_id.clone(),
            }))
            .expect(
                "sandboxed profile build succeeds against this machine's reachable Docker daemon",
            );

        // The ceiling is live once the build succeeds (which now requires a
        // reachable Docker daemon for the reaper spawn — see
        // `sandboxed_profile_fails_closed_when_docker_unreachable` for the
        // fail-closed path when the daemon is not reachable).
        let tenant_id = crate::sandbox::resolve_local_runtime_tenant_id(None).unwrap();
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
    /// level by `sandbox::reaper::tests::docker_unreachable_fails_the_spawn_closed`:
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
                bundle: Some(local_bundle_for_test()),
                local_runtime_identity: None,
                resource_governor: governor(),
                owner_user_id,
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
    }
}
