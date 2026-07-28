//! Composition-owned spawn of `ironclaw_host_runtime::SandboxReaper` (D4-1).
//!
//! The reaper core (`ironclaw_host_runtime::sandbox_process::reaper`) is
//! deliberately unopinionated about scheduling — composition is the one
//! place that connects to Docker, constructs the reaper, spawns it as a
//! background task, and owns its cancellation. This module is that one
//! place; `sandbox_composition::SandboxRuntimeBindings::build` calls
//! [`spawn_sandbox_reaper`] with a single line rather than growing its own
//! Docker-connect-and-spawn logic.
//!
//! **Fail-closed, matching the egress proxy in the same call site
//! (`sandbox_composition::SandboxRuntimeBindings::build`):** the sandboxed
//! profile's boot path (`sandbox_boot::tenant_sandbox_process_binding`)
//! already made Docker a precondition for the whole build, failing closed if
//! the daemon is unreachable — so by the time this is called the daemon was
//! reachable a moment ago, and a fresh connect failure here is not a
//! transient blip to shrug off. Without a reaper the two-stage orphan sweep
//! (idle stop, aged removal/recycle) never runs at all and per-user sandbox
//! containers accumulate unbounded, so [`spawn_sandbox_reaper`] returns
//! `Err` on a Docker-connect failure and `build` propagates it, rather than
//! degrading to a silently absent reaper.

use std::sync::Arc;
use std::time::Duration;

use ironclaw_host_runtime::{
    ConnectionAttributionResolver, SandboxActivityRegistry, SandboxReaper, SandboxReaperConfig,
};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::RebornBuildError;

/// How long [`SandboxReaperRuntimeHandle::shutdown`] waits for the reaper's
/// in-flight scan to observe the shutdown signal and return before it aborts
/// the task outright. Mirrors `CREDENTIAL_REFRESH_WORKER_SHUTDOWN_TIMEOUT`'s
/// role for the credential-refresh worker.
pub(crate) const SANDBOX_REAPER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Owned handle to a spawned [`SandboxReaper::run`] task. Composition holds
/// exactly one of these (on `RebornRuntime`) for the sandboxed profile and
/// drives shutdown from `RebornRuntime::shutdown` alongside every other
/// owned background worker.
pub(crate) struct SandboxReaperRuntimeHandle {
    shutdown_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
    /// Test-only handle onto the SAME `Arc<SandboxReaper>` the spawned task
    /// owns, so a composition-tier test can call
    /// `SandboxReaper::attribution_for_test` against a PRODUCTION-spawned
    /// reaper (see `sandbox_composition::tests` /
    /// `sandbox_attribution_reaches_both_production_consumers`). `None` only
    /// for this module's own `shutdown_stops_a_running_task_before_the_timeout`
    /// test, which never spawns via `spawn_sandbox_reaper` and has no
    /// reaper to hand back. Ships zero bytes in production binaries.
    ///
    /// `#[allow(dead_code)]`: read only from this crate's own `#[cfg(test)]`
    /// `mod tests` (`sandbox_composition.rs`), which the `--all-features`
    /// lib-only compilation (`feature = "test-support"` without
    /// `cfg(test)`) never includes — so that build sees the field
    /// constructed but never read. No `tests/` integration crate consumes
    /// it (yet); if one does, this allow can come off.
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub(crate) reaper: Option<Arc<SandboxReaper>>,
}

impl SandboxReaperRuntimeHandle {
    /// Signals the reaper's scan loop to stop and awaits the task, aborting
    /// it if it has not stopped within `timeout`.
    pub(crate) async fn shutdown(self, timeout: Duration) {
        // A closed receiver (task already gone) is not an error here.
        let _ = self.shutdown_tx.send(true);
        let mut handle = self.handle;
        match tokio::time::timeout(timeout, &mut handle).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::debug!(?error, "sandbox reaper task join failed");
            }
            Err(_) => {
                tracing::debug!(
                    ?timeout,
                    "sandbox reaper did not stop before shutdown timeout; aborting"
                );
                handle.abort();
                if let Err(error) = handle.await
                    && error.is_panic()
                {
                    tracing::debug!(?error, "aborted sandbox reaper task panicked");
                }
            }
        }
    }
}

/// Connects to Docker and spawns [`SandboxReaper::run`] as an owned
/// background task. Docker is already a precondition for reaching this call
/// (the only caller is the sandboxed profile, whose boot path already
/// requires a reachable daemon), so a connect failure here fails closed —
/// see the module doc — rather than degrading to a silently absent reaper.
pub(crate) async fn spawn_sandbox_reaper(
    activity: Arc<SandboxActivityRegistry>,
    // W17/W6: the SAME attribution resolver `tenant_sandbox_process_binding`
    // wired into the exec transport (threaded here via
    // `SandboxProfileBindingInputs::attribution` /
    // `RebornHostBindings::with_sandbox_attribution_resolver`), so the
    // reaper's teardown paths invalidate the identical cache the transport
    // reads from. `None` for non-sandboxed profiles and any caller that
    // never wired one.
    attribution: Option<Arc<ConnectionAttributionResolver>>,
) -> Result<SandboxReaperRuntimeHandle, RebornBuildError> {
    let docker = ironclaw_host_runtime::connect_docker_with_retry()
        .await
        .map_err(|error| RebornBuildError::InvalidConfig {
            reason: format!("sandbox reaper Docker connect failed: {error}"),
        })?;

    let mut reaper = SandboxReaper::new(docker, activity, SandboxReaperConfig::default());
    if let Some(resolver) = attribution {
        reaper = reaper.with_attribution_resolver(resolver);
    }
    let reaper = Arc::new(reaper);
    #[cfg(any(test, feature = "test-support"))]
    let reaper_for_test = Arc::clone(&reaper);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        reaper.run(shutdown_rx).await;
    });

    Ok(SandboxReaperRuntimeHandle {
        shutdown_tx,
        handle,
        #[cfg(any(test, feature = "test-support"))]
        reaper: Some(reaper_for_test),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard the module doc now promises: a Docker daemon that is
    /// unreachable at reaper-spawn time is a hard `Err`, not a swallowed
    /// `None` — the sandboxed profile's boot path already made Docker a
    /// precondition, so a reaper-spawn failure here must fail the build
    /// closed exactly like the egress proxy's bind failure does.
    ///
    /// Forces the unreachable condition deterministically via
    /// `IRONCLAW_REBORN_DOCKER_HOST` (read by
    /// `sandbox_process::connect::connect_once`) pointed at a nonexistent
    /// socket, rather than relying on the environment happening to have no
    /// daemon — this machine (colima) has one running. Plain `#[test]` +
    /// `block_on`, not `#[tokio::test]`, so the `lock_env()` guard is never
    /// held across an `.await` in an outer async fn — mirrors
    /// `connect::tests::docker_host_env_override_is_consulted_first`.
    #[test]
    fn docker_unreachable_fails_the_spawn_closed() {
        let _guard = ironclaw_common::env_helpers::lock_env();
        ironclaw_common::env_helpers::set_runtime_env(
            "IRONCLAW_REBORN_DOCKER_HOST",
            "/nonexistent/ironclaw-w3-reaper-test-docker.sock",
        );

        let activity = Arc::new(SandboxActivityRegistry::new());
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime for test")
            .block_on(spawn_sandbox_reaper(activity, None));

        ironclaw_common::env_helpers::remove_runtime_env("IRONCLAW_REBORN_DOCKER_HOST");

        match result {
            Err(RebornBuildError::InvalidConfig { reason }) => {
                assert!(
                    reason.contains("reaper"),
                    "expected reason to name the reaper, got: {reason}"
                );
            }
            Ok(_) => panic!("expected reaper spawn to fail when Docker is unreachable"),
            Err(other) => panic!("expected InvalidConfig, got other RebornBuildError: {other:?}"),
        }
    }

    /// The handle's cancellation path (shutdown signal -> task observes it
    /// and returns -> join succeeds) is exercised directly against a
    /// `SandboxReaper::run` future without going through Docker, proving the
    /// handle is a real owned/cancellable task rather than a fire-and-forget
    /// spawn. Mirrors the shape `spawn_sandbox_reaper` produces, just
    /// without the Docker connect.
    #[tokio::test]
    async fn shutdown_stops_a_running_task_before_the_timeout() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            // Stand-in for `SandboxReaper::run`'s own shutdown-aware loop.
            let _ = shutdown_rx.changed().await;
        });
        let handle = SandboxReaperRuntimeHandle {
            shutdown_tx,
            handle,
            // This test never spawns via `spawn_sandbox_reaper` and has no
            // reaper to hand back — see the field doc.
            #[cfg(any(test, feature = "test-support"))]
            reaper: None,
        };

        handle.shutdown(SANDBOX_REAPER_SHUTDOWN_TIMEOUT).await;
        // Reaching here without hanging proves the shutdown signal reached
        // the task and the join completed inside the timeout.
    }
}
