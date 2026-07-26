//! Docker daemon / sandbox-image availability gate for real-Docker
//! integration-tier tests under `tests/integration/`.
//!
//! Real-Docker tests run only where a daemon (and the locally-built
//! `ironclaw-worker` image) is reachable — CI/hosted Docker runners, not a
//! typical dev machine. Callers MUST skip with a visible "SKIP: ..." line on
//! `eprintln!` when either check fails, never a silent pass — a quietly
//! vanishing assertion is indistinguishable from a real green run.
//!
//! Deliberately duplicated (not `#[path]`-shared) from
//! `crates/ironclaw_host_runtime/tests/support/docker_gate.rs`: that file
//! lives inside a different crate's private test tree, and reaching into it
//! via a cross-crate relative `#[path]` would couple this integration suite
//! to `ironclaw_host_runtime`'s test directory layout. This copy is the
//! `tests/integration/`-local instance of the same tiny gate.

use std::process::Command;

/// True iff `IRONCLAW_REQUIRE_DOCKER_TESTS=1` is set. CI sets this so a
/// missing daemon/image is a hard test failure instead of a silent skip (the
/// exact gap that let sandbox security bugs ship unnoticed — docker-gated
/// tests only ran on one developer's laptop). Unset locally, so dev machines
/// keep today's skip-and-pass behavior.
fn docker_tests_required() -> bool {
    std::env::var("IRONCLAW_REQUIRE_DOCKER_TESTS").as_deref() == Ok("1")
}

/// True iff the `docker` CLI can reach a live daemon (`docker version`
/// succeeds only against a running daemon).
///
/// When `IRONCLAW_REQUIRE_DOCKER_TESTS=1` and no daemon is reachable, this
/// panics rather than returning `false` — callers gate on this function
/// returning `false` to print `SKIP: ...` and return early, which must not
/// happen in CI.
pub fn docker_available() -> bool {
    let available = Command::new("docker")
        .arg("version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !available && docker_tests_required() {
        panic!(
            "IRONCLAW_REQUIRE_DOCKER_TESTS=1 but no Docker daemon is reachable \
             (`docker version` failed) — docker-gated tests must not silently \
             skip in CI"
        );
    }
    available
}

/// True iff `image` is present in the local Docker image store (i.e. it was
/// built, not just referenced). The Reborn sandbox worker image
/// (`ironclaw-worker:latest` by default, `IRONCLAW_REBORN_SANDBOX_IMAGE` /
/// `IRONCLAW_SANDBOX_IMAGE` override) is never pulled automatically — a
/// daemon can be reachable with the image still missing.
///
/// Same "fail instead of skip" behavior as [`docker_available`] under
/// `IRONCLAW_REQUIRE_DOCKER_TESTS=1`.
pub fn docker_image_available(image: &str) -> bool {
    let available = Command::new("docker")
        .args(["image", "inspect", image])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !available && docker_tests_required() {
        panic!(
            "IRONCLAW_REQUIRE_DOCKER_TESTS=1 but sandbox image {image:?} is not \
             present locally — docker-gated tests must not silently skip in CI"
        );
    }
    available
}

/// Resolve the sandbox worker image name the same way
/// `RebornSandboxConfig::new` does, so the gate checks the image the test
/// will actually launch.
pub fn configured_sandbox_image() -> String {
    std::env::var("IRONCLAW_REBORN_SANDBOX_IMAGE")
        .or_else(|_| std::env::var("IRONCLAW_SANDBOX_IMAGE"))
        .unwrap_or_else(|_| "ironclaw-worker:latest".to_string())
}
