//! W6 phase 2 — the first harness-driven proof that a scripted `builtin.shell`
//! turn dispatches into a REAL `TenantSandbox` Docker container, not the host
//! and not the inert `RecordingProcessPort`.
//!
//! Root cause this test exists to fix: `core_builtin_tools()`
//! (`support/harness/profiles/core_builtin.rs`) hand-assembles a `HostRuntime`
//! via `local_dev_host_runtime_with_http_egress` and never calls
//! `build_runtime`, so `.with_live_shell()`/`builtin.shell` on that path can
//! only ever reach the unsandboxed host process port — the
//! `HostedSingleTenantVolumeSandboxed` composition path
//! (`ironclaw_reborn_composition::tenant_sandbox_process_binding`) had never
//! been driven from the integration harness at all. This test wires a NEW
//! profile (`support/harness/profiles/sandbox_shell.rs`) through
//! `new_with_options`/`build_runtime` — the same production entry point
//! `ironclaw_reborn_cli::runtime::build_sandboxed_local_runtime_services_input`
//! uses — so `builtin.shell` genuinely reaches a container.
//!
//! Docker-gated and opt-in: skips cleanly (a visible `SKIP: ...` line) with no
//! Docker daemon or no locally-built sandbox image reachable — never a silent
//! pass. The DEFAULT hermetic harness lane is unaffected: nothing here runs
//! unless this specific test binary is invoked, and every other integration
//! test still builds zero Docker state.
//!
//! FINDING (see the PR/report): `.with_sandbox_shell_tools(tenant_id,
//! user_id)` cannot actually vary the container's real identity. Every plain
//! (non-multiuser) `RebornIntegrationHarness` submits its turn under the ONE
//! fixed `test_product_scope("tenant-itest", "host-user", ...)` scope
//! (`support/group.rs::build_base`) — capability dispatch resolves its
//! `ResourceScope` from the submitted run's own actor, never from this
//! harness's `user_id`/`local_runtime_identity`. So every sandboxed-shell
//! test in this suite targets the SAME persistent container regardless of
//! what identity is minted here. The pre-run cleanup below is the actual
//! mechanism keeping this test hermetic across repeat local runs (a
//! persistent container's Docker-level bind mount is fixed at container
//! CREATE time — reusing it across two different `$HOME`-rooted `TempDir`s
//! would otherwise bind-mount a directory that no longer exists once the
//! prior run's `TempDir` was dropped).

#[path = "support/docker_gate.rs"]
mod docker_gate;
#[allow(dead_code)]
#[path = "support/mod.rs"]
mod reborn_support;
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;

use reborn_support::builder::RebornIntegrationHarness;
use reborn_support::reply::RebornScriptedReply;
use reborn_support::sandbox_shell_identity::{unique_test_tenant_id, unique_test_user_id};
use serde_json::json;

/// Printed only when the shell command actually ran with `/.dockerenv`
/// present — a file Docker creates inside every container and never on a
/// bare dev host. Distinguishes "ran in a real container" from "ran on the
/// host" or "never ran at all" (the inert `RecordingProcessPort` records the
/// command string but spawns nothing, so it could never print this marker).
const IN_CONTAINER_MARKER: &str = "SANDBOX_SHELL_IN_CONTAINER";

/// Docker label every `TenantSandbox` user container carries (the
/// `ironclaw_host_runtime::sandbox_process::exec_transport::LABEL_PREFIX`
/// tenant label), fixed to `"tenant-itest"` for every harness build in this
/// suite (see the module doc FINDING). Used to find/remove THIS suite's
/// sandbox container by label rather than by a name this test cannot
/// actually control.
const ITEST_TENANT_LABEL_FILTER: &str = "label=ironclaw.tenant=tenant-itest";

/// Proves the scripted `builtin.shell` call executed inside a real
/// `TenantSandbox` container: the command only echoes [`IN_CONTAINER_MARKER`]
/// when `/.dockerenv` exists, and separately reports the exec uid, which the
/// sandbox always runs as the unprivileged `SANDBOX_EXEC_UID` (1000,
/// `ironclaw_host_runtime::sandbox_process::exec_transport`), not the host
/// user running this test. `wait_for_status(Completed)` alone would pass
/// identically whether the command ran on the host, in the inert port, or
/// nowhere — these two independent markers are what make the assertion
/// discriminating.
#[test]
fn sandbox_shell_turn_executes_in_a_real_container() {
    run_with_larger_stack(async {
        if !docker_gate::docker_available() {
            eprintln!(
                "SKIP: no docker daemon reachable — \
                 sandbox_shell_turn_executes_in_a_real_container requires a real Docker daemon \
                 (CI/hosted Docker lane only)"
            );
            return;
        }
        let image = docker_gate::configured_sandbox_image();
        if !docker_gate::docker_image_available(&image) {
            eprintln!(
                "SKIP: sandbox worker image {image:?} is not built locally — \
                 sandbox_shell_turn_executes_in_a_real_container requires a locally-built \
                 ironclaw-worker image (CI/hosted Docker lane only)"
            );
            return;
        }

        // Remove any leftover persistent container from a PRIOR local run of
        // this test before building the harness. Necessary because the
        // container is keyed by the fixed itest scope (see the module doc
        // FINDING): a stale container's Docker-level bind mount still points
        // at a previous run's now-deleted `$HOME`-rooted `TempDir`, and Docker
        // does not update an existing container's bind source on reuse.
        remove_itest_sandbox_containers();

        // Minted fresh per run for identity hygiene and so
        // `HostRuntimeHarnessOptions::with_local_runtime_identity`/this
        // harness's own `user_id` are real, non-colliding values (used by
        // composition's own internal bookkeeping) — see the module doc
        // FINDING for why this does NOT vary the container's actual identity.
        let tenant_id = unique_test_tenant_id("sandbox-shell-tenant").expect("unique tenant id");
        let user_id = unique_test_user_id("sandbox-shell-user").expect("unique user id");

        let build_result = RebornIntegrationHarness::test_default()
            .with_sandbox_shell_tools(tenant_id, user_id)
            .script([
                RebornScriptedReply::tool_call(
                    "builtin.shell",
                    json!({
                        "command": format!(
                            "test -f /.dockerenv && echo {IN_CONTAINER_MARKER}; id -u"
                        )
                    }),
                ),
                RebornScriptedReply::text("ran in the sandbox"),
            ])
            .build()
            .await;

        let assertion_result = async {
            let h = build_result.map_err(|error| {
                format!(
                    "sandbox-shell harness failed to build (Docker connect + composition): {error}"
                )
            })?;

            h.submit_turn("run a sandboxed shell command")
                .await
                .map_err(|error| format!("turn did not complete: {error}"))?;

            // Independent signal 1: `/.dockerenv` only exists inside a real
            // Docker container.
            h.assert_tool_result_contains(IN_CONTAINER_MARKER)
                .await
                .map_err(|error| {
                    format!(
                        "shell command did not report /.dockerenv present — \
                         did not run inside a real container: {error}"
                    )
                })?;
            // Independent signal 2: the sandboxed exec always runs as the
            // unprivileged sandbox uid (1000), never the host user running
            // this test process.
            h.assert_tool_result_contains("1000")
                .await
                .map_err(|error| {
                    format!(
                        "shell command did not report the sandbox exec uid (1000), so it did not \
                     run as the sandbox user: {error}"
                    )
                })?;
            h.assert_reply_contains("ran in the sandbox")
                .await
                .map_err(|error| format!("final reply not finalized: {error}"))?;
            Ok::<(), String>(())
        }
        .await;

        // Best-effort teardown: this container is PERSISTENT by design
        // (`docs/plans/2026-07-*persistent-sandbox-container*`), so nothing
        // reaps it automatically outside a running reaper task, which this
        // harness never starts. Removed regardless of pass/fail, so a
        // failing assertion still cleans up. See the report for what a real
        // `Drop`-based teardown still needs (an async-safe hook this harness
        // does not yet expose).
        remove_itest_sandbox_containers();

        assertion_result.expect("sandbox-shell turn assertions");
    });
}

/// Best-effort `docker rm -f` of every container carrying this suite's fixed
/// itest tenant label. Never panics on failure (Docker CLI absence, no
/// matching containers, a transient daemon hiccup) — cleanup must not mask
/// the real assertion outcome.
fn remove_itest_sandbox_containers() {
    let Ok(list) = std::process::Command::new("docker")
        .args(["ps", "-a", "-q", "--filter", ITEST_TENANT_LABEL_FILTER])
        .output()
    else {
        return;
    };
    for id in String::from_utf8_lossy(&list.stdout).lines() {
        let id = id.trim();
        if !id.is_empty() {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", id])
                .output();
        }
    }
}

/// Spawns `test` on a dedicated 16MB-stack thread with a current-thread tokio
/// runtime — mirrors `tests/integration/process_port.rs::run_with_larger_stack`
/// (needed there for the real subprocess path; the Docker exec path here adds
/// at least as much async-state-machine depth on top of the full
/// `product_surface → composition → webui_v2 → runtime` chain).
fn run_with_larger_stack<F>(test: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name("sandbox_shell_turn_executes_in_a_real_container".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio test runtime")
                .block_on(test);
        })
        .expect("spawn stack-sized test thread");
    if let Err(panic) = handle.join() {
        std::panic::resume_unwind(panic);
    }
}
