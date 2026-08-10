//! Full-turn proof that the sandbox profile routes `builtin.shell` into Docker.

#[path = "support/docker_gate.rs"]
mod docker_gate;
#[allow(dead_code)]
#[path = "support/mod.rs"]
mod reborn_support;
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;

use ironclaw_host_api::ids::{TenantId, TenantUserWorkspaceKey, UserId};
use reborn_support::builder::RebornIntegrationHarness;
use reborn_support::group::GroupCapability;
use reborn_support::reply::RebornScriptedReply;
use serde_json::json;

const CONTAINER_MARKER: &str = "SANDBOX_SHELL_IN_CONTAINER";
const LEAF_ONLY_MARKER: &str = "SANDBOX_CANONICAL_LEAF_ONLY";
const PERSISTENCE_MARKER: &str = "SANDBOX_WORKSPACE_PERSISTED";

#[test]
fn sandbox_shell_turn_executes_in_a_real_container() {
    run_with_larger_stack(async {
        if !docker_gate::docker_available().await {
            eprintln!("SKIP: sandbox shell turn requires a Docker daemon");
            return;
        }
        let image = docker_gate::configured_sandbox_image();
        if !docker_gate::docker_image_available(&image).await {
            eprintln!("SKIP: sandbox worker image {image:?} is not built");
            return;
        }

        let tenant = TenantId::new("tenant-itest").expect("sandbox tenant id");
        let sibling = UserId::new("sandbox-sibling").expect("sandbox sibling id");
        let sibling_key = TenantUserWorkspaceKey::from_tenant_user(&tenant, &sibling);

        let harness = RebornIntegrationHarness::test_default()
            .with_sandbox_shell_tools()
            .script([
                RebornScriptedReply::tool_call(
                    "builtin.shell",
                    json!({
                        "command": format!(
                            r#"python - <<'PY'
import os
from pathlib import Path

assert Path('/.dockerenv').is_file()
assert Path('selected-leaf-sentinel.txt').read_text() == 'host-selected-leaf'
for relative in [
    'reborn-home-sentinel.txt',
    'state/reborn-state-sentinel.txt',
    'state/.reborn-secrets-master-key',
    'state/provider-credential-sentinel.txt',
    'system/system-sentinel.txt',
    'users/{sibling}/sibling-sentinel.txt',
]:
    assert not (Path('/workspace') / relative).exists(), relative
forbidden_env = [
    'IRONCLAW_REBORN_HOME', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
    'NEARAI_API_KEY', 'GITHUB_TOKEN', 'GH_TOKEN', 'RAILWAY_TOKEN',
    'RAILWAY_API_TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
]
assert all(name not in os.environ for name in forbidden_env)
Path('container-write.txt').write_text('container-owned-leaf')
Path('persistence-marker.txt').write_text('{PERSISTENCE_MARKER}')
print('{LEAF_ONLY_MARKER}')
print('{CONTAINER_MARKER}')
PY"#,
                            sibling = sibling_key.digest_segment(),
                        )
                    }),
                ),
                RebornScriptedReply::tool_call(
                    "builtin.shell",
                    json!({"command": "cat /workspace/persistence-marker.txt && uid=$(id -u) && test \"$uid\" -ne 0 && echo NON_ROOT_UID_OK"}),
                ),
                RebornScriptedReply::text("ran in the sandbox"),
            ])
            .build()
            .await
            .expect("sandbox-shell harness builds");

        let installation_home = match &harness._shared.capability {
            GroupCapability::HostRuntime(capability) => capability.storage_root_for_test(),
            GroupCapability::Recording
            | GroupCapability::RecordingNoProgress
            | GroupCapability::RecordingRecoverablePortError => {
                panic!("sandbox profile must use the production host-runtime capability path")
            }
        };
        let caller_key =
            TenantUserWorkspaceKey::from_scope(&harness.turn_scope.to_resource_scope());
        let selected_leaf = installation_home
            .join("workspaces")
            .join("users")
            .join(caller_key.digest_segment());
        let sibling_leaf = installation_home
            .join("workspaces")
            .join("users")
            .join(sibling_key.digest_segment());
        std::fs::create_dir_all(&selected_leaf).expect("selected workspace leaf");
        std::fs::create_dir_all(&sibling_leaf).expect("sibling workspace leaf");
        std::fs::create_dir_all(installation_home.join("state")).expect("canonical state root");
        std::fs::create_dir_all(installation_home.join("system")).expect("canonical system root");
        std::fs::write(
            selected_leaf.join("selected-leaf-sentinel.txt"),
            "host-selected-leaf",
        )
        .expect("selected sentinel");
        std::fs::write(
            sibling_leaf.join("sibling-sentinel.txt"),
            "host-sibling-only",
        )
        .expect("sibling sentinel");
        std::fs::write(
            installation_home.join("reborn-home-sentinel.txt"),
            "host-reborn-home-only",
        )
        .expect("Reborn home sentinel");
        std::fs::write(
            installation_home.join("state/reborn-state-sentinel.txt"),
            "host-state-only",
        )
        .expect("state sentinel");
        std::fs::write(
            installation_home.join("state/.reborn-secrets-master-key"),
            "host-master-key-only",
        )
        .expect("master-key sentinel");
        std::fs::write(
            installation_home.join("state/provider-credential-sentinel.txt"),
            "host-provider-credential-only",
        )
        .expect("provider credential sentinel");
        std::fs::write(
            installation_home.join("system/system-sentinel.txt"),
            "host-system-only",
        )
        .expect("system sentinel");

        harness
            .submit_turn("run a sandboxed shell command")
            .await
            .expect("turn completes");
        harness
            .assert_model_tools_contains("builtin__shell")
            .await
            .expect("shell is model-visible");
        harness
            .assert_tool_invoked("builtin.shell")
            .await
            .expect("shell dispatches");
        harness
            .assert_tool_result_contains(CONTAINER_MARKER)
            .await
            .expect("command ran in Docker");
        harness
            .assert_tool_result_contains(LEAF_ONLY_MARKER)
            .await
            .expect("sandbox received only its selected canonical workspace leaf");
        harness
            .assert_tool_result_contains("NON_ROOT_UID_OK")
            .await
            .expect("command ran as a non-root sandbox uid");
        harness
            .assert_tool_result_contains(PERSISTENCE_MARKER)
            .await
            .expect("workspace persisted across shell calls");
        harness
            .assert_reply_contains("ran in the sandbox")
            .await
            .expect("turn finalized");
        assert_eq!(
            std::fs::read_to_string(selected_leaf.join("container-write.txt"))
                .expect("container writes stay in the selected leaf"),
            "container-owned-leaf"
        );
        assert_eq!(
            std::fs::read_to_string(sibling_leaf.join("sibling-sentinel.txt"))
                .expect("sibling sentinel remains host-only"),
            "host-sibling-only"
        );
    });
}

fn run_with_larger_stack<F>(test: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name("sandbox-shell-turn".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio test runtime")
                .block_on(test);
        })
        .expect("spawn sandbox shell test thread");
    if let Err(panic) = handle.join() {
        std::panic::resume_unwind(panic);
    }
}
