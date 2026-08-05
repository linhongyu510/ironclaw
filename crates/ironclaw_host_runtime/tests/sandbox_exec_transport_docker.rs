//! Real-Docker tests for the exec-based persistent container lifecycle
//! ([`sandbox_process::exec_transport`]), driven through the public
//! [`RuntimeProcessPort::run_command`] surface rather than the crate-private
//! `ensure_container`/`exec_in_container` helpers, per this crate's own
//! convention (`sandbox_reaper_docker.rs`, `cli_session_docker.rs`,
//! `sandbox_workspace_fs_parity_docker.rs`).
//!
//! Requires a reachable Docker daemon AND a locally-built `ironclaw-worker`
//! image, same gate as those sibling files. Neither is available on this
//! development machine — these tests are authored to run for real in
//! CI/hosted Docker lanes and skip cleanly (a visible `SKIP: ...` line, never
//! a silent pass) everywhere else.

#[path = "support/docker_gate.rs"]
mod docker_gate;
#[path = "support/sandbox_transport.rs"]
mod sandbox_transport;

use std::collections::HashMap;

use bollard::{
    Docker,
    container::{
        Config, CreateContainerOptions, InspectContainerOptions, ListContainersOptions,
        RemoveContainerOptions, StartContainerOptions,
    },
    models::HostConfig,
};
use ironclaw_host_api::{
    ids::{AgentId, InvocationId, TenantId, UserId},
    resource::ResourceScope,
};
use ironclaw_host_runtime::{
    CommandExecutionRequest, RebornSandboxConfig, RebornSandboxUserKey,
    RebornScopedSandboxCommandTransport, RuntimeProcessError, RuntimeProcessPort,
};

// Docker label keys the production launch config attaches (see
// `sandbox_process/registry.rs`). Written as literals here, matching
// `sandbox_reaper_docker.rs`'s own convention — those helper fns are
// `pub(crate)` and unreachable from an integration test.
const LABEL_TENANT: &str = "ironclaw.tenant";
const LABEL_USER: &str = "ironclaw.user";
const LABEL_SECURITY_POSTURE: &str = "ironclaw.security_posture";
const EXPECTED_SANDBOX_PIDS_LIMIT: i64 = 1024;

fn scope(tenant: &str, user: &str) -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new(tenant).expect("tenant id"),
        user_id: UserId::new(user).expect("user id"),
        agent_id: Some(AgentId::new("reborn-cli").expect("agent id")),
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

fn request(scope: ResourceScope, command: &str) -> CommandExecutionRequest {
    CommandExecutionRequest {
        scope,
        mounts: None,
        command: command.to_string(),
        workdir: None,
        timeout_secs: Some(10),
        output_limit_bytes: None,
        extra_env: HashMap::new(),
        background: false,
    }
}

fn background_request(scope: ResourceScope, command: &str) -> CommandExecutionRequest {
    let mut request = request(scope, command);
    request.background = true;
    request
}

/// Finds the single container labeled for `{tenant, user}`, the same way the
/// production `ensure_container` lookup does (see `exec_transport.rs`).
async fn find_labeled_container(docker: &Docker, tenant: &str, user: &str) -> Option<String> {
    let filters = HashMap::from([(
        "label".to_string(),
        vec![
            format!("{LABEL_TENANT}={tenant}"),
            format!("{LABEL_USER}={user}"),
        ],
    )]);
    let found = docker
        .list_containers(Some(ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        }))
        .await
        .expect("container lookup succeeds");
    found.into_iter().next().and_then(|summary| summary.id)
}

async fn best_effort_remove(docker: &Docker, container_id: &str) {
    let _ = docker
        .remove_container(
            container_id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

async fn assert_container_stopped(docker: &Docker, container_id: &str) {
    let running = docker
        .inspect_container(container_id, None::<InspectContainerOptions>)
        .await
        .expect("container inspect succeeds")
        .state
        .and_then(|state| state.running);
    assert_eq!(
        running,
        Some(false),
        "foreground-only sandbox must be stopped between commands"
    );
}

macro_rules! skip_unless_docker_ready {
    ($test_name:literal) => {{
        if !docker_gate::docker_available() {
            eprintln!(
                "SKIP: no docker daemon reachable — {} requires a real Docker daemon (CI/hosted Docker lane only)",
                $test_name
            );
            return;
        }
        let image = docker_gate::configured_sandbox_image();
        if !docker_gate::docker_image_available(&image) {
            eprintln!(
                "SKIP: sandbox worker image {image:?} is not built locally — {} requires a locally-built ironclaw-worker image (CI/hosted Docker lane only)",
                $test_name
            );
            return;
        }
        image
    }};
}

/// A sandbox process port selected by the deployment profile reaches the real
/// Docker transport without a second, user-controlled enablement gate.
#[tokio::test]
async fn sandbox_profile_process_port_runs_in_container() {
    let image = skip_unless_docker_ready!("sandbox_profile_process_port_runs_in_container");

    const TENANT: &str = "enablement-gate-tenant";
    const USER: &str = "enablement-gate-user";
    let docker = Docker::connect_with_local_defaults().expect("docker connects");
    if let Some(stale_id) = find_labeled_container(&docker, TENANT, USER).await {
        best_effort_remove(&docker, &stale_id).await;
    }

    let temp = tempfile::tempdir().expect("sandbox workspace root");
    let config = RebornSandboxConfig::new(temp.path().to_path_buf()).with_image(image);
    let transport = RebornScopedSandboxCommandTransport::connect(config)
        .await
        .expect("sandbox transport connects");
    let port = transport.into_process_port();
    let user_scope = scope(TENANT, USER);

    let output = port
        .run_command(request(user_scope, "echo sandbox-enabled"))
        .await
        .expect("sandbox profile reaches the real sandbox transport");
    assert!(output.sandboxed);
    assert!(output.output.contains("sandbox-enabled"));

    let container_id = find_labeled_container(&docker, TENANT, USER)
        .await
        .expect("sandbox-profile command creates a labeled sandbox container");
    best_effort_remove(&docker, &container_id).await;
}

/// Real-container proof of the complete PR1 containment posture. This checks
/// guest-visible behavior and the daemon's authoritative HostConfig so a
/// future image or launch-config change cannot silently weaken isolation.
#[tokio::test]
async fn python_worker_is_networkless_readonly_non_root_and_credential_free() {
    let image = skip_unless_docker_ready!(
        "python_worker_is_networkless_readonly_non_root_and_credential_free"
    );

    const TENANT: &str = "containment-tenant";
    const USER: &str = "containment-user";
    let docker = Docker::connect_with_local_defaults().expect("docker connects");
    if let Some(stale_id) = find_labeled_container(&docker, TENANT, USER).await {
        best_effort_remove(&docker, &stale_id).await;
    }

    let temp = tempfile::tempdir().expect("sandbox workspace root");
    let config = RebornSandboxConfig::new(temp.path().to_path_buf()).with_image(image);
    let port = RebornScopedSandboxCommandTransport::connect(config)
        .await
        .expect("sandbox transport connects")
        .into_process_port();
    let probe = port
        .run_command(request(
            scope(TENANT, USER),
            "python3 - <<'PY'\n\
             import os\n\
             from pathlib import Path\n\
             assert os.getuid() == 1000\n\
             assert Path.cwd() == Path('/workspace')\n\
             assert not Path('/host').exists()\n\
             assert not Path('/var/run/docker.sock').exists()\n\
             routes = [line.split() for line in Path('/proc/net/route').read_text().splitlines()[1:]]\n\
             assert not any(route[1] == '00000000' for route in routes)\n\
             root_mount = next(line.split() for line in Path('/proc/mounts').read_text().splitlines() if line.split()[1] == '/')\n\
             assert 'ro' in root_mount[3].split(',')\n\
             Path('/workspace/persistence-probe.txt').write_text('ok')\n\
             forbidden = ['RAILWAY_TOKEN', 'RAILWAY_API_TOKEN', 'NEARAI_API_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'AWS_SECRET_ACCESS_KEY']\n\
             assert not any(name in os.environ for name in forbidden)\n\
             print('IRONCLAW_DOCKER_SANDBOX_CONTAINMENT_OK')\n\
             PY",
        ))
        .await
        .expect("containment probe executes");
    assert_eq!(
        probe.exit_code, 0,
        "containment probe failed: {}",
        probe.output
    );
    assert!(
        probe
            .output
            .contains("IRONCLAW_DOCKER_SANDBOX_CONTAINMENT_OK")
    );

    let container_id = find_labeled_container(&docker, TENANT, USER)
        .await
        .expect("containment probe creates a labeled container");
    let inspected = docker
        .inspect_container(&container_id, None::<InspectContainerOptions>)
        .await
        .expect("container inspect succeeds");
    let host = inspected.host_config.expect("container has HostConfig");
    assert_eq!(host.network_mode.as_deref(), Some("none"));
    assert_eq!(host.readonly_rootfs, Some(true));
    assert_eq!(host.cap_drop, Some(vec!["ALL".to_string()]));
    assert!(
        host.security_opt
            .unwrap_or_default()
            .iter()
            .any(|option| option.contains("no-new-privileges"))
    );
    assert_eq!(
        inspected.config.and_then(|config| config.user),
        Some("1000:1000".to_string())
    );

    best_effort_remove(&docker, &container_id).await;
}

/// Drives the public process port against a real pre-limit container. The
/// missing PID limit must make its stamped posture stale, causing the caller
/// to destroy it and launch a replacement whose live Docker HostConfig has
/// the finite limit.
#[tokio::test]
async fn missing_pid_limit_recycles_container_and_replacement_has_finite_limit() {
    let image = skip_unless_docker_ready!(
        "missing_pid_limit_recycles_container_and_replacement_has_finite_limit"
    );

    const TENANT: &str = "pids-limit-tenant";
    const USER: &str = "pids-limit-user";
    let docker = Docker::connect_with_local_defaults().expect("docker connects");
    if let Some(stale_id) = find_labeled_container(&docker, TENANT, USER).await {
        best_effort_remove(&docker, &stale_id).await;
    }

    let stale = docker
        .create_container(
            Some(CreateContainerOptions {
                name: format!("ironclaw-test-no-pids-limit-{}", uuid::Uuid::new_v4()),
                platform: None,
            }),
            Config {
                image: Some(image.clone()),
                cmd: Some(vec!["sleep".to_string(), "infinity".to_string()]),
                labels: Some(HashMap::from([
                    (LABEL_TENANT.to_string(), TENANT.to_string()),
                    (LABEL_USER.to_string(), USER.to_string()),
                    (
                        LABEL_SECURITY_POSTURE.to_string(),
                        "pre-pids-limit-posture".to_string(),
                    ),
                ])),
                host_config: Some(HostConfig {
                    pids_limit: None,
                    auto_remove: Some(false),
                    network_mode: Some("none".to_string()),
                    ..Default::default()
                }),
                user: Some("1000:1000".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("legacy no-limit container creates");
    docker
        .start_container(&stale.id, None::<StartContainerOptions<String>>)
        .await
        .expect("legacy no-limit container starts");

    let temp = tempfile::tempdir().expect("sandbox workspace root");
    let config = RebornSandboxConfig::new(temp.path().to_path_buf()).with_image(image);
    let transport = RebornScopedSandboxCommandTransport::connect(config)
        .await
        .expect("sandbox transport connects");
    let port = transport.into_process_port();
    let output = port
        .run_command(request(scope(TENANT, USER), "echo finite-pids"))
        .await
        .expect("command recycles the stale container and runs in its replacement");
    assert!(output.output.contains("finite-pids"));

    assert!(
        docker
            .inspect_container(&stale.id, None::<InspectContainerOptions>)
            .await
            .is_err(),
        "the no-limit container must be destroyed on posture mismatch"
    );
    let replacement_id = find_labeled_container(&docker, TENANT, USER)
        .await
        .expect("replacement container exists");
    assert_ne!(replacement_id, stale.id);
    let replacement = docker
        .inspect_container(&replacement_id, None::<InspectContainerOptions>)
        .await
        .expect("replacement container inspects");
    assert_eq!(
        replacement
            .host_config
            .and_then(|host_config| host_config.pids_limit),
        Some(EXPECTED_SANDBOX_PIDS_LIMIT),
        "the replacement must apply the finite cgroup PID limit"
    );

    best_effort_remove(&docker, &replacement_id).await;
}

#[tokio::test]
async fn exec_reuses_container_across_commands_file_persists_env_does_not() {
    let image = skip_unless_docker_ready!(
        "exec_reuses_container_across_commands_file_persists_env_does_not"
    );

    let docker = Docker::connect_with_local_defaults().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let user_scope = scope("exec-reuse-tenant", "exec-reuse-user");
    let workspace = RebornSandboxUserKey::from_scope(&user_scope).workspace_path(temp.path());
    std::fs::create_dir_all(&workspace).unwrap();
    let port = sandbox_transport::connect_for_test(&workspace, &image)
        .await
        .expect("sandbox transport connects");

    port.run_command(request(
        user_scope.clone(),
        "echo persisted > /workspace/marker.txt",
    ))
    .await
    .expect("write command succeeds");

    let read = port
        .run_command(request(user_scope.clone(), "cat /workspace/marker.txt"))
        .await
        .expect("read command succeeds against the SAME container");
    assert!(
        read.output.contains("persisted"),
        "file written in one command must be visible to the next: {read:?}"
    );

    let mut with_env = request(user_scope.clone(), "echo $PROBE_VAR");
    with_env.extra_env = HashMap::from([("PROBE_VAR".to_string(), "set".to_string())]);
    let with_env_error = port
        .run_command(with_env)
        .await
        .expect_err("caller-provided environment must be rejected before Docker exec");
    assert!(
        format!("{with_env_error}")
            .contains("does not accept caller-provided environment variables")
    );

    let without_env = port
        .run_command(request(user_scope.clone(), "echo [$PROBE_VAR]"))
        .await
        .expect("later command succeeds");
    assert!(
        without_env.output.contains("[]"),
        "env set in one command must NOT bleed into the next (stateless exec): {without_env:?}"
    );

    if let Some(container_id) =
        find_labeled_container(&docker, "exec-reuse-tenant", "exec-reuse-user").await
    {
        best_effort_remove(&docker, &container_id).await;
    }
}

#[tokio::test]
async fn stopped_container_restarts_transparently_on_next_exec() {
    let image = skip_unless_docker_ready!("stopped_container_restarts_transparently_on_next_exec");

    let docker = Docker::connect_with_local_defaults().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let user_scope = scope("restart-tenant", "restart-user");
    let workspace = RebornSandboxUserKey::from_scope(&user_scope).workspace_path(temp.path());
    std::fs::create_dir_all(&workspace).unwrap();
    let port = sandbox_transport::connect_for_test(&workspace, &image)
        .await
        .expect("sandbox transport connects");

    port.run_command(request(user_scope.clone(), "true"))
        .await
        .expect("first command creates the container");
    let container_id = find_labeled_container(&docker, "restart-tenant", "restart-user")
        .await
        .expect("container exists after first command");
    assert_container_stopped(&docker, &container_id).await;

    let output = port
        .run_command(request(user_scope, "echo alive"))
        .await
        .expect("command against a transparently restarted container succeeds");
    assert!(output.output.contains("alive"));

    let reused_id = find_labeled_container(&docker, "restart-tenant", "restart-user")
        .await
        .expect("container still exists");
    assert_eq!(
        reused_id, container_id,
        "restart must reuse the same container, not recreate one"
    );

    best_effort_remove(&docker, &container_id).await;
}

#[tokio::test]
async fn timeout_kills_process_group_but_container_survives() {
    let image = skip_unless_docker_ready!("timeout_kills_process_group_but_container_survives");

    let docker = Docker::connect_with_local_defaults().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let user_scope = scope("timeout-tenant", "timeout-user");
    let workspace = RebornSandboxUserKey::from_scope(&user_scope).workspace_path(temp.path());
    std::fs::create_dir_all(&workspace).unwrap();
    let port = sandbox_transport::connect_for_test(&workspace, &image)
        .await
        .expect("sandbox transport connects");

    let mut timeout_request = request(user_scope.clone(), "sleep 100");
    timeout_request.timeout_secs = Some(1);
    let timed_out = port.run_command(timeout_request).await;
    assert!(
        matches!(timed_out, Err(RuntimeProcessError::Timeout(_))),
        "long-running command must time out: {timed_out:?}"
    );

    let still_alive = port
        .run_command(request(user_scope, "echo alive"))
        .await
        .expect("the container itself must survive a timeout kill of the exec'd process group");
    assert!(still_alive.output.contains("alive"));

    if let Some(container_id) =
        find_labeled_container(&docker, "timeout-tenant", "timeout-user").await
    {
        best_effort_remove(&docker, &container_id).await;
    }
}

/// Proves the timeout path leaves no process running: PR1 stops the entire
/// user container after every foreground result, including timeout errors,
/// then transparently restarts the same retained container on the next call.
#[tokio::test]
async fn timed_out_process_is_actually_killed_and_container_survives() {
    let image =
        skip_unless_docker_ready!("timed_out_process_is_actually_killed_and_container_survives");

    let docker = Docker::connect_with_local_defaults().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let user_scope = scope("timeout-kill-tenant", "timeout-kill-user");
    let workspace = RebornSandboxUserKey::from_scope(&user_scope).workspace_path(temp.path());
    std::fs::create_dir_all(&workspace).unwrap();
    let port = sandbox_transport::connect_for_test(&workspace, &image)
        .await
        .expect("sandbox transport connects");

    let mut timeout_request = request(user_scope.clone(), "sleep 8171");
    timeout_request.timeout_secs = Some(1);
    let timed_out = port.run_command(timeout_request).await;
    assert!(
        matches!(timed_out, Err(RuntimeProcessError::Timeout(_))),
        "long-running command must time out: {timed_out:?}"
    );

    let container_id = find_labeled_container(&docker, "timeout-kill-tenant", "timeout-kill-user")
        .await
        .expect("container exists after the timed-out command");
    assert_container_stopped(&docker, &container_id).await;

    // The container itself must still be usable.
    let still_alive = port
        .run_command(request(user_scope, "echo alive"))
        .await
        .expect("the container itself must survive a timeout kill of the exec'd process group");
    assert!(still_alive.output.contains("alive"));
    assert_container_stopped(&docker, &container_id).await;

    best_effort_remove(&docker, &container_id).await;
}

#[tokio::test]
async fn cross_user_containers_and_workspaces_are_isolated() {
    let image = skip_unless_docker_ready!("cross_user_containers_and_workspaces_are_isolated");

    let docker = Docker::connect_with_local_defaults().unwrap();
    let temp = tempfile::tempdir().unwrap();

    let scope_a = scope("isolation-tenant", "isolation-user-a");
    let scope_b = scope("isolation-tenant", "isolation-user-b");
    let workspace_a = RebornSandboxUserKey::from_scope(&scope_a).workspace_path(temp.path());
    let workspace_b = RebornSandboxUserKey::from_scope(&scope_b).workspace_path(temp.path());
    let config = RebornSandboxConfig::new(temp.path().to_path_buf()).with_image(image);
    let port = RebornScopedSandboxCommandTransport::connect(config)
        .await
        .expect("shared-root sandbox transport connects")
        .into_process_port();

    port.run_command(request(
        scope_a,
        "echo user-a-secret > /workspace/user-a-only.txt",
    ))
    .await
    .unwrap();

    let leak_check = port
        .run_command(request(
            scope_b,
            "cat /workspace/user-a-only.txt 2>&1 || echo NOT_FOUND",
        ))
        .await
        .unwrap();
    assert!(
        leak_check.output.contains("NOT_FOUND"),
        "user B's container must not see user A's workspace file: {leak_check:?}"
    );

    let container_a = find_labeled_container(&docker, "isolation-tenant", "isolation-user-a")
        .await
        .expect("container A exists");
    let container_b = find_labeled_container(&docker, "isolation-tenant", "isolation-user-b")
        .await
        .expect("container B exists");
    assert_ne!(
        container_a, container_b,
        "distinct users must get distinct containers"
    );

    // The design's hard invariant: user B's workspace host path must not
    // appear ANYWHERE in user A's container mount table, and vice versa — a
    // bind-mount-source leak would be a full sandbox escape.
    let inspected_a = docker
        .inspect_container(&container_a, None::<InspectContainerOptions>)
        .await
        .unwrap();
    let binds_a = inspected_a.host_config.unwrap().binds.unwrap_or_default();
    let workspace_b_str = workspace_b.to_string_lossy().to_string();
    assert!(
        binds_a.iter().all(|bind| !bind.contains(&workspace_b_str)),
        "user B's workspace path must not appear in user A's mount table: {binds_a:?}"
    );

    let inspected_b = docker
        .inspect_container(&container_b, None::<InspectContainerOptions>)
        .await
        .unwrap();
    let binds_b = inspected_b.host_config.unwrap().binds.unwrap_or_default();
    let workspace_a_str = workspace_a.to_string_lossy().to_string();
    assert!(
        binds_b.iter().all(|bind| !bind.contains(&workspace_a_str)),
        "user A's workspace path must not appear in user B's mount table: {binds_b:?}"
    );

    best_effort_remove(&docker, &container_a).await;
    best_effort_remove(&docker, &container_b).await;
}

#[tokio::test]
async fn worker_image_provides_python_under_non_root_workspace_home() {
    let image =
        skip_unless_docker_ready!("worker_image_provides_python_under_non_root_workspace_home");

    let docker = Docker::connect_with_local_defaults().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let user_scope = scope("fat-image-tenant", "fat-image-user");
    let workspace = RebornSandboxUserKey::from_scope(&user_scope).workspace_path(temp.path());
    std::fs::create_dir_all(&workspace).unwrap();
    let port = sandbox_transport::connect_for_test(&workspace, &image)
        .await
        .expect("sandbox transport connects");

    let mut probe_request = request(
        user_scope,
        "command -v python3 && python3 -c 'print(\"python-ok\")' && whoami && echo $HOME",
    );
    probe_request.timeout_secs = Some(20);
    let probe = port
        .run_command(probe_request)
        .await
        .expect("probe command succeeds");

    assert!(
        probe.output.contains("/python3"),
        "expected Python on PATH: {probe:?}"
    );
    assert!(
        probe.output.contains("python-ok"),
        "Python must execute: {probe:?}"
    );
    assert!(
        probe.output.contains("sandbox"),
        "must run as the non-root sandbox user: {probe:?}"
    );
    assert!(
        !probe.output.contains("\nroot\n"),
        "must not run as root: {probe:?}"
    );
    assert!(
        probe.output.contains("/workspace/.home"),
        "HOME must be workspace-relative: {probe:?}"
    );

    if let Some(container_id) =
        find_labeled_container(&docker, "fat-image-tenant", "fat-image-user").await
    {
        best_effort_remove(&docker, &container_id).await;
    }
}

/// Every command dispatched into the sandbox must run as the unprivileged
/// `sandbox` user (uid 1000), never root — `exec_in_container`'s
/// `CreateExecOptions` used to omit `user` entirely, so `docker exec`
/// defaulted to the container's own configured user, which for this
/// persistent container is root (the image ENTRYPOINT itself needs root to
/// `capsh --drop=all --user=sandbox` before handing off; see
/// `user_container_launch_config`). This asserts the exec identity directly
/// via `id -u`/`id -g`, independent of the broader
/// `worker_image_provides_python_under_non_root_workspace_home`
/// probe above.
#[tokio::test]
async fn dispatched_command_runs_as_the_non_root_sandbox_user() {
    let image = skip_unless_docker_ready!("dispatched_command_runs_as_the_non_root_sandbox_user");

    let docker = Docker::connect_with_local_defaults().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let user_scope = scope("exec-identity-tenant", "exec-identity-user");
    let workspace = RebornSandboxUserKey::from_scope(&user_scope).workspace_path(temp.path());
    std::fs::create_dir_all(&workspace).unwrap();
    let port = sandbox_transport::connect_for_test(&workspace, &image)
        .await
        .expect("sandbox transport connects");

    let identity = port
        .run_command(request(user_scope, "id -u; id -g; whoami"))
        .await
        .expect("identity probe command succeeds");
    assert!(
        identity.output.contains("1000"),
        "dispatched command must run as uid/gid 1000 (sandbox), not root: {identity:?}"
    );
    assert!(
        !identity.output.contains("\n0\n") && !identity.output.starts_with("0\n"),
        "dispatched command must not report uid/gid 0: {identity:?}"
    );
    assert!(
        identity.output.contains("sandbox"),
        "whoami must report the sandbox user: {identity:?}"
    );

    if let Some(container_id) =
        find_labeled_container(&docker, "exec-identity-tenant", "exec-identity-user").await
    {
        best_effort_remove(&docker, &container_id).await;
    }
}

/// PR1 exposes foreground execution only. Pin that local Docker matches the
/// Railway provider and rejects background requests before provisioning a
/// user container.
#[tokio::test]
async fn background_command_is_rejected_before_container_creation() {
    let image =
        skip_unless_docker_ready!("background_command_is_rejected_before_container_creation");

    let docker = Docker::connect_with_local_defaults().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let user_scope = scope("background-tenant", "background-user");
    let workspace = RebornSandboxUserKey::from_scope(&user_scope).workspace_path(temp.path());
    std::fs::create_dir_all(&workspace).unwrap();
    let port = sandbox_transport::connect_for_test(&workspace, &image)
        .await
        .expect("sandbox transport connects");

    let result = port
        .run_command(background_request(user_scope, "echo must-not-run"))
        .await;
    assert!(
        matches!(
            result,
            Err(RuntimeProcessError::ExecutionFailed(ref reason))
                if reason.contains("does not support background commands")
        ),
        "background request must fail closed: {result:?}"
    );
    assert!(
        find_labeled_container(&docker, "background-tenant", "background-user")
            .await
            .is_none(),
        "rejected background request must not provision a container"
    );
}

/// A foreground command can detach internally without setting the API's
/// `background` bit. Stopping the whole container after the result is the
/// provider-independent boundary that prevents such a process from surviving.
#[tokio::test]
async fn internally_detached_process_cannot_survive_foreground_completion() {
    let image = skip_unless_docker_ready!(
        "internally_detached_process_cannot_survive_foreground_completion"
    );

    let docker = Docker::connect_with_local_defaults().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let user_scope = scope("detached-tenant", "detached-user");
    let workspace = RebornSandboxUserKey::from_scope(&user_scope).workspace_path(temp.path());
    std::fs::create_dir_all(&workspace).unwrap();
    let port = sandbox_transport::connect_for_test(&workspace, &image)
        .await
        .expect("sandbox transport connects");

    let detached = port
        .run_command(request(
            user_scope.clone(),
            "python -c 'import subprocess; subprocess.Popen([\"python\", \"-c\", \"import time; time.sleep(300)\"], start_new_session=True); print(\"detached\")'",
        ))
        .await
        .expect("foreground launcher completes");
    assert!(detached.output.contains("detached"));

    let container_id = find_labeled_container(&docker, "detached-tenant", "detached-user")
        .await
        .expect("retained user container exists");
    assert_container_stopped(&docker, &container_id).await;

    let restarted = port
        .run_command(request(user_scope, "python -c 'print(\"restarted\")'"))
        .await
        .expect("same retained container restarts for the next foreground call");
    assert!(restarted.output.contains("restarted"));
    let reused_id = find_labeled_container(&docker, "detached-tenant", "detached-user")
        .await
        .expect("retained user container still exists");
    assert_eq!(reused_id, container_id);
    assert_container_stopped(&docker, &container_id).await;

    best_effort_remove(&docker, &container_id).await;
}
