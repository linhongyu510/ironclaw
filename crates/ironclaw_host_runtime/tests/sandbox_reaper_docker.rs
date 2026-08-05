//! Real-Docker tests for [`ironclaw_host_runtime::SandboxReaper`]'s two-stage
//! per-user lifecycle.
//!
//! `sandbox_process/reaper.rs`'s no-Docker unit tests already pin the pure
//! stage-decision logic (`decide_reap_action` on a fake clock: idle→stop,
//! retention→remove, forced-recycle by age, and "never reap on uncertainty").
//! These tests prove the Docker-facing half: that a reaper pointed at a real
//! daemon actually stops a container it decides to stop, actually removes one
//! it decides to remove, and actually leaves alone one it decides to keep.
//!
//! The first three cases hand the reaper an *empty* activity registry (every
//! container reads back `idle == None`) and drive all three [`ReapAction`]s
//! using the wall-clock
//! `ironclaw.created_at` label — a container whose label places its age past
//! `forced_recycle_after` is stopped (if running) or removed (if stopped),
//! while a young running container survives. The fourth case pushes real
//! activity and exercises idle-stop plus the host-side Docker `top` veto
//! against the daemon's actual response shape.
//!
//! Requires a reachable Docker daemon AND a locally-built `ironclaw-worker`
//! image, same gate as `sandbox_cross_tenant_escape.rs`. Neither is available
//! on this development machine — the tests are authored to run for real in
//! CI/hosted Docker lanes and skip cleanly (a visible `SKIP: ...` line, never
//! a silent pass) everywhere else.

#[path = "support/docker_gate.rs"]
mod docker_gate;

use std::{collections::HashMap, sync::Arc, time::Duration};

use bollard::{
    Docker,
    container::{
        Config, CreateContainerOptions, InspectContainerOptions, RemoveContainerOptions,
        StartContainerOptions, TopOptions,
    },
    exec::{CreateExecOptions, StartExecOptions, StartExecResults},
    models::{ContainerTopResponse, HostConfig},
};
use chrono::Utc;
use ironclaw_host_api::ids::{TenantId, UserId};
use ironclaw_host_runtime::{
    RebornSandboxUserKey, SandboxActivityRegistry, SandboxReaper, SandboxReaperConfig,
};

// The persistent-container identity labels the production launch config
// attaches (see `sandbox_process/registry.rs`). Written as literals here
// because those helper fns are `pub(crate)` and unreachable from an
// integration test — the reaper's real listing filter keys on
// `ironclaw.created_at`, and it rebuilds the per-user key from
// `ironclaw.tenant`/`ironclaw.user`.
const LABEL_TENANT: &str = "ironclaw.tenant";
const LABEL_USER: &str = "ironclaw.user";
const LABEL_CREATED_AT: &str = "ironclaw.created_at";

fn user_labels(created_at: chrono::DateTime<Utc>) -> HashMap<String, String> {
    user_labels_for("reaper-docker-user", created_at)
}

fn user_labels_for(user: &str, created_at: chrono::DateTime<Utc>) -> HashMap<String, String> {
    let tenant = TenantId::new("reaper-docker-tenant").unwrap();
    let user = UserId::new(user).unwrap();
    HashMap::from([
        (LABEL_TENANT.to_string(), tenant.as_str().to_string()),
        (LABEL_USER.to_string(), user.as_str().to_string()),
        (LABEL_CREATED_AT.to_string(), created_at.to_rfc3339()),
    ])
}

fn reaper_user_key(user: &str) -> RebornSandboxUserKey {
    RebornSandboxUserKey::from_tenant_user(
        &TenantId::new("reaper-docker-tenant").expect("valid tenant"),
        &UserId::new(user).expect("valid user"),
    )
}

/// A test config whose `forced_recycle_after` is short enough that a
/// container carrying a `created_at` label a couple of minutes in the past is
/// past the recycle age, without any real waiting. `idle_stop_after` and
/// `remove_stopped_after` are left large so the *only* trigger these tests
/// exercise is age-based forced recycle (the one axis an integration test can
/// drive without touching the crate-private activity registry).
fn forced_recycle_config() -> SandboxReaperConfig {
    SandboxReaperConfig {
        scan_interval: Duration::from_secs(300),
        idle_stop_after: Duration::from_secs(900),
        remove_stopped_after: Duration::from_secs(7 * 24 * 3600),
        forced_recycle_after: Duration::from_secs(60),
        label_prefix: "ironclaw".to_string(),
    }
}

/// Starts a long-running labeled container (bypassing the command transport,
/// which blocks until its command exits — these tests need a container that is
/// still *running* when the reaper scans it).
async fn start_running_container(
    docker: &Docker,
    image: &str,
    labels: HashMap<String, String>,
) -> String {
    let container_id = create_labeled_container_with_args(
        docker,
        image,
        labels,
        vec!["sleep".to_string(), "300".to_string()],
    )
    .await;
    docker
        .start_container(&container_id, None::<StartContainerOptions<String>>)
        .await
        .expect("container start should succeed against a reachable daemon");
    container_id
}

/// Creates, starts, and waits for a labeled container to exit, leaving it in
/// the `exited` state with a real `finished_at` — the shape the reaper's
/// remove branch requires (a stopped container with a known stop time).
async fn start_then_exit_container(
    docker: &Docker,
    image: &str,
    labels: HashMap<String, String>,
) -> String {
    let container_id = create_labeled_container(docker, image, labels, "exit 0").await;
    docker
        .start_container(&container_id, None::<StartContainerOptions<String>>)
        .await
        .expect("container start should succeed against a reachable daemon");
    for _ in 0..50 {
        if !container_running(docker, &container_id).await {
            return container_id;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("container did not reach the exited state within the poll window");
}

async fn create_labeled_container(
    docker: &Docker,
    image: &str,
    labels: HashMap<String, String>,
    command: &str,
) -> String {
    create_labeled_container_with_args(
        docker,
        image,
        labels,
        vec!["sh".to_string(), "-c".to_string(), command.to_string()],
    )
    .await
}

async fn create_labeled_container_with_args(
    docker: &Docker,
    image: &str,
    labels: HashMap<String, String>,
    command: Vec<String>,
) -> String {
    let name = format!("ironclaw-reaper-docker-test-{}", uuid::Uuid::new_v4());
    let config = Config {
        image: Some(image.to_string()),
        cmd: Some(command),
        labels: Some(labels),
        host_config: Some(HostConfig {
            auto_remove: Some(false),
            network_mode: Some("none".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    docker
        .create_container(
            Some(CreateContainerOptions {
                name,
                platform: None,
            }),
            config,
        )
        .await
        .expect("container create should succeed against a reachable daemon")
        .id
}

async fn container_exists(docker: &Docker, container_id: &str) -> bool {
    docker
        .inspect_container(container_id, None::<InspectContainerOptions>)
        .await
        .is_ok()
}

async fn container_running(docker: &Docker, container_id: &str) -> bool {
    docker
        .inspect_container(container_id, None::<InspectContainerOptions>)
        .await
        .ok()
        .and_then(|c| c.state.and_then(|s| s.running))
        .unwrap_or(false)
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

fn valid_pid_row_count(observation: &ContainerTopResponse) -> Option<usize> {
    let titles = observation.titles.as_ref()?;
    let processes = observation.processes.as_ref()?;
    let mut pid_columns = titles
        .iter()
        .enumerate()
        .filter(|(_, title)| title.trim().eq_ignore_ascii_case("PID"));
    let (pid_column, _) = pid_columns.next()?;
    if pid_columns.next().is_some() || processes.is_empty() {
        return None;
    }
    for process in processes {
        if process.len() != titles.len()
            || process
                .get(pid_column)
                .and_then(|pid| pid.trim().parse::<u64>().ok())
                .is_none_or(|pid| pid == 0)
        {
            return None;
        }
    }
    Some(processes.len())
}

async fn wait_for_top_process_count(
    docker: &Docker,
    container_id: &str,
    expected: impl Fn(usize) -> bool,
) -> ContainerTopResponse {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut poll = tokio::time::interval(Duration::from_millis(25));
        loop {
            poll.tick().await;
            if let Ok(observation) = docker
                .top_processes(container_id, Some(TopOptions { ps_args: "-eo pid" }))
                .await
                && valid_pid_row_count(&observation).is_some_and(&expected)
            {
                return observation;
            }
        }
    })
    .await
    .expect("Docker top response did not reach the expected process count")
}

async fn start_background_sleep(docker: &Docker, container_id: &str) {
    let exec = docker
        .create_exec(
            container_id,
            CreateExecOptions {
                cmd: Some(vec!["sleep".to_string(), "300".to_string()]),
                attach_stdout: Some(false),
                attach_stderr: Some(false),
                ..Default::default()
            },
        )
        .await
        .expect("background exec creation should succeed");
    let started = docker
        .start_exec(
            &exec.id,
            Some(StartExecOptions {
                detach: true,
                ..Default::default()
            }),
        )
        .await
        .expect("background exec start should succeed");
    assert!(matches!(started, StartExecResults::Detached));
}

#[tokio::test]
async fn idle_stop_does_not_preserve_a_detached_process() {
    if !docker_gate::docker_available() {
        eprintln!(
            "SKIP: no docker daemon reachable — idle_stop_does_not_preserve_a_detached_process requires a real Docker daemon"
        );
        return;
    }
    let image = docker_gate::configured_sandbox_image();
    if !docker_gate::docker_image_available(&image) {
        eprintln!(
            "SKIP: sandbox worker image {image:?} is not built locally — idle_stop_does_not_preserve_a_detached_process requires the worker image"
        );
        return;
    }

    let docker = Docker::connect_with_local_defaults().expect("Docker client should connect");
    let activity = Arc::new(SandboxActivityRegistry::new());
    let config = SandboxReaperConfig {
        idle_stop_after: Duration::ZERO,
        forced_recycle_after: Duration::from_secs(24 * 3600),
        ..forced_recycle_config()
    };
    let reaper = SandboxReaper::new(docker.clone(), Arc::clone(&activity), config);
    let user = format!("top-shape-{}", uuid::Uuid::new_v4());
    let key = reaper_user_key(&user);

    let init_only =
        start_running_container(&docker, &image, user_labels_for(&user, Utc::now())).await;
    let init_observation =
        wait_for_top_process_count(&docker, &init_only, |count| count == 2).await;
    assert_eq!(valid_pid_row_count(&init_observation), Some(2));
    activity.touch(&key);
    reaper
        .scan_and_reap()
        .await
        .expect("init-only reaper scan should succeed");
    assert!(
        !container_running(&docker, &init_only).await,
        "the worker's two-process init chain must permit idle stop"
    );
    best_effort_remove(&docker, &init_only).await;

    let with_background =
        start_running_container(&docker, &image, user_labels_for(&user, Utc::now())).await;
    wait_for_top_process_count(&docker, &with_background, |count| count == 2).await;
    start_background_sleep(&docker, &with_background).await;
    let live_observation =
        wait_for_top_process_count(&docker, &with_background, |count| count > 2).await;
    assert!(valid_pid_row_count(&live_observation).is_some_and(|count| count > 2));
    activity.touch(&key);
    reaper
        .scan_and_reap()
        .await
        .expect("background-process reaper scan should succeed");
    let background_survived = container_running(&docker, &with_background).await;
    best_effort_remove(&docker, &with_background).await;
    assert!(
        !background_survived,
        "PR1 foreground-only lifecycle must not let a detached process veto idle stop"
    );
}

#[tokio::test]
async fn young_running_container_survives_scan() {
    if !docker_gate::docker_available() {
        eprintln!(
            "SKIP: no docker daemon reachable — young_running_container_survives_scan requires a real Docker daemon (CI/hosted Docker lane only)"
        );
        return;
    }
    let image = docker_gate::configured_sandbox_image();
    if !docker_gate::docker_image_available(&image) {
        eprintln!(
            "SKIP: sandbox worker image {image:?} is not built locally — young_running_container_survives_scan requires a locally-built ironclaw-worker image (CI/hosted Docker lane only)"
        );
        return;
    }

    let docker = Docker::connect_with_local_defaults().unwrap();
    // Freshly created: not past forced-recycle age, and the empty activity
    // registry reports `idle == None` — "never reap on uncertainty" keeps it.
    let labels = user_labels(Utc::now());
    let container_id = start_running_container(&docker, &image, labels).await;

    let reaper = SandboxReaper::new(
        docker.clone(),
        Arc::new(SandboxActivityRegistry::new()),
        forced_recycle_config(),
    );
    reaper
        .scan_and_reap()
        .await
        .expect("scan against a reachable daemon should succeed");

    let survived = container_exists(&docker, &container_id).await;
    best_effort_remove(&docker, &container_id).await;
    assert!(
        survived,
        "a young running container with no idle record must survive the scan"
    );
}

#[tokio::test]
async fn running_container_past_forced_recycle_age_is_stopped_not_removed() {
    if !docker_gate::docker_available() {
        eprintln!(
            "SKIP: no docker daemon reachable — running_container_past_forced_recycle_age_is_stopped_not_removed requires a real Docker daemon (CI/hosted Docker lane only)"
        );
        return;
    }
    let image = docker_gate::configured_sandbox_image();
    if !docker_gate::docker_image_available(&image) {
        eprintln!(
            "SKIP: sandbox worker image {image:?} is not built locally — running_container_past_forced_recycle_age_is_stopped_not_removed requires a locally-built ironclaw-worker image (CI/hosted Docker lane only)"
        );
        return;
    }

    let docker = Docker::connect_with_local_defaults().unwrap();
    // Age (via the created_at label) is past forced_recycle_after while the
    // container is still running: forced recycle stops it first (stop, not
    // remove — the user's workspace bind mount is preserved for restart).
    let labels = user_labels(Utc::now() - chrono::Duration::seconds(120));
    let container_id = start_running_container(&docker, &image, labels).await;

    let reaper = SandboxReaper::new(
        docker.clone(),
        Arc::new(SandboxActivityRegistry::new()),
        forced_recycle_config(),
    );
    reaper
        .scan_and_reap()
        .await
        .expect("scan against a reachable daemon should succeed");

    let still_exists = container_exists(&docker, &container_id).await;
    let still_running = container_running(&docker, &container_id).await;
    best_effort_remove(&docker, &container_id).await;
    assert!(
        still_exists,
        "a running container past forced-recycle age must be stopped, not removed"
    );
    assert!(
        !still_running,
        "a running container past forced-recycle age must be stopped"
    );
}

#[tokio::test]
async fn stopped_container_past_forced_recycle_age_is_removed() {
    if !docker_gate::docker_available() {
        eprintln!(
            "SKIP: no docker daemon reachable — stopped_container_past_forced_recycle_age_is_removed requires a real Docker daemon (CI/hosted Docker lane only)"
        );
        return;
    }
    let image = docker_gate::configured_sandbox_image();
    if !docker_gate::docker_image_available(&image) {
        eprintln!(
            "SKIP: sandbox worker image {image:?} is not built locally — stopped_container_past_forced_recycle_age_is_removed requires a locally-built ironclaw-worker image (CI/hosted Docker lane only)"
        );
        return;
    }

    let docker = Docker::connect_with_local_defaults().unwrap();
    // Already stopped (known finished_at) and past forced-recycle age: removed
    // outright even though it is still within the normal retention window —
    // but only once the same container has produced a Remove verdict on two
    // consecutive scans (the removal debounce).
    let labels = user_labels(Utc::now() - chrono::Duration::seconds(120));
    let container_id = start_then_exit_container(&docker, &image, labels).await;

    let reaper = SandboxReaper::new(
        docker.clone(),
        Arc::new(SandboxActivityRegistry::new()),
        forced_recycle_config(),
    );
    reaper
        .scan_and_reap()
        .await
        .expect("first scan against a reachable daemon should succeed");

    let survived_first_scan = container_exists(&docker, &container_id).await;
    assert!(
        survived_first_scan,
        "the first Remove verdict must only mark the container pending, not remove it"
    );

    reaper
        .scan_and_reap()
        .await
        .expect("second scan against a reachable daemon should succeed");

    let survived = container_exists(&docker, &container_id).await;
    if survived {
        best_effort_remove(&docker, &container_id).await;
    }
    assert!(
        !survived,
        "a stopped container past forced-recycle age must be removed on the second \
         consecutive Remove verdict"
    );
}
