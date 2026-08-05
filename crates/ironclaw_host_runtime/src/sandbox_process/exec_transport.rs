//! Exec-based lifecycle for the persistent per-user sandbox container.
//!
//! Replaces the ephemeral per-command create/run/remove model entirely —
//! there is no fallback path, per the design's "Relation to ephemeral
//! model: Replace" decision. [`ensure_container`] reuses (or transparently
//! restarts) the one container that already exists for a `{tenant, user}`
//! pair, keyed by the Docker labels [`super::registry`] attaches; every
//! individual shell command then runs as a fresh `docker exec` via
//! [`exec_in_container`] rather than a fresh container.

use std::{
    net::IpAddr,
    path::Path,
    time::{Duration, Instant},
};

use bollard::{
    Docker,
    container::{
        Config, CreateContainerOptions, InspectContainerOptions, ListContainersOptions, LogOutput,
        RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
    },
    errors::Error as DockerError,
    exec::{CreateExecOptions, StartExecOptions, StartExecResults},
    models::{HostConfig, Ipam, IpamConfig},
    network::{CreateNetworkOptions, InspectNetworkOptions},
};
use futures_util::StreamExt;
use ironclaw_common::hashing::sha256_hex;
use ironclaw_host_api::ids::{TenantId, UserId};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{CommandExecutionOutput, RuntimeProcessError};

use super::{
    ContainerWorkdir, LABEL_PREFIX, RebornSandboxConfig, RebornSandboxUserKey,
    attribution::{self, ConnectionAttributionResolver},
    broker::{
        SANDBOX_EGRESS_NETWORK_GATEWAY, SANDBOX_EGRESS_NETWORK_NAME, SANDBOX_EGRESS_NETWORK_SUBNET,
    },
    mounts,
    registry::{self, build_user_container_labels, user_container_label_filter},
    shell_single_quote,
};

#[cfg(test)]
use super::worker_spec::DOCKER_WORKER_PIDS_LIMIT as SANDBOX_PIDS_LIMIT;

/// Finds the one container already labeled for `{tenant_id, user_id}` and
/// makes sure it is running (creating or restarting it as needed), or
/// creates a fresh one if none exists yet. Returns the container ID a
/// subsequent [`exec_in_container`] call can target.
///
/// `attribution`: when `Some`, wired so a posture-mismatch recycle below
/// invalidates the egress-proxy attribution cache for the IP the recycled
/// container releases (see `attribution`'s module doc, "W17"). `None` — the
/// only value any current production caller passes, since nothing
/// constructs a resolver yet (W6 is its consumer) — makes this a no-op,
/// same as before this parameter existed.
pub(super) struct EnsureContainerRequest<'a> {
    pub config: &'a RebornSandboxConfig,
    pub key: &'a RebornSandboxUserKey,
    pub tenant_id: &'a TenantId,
    pub user_id: &'a UserId,
    pub workspace: &'a Path,
    pub network_ready: &'a tokio::sync::OnceCell<()>,
    pub attribution: Option<&'a ConnectionAttributionResolver>,
}

pub(super) async fn ensure_container(
    docker: &Docker,
    request: EnsureContainerRequest<'_>,
) -> Result<String, RuntimeProcessError> {
    let EnsureContainerRequest {
        config,
        key,
        tenant_id,
        user_id,
        workspace,
        network_ready,
        attribution,
    } = request;
    ensure_egress_network_once(docker, config, network_ready).await?;
    let filters = user_container_label_filter(LABEL_PREFIX, tenant_id, user_id);
    let found = docker
        .list_containers(Some(ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        }))
        .await
        .map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!(
                "sandbox container lookup failed: {error}"
            ))
        })?;

    match found.as_slice() {
        [] => {
            create_and_start_user_container(docker, config, key, tenant_id, user_id, workspace)
                .await
        }
        [existing] => {
            let container_id = existing.id.clone().ok_or_else(|| {
                RuntimeProcessError::ExecutionFailed(
                    "sandbox container lookup returned an unnamed container".to_string(),
                )
            })?;
            let existing_stamp = existing
                .labels
                .as_ref()
                .and_then(|labels| labels.get(&registry::label_security_posture(LABEL_PREFIX)))
                .map(String::as_str);
            let expected_stamp = security_posture_stamp(&security_posture_fields(config));
            if existing_stamp != Some(expected_stamp.as_str()) {
                // Read the IP this container holds *before* removing it —
                // once it's gone `docker inspect`/`docker ps` can no longer
                // tell us, and that IP is exactly what a torn-down
                // container's stale attribution-cache entry is keyed on.
                let released_ip =
                    attribution::container_ip_on_network(existing, SANDBOX_EGRESS_NETWORK_NAME);
                recycle_stale_container(docker, &container_id, released_ip, attribution).await?;
                return create_and_start_user_container(
                    docker, config, key, tenant_id, user_id, workspace,
                )
                .await;
            }
            ensure_running(docker, &container_id).await?;
            Ok(container_id)
        }
        multiple => Err(RuntimeProcessError::ExecutionFailed(format!(
            "sandbox container registry has {} containers for one user; expected at most one",
            multiple.len()
        ))),
    }
}

/// Destroys a container whose stamped security posture
/// ([`registry::label_security_posture`]) no longer matches what
/// [`security_posture_fields`] says this code would create today — e.g. an
/// older deployment's container still has PID 1 running as root, from
/// before W1's non-root-init fix. This is the container-side analogue of
/// [`verify_existing_egress_network_posture`], but deliberately does the
/// opposite thing on mismatch: that function fails closed because other
/// containers may already be attached to the shared network, so pulling it
/// out from under them is worse than a loud failure. A per-user sandbox
/// container has no such peers — it is disposable, and recreating it is
/// already the normal healthy path (every fresh sandbox starts this way),
/// so silently recycling it here is strictly safer than reusing a
/// stale-posture container for up to the reaper's 7-day forced-recycle
/// window.
///
/// `released_ip`/`attribution`: the IP the removed container held on the
/// egress network (if any) and a wired attribution-cache handle (if any) —
/// once the container is gone, that IP is free for Docker to hand to a
/// *different* user's container, so this collapses the attribution cache's
/// staleness window to zero for it rather than leaving a stale entry to
/// serve the previous owner until the TTL expires (see `attribution`'s
/// module doc, "W17"). A no-op when either is `None`.
async fn recycle_stale_container(
    docker: &Docker,
    container_id: &str,
    released_ip: Option<IpAddr>,
    attribution: Option<&ConnectionAttributionResolver>,
) -> Result<(), RuntimeProcessError> {
    docker
        .remove_container(
            container_id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await
        .map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!(
                "stale-security-posture sandbox container removal failed: {error}"
            ))
        })?;
    if let (Some(attribution), Some(ip)) = (attribution, released_ip) {
        attribution.invalidate(ip);
    }
    Ok(())
}

async fn ensure_running(docker: &Docker, container_id: &str) -> Result<(), RuntimeProcessError> {
    let inspected = docker
        .inspect_container(container_id, None::<InspectContainerOptions>)
        .await
        .map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!(
                "sandbox container inspect failed: {error}"
            ))
        })?;
    let running = inspected
        .state
        .as_ref()
        .and_then(|state| state.running)
        .unwrap_or(false);
    if !running {
        docker
            .start_container(container_id, None::<StartContainerOptions<String>>)
            .await
            .map_err(|error| {
                RuntimeProcessError::ExecutionFailed(format!(
                    "sandbox container restart failed: {error}"
                ))
            })?;
        wait_until_running(docker, container_id).await?;
    }
    Ok(())
}

/// Bound on how long [`wait_until_running`] polls before giving up.
const CONTAINER_RUNNING_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval between [`wait_until_running`] poll attempts.
const CONTAINER_RUNNING_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// `docker.start_container` returns as soon as Docker has *accepted* the
/// start request — it does not wait for the container to actually transition
/// to `State.Running`. An `exec` fired immediately after a bare
/// `start_container` therefore races that transition and can hit a 409
/// "container is not running" even though the start call itself reported
/// success. Poll `inspect_container` until `state.running` flips true (or
/// [`CONTAINER_RUNNING_WAIT_TIMEOUT`] elapses) so both call sites that start
/// a container — [`create_and_start_user_container`] and the restart branch
/// of [`ensure_running`] — hand back a container an immediate `exec` can
/// actually reach.
async fn wait_until_running(
    docker: &Docker,
    container_id: &str,
) -> Result<(), RuntimeProcessError> {
    let deadline = Instant::now() + CONTAINER_RUNNING_WAIT_TIMEOUT;
    loop {
        let inspected = docker
            .inspect_container(container_id, None::<InspectContainerOptions>)
            .await
            .map_err(|error| {
                RuntimeProcessError::ExecutionFailed(format!(
                    "sandbox container inspect failed while waiting for running state: {error}"
                ))
            })?;
        let running = inspected
            .state
            .as_ref()
            .and_then(|state| state.running)
            .unwrap_or(false);
        if running {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(RuntimeProcessError::ExecutionFailed(format!(
                "sandbox container did not reach running state within {CONTAINER_RUNNING_WAIT_TIMEOUT:?}"
            )));
        }
        tokio::time::sleep(CONTAINER_RUNNING_POLL_INTERVAL).await;
    }
}

/// Idempotently creates the pinned internal egress network (E1) before a
/// container that needs it joins. A no-op unless `config` actually resolves
/// to [`SANDBOX_EGRESS_NETWORK_NAME`] (no-net and fully-open-bridge configs
/// never call the Docker network API here).
///
/// Docker network creation is not atomic-on-conflict the way `CREATE TABLE
/// IF NOT EXISTS` is, so a losing racer against a concurrent create (e.g.
/// two users' first sandbox commands landing at once) gets a server error
/// back instead of success — [`is_network_already_exists_error`] treats that
/// as success too, since the end state (the network exists) is what this
/// function promises.
async fn ensure_egress_network(
    docker: &Docker,
    config: &RebornSandboxConfig,
) -> Result<(), RuntimeProcessError> {
    if config.container_network_mode().as_deref() != Some(SANDBOX_EGRESS_NETWORK_NAME) {
        return Ok(());
    }
    ensure_default_egress_network(docker).await
}

/// Creates or verifies the production sandbox egress network without
/// launching a user container. Composition calls this before binding the
/// host-side proxy to the network gateway, so an unsupported Docker topology
/// fails during sandbox-profile boot instead of after the first user's shell
/// command has already started a container.
pub(super) async fn ensure_default_egress_network(
    docker: &Docker,
) -> Result<(), RuntimeProcessError> {
    match docker
        .create_network(sandbox_egress_network_create_options())
        .await
    {
        Ok(_) => Ok(()),
        // "Already exists" only proves *a* network by this name is present,
        // not that it has the isolation posture this function requires — an
        // older deployment's network (created before `enable_icc` was added
        // below, or hand-rolled) would silently leave containers on a
        // lateral-movement-capable network forever, since (unlike
        // containers, which the reaper recycles) nothing ever recreates this
        // network. Verify the existing network's actual options before
        // treating this as success.
        Err(error) if is_network_already_exists_error(&error) => {
            verify_existing_egress_network_posture(docker).await
        }
        Err(error) => Err(RuntimeProcessError::ExecutionFailed(format!(
            "sandbox egress network ensure failed: {error}"
        ))),
    }
}

/// Inspects the already-existing [`SANDBOX_EGRESS_NETWORK_NAME`] network and
/// fails closed if its live options don't match what
/// [`sandbox_egress_network_create_options`] requires — in particular
/// [`SANDBOX_EGRESS_NETWORK_ICC_OPTION_KEY`], the setting that removes the
/// container↔container path a shared-network deployment would otherwise
/// leave open (see this module's `enable_icc` doc comment). Deliberately
/// does not delete or recreate the network on mismatch — other containers
/// may already be attached, and pulling the network out from under a
/// running deployment is worse than a loud, explicit failure.
async fn verify_existing_egress_network_posture(
    docker: &Docker,
) -> Result<(), RuntimeProcessError> {
    let network = docker
        .inspect_network(
            SANDBOX_EGRESS_NETWORK_NAME,
            None::<InspectNetworkOptions<String>>,
        )
        .await
        .map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!(
                "sandbox egress network {SANDBOX_EGRESS_NETWORK_NAME:?} already exists but \
                 could not be inspected to verify its isolation posture: {error}"
            ))
        })?;

    let expected = sandbox_egress_network_create_options();
    let expected_icc = expected
        .options
        .get(SANDBOX_EGRESS_NETWORK_ICC_OPTION_KEY)
        .cloned();
    let actual_internal = network.internal;
    let actual_icc = network
        .options
        .as_ref()
        .and_then(|options| options.get(SANDBOX_EGRESS_NETWORK_ICC_OPTION_KEY))
        .cloned();
    let expected_ipam = expected
        .ipam
        .config
        .as_ref()
        .and_then(|configs| configs.first());
    let actual_ipam = network
        .ipam
        .as_ref()
        .and_then(|ipam| ipam.config.as_ref())
        .and_then(|configs| configs.first());
    let expected_subnet = expected_ipam.and_then(|config| config.subnet.as_deref());
    let expected_gateway = expected_ipam.and_then(|config| config.gateway.as_deref());
    let actual_subnet = actual_ipam.and_then(|config| config.subnet.as_deref());
    let actual_gateway = actual_ipam.and_then(|config| config.gateway.as_deref());
    let actual_driver = network.driver.as_deref();

    if actual_internal == Some(expected.internal)
        && actual_icc == expected_icc
        && actual_driver == Some(expected.driver.as_str())
        && actual_subnet == expected_subnet
        && actual_gateway == expected_gateway
    {
        return Ok(());
    }

    Err(RuntimeProcessError::ExecutionFailed(format!(
        "sandbox egress network {SANDBOX_EGRESS_NETWORK_NAME:?} already exists but its isolation \
         posture does not match what this deployment requires — expected driver={:?}, \
         subnet={:?}, gateway={:?}, internal={:?}, and {}={:?}; found driver={:?}, subnet={:?}, \
         gateway={:?}, internal={:?}, and {}={:?}. Refusing to proceed silently: a mismatched \
         network would break the proxy route, leave container-to-container lateral movement \
         open, or undermine source-IP attribution. Recreate {SANDBOX_EGRESS_NETWORK_NAME:?} \
         manually with the required options (no containers may currently be attached).",
        expected.driver,
        expected_subnet,
        expected_gateway,
        expected.internal,
        SANDBOX_EGRESS_NETWORK_ICC_OPTION_KEY,
        expected_icc,
        actual_driver,
        actual_subnet,
        actual_gateway,
        actual_internal,
        SANDBOX_EGRESS_NETWORK_ICC_OPTION_KEY,
        actual_icc,
    )))
}

/// Gates [`ensure_egress_network`] behind `network_ready` so the (already
/// idempotent, per [`is_network_already_exists_error`]) create attempt only
/// actually rounds-trips to Docker once per process instead of on every
/// [`ensure_container`] call — `ensure_container` runs once per command
/// dispatch, so without this every command after the first pays a wasted
/// create-network round trip that Docker always 409s. `OnceCell` keeps this
/// correct under a race: concurrent callers before the first success share
/// the same in-flight attempt, and a failed attempt leaves the cell
/// uninitialized so the next call retries rather than wedging forever.
async fn ensure_egress_network_once(
    docker: &Docker,
    config: &RebornSandboxConfig,
    network_ready: &tokio::sync::OnceCell<()>,
) -> Result<(), RuntimeProcessError> {
    network_ready
        .get_or_try_init(|| ensure_egress_network(docker, config))
        .await
        .map(|_| ())
}

/// The bridge-driver option key that disables inter-container communication
/// (ICC) on the network — verified empirically (see the doc comment on
/// [`sandbox_egress_network_create_options`]'s `options` field below) to
/// drop container↔container TCP/ICMP on the shared L2 while leaving
/// container↔gateway reachability (the egress proxy path) intact.
const SANDBOX_EGRESS_NETWORK_ICC_OPTION_KEY: &str = "com.docker.network.bridge.enable_icc";

/// Pure builder for the `internal: true`, pinned-subnet network Docker
/// creates for [`SANDBOX_EGRESS_NETWORK_NAME`] — kept as a standalone
/// function so its shape is unit-testable without a Docker daemon (mirrors
/// how [`user_container_launch_config`] separates config assembly from the
/// `docker.create_container` call).
fn sandbox_egress_network_create_options() -> CreateNetworkOptions<String> {
    CreateNetworkOptions {
        name: SANDBOX_EGRESS_NETWORK_NAME.to_string(),
        check_duplicate: true,
        driver: "bridge".to_string(),
        // The load-bearing setting: no default route off-host, so the
        // egress proxy (reached at the pinned gateway, see
        // `SANDBOX_EGRESS_NETWORK_GATEWAY`) is the only way out.
        internal: true,
        ipam: Ipam {
            config: Some(vec![IpamConfig {
                subnet: Some(SANDBOX_EGRESS_NETWORK_SUBNET.to_string()),
                gateway: Some(SANDBOX_EGRESS_NETWORK_GATEWAY.to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        },
        // Every per-user sandbox container shares this ONE network, so
        // `internal: true` alone isn't enough: it removes the default route
        // *off-host*, but says nothing about container-to-container traffic
        // on the shared L2 — user A's container can otherwise reach user
        // B's container directly. Disabling ICC closes that lateral path
        // and is also what makes source-IP attribution at the egress proxy
        // sound (a container that can't reach its neighbors can't intercept
        // or spoof their traffic either). Verified empirically: with this
        // set, container-to-container TCP and ICMP are dropped while
        // container-to-gateway reachability (the proxy path) is preserved.
        options: [(
            SANDBOX_EGRESS_NETWORK_ICC_OPTION_KEY.to_string(),
            "false".to_string(),
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    }
}

/// True when `error` indicates the network already exists (a prior boot, or
/// a concurrent racer, created it first) — the outcome
/// [`ensure_egress_network`] wants, not a failure. Matches on Docker's
/// typical 409-conflict status as well as the "already exists" message
/// text, since different Docker/DinD versions have been observed to surface
/// this either way.
fn is_network_already_exists_error(error: &DockerError) -> bool {
    match error {
        DockerError::DockerResponseServerError {
            status_code,
            message,
        } => *status_code == 409 || message.to_lowercase().contains("already exists"),
        _ => false,
    }
}

async fn create_and_start_user_container(
    docker: &Docker,
    config: &RebornSandboxConfig,
    key: &RebornSandboxUserKey,
    tenant_id: &TenantId,
    user_id: &UserId,
    workspace: &Path,
) -> Result<String, RuntimeProcessError> {
    let launch = user_container_launch_config(config, tenant_id, user_id, workspace).await?;
    let created = docker
        .create_container(
            Some(CreateContainerOptions {
                name: key.container_name(),
                platform: None,
            }),
            launch,
        )
        .await
        .map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!(
                "sandbox container create failed: {error}"
            ))
        })?;
    docker
        .start_container(&created.id, None::<StartContainerOptions<String>>)
        .await
        .map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!("sandbox container start failed: {error}"))
        })?;
    wait_until_running(docker, &created.id).await?;
    Ok(created.id)
}

/// The security-relevant subset of a container's launch configuration —
/// every field whose value determines the container's security posture
/// (as opposed to resource accounting like `memory`/`cpu_shares`, which
/// don't gate what a compromised process inside the container can do).
/// [`security_posture_stamp`] hashes this struct into the label
/// [`ensure_container`] compares against; [`user_container_launch_config`]
/// builds `HostConfig`'s matching fields directly from the same struct, so
/// there is exactly one place that decides what "the current posture" is —
/// the stamp can never silently drift from what a freshly created
/// container actually gets.
///
/// `pids_limit` is part of the stamped posture so containers created before
/// the finite task limit was introduced, or under a different limit, are
/// recycled before they can be reused.
///
/// `ca_bundle_hash` closes RUN-001: the sandbox CA root is regenerated
/// fresh in memory on every host-process start (see `ca.rs`'s module doc),
/// but a persistent container survives that restart untouched. Without a
/// stable identity of the live trust bundle in the stamp, a reused
/// container keeps trusting the OLD CA while the restarted proxy signs
/// with a NEW one, and every intercepted bound-host TLS request inside it
/// then fails certificate verification while both sides report healthy.
/// Hashing `ca_bundle_pem` here — the exact bytes [`mounts::materialize_ca_bundle`]
/// writes into the container's bind-mounted trust bundle — makes a rotated
/// CA force the same recycle-on-create path as any other posture change.
struct SecurityPostureFields {
    user: Option<String>,
    cap_add: Option<Vec<String>>,
    cap_drop: Option<Vec<String>>,
    readonly_rootfs: Option<bool>,
    network_mode: Option<String>,
    pids_limit: Option<i64>,
    ca_bundle_hash: Option<String>,
}

/// The security posture this code creates containers with today, given
/// `config`. Deliberately independent of `tenant_id`/`user_id`/`workspace`:
/// none of the security-relevant fields vary per user, so
/// `ensure_container` can compute "what posture would a fresh container
/// get" synchronously, with no Docker round trip and no async mount
/// preparation, purely to compare against an existing container's stamped
/// label.
fn security_posture_fields(config: &RebornSandboxConfig) -> SecurityPostureFields {
    let worker = super::worker_spec::DockerWorkerSecuritySpec::new(config.container_network_mode());
    SecurityPostureFields {
        // See `user_container_launch_config`'s doc comment: PID 1 is pinned
        // directly to uid 1000 at create time (W1), not via an in-container
        // privilege drop.
        user: Some(worker.user()),
        cap_add: None,
        cap_drop: Some(worker.cap_drop()),
        readonly_rootfs: Some(worker.readonly_rootfs()),
        network_mode: worker.network_mode(),
        pids_limit: Some(worker.pids_limit()),
        // Same helper `materialize_ca_bundle`'s caller already threads
        // through key_codec.rs's usage — reused here rather than adding a
        // second hashing utility to this crate.
        ca_bundle_hash: config
            .ca_bundle_pem
            .as_deref()
            .map(|pem| sha256_hex(pem.as_bytes())),
    }
}

/// Hashes [`SecurityPostureFields`] into a single deterministic value used
/// as a container label — the container-side analogue of the network
/// posture check in [`verify_existing_egress_network_posture`]. Uses SHA-256
/// over an explicit, fixed-order serialization of the fields (never a
/// `HashMap`'s iteration order, and never `std::collections::hash_map::
/// DefaultHasher`, which is an unspecified algorithm not guaranteed stable
/// across Rust versions) so the same posture always stamps identically
/// across process restarts and Rust toolchain upgrades, and a changed
/// field — flip `user`, add a capability, flip `readonly_rootfs` — always
/// changes the stamp.
fn security_posture_stamp(fields: &SecurityPostureFields) -> String {
    let canonical = format!(
        "user={:?}\ncap_add={:?}\ncap_drop={:?}\nreadonly_rootfs={:?}\nnetwork_mode={:?}\npids_limit={:?}\nca_bundle_hash={:?}",
        fields.user,
        fields.cap_add,
        fields.cap_drop,
        fields.readonly_rootfs,
        fields.network_mode,
        fields.pids_limit,
        fields.ca_bundle_hash,
    );
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// The persistent container's own launch `cmd` is a no-op long-lived
/// process (`sleep infinity`) — the container never runs the model's
/// command directly; every command arrives later via `docker exec`.
pub(super) async fn user_container_launch_config(
    config: &RebornSandboxConfig,
    tenant_id: &TenantId,
    user_id: &UserId,
    workspace: &Path,
) -> Result<Config<String>, RuntimeProcessError> {
    let posture = security_posture_fields(config);
    let posture_stamp = security_posture_stamp(&posture);
    let labels = build_user_container_labels(LABEL_PREFIX, tenant_id, user_id, &posture_stamp);
    let mut env = config.command_env(std::collections::HashMap::new())?;
    env.push("HOME=/workspace/.home".to_string());
    // Setting `Config.env`'s PATH replaces the image value. Keep Python's
    // user-install bin directory plus standard system paths; PR1 deliberately
    // ships no Node, Rust, provider-specific CLI, or tmux toolchain.
    env.push(
        "PATH=/workspace/.home/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            .to_string(),
    );
    // Historically `config.container_identity.container_user()` (default
    // `None`, i.e. image default) fed `Config.user` here, and the image's
    // own trailing `USER root` + entrypoint `capsh --drop=all --user=sandbox`
    // dropped to uid 1000 *inside* the container after PID 1 already started
    // as root. That capsh exec is gone (see docker/process-sandbox-
    // entrypoint.sh) and `cap_add` below no longer re-adds
    // SETPCAP/SETUID/SETGID, so nothing in-container can perform that drop
    // any more — `posture.user` (below, and see [`security_posture_fields`])
    // pins PID 1 to uid 1000 directly instead, matching the fixed identity
    // every `docker exec` (`SANDBOX_EXEC_UID`/`GID`) already assumes.
    let mut binds = vec![mounts::workspace_bind(workspace)?.into_docker_bind()];
    if let Some(ca_bundle_pem) = config.ca_bundle_pem.as_deref() {
        let bundle_path =
            mounts::materialize_ca_bundle(&config.workspace_root, ca_bundle_pem).await?;
        binds.push(mounts::ca_bundle_bind(&bundle_path)?.into_docker_bind());
        // OpenSSL-linked clients (`curl`, `git`, most of Python's `ssl`
        // module) read `SSL_CERT_FILE`; `requests`/`pip` read
        // `REQUESTS_CA_BUNDLE`; `curl` also honors `CURL_CA_BUNDLE`
        // specifically; `git`'s own libcurl wrapper reads `GIT_SSL_CAINFO`;
        // Node.js reads `NODE_EXTRA_CA_CERTS` (additive there, unlike the
        // others). Setting all five covers `curl`/`pip`/`npm`/`git` — the
        // tools `Dockerfile.process-sandbox` installs and the sandboxed
        // shell's stated purpose (module doc) targets. NOT covered: JVM
        // (`-Djavax.net.ssl.trustStore`), Go's `net/http` (no env var; reads
        // `SSL_CERT_FILE`/`SSL_CERT_DIR` ONLY via its own cgo/non-cgo system
        // pool resolution, which does honor `SSL_CERT_FILE` on Linux) — Go
        // is therefore covered incidentally, but this list does not
        // guarantee it — and any client with its own bundled trust store
        // (e.g. some Electron/Node native binaries) that ignores
        // `NODE_EXTRA_CA_CERTS`.
        for var in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
            "NODE_EXTRA_CA_CERTS",
        ] {
            env.push(format!("{var}={}", mounts::CONTAINER_CA_BUNDLE_PATH));
        }
    }
    let host_config = HostConfig {
        binds: Some(binds),
        memory: Some(config.memory_bytes as i64),
        cpu_shares: Some(config.cpu_shares as i64),
        auto_remove: Some(false),
        network_mode: posture.network_mode.clone(),
        cap_drop: posture.cap_drop.clone(),
        // No caps are re-added: PID 1 is created directly as uid 1000 (via
        // `user` below) instead of starting as root and dropping privilege
        // in-container via `capsh --drop=all --user=sandbox`. That capsh
        // exec previously required re-adding exactly
        // CAP_SETPCAP/CAP_SETUID/CAP_SETGID so it could drop its own
        // remaining capabilities and switch users — a circular grant that
        // existed solely to enable the drop. Removing the capsh step
        // (docker/process-sandbox-entrypoint.sh) eliminates the need for
        // those caps entirely, closing the root-init window: the container
        // never has a PID 1 that runs as root with privilege-manipulating
        // capabilities.
        cap_add: posture.cap_add.clone(),
        security_opt: Some(
            super::worker_spec::DockerWorkerSecuritySpec::new(posture.network_mode.clone())
                .security_options(),
        ),
        readonly_rootfs: posture.readonly_rootfs,
        pids_limit: posture.pids_limit,
        tmpfs: Some(
            [("/tmp".to_string(), "size=512M".to_string())]
                .into_iter()
                .collect(),
        ),
        ..Default::default()
    };
    Ok(Config {
        image: Some(config.image.clone()),
        cmd: Some(vec!["sleep".to_string(), "infinity".to_string()]),
        env: Some(env),
        labels: Some(labels),
        host_config: Some(host_config),
        user: posture.user.clone(),
        attach_stdout: Some(false),
        attach_stderr: Some(false),
        ..Default::default()
    })
}

/// Builds the wrapped command line [`exec_in_container`] actually launches,
/// and the counterpart [`kill_exec_process_group`] reads back from to issue
/// a timeout kill that actually works. The prior `setsid`-based wrapper's
/// `kill -KILL -<inspect_exec_pid>` was silently non-functional.
/// Empirically-confirmed root causes, in order of what made the OLD wrapper
/// unfixable without a bigger structural change here:
///
/// 1. **PID-namespace mismatch.** `docker inspect_exec`'s reported `Pid` is
///    a HOST-namespace value: creating an exec, reading its `Pid` back via
///    the Docker API, and checking `/proc/<pid>` INSIDE the very container
///    that exec is running in shows nothing there — confirmed against a
///    real daemon. `kill_exec_process_group` issues its kill via a NEW
///    `docker exec` (which only ever sees the container's OWN pid
///    namespace), so that reported number can never resolve there, no
///    matter what process-group structure the wrapped command creates.
/// 2. **`setsid`'s internal fork (compounding, not the root cause).** Every
///    `docker exec`'s own top-level process is *already* the leader of a
///    fresh process group, distinct from PID 1's and from every other
///    exec's — confirmed by creating consecutive bare execs and reading
///    each one's own pgid back from `/proc/<pid>/stat` inside the
///    container: each lands in a pgid equal to its own, distinct pid.
///    `setsid()` cannot be called on a process that is already a group
///    leader, so `setsid --wait` forked an extra child to do the actual
///    `setsid()` + exec, leaving the pid Docker reports (the *waiting*
///    parent) with no live children in its own group at all — the second
///    layer of brokenness on top of (1).
///
/// Fix: since a bare exec's own top-level process is already an isolated
/// group leader (root cause 2 needs no `setsid` at all), this wrapper has
/// that process report its own pid — via `$$`, evaluated from INSIDE the
/// container, so it is inherently container-namespace-correct (fixing root
/// cause 1) — to a per-exec marker file under `/workspace/.ironclaw`
/// *before* running `command`. [`kill_exec_process_group`] reads that file
/// back through a second `docker exec` (also container-namespace-scoped, so
/// the two sides always agree) to get a pgid a `kill -KILL -<pgid>` can
/// actually resolve.
///
/// Deliberately does NOT `exec` into the inner `sh -c command` the way the
/// `setsid` wrapper does — staying in a normal fork+wait lets it clean up
/// the marker file and propagate the real exit status afterward, without
/// reintroducing the "the wrapper's own launch status shadows the command's
/// real exit code" failure mode `--wait` exists to avoid above. `command`'s
/// own children (anything it forks, backgrounds, or execs) inherit this
/// same process group by default — no `setsid` call anywhere in this
/// path — so `kill -KILL -<pgid>` reaps the whole family, not just the
/// single top-level process.
fn wrap_foreground_command_reporting_pgid(command: &str, pgid_marker: &str) -> String {
    let marker_path = foreground_pgid_marker_path(pgid_marker);
    format!(
        "mkdir -p {PROCESS_STATE_DIR} && echo $$ >{marker_path} && sh -c {}; \
         status=$?; rm -f {marker_path}; exit $status",
        shell_single_quote(command),
    )
}

const PROCESS_STATE_DIR: &str = "/workspace/.ironclaw";

/// Path (inside the container) [`wrap_foreground_command_reporting_pgid`]
/// writes its self-reported pgid to and [`kill_exec_process_group`] reads it
/// back from. Markers are per-exec scratch files under the writable workspace.
fn foreground_pgid_marker_path(pgid_marker: &str) -> String {
    format!("{PROCESS_STATE_DIR}/{pgid_marker}.pgid")
}

/// The unprivileged user (baked into the image by
/// `docker/process-sandbox-entrypoint.sh`, uid 1000) every dispatched
/// command must run as. The container's own init process (PID 1) also runs
/// as this identity now (see [`user_container_launch_config`], which sets
/// `Config.user` to `SANDBOX_EXEC_UID`:`SANDBOX_EXEC_GID` directly) — there
/// is no longer a root init window. Every `CreateExecOptions` built in this
/// module must still set `user` to this value explicitly.
const SANDBOX_EXEC_USER: &str = "sandbox";

/// Numeric uid/gid backing [`SANDBOX_EXEC_USER`] — `Dockerfile.
/// process-sandbox` bakes this in unconditionally (`useradd -m -u 1000 ...
/// sandbox`), so it is the same for every container regardless of image
/// tag. `sandbox_process::prepare_workspace` uses these (not the name)
/// because a host-side `chown` needs a numeric id, not an in-container
/// username.
pub(super) const SANDBOX_EXEC_UID: u32 = 1000;
pub(super) const SANDBOX_EXEC_GID: u32 = 1000;

pub(super) async fn exec_in_container(
    docker: &Docker,
    container_id: &str,
    workdir: ContainerWorkdir,
    env: Vec<String>,
    command: String,
    timeout: Duration,
    output_limit: usize,
) -> Result<CommandExecutionOutput, RuntimeProcessError> {
    // Unique per invocation, generated host-side before `create_exec` (not
    // derived from the eventual `exec.id`) purely because the wrapped
    // command string has to be built before that id exists — see
    // `wrap_foreground_command_reporting_pgid`'s doc comment for why this
    // marker file replaces `inspect_exec`'s `Pid` as the timeout kill's
    // target.
    let pgid_marker = Uuid::new_v4().to_string();
    let wrapped = wrap_foreground_command_reporting_pgid(&command, &pgid_marker);
    let exec = docker
        .create_exec(
            container_id,
            CreateExecOptions {
                cmd: Some(vec!["sh".to_string(), "-c".to_string(), wrapped]),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                working_dir: Some(workdir.into_string()),
                env: Some(env),
                user: Some(SANDBOX_EXEC_USER.to_string()),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!("sandbox exec create failed: {error}"))
        })?;
    let started_at = Instant::now();

    let run = async {
        match docker
            .start_exec(
                &exec.id,
                Some(StartExecOptions {
                    detach: false,
                    tty: false,
                    ..Default::default()
                }),
            )
            .await
            .map_err(|error| {
                RuntimeProcessError::ExecutionFailed(format!("sandbox exec start failed: {error}"))
            })? {
            StartExecResults::Attached { output, .. } => {
                collect_exec_output(output, output_limit).await
            }
            StartExecResults::Detached => Err(RuntimeProcessError::ExecutionFailed(
                "sandbox exec unexpectedly detached".to_string(),
            )),
        }
    };

    let output = match tokio::time::timeout(timeout, run).await {
        Ok(result) => result?,
        Err(_) => {
            kill_exec_process_group(docker, container_id, &pgid_marker).await;
            return Err(RuntimeProcessError::Timeout(timeout));
        }
    };

    let exit_code = docker
        .inspect_exec(&exec.id)
        .await
        .map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!("sandbox exec inspect failed: {error}"))
        })?
        .exit_code
        .unwrap_or(-1);

    Ok(CommandExecutionOutput {
        output,
        saved_output: None,
        exit_code,
        sandboxed: true,
        duration: started_at.elapsed(),
    })
}

/// Stops the persistent user container after one foreground command.
///
/// PR1 deliberately has no background-process lifecycle. Stopping the
/// container after every command is the fail-closed boundary: even a command
/// that detaches into a new session cannot leave a daemon running after the
/// foreground result returns. Docker retains the stopped container's writable
/// layer and the host-mounted `/workspace`, and [`ensure_container`] restarts
/// the same container for the user's next command.
pub(super) async fn stop_container_after_command(
    docker: &Docker,
    container_id: &str,
) -> Result<(), RuntimeProcessError> {
    match docker
        .stop_container(container_id, Some(StopContainerOptions { t: 0 }))
        .await
    {
        Ok(()) => Ok(()),
        Err(stop_error) => {
            // A command may have stopped its own container. Treat that as the
            // required postcondition only when Docker independently confirms
            // the container is no longer running; uncertainty fails closed.
            let stopped = docker
                .inspect_container(container_id, None::<InspectContainerOptions>)
                .await
                .ok()
                .and_then(|container| container.state)
                .and_then(|state| state.running)
                .is_some_and(|running| !running);
            if stopped {
                Ok(())
            } else {
                Err(RuntimeProcessError::ExecutionFailed(format!(
                    "sandbox container could not be stopped after foreground command: {stop_error}"
                )))
            }
        }
    }
}

/// Best-effort: kills the whole process group the timed-out exec started
/// (see [`wrap_foreground_command_reporting_pgid`]), but never fails the
/// caller over it — the caller already treats the command as having timed
/// out regardless of whether this cleanup exec itself succeeds.
///
/// Reads the pgid back from `pgid_marker`'s marker file rather than
/// `docker.inspect_exec`'s reported `Pid` — that field is a host-namespace
/// value that never resolves inside a `docker exec` issued into the
/// container (see `wrap_foreground_command_reporting_pgid`'s doc comment for
/// the empirical proof this function used to be a silent no-op). Both the
/// write (by the timed-out exec, before it ran `command`) and this read
/// happen via `docker exec`, so they always agree on the same
/// container-local pid namespace.
///
/// Also removes the marker file: it is the ONLY place left to clean it up
/// once the wrapped command has been killed mid-flight — the wrapped
/// script's own `rm -f` (see [`wrap_foreground_command_reporting_pgid`])
/// only ever runs on normal completion.
async fn kill_exec_process_group(docker: &Docker, container_id: &str, pgid_marker: &str) {
    let marker_path = foreground_pgid_marker_path(pgid_marker);
    let kill_cmd = format!(
        "kill -KILL -$(cat {marker_path} 2>/dev/null) 2>/dev/null || true; rm -f {marker_path}"
    );
    if let Ok(kill_exec) = docker
        .create_exec(
            container_id,
            CreateExecOptions {
                cmd: Some(vec!["sh".to_string(), "-c".to_string(), kill_cmd]),
                attach_stdout: Some(false),
                attach_stderr: Some(false),
                user: Some(SANDBOX_EXEC_USER.to_string()),
                ..Default::default()
            },
        )
        .await
        && let Err(error) = docker
            .start_exec(
                &kill_exec.id,
                Some(StartExecOptions {
                    detach: true,
                    ..Default::default()
                }),
            )
            .await
    {
        tracing::debug!(?error, "best-effort sandbox exec timeout kill failed");
    }
}

async fn collect_exec_output(
    mut stream: std::pin::Pin<
        Box<dyn futures_util::Stream<Item = Result<LogOutput, bollard::errors::Error>> + Send>,
    >,
    limit: usize,
) -> Result<String, RuntimeProcessError> {
    let mut stdout = String::new();
    let mut stderr = String::new();
    let half_limit = limit / 2;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(LogOutput::StdOut { message }) => {
                super::append_with_limit(
                    &mut stdout,
                    &String::from_utf8_lossy(&message),
                    half_limit,
                );
            }
            Ok(LogOutput::StdErr { message }) => {
                super::append_with_limit(
                    &mut stderr,
                    &String::from_utf8_lossy(&message),
                    half_limit,
                );
            }
            Ok(_) => {}
            Err(error) => {
                return Err(RuntimeProcessError::ExecutionFailed(format!(
                    "sandbox exec output collection failed: {error}"
                )));
            }
        }
    }
    if stderr.is_empty() {
        Ok(stdout)
    } else if stdout.is_empty() {
        Ok(stderr)
    } else {
        Ok(format!("{stdout}\n\n--- stderr ---\n{stderr}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreground_wrapper_reports_its_own_pid_before_running_and_cleans_up_after() {
        let wrapped = wrap_foreground_command_reporting_pgid("echo hi && sleep 1", "marker-abc");
        assert_eq!(
            wrapped,
            "mkdir -p /workspace/.ironclaw && echo $$ >/workspace/.ironclaw/marker-abc.pgid && \
             sh -c 'echo hi && sleep 1'; status=$?; rm -f /workspace/.ironclaw/marker-abc.pgid; \
             exit $status"
        );
    }

    #[test]
    fn foreground_wrapper_never_execs_over_itself() {
        // The whole point of NOT using `exec` here (unlike the setsid
        // wrapper) is staying alive long enough to `rm` the marker file and
        // report the real exit status after `command` finishes — an `exec`
        // anywhere in this wrapper would silently regress that.
        let wrapped = wrap_foreground_command_reporting_pgid("true", "m");
        assert!(
            !wrapped.contains("exec "),
            "the foreground wrapper must not `exec` over itself: {wrapped}"
        );
    }

    #[tokio::test]
    async fn user_container_launch_config_uses_persistent_cmd_and_user_labels() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let config = RebornSandboxConfig::new(temp.path().join("workspaces"));
        let tenant = ironclaw_host_api::ids::TenantId::new("tenant-a").unwrap();
        let user = ironclaw_host_api::ids::UserId::new("user-a").unwrap();

        let launch = user_container_launch_config(&config, &tenant, &user, &workspace)
            .await
            .unwrap();

        assert_eq!(
            launch.cmd,
            Some(vec!["sleep".to_string(), "infinity".to_string()])
        );
        let labels = launch.labels.unwrap();
        assert_eq!(labels.get("ironclaw.tenant").unwrap(), "tenant-a");
        assert_eq!(labels.get("ironclaw.user").unwrap(), "user-a");
        let env = launch.env.unwrap();
        assert!(env.iter().any(|e| e == "HOME=/workspace/.home"));
        let path_entry = env
            .iter()
            .find(|e| e.starts_with("PATH="))
            .unwrap_or_else(|| panic!("launch env must set an explicit PATH: {env:?}"));
        for expected in ["/workspace/.home/.local/bin", "/usr/local/bin", "/usr/bin"] {
            assert!(
                path_entry.contains(expected),
                "PATH must include {expected} (setting Config.env PATH replaces the \
                 image-baked ENV PATH for every docker exec): {path_entry:?}"
            );
        }
        let host_config = launch.host_config.unwrap();
        assert_eq!(host_config.auto_remove, Some(false));
        assert_eq!(
            host_config.pids_limit,
            Some(SANDBOX_PIDS_LIMIT),
            "every newly launched sandbox container must have a finite cgroup PID limit"
        );

        // The launch config's own labels must carry the same stamp
        // `security_posture_stamp` would compute for this config — the
        // single-source-of-truth property `ensure_container` depends on.
        let stamped = labels
            .get(&registry::label_security_posture(LABEL_PREFIX))
            .expect("launch config must stamp a security-posture label");
        assert_eq!(
            stamped,
            &security_posture_stamp(&security_posture_fields(&config)),
            "the label baked into the launch config must match what \
             ensure_container computes as the expected posture"
        );
    }

    /// When `RebornSandboxConfig` carries no CA bundle (the default — no
    /// production caller sets one unless TLS interception is configured),
    /// `user_container_launch_config` must add neither the CA bind nor any
    /// of the `SSL_CERT_FILE`-family env vars: exactly the pre-W5 shape.
    #[tokio::test]
    async fn user_container_launch_config_omits_ca_bundle_wiring_when_unconfigured() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let config = RebornSandboxConfig::new(temp.path().join("workspaces"));
        let tenant = ironclaw_host_api::ids::TenantId::new("tenant-a").unwrap();
        let user = ironclaw_host_api::ids::UserId::new("user-a").unwrap();

        let launch = user_container_launch_config(&config, &tenant, &user, &workspace)
            .await
            .unwrap();

        let host_config = launch.host_config.unwrap();
        let binds = host_config.binds.unwrap();
        assert_eq!(
            binds.len(),
            1,
            "no CA bundle configured: only the workspace bind should be present: {binds:?}"
        );
        let env = launch.env.unwrap();
        assert!(
            !env.iter().any(|e| e.starts_with("SSL_CERT_FILE=")),
            "no CA bundle configured: SSL_CERT_FILE must not be set: {env:?}"
        );
    }

    /// When `RebornSandboxConfig` carries a CA bundle (composition wires
    /// this from `SandboxEgressProxyBinding::ca_bundle_pem` — see
    /// `RebornSandboxConfig::with_ca_bundle_pem`'s doc), the launch config
    /// must bind-mount a real, readable file at the fixed container path
    /// and point every `SSL_CERT_FILE`-family env var at it. Verifies the
    /// bind's HOST-side source is a real file containing the exact bundle
    /// text (not merely that a bind string was appended), proving
    /// `materialize_ca_bundle` actually wrote it before the bind referenced
    /// it.
    #[tokio::test]
    async fn user_container_launch_config_wires_ca_bundle_when_configured() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let bundle_pem =
            "-----BEGIN CERTIFICATE-----\nfake-bundle-content\n-----END CERTIFICATE-----\n";
        let config =
            RebornSandboxConfig::new(temp.path().join("workspaces")).with_ca_bundle_pem(bundle_pem);
        let tenant = ironclaw_host_api::ids::TenantId::new("tenant-a").unwrap();
        let user = ironclaw_host_api::ids::UserId::new("user-a").unwrap();

        let launch = user_container_launch_config(&config, &tenant, &user, &workspace)
            .await
            .unwrap();

        let host_config = launch.host_config.unwrap();
        let binds = host_config.binds.unwrap();
        let ca_bind = binds
            .iter()
            .find(|bind| bind.contains(mounts::CONTAINER_CA_BUNDLE_PATH))
            .unwrap_or_else(|| panic!("expected a CA bundle bind in {binds:?}"));
        assert!(
            ca_bind.ends_with(":ro"),
            "the CA bundle bind must be read-only: {ca_bind}"
        );
        let host_source = ca_bind
            .rsplit_once(&format!(":{}:ro", mounts::CONTAINER_CA_BUNDLE_PATH))
            .map(|(source, _)| source)
            .unwrap_or_else(|| panic!("could not parse the host source out of {ca_bind}"));
        let written = tokio::fs::read_to_string(host_source).await.unwrap();
        assert_eq!(
            written, bundle_pem,
            "the bind-mounted file must contain exactly the configured bundle text"
        );

        let env = launch.env.unwrap();
        for var in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
            "NODE_EXTRA_CA_CERTS",
        ] {
            let expected = format!("{var}={}", mounts::CONTAINER_CA_BUNDLE_PATH);
            assert!(
                env.contains(&expected),
                "expected {expected:?} in launch env: {env:?}"
            );
        }
    }

    /// Zero-exposure credentials (`.claude/rules/safety-and-sandbox.md`):
    /// "Capabilities, runtime lanes, containers, events, logs, and model
    /// context carry credential references or redacted metadata" — never
    /// raw secret material. This is the seam test for the container side of
    /// that invariant: stage a REAL secret in the two production stores a
    /// (not-yet-built) W6 wiring would read from —
    /// `credential_firewall::SandboxCredentialFirewall` (the obligation
    /// chokepoint) and `crate::obligations::RuntimeSecretInjectionStore`
    /// (the material behind it, keyed the same way
    /// `StagedCredentialObligationSource` documents) — under the exact
    /// `(tenant_id, user_id)` this call builds a launch config for, then
    /// call the real production `user_container_launch_config` and prove
    /// the secret reaches NONE of: the container env map, any bind-mount
    /// source path or the file tree under it, the `cmd`, or the writable
    /// workspace directory itself.
    ///
    /// `user_container_launch_config` does not take a firewall/secret-store
    /// argument today — nothing wires credential material into container
    /// launch yet (see `credential_firewall`'s module doc: W6, the proxy
    /// consumer, "not built yet"). So this test cannot drive an actual
    /// resolved-and-injected credential through the real call chain; it
    /// pins the currently-true invariant that staging a credential
    /// alongside a launch-config build has zero effect on that build's
    /// output, which is exactly what a regression in a future wiring would
    /// break. See the PR description for the RED/GREEN proof that this
    /// assertion set actually binds (a planted leak in
    /// `user_container_launch_config` was caught and reverted).
    #[tokio::test]
    async fn user_container_launch_config_never_leaks_staged_credential_material() {
        use std::sync::Arc;

        use ironclaw_host_api::{
            ids::{CapabilityId, ExtensionId, InvocationId},
            resource::ResourceScope,
        };
        use ironclaw_secrets::SecretMaterial;

        use super::super::credential_firewall::{
            SandboxCredentialConnectionIdentity, SandboxCredentialDecision,
            SandboxCredentialFirewall, StagedCredentialObligation,
            StagedCredentialObligationSource,
        };
        use crate::obligations::RuntimeSecretInjectionStore;

        const CANARY_SECRET: &str = "sbx-canary-do-not-leak-4f9c2a71bE";

        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        // A decoy file already living in the workspace before launch-config
        // build, so the recursive file-content scan below is proven to
        // actually read file bytes, not just enumerate bind path strings.
        std::fs::write(workspace.join("decoy.txt"), "nothing secret in here").unwrap();
        let config = RebornSandboxConfig::new(temp.path().join("workspaces"));
        let tenant = ironclaw_host_api::ids::TenantId::new("tenant-secret").unwrap();
        let user = ironclaw_host_api::ids::UserId::new("user-secret").unwrap();

        let scope = ResourceScope {
            tenant_id: tenant.clone(),
            user_id: user.clone(),
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        };
        let capability_id = CapabilityId::new("sandbox.shell").unwrap();
        let secret_handle = ironclaw_host_api::ids::SecretHandle::new("github-pat").unwrap();
        let provider = ExtensionId::new("github").unwrap();

        // The real secret material, staged exactly where the future W6
        // proxy wiring would read it from — keyed by (scope, capability_id,
        // secret_handle), the same key `StagedCredentialObligationSource`
        // carries (see that type's doc).
        let secrets_store = RuntimeSecretInjectionStore::new();
        secrets_store
            .insert(
                &scope,
                &capability_id,
                &secret_handle,
                SecretMaterial::from(CANARY_SECRET),
            )
            .unwrap();

        // The matching obligation staged in the real firewall chokepoint —
        // proves the seam under test is genuinely "live" for this
        // tenant/user, not exercised against an empty firewall.
        let firewall = Arc::new(SandboxCredentialFirewall::new());
        let _lease = firewall.stage(
            &tenant,
            &user,
            StagedCredentialObligation::new(
                StagedCredentialObligationSource {
                    scope: scope.clone(),
                    capability_id: capability_id.clone(),
                    provider_or_extension_id: provider,
                    secret_handle: secret_handle.clone(),
                },
                Vec::new(),
                Duration::from_secs(60),
            ),
        );
        let decision = firewall
            .authorize(
                Some(SandboxCredentialConnectionIdentity {
                    tenant_id: &tenant,
                    user_id: &user,
                    invocation_id: scope.invocation_id,
                }),
                Instant::now() + Duration::from_secs(5),
            )
            .expect("attributed lookup within deadline must not error");
        assert!(
            matches!(decision, SandboxCredentialDecision::Grant(_)),
            "test setup bug: the obligation must be live before exercising the launch-config \
             seam, otherwise this test would trivially pass with nothing staged"
        );

        let launch = user_container_launch_config(&config, &tenant, &user, &workspace)
            .await
            .unwrap();

        // Whole-struct scan first: catches the secret in ANY field,
        // including ones not explicitly enumerated below.
        let launch_json =
            serde_json::to_string(&launch).expect("bollard's Config<String> derives Serialize");
        assert!(
            !launch_json.contains(CANARY_SECRET),
            "container launch config must never carry staged credential material \
             (zero-exposure credentials): {launch_json}"
        );

        let env = launch.env.clone().unwrap_or_default();
        assert!(
            !env.iter().any(|entry| entry.contains(CANARY_SECRET)),
            "container env map must not carry the staged secret: {env:?}"
        );

        let host_config = launch.host_config.clone().unwrap_or_default();
        for bind in host_config.binds.clone().unwrap_or_default() {
            assert!(
                !bind.contains(CANARY_SECRET),
                "bind-mount spec must not carry the staged secret: {bind}"
            );
            let source = bind
                .split(':')
                .next()
                .expect("bind spec must have a source segment");
            assert_no_secret_under_path(Path::new(source), CANARY_SECRET);
        }

        let cmd = launch.cmd.clone().unwrap_or_default();
        assert!(
            !cmd.iter().any(|arg| arg.contains(CANARY_SECRET)),
            "container cmd/exec arguments must not carry the staged secret: {cmd:?}"
        );

        // The writable workspace itself, independent of what got bind-
        // mounted above (the workspace bind's source IS this path, but
        // scanning it directly keeps the assertion meaningful even if the
        // bind-building logic above changes).
        assert_no_secret_under_path(&workspace, CANARY_SECRET);
    }

    /// Recursively asserts no file under `path` contains `secret` as a
    /// substring. Used by
    /// [`user_container_launch_config_never_leaks_staged_credential_material`]
    /// to scan both bind-mount source trees and the writable workspace.
    #[cfg(test)]
    fn assert_no_secret_under_path(path: &Path, secret: &str) {
        if path.is_file() {
            let contents = std::fs::read(path)
                .unwrap_or_else(|error| panic!("failed to read {path:?} for secret scan: {error}"));
            let text = String::from_utf8_lossy(&contents);
            assert!(
                !text.contains(secret),
                "file {path:?} must not contain the staged secret"
            );
            return;
        }
        if path.is_dir() {
            for entry in std::fs::read_dir(path)
                .unwrap_or_else(|error| panic!("failed to read dir {path:?}: {error}"))
            {
                let entry = entry.unwrap_or_else(|error| panic!("dir entry error: {error}"));
                assert_no_secret_under_path(&entry.path(), secret);
            }
        }
    }

    #[test]
    fn security_posture_stamp_is_deterministic_for_the_same_fields() {
        let temp = tempfile::tempdir().unwrap();
        let config = RebornSandboxConfig::new(temp.path().join("workspaces"));

        let first = security_posture_stamp(&security_posture_fields(&config));
        let second = security_posture_stamp(&security_posture_fields(&config));

        assert_eq!(
            first, second,
            "the same config must always produce the same posture stamp"
        );
    }

    #[test]
    fn security_posture_stamp_changes_when_user_flips() {
        let temp = tempfile::tempdir().unwrap();
        let config = RebornSandboxConfig::new(temp.path().join("workspaces"));
        let baseline = security_posture_fields(&config);
        let baseline_stamp = security_posture_stamp(&baseline);

        let mut root_pid1 = security_posture_fields(&config);
        root_pid1.user = None; // the pre-W1 posture: image-default (root) PID 1

        assert_ne!(
            baseline_stamp,
            security_posture_stamp(&root_pid1),
            "flipping the pinned uid:gid user must change the stamp — this is exactly the \
             W1 hardening a stale container must be recycled to pick up"
        );
    }

    #[test]
    fn security_posture_stamp_changes_when_cap_add_flips() {
        let temp = tempfile::tempdir().unwrap();
        let config = RebornSandboxConfig::new(temp.path().join("workspaces"));
        let baseline = security_posture_fields(&config);
        let baseline_stamp = security_posture_stamp(&baseline);

        let mut with_caps = security_posture_fields(&config);
        with_caps.cap_add = Some(vec![
            "CAP_SETUID".to_string(),
            "CAP_SETGID".to_string(),
            "CAP_SETPCAP".to_string(),
        ]);

        assert_ne!(
            baseline_stamp,
            security_posture_stamp(&with_caps),
            "re-adding capabilities must change the stamp"
        );
    }

    #[test]
    fn security_posture_stamp_changes_when_network_mode_flips() {
        let temp = tempfile::tempdir().unwrap();
        let no_net_config = RebornSandboxConfig::new(temp.path().join("workspaces"));
        let egress_config = RebornSandboxConfig::new(temp.path().join("workspaces-2"))
            .with_network_broker_port(8181);

        assert_ne!(
            security_posture_stamp(&security_posture_fields(&no_net_config)),
            security_posture_stamp(&security_posture_fields(&egress_config)),
            "a different container_network_mode must change the stamp"
        );
    }

    #[test]
    fn security_posture_stamp_changes_when_pids_limit_is_missing_or_different() {
        let temp = tempfile::tempdir().unwrap();
        let config = RebornSandboxConfig::new(temp.path().join("workspaces"));
        let baseline = security_posture_fields(&config);
        let baseline_stamp = security_posture_stamp(&baseline);

        assert_eq!(baseline.pids_limit, Some(SANDBOX_PIDS_LIMIT));

        let mut missing_limit = security_posture_fields(&config);
        missing_limit.pids_limit = None;
        assert_ne!(
            baseline_stamp,
            security_posture_stamp(&missing_limit),
            "a container without the finite PID limit must have a stale posture stamp"
        );

        let mut different_limit = security_posture_fields(&config);
        different_limit.pids_limit = Some(SANDBOX_PIDS_LIMIT + 1);
        assert_ne!(
            baseline_stamp,
            security_posture_stamp(&different_limit),
            "a container with a different PID limit must have a stale posture stamp"
        );
    }

    #[test]
    fn sandbox_egress_network_create_options_pins_internal_subnet_and_gateway() {
        let options = sandbox_egress_network_create_options();

        assert_eq!(options.name, SANDBOX_EGRESS_NETWORK_NAME);
        assert!(
            options.internal,
            "must have no default route off-host (E1) — that's what makes the proxy the only way out"
        );
        let ipam_config = options
            .ipam
            .config
            .as_ref()
            .and_then(|configs| configs.first())
            .expect("network create options must pin an IPAM config");
        assert_eq!(
            ipam_config.subnet.as_deref(),
            Some(SANDBOX_EGRESS_NETWORK_SUBNET)
        );
        assert_eq!(
            ipam_config.gateway.as_deref(),
            Some(SANDBOX_EGRESS_NETWORK_GATEWAY)
        );
        assert_eq!(
            options
                .options
                .get(SANDBOX_EGRESS_NETWORK_ICC_OPTION_KEY)
                .map(String::as_str),
            Some("false"),
            "must disable inter-container communication (E-ICC) — otherwise a container on \
             this shared network can reach another user's container directly, defeating \
             lateral-movement isolation and source-IP attribution at the egress proxy"
        );
    }

    #[test]
    fn already_exists_network_error_is_treated_as_idempotent_success() {
        let conflict = DockerError::DockerResponseServerError {
            status_code: 409,
            message: format!("network with name {SANDBOX_EGRESS_NETWORK_NAME} already exists"),
        };
        assert!(is_network_already_exists_error(&conflict));

        let message_only = DockerError::DockerResponseServerError {
            status_code: 500,
            message: "Error: network with name ironclaw-sandbox-egress already exists".to_string(),
        };
        assert!(is_network_already_exists_error(&message_only));

        let unrelated = DockerError::DockerResponseServerError {
            status_code: 500,
            message: "internal server error".to_string(),
        };
        assert!(!is_network_already_exists_error(&unrelated));
    }

    #[tokio::test]
    async fn ensure_egress_network_is_a_no_op_for_none_network_configs() {
        // No live Docker daemon needed: `ensure_egress_network` must return
        // early (never issue a `docker.create_network` call) for a config
        // whose `container_network_mode()` isn't the egress network, so an
        // unreachable `Docker` handle is never actually used. Building an
        // HTTP-transport `Docker` client is lazy (no connection attempt
        // until a request is sent), unlike `connect_with_local_defaults`,
        // which stats the Unix socket path at construction and fails
        // immediately in this sandboxed environment (no
        // `/var/run/docker.sock`) — this exercises the guard clause without
        // either.
        let docker =
            Docker::connect_with_http("http://127.0.0.1:0", 120, bollard::API_DEFAULT_VERSION)
                .expect("HTTP-transport client construction performs no I/O");
        let temp = tempfile::tempdir().unwrap();

        let none_network_config = RebornSandboxConfig::new(temp.path().join("workspaces"));
        assert_eq!(
            none_network_config.container_network_mode(),
            Some("none".to_string())
        );
        ensure_egress_network(&docker, &none_network_config)
            .await
            .expect("no-net config must skip the network API entirely");
    }

    /// Once `network_ready` is initialized (as a prior `ensure_container`
    /// call would have left it after a successful ensure), a second call
    /// must short-circuit past `ensure_egress_network` entirely — proven
    /// here by pointing at an unreachable Docker transport with a config
    /// that *does* require the egress network: if the gate failed to
    /// short-circuit, this would try to reach Docker and return `Err`.
    #[tokio::test]
    async fn ensure_egress_network_once_short_circuits_once_already_initialized() {
        let docker =
            Docker::connect_with_http("http://127.0.0.1:0", 120, bollard::API_DEFAULT_VERSION)
                .expect("HTTP-transport client construction performs no I/O");
        let temp = tempfile::tempdir().unwrap();
        let egress_config =
            RebornSandboxConfig::new(temp.path().join("workspaces")).with_network_broker_port(8181);
        assert_eq!(
            egress_config.container_network_mode(),
            Some(SANDBOX_EGRESS_NETWORK_NAME.to_string()),
            "test config must actually require the egress network for this test to be meaningful"
        );

        let network_ready = tokio::sync::OnceCell::new();
        network_ready
            .set(())
            .expect("freshly constructed OnceCell always accepts the first set");

        ensure_egress_network_once(&docker, &egress_config, &network_ready)
            .await
            .expect(
                "an already-initialized gate must short-circuit past the unreachable docker call",
            );
    }

    /// Sanity check paired with the short-circuit test above: an
    /// UNinitialized gate must still actually attempt the ensure (and thus
    /// surface the unreachable-Docker error) — otherwise the short-circuit
    /// test would pass vacuously regardless of whether gating works.
    #[tokio::test]
    async fn ensure_egress_network_once_attempts_the_ensure_when_not_yet_initialized() {
        let docker =
            Docker::connect_with_http("http://127.0.0.1:0", 120, bollard::API_DEFAULT_VERSION)
                .expect("HTTP-transport client construction performs no I/O");
        let temp = tempfile::tempdir().unwrap();
        let egress_config =
            RebornSandboxConfig::new(temp.path().join("workspaces")).with_network_broker_port(8181);

        let network_ready = tokio::sync::OnceCell::new();
        let result = ensure_egress_network_once(&docker, &egress_config, &network_ready).await;
        assert!(
            result.is_err(),
            "a not-yet-initialized gate must still attempt the ensure and surface the \
             unreachable-docker failure, not silently succeed"
        );
    }
}

// `#[path]` resolution for a module declared inline inside another inline
// module is relative to a *fictitious* per-module directory chain (here
// `src/sandbox_process/exec_transport/docker_tests/`, which does not exist
// on disk) — verified empirically, since none of those intermediate
// directories are real. Declaring `docker_gate` at THIS file's top level
// instead resolves relative to `exec_transport.rs`'s own real directory
// (`src/sandbox_process/`, two levels above the crate root), matching the
// convention `sandbox_reaper_docker.rs` uses one level up (that file sits
// directly in `tests/`, so it only needs `"support/docker_gate.rs"`).
//
// `pub(crate)` (rather than private) so `attribution`'s own real-Docker test
// can reuse this exact module instance instead of re-declaring the same
// `#[path]` a second time — clippy's `duplicate_mod` lint flags loading the
// same file into two module locations, and there is only one Docker gate
// convention in this crate, not one per file.
#[cfg(test)]
#[path = "../../tests/support/docker_gate.rs"]
pub(crate) mod docker_gate;

/// Real-Docker tests for the exec-based persistent container lifecycle that
/// genuinely need crate-private data. The rest of this module's former
/// coverage moved to
/// `crates/ironclaw_host_runtime/tests/sandbox_exec_transport_docker.rs`,
/// driven through the public `RuntimeProcessPort::run_command` surface —
/// this one test stays inline because it asserts the applied Docker
/// `HostConfig` against `RebornSandboxConfig`'s private `memory_bytes` /
/// `cpu_shares` fields, which have no public accessor and aren't worth
/// adding solely to relocate a test. Gated the way `sandbox_reaper_docker.rs`
/// already gates its tests: a visible `SKIP: ...` line, never a silent
/// `#[ignore]` vanish.
#[cfg(test)]
mod docker_tests {
    #[cfg(unix)]
    use super::super::prepare_workspace_unix;
    use super::*;
    use std::collections::HashMap;

    use bollard::{
        container::{NetworkingConfig, RemoveContainerOptions},
        models::{EndpointIpamConfig, EndpointSettings},
    };

    fn docker_tests_config(workspaces_root: &Path) -> RebornSandboxConfig {
        RebornSandboxConfig::new(workspaces_root.to_path_buf())
            .with_image(docker_gate::configured_sandbox_image())
    }

    /// Creates and chowns a host workspace directory exactly the way
    /// production's `prepare_workspace` does (`sandbox_process.rs`), so
    /// these tests' manually-built containers see the same uid/gid-1000-
    /// writable directory a real `ensure_container` caller would bind-mount.
    ///
    /// A plain `std::fs::create_dir_all` leaves the directory owned by
    /// whatever uid this host test process runs as — never 1000 — so
    /// without this the container's non-root PID 1 (uid 1000, no root init
    /// window since W1) can't write into it and `mkdir -p /workspace/.ironclaw`
    /// fails with `Permission denied` before the test's real assertions run.
    async fn create_writable_workspace(config: &RebornSandboxConfig, workspace: &Path) {
        #[cfg(unix)]
        prepare_workspace_unix(
            &config.workspace_root,
            workspace,
            config.container_identity.workspace_mode(),
        )
        .expect("preparing the test workspace should succeed");

        #[cfg(not(unix))]
        std::fs::create_dir_all(workspace).unwrap();
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

    /// Removes any container already labeled for `{tenant_id, user_id}`
    /// before a test builds a fresh workspace and calls `ensure_container`.
    ///
    /// `ensure_container` finds its container purely by the `{tenant, user}`
    /// Docker labels (see its doc comment) and reuses whatever it finds
    /// WITHOUT checking that container's `/workspace` bind-mount source
    /// still exists on the host. These tests' labels are fixed across runs,
    /// but each run creates its own `tempfile::tempdir()` workspace that is
    /// deleted the moment the test function returns (`TempDir::drop`) — so
    /// a container that survives past that point (killed test, panic before
    /// `best_effort_remove`, a leftover from a prior local run) is bound to
    /// an already-deleted directory. The next run's `ensure_container` finds
    /// that same labeled container, reuses it untouched (its security-
    /// posture stamp still matches), and every exec inside it then fails —
    /// `mkdir: cannot create directory '/workspace/.ironclaw'` — because the
    /// bind source is gone, regardless of how carefully THIS run chowns its
    /// own fresh workspace (chowning a directory nothing mounts is a no-op).
    ///
    /// Mirrors `tests/integration/reborn_sandbox_egress_proxy.rs`'s
    /// `remove_egress_proxy_test_sandbox_containers` (same root cause, same
    /// fix shape); implemented over the `Docker` handle these tests already
    /// hold instead of shelling out to the `docker` CLI, since every other
    /// helper in this module already talks to Docker the same way.
    async fn remove_labeled_test_containers(
        docker: &Docker,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) {
        let filters = user_container_label_filter(LABEL_PREFIX, tenant_id, user_id);
        let Ok(found) = docker
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters,
                ..Default::default()
            }))
            .await
        else {
            return;
        };
        for container in found {
            if let Some(id) = container.id {
                best_effort_remove(docker, &id).await;
            }
        }
    }

    async fn best_effort_remove_network(docker: &Docker, network_name: &str) {
        let _ = docker.remove_network(network_name).await;
    }

    /// `SANDBOX_EGRESS_NETWORK_NAME` is one real, singleton Docker resource.
    /// `cargo test`'s default parallel runner would otherwise let this
    /// module's network-recreating tests race each other for the same
    /// name (the other `docker_tests` below use `disable_network: true`
    /// with no broker, which resolves to the `none` network mode and never
    /// touches this network at all — see `container_network_mode`). Every
    /// test that creates, deletes, or posture-checks the real egress
    /// network acquires this lock for its duration instead of relying on
    /// `--test-threads=1`.
    static EGRESS_NETWORK_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A tiny (`busybox`, already present wherever these tests actually run)
    /// container attached to `network_name`, running `command` under `sh
    /// -c`. Used by the ICC probes below instead of the real sandbox worker
    /// image — these tests only need raw network reachability between two
    /// containers, not the sandbox's exec/workdir/user conventions.
    async fn start_probe_container(
        docker: &Docker,
        network_name: &str,
        name: &str,
        command: &str,
    ) -> String {
        let created = docker
            .create_container(
                Some(CreateContainerOptions {
                    name: name.to_string(),
                    platform: None,
                }),
                Config {
                    image: Some("busybox:1.36".to_string()),
                    cmd: Some(vec![
                        "sh".to_string(),
                        "-c".to_string(),
                        command.to_string(),
                    ]),
                    host_config: Some(HostConfig {
                        network_mode: Some(network_name.to_string()),
                        auto_remove: Some(false),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .expect("probe container create succeeds");
        docker
            .start_container(&created.id, None::<StartContainerOptions<String>>)
            .await
            .expect("probe container start succeeds");
        created.id
    }

    /// The probe container's IPv4 address on `network_name`, read back via
    /// `docker inspect` rather than assumed — this is what another
    /// container would actually dial.
    async fn probe_container_ip(docker: &Docker, container_id: &str, network_name: &str) -> String {
        let inspected = docker
            .inspect_container(container_id, None::<InspectContainerOptions>)
            .await
            .expect("probe container inspect succeeds");
        inspected
            .network_settings
            .and_then(|settings| settings.networks)
            .and_then(|networks| networks.get(network_name).cloned())
            .and_then(|endpoint| endpoint.ip_address)
            .filter(|ip| !ip.is_empty())
            .unwrap_or_else(|| panic!("probe container {container_id} has no IP on {network_name}"))
    }

    /// A short exec inside `container_id`, returning `(stdout, exit_code)`.
    /// Deliberately bypasses [`exec_in_container`] (which assumes the
    /// sandbox worker image's fixed uid/workdir conventions) — these probe
    /// containers are plain `busybox`, so the exec just runs as the image
    /// default user with no working-directory requirement.
    async fn probe_exec(docker: &Docker, container_id: &str, command: &str) -> (String, i64) {
        let exec = docker
            .create_exec(
                container_id,
                CreateExecOptions {
                    cmd: Some(vec![
                        "sh".to_string(),
                        "-c".to_string(),
                        command.to_string(),
                    ]),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    ..Default::default()
                },
            )
            .await
            .expect("probe exec create succeeds");
        let output = match docker
            .start_exec(
                &exec.id,
                Some(StartExecOptions {
                    detach: false,
                    tty: false,
                    ..Default::default()
                }),
            )
            .await
            .expect("probe exec start succeeds")
        {
            StartExecResults::Attached { output, .. } => collect_exec_output(output, 4096)
                .await
                .expect("probe exec output collects"),
            StartExecResults::Detached => panic!("probe exec unexpectedly detached"),
        };
        let exit_code = docker
            .inspect_exec(&exec.id)
            .await
            .expect("probe exec inspect succeeds")
            .exit_code
            .unwrap_or(-1);
        (output, exit_code)
    }

    /// Recreates the real [`SANDBOX_EGRESS_NETWORK_NAME`] network with the
    /// production create options, after best-effort tearing down whatever
    /// was there before (this box, like any dev machine, may still have an
    /// older network by this name left over from before `enable_icc` was
    /// added — see this module's `enable_icc` doc comment). Tests using
    /// this must not depend on ambient network state and must clean up
    /// after themselves.
    async fn recreate_real_egress_network(docker: &Docker) {
        best_effort_remove_stale_network_containers(docker, SANDBOX_EGRESS_NETWORK_NAME).await;
        best_effort_remove_network(docker, SANDBOX_EGRESS_NETWORK_NAME).await;
        docker
            .create_network(sandbox_egress_network_create_options())
            .await
            .expect("fresh egress network create succeeds");
    }

    /// Force-removes any containers still attached to `network_name` from a
    /// prior interrupted test run — `remove_network` refuses to delete a
    /// network with attached containers, so a stale container left over
    /// from a killed test process would otherwise wedge every later test
    /// that needs a clean network.
    async fn best_effort_remove_stale_network_containers(docker: &Docker, network_name: &str) {
        let mut filters = std::collections::HashMap::new();
        filters.insert("network".to_string(), vec![network_name.to_string()]);
        let Ok(containers) = docker
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters,
                ..Default::default()
            }))
            .await
        else {
            return;
        };
        for container in containers {
            if let Some(id) = container.id {
                best_effort_remove(docker, &id).await;
            }
        }
    }

    /// Plan row 11: `enable_icc=false` must actually block container-to-
    /// container traffic on the shared egress network, not just be set in
    /// the create-options struct (that's the pure unit test above). Proves
    /// the block with a real attack — A tries to open TCP to B — and
    /// separately proves B's listener was genuinely alive throughout,
    /// checked from B itself: without that second check, a dead listener
    /// would make the "blocked" assertion pass for the wrong reason.
    #[tokio::test]
    async fn icc_disabled_blocks_container_to_container() {
        if !docker_gate::docker_available() {
            eprintln!(
                "SKIP: no docker daemon reachable — icc_disabled_blocks_container_to_container requires a real Docker daemon (CI/hosted Docker lane only)"
            );
            return;
        }

        let _network_guard = EGRESS_NETWORK_TEST_LOCK.lock().await;
        let docker = Docker::connect_with_local_defaults().unwrap();
        recreate_real_egress_network(&docker).await;

        let b_name = format!("ironclaw-test-icc-b-{}", uuid::Uuid::new_v4());
        let a_name = format!("ironclaw-test-icc-a-{}", uuid::Uuid::new_v4());
        let b_id = start_probe_container(
            &docker,
            SANDBOX_EGRESS_NETWORK_NAME,
            &b_name,
            // Restart the listener after every connection attempt so
            // ordering between the attack and the aliveness check below
            // can't accidentally consume the one-shot listener and produce
            // a false "blocked" result.
            "while true; do nc -l -p 8080 -e /bin/true; done",
        )
        .await;
        let a_id =
            start_probe_container(&docker, SANDBOX_EGRESS_NETWORK_NAME, &a_name, "sleep 300").await;
        let b_ip = probe_container_ip(&docker, &b_id, SANDBOX_EGRESS_NETWORK_NAME).await;

        let (_output, exit_code) =
            probe_exec(&docker, &a_id, &format!("nc -z -w2 {b_ip} 8080")).await;
        assert_ne!(
            exit_code, 0,
            "with enable_icc=false, container A must NOT be able to open a TCP connection to \
             container B's IP on the shared egress network — got exit code {exit_code}, \
             expected a non-zero (blocked/timed out) connect"
        );

        let (_output, listener_exit_code) =
            probe_exec(&docker, &b_id, "nc -z -w1 127.0.0.1 8080").await;
        assert_eq!(
            listener_exit_code, 0,
            "B's own listener must still be alive after A's blocked connection attempt — \
             otherwise the block above could be a dead-listener false pass rather than real \
             ICC isolation"
        );

        best_effort_remove(&docker, &a_id).await;
        best_effort_remove(&docker, &b_id).await;
        best_effort_remove_network(&docker, SANDBOX_EGRESS_NETWORK_NAME).await;
    }

    /// Plan row 12: `enable_icc=false` must not over-block — a container on
    /// the egress network still needs to reach the network's own gateway,
    /// since that's where the egress proxy is reached (see
    /// `SANDBOX_EGRESS_NETWORK_GATEWAY`'s doc comment). ICC only affects the
    /// bridge's inter-port forwarding, not traffic to the bridge's own
    /// gateway address, so this proves the isolation setting didn't
    /// accidentally sever the one path containers are actually supposed to
    /// use.
    #[tokio::test]
    async fn icc_disabled_preserves_gateway_reachability() {
        if !docker_gate::docker_available() {
            eprintln!(
                "SKIP: no docker daemon reachable — icc_disabled_preserves_gateway_reachability requires a real Docker daemon (CI/hosted Docker lane only)"
            );
            return;
        }

        let _network_guard = EGRESS_NETWORK_TEST_LOCK.lock().await;
        let docker = Docker::connect_with_local_defaults().unwrap();
        recreate_real_egress_network(&docker).await;

        let name = format!("ironclaw-test-icc-gateway-{}", uuid::Uuid::new_v4());
        let container_id =
            start_probe_container(&docker, SANDBOX_EGRESS_NETWORK_NAME, &name, "sleep 300").await;

        let (output, exit_code) = probe_exec(
            &docker,
            &container_id,
            &format!("ping -c1 -W2 {SANDBOX_EGRESS_NETWORK_GATEWAY}"),
        )
        .await;
        assert_eq!(
            exit_code, 0,
            "a container on the icc-disabled egress network must still reach its own gateway \
             ({SANDBOX_EGRESS_NETWORK_GATEWAY}) — enable_icc must not sever the proxy path: \
             {output}"
        );

        best_effort_remove(&docker, &container_id).await;
        best_effort_remove_network(&docker, SANDBOX_EGRESS_NETWORK_NAME).await;
    }

    /// The fail-closed half of W1.5: an existing network that does NOT
    /// carry the required `enable_icc=false` option (an older deployment's
    /// network, or a hand-rolled one) must make `ensure_egress_network`
    /// error out naming the mismatch — not silently succeed, which is what
    /// the pre-fix "already exists ⇒ Ok" branch did. Deterministic by
    /// construction: creates a network by the right name with deliberately
    /// wrong options, rather than relying on whatever this machine happens
    /// to have lying around.
    #[tokio::test]
    async fn ensure_egress_network_fails_closed_on_posture_mismatch() {
        if !docker_gate::docker_available() {
            eprintln!(
                "SKIP: no docker daemon reachable — ensure_egress_network_fails_closed_on_posture_mismatch requires a real Docker daemon (CI/hosted Docker lane only)"
            );
            return;
        }

        let _network_guard = EGRESS_NETWORK_TEST_LOCK.lock().await;
        let docker = Docker::connect_with_local_defaults().unwrap();
        best_effort_remove_stale_network_containers(&docker, SANDBOX_EGRESS_NETWORK_NAME).await;
        best_effort_remove_network(&docker, SANDBOX_EGRESS_NETWORK_NAME).await;

        // A network with the right name, right subnet/gateway/internal —
        // but WITHOUT enable_icc=false, exactly like the old network this
        // fix must not silently accept.
        docker
            .create_network(CreateNetworkOptions {
                name: SANDBOX_EGRESS_NETWORK_NAME.to_string(),
                check_duplicate: true,
                driver: "bridge".to_string(),
                internal: true,
                ipam: Ipam {
                    config: Some(vec![IpamConfig {
                        subnet: Some(SANDBOX_EGRESS_NETWORK_SUBNET.to_string()),
                        gateway: Some(SANDBOX_EGRESS_NETWORK_GATEWAY.to_string()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .expect("posture-mismatched network create succeeds");

        let temp = tempfile::tempdir().unwrap();
        let egress_config =
            RebornSandboxConfig::new(temp.path().join("workspaces")).with_network_broker_port(8181);
        assert_eq!(
            egress_config.container_network_mode(),
            Some(SANDBOX_EGRESS_NETWORK_NAME.to_string()),
            "test config must actually require the egress network for this test to be meaningful"
        );

        let result = ensure_egress_network(&docker, &egress_config).await;
        let error = result.expect_err(
            "an existing network missing enable_icc=false must be rejected, not silently \
             accepted as if isolation were already in place",
        );
        let message = error.to_string();
        assert!(
            message.contains(SANDBOX_EGRESS_NETWORK_ICC_OPTION_KEY),
            "the fail-closed error must name the mismatched option so an operator can act on \
             it: {message}"
        );

        best_effort_remove_network(&docker, SANDBOX_EGRESS_NETWORK_NAME).await;

        // A network can carry the isolation flags while still pointing at a
        // different gateway. That must also be rejected because the proxy URL
        // and host listener both rely on the pinned 10.200.0.1 address.
        docker
            .create_network(CreateNetworkOptions {
                name: SANDBOX_EGRESS_NETWORK_NAME.to_string(),
                check_duplicate: true,
                driver: "bridge".to_string(),
                internal: true,
                ipam: Ipam {
                    config: Some(vec![IpamConfig {
                        subnet: Some("10.201.0.0/24".to_string()),
                        gateway: Some("10.201.0.1".to_string()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
                options: [(
                    SANDBOX_EGRESS_NETWORK_ICC_OPTION_KEY.to_string(),
                    "false".to_string(),
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            })
            .await
            .expect("gateway-mismatched network create succeeds");

        let error = ensure_egress_network(&docker, &egress_config)
            .await
            .expect_err("an existing network with the wrong gateway must be rejected");
        assert!(
            error.to_string().contains("gateway"),
            "the fail-closed error must name the gateway mismatch: {error}"
        );

        best_effort_remove_network(&docker, SANDBOX_EGRESS_NETWORK_NAME).await;
    }

    /// Guards against the applied container's `HostConfig` diverging from
    /// `RebornSandboxConfig` — a limit can be coded into
    /// `user_container_launch_config` and unit-tested against the Rust
    /// `Config` struct while never actually taking effect against the real
    /// Docker daemon (e.g. a field docker silently ignores or overrides).
    /// This asserts against `docker inspect`'s own view, not the struct we
    /// built.
    #[tokio::test]
    async fn applied_container_limits_match_config_via_docker_inspect() {
        if !docker_gate::docker_available() {
            eprintln!(
                "SKIP: no docker daemon reachable — applied_container_limits_match_config_via_docker_inspect requires a real Docker daemon (CI/hosted Docker lane only)"
            );
            return;
        }
        let image = docker_gate::configured_sandbox_image();
        if !docker_gate::docker_image_available(&image) {
            eprintln!(
                "SKIP: sandbox worker image {image:?} is not built locally — requires a locally-built ironclaw-worker image (CI/hosted Docker lane only)"
            );
            return;
        }

        let docker = Docker::connect_with_local_defaults().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let config = docker_tests_config(temp.path());
        let tenant = ironclaw_host_api::ids::TenantId::new("limits-tenant").unwrap();
        let user = ironclaw_host_api::ids::UserId::new("limits-user").unwrap();
        // See `remove_labeled_test_containers`'s doc: a container leaked from
        // a prior local/CI run of this test carries the same fixed labels
        // but a bind-mount source `ensure_container` below cannot know is
        // stale — remove it before this run's fresh workspace exists.
        remove_labeled_test_containers(&docker, &tenant, &user).await;
        let key = RebornSandboxUserKey::from_tenant_user(&tenant, &user);
        let workspace = key.workspace_path(temp.path());
        create_writable_workspace(&config, &workspace).await;

        let network_ready = tokio::sync::OnceCell::new();
        let container_id = ensure_container(
            &docker,
            EnsureContainerRequest {
                config: &config,
                key: &key,
                tenant_id: &tenant,
                user_id: &user,
                workspace: &workspace,
                network_ready: &network_ready,
                attribution: None,
            },
        )
        .await
        .expect("ensure_container succeeds");

        let inspected = docker
            .inspect_container(&container_id, None::<InspectContainerOptions>)
            .await
            .expect("inspect succeeds");
        let host_config = inspected
            .host_config
            .expect("inspected container has a host config");

        assert_eq!(
            host_config.memory,
            Some(config.memory_bytes as i64),
            "applied memory limit must match config: {host_config:?}"
        );
        assert_eq!(
            host_config.cpu_shares,
            Some(config.cpu_shares as i64),
            "applied cpu_shares must match config: {host_config:?}"
        );
        assert_eq!(
            host_config.pids_limit,
            Some(SANDBOX_PIDS_LIMIT),
            "applied container must have the finite cgroup PID limit: {host_config:?}"
        );
        assert_eq!(
            host_config.readonly_rootfs,
            Some(true),
            "applied container must have a readonly rootfs: {host_config:?}"
        );
        let cap_drop = host_config.cap_drop.unwrap_or_default();
        assert!(
            cap_drop.iter().any(|cap| cap == "ALL"),
            "applied container must drop ALL capabilities: {cap_drop:?}"
        );
        let cap_add = host_config.cap_add.unwrap_or_default();
        assert!(
            cap_add.is_empty(),
            "the image entrypoint no longer execs `capsh --drop=all --user=sandbox` (removed \
             so the container never runs an init process with privilege-manipulating \
             capabilities), so nothing re-adds SETPCAP/SETUID/SETGID any more — applied \
             cap_add must be empty: {cap_add:?}"
        );
        let security_opt = host_config.security_opt.unwrap_or_default();
        assert!(
            security_opt
                .iter()
                .any(|opt| opt == "no-new-privileges:true"),
            "applied container must set no-new-privileges: {security_opt:?}"
        );

        // The container-create config itself must pin PID 1 to uid 1000 —
        // previously only `docker exec` identity was proven (every exec
        // already ran as uid 1000 via `SANDBOX_EXEC_USER`), leaving the
        // container's own init process (PID 1) running as root. That is the
        // actual gap this test guards: the *configured* User.
        assert_eq!(
            inspected.config.as_ref().and_then(|c| c.user.clone()),
            Some("1000:1000".to_string()),
            "applied container's configured User must be uid:gid 1000:1000, not root or the \
             `sandbox` username: {:?}",
            inspected.config
        );

        // ...and the *live* PID 1 itself, read via `/proc/1/status` from
        // inside the container's own pid namespace (an exec'd process always
        // shares PID 1's pid namespace, so this reflects the real init
        // process, not just the exec's own identity).
        let proc1_status = exec_in_container(
            &docker,
            &container_id,
            ContainerWorkdir::workspace_root(),
            Vec::new(),
            "cat /proc/1/status".to_string(),
            Duration::from_secs(10),
            4096,
        )
        .await
        .expect("exec reading /proc/1/status succeeds");
        let uid_line = proc1_status
            .output
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .unwrap_or_else(|| panic!("/proc/1/status must contain a Uid line: {proc1_status:?}"));
        assert!(
            uid_line
                .split_whitespace()
                .skip(1)
                .all(|field| field == "1000"),
            "PID 1 itself (the container's init process) must run as uid 1000, not root — \
             this is the actual root-init-window gap: {uid_line:?}"
        );

        best_effort_remove(&docker, &container_id).await;
    }

    /// Pins the property W5's planned CA trust distribution depends on: the
    /// persistent container's entrypoint (`docker/process-sandbox-
    /// entrypoint.sh`) must never attempt a `cp`/`update-ca-certificates`
    /// step, because that would run under uid 1000 with a readonly rootfs
    /// and fail — and `set -eu` would abort the entrypoint, so the
    /// container would never start. This builds the exact launch config
    /// `create_and_start_user_container` would produce, adds `SSL_CERT_FILE`
    /// (W5's planned trust-distribution mechanism), and asserts the
    /// container is still running once the entrypoint has run.
    #[tokio::test]
    async fn persistent_container_starts_with_ssl_cert_file_but_no_lockdown() {
        if !docker_gate::docker_available() {
            eprintln!(
                "SKIP: no docker daemon reachable — persistent_container_starts_with_ssl_cert_file_but_no_lockdown requires a real Docker daemon (CI/hosted Docker lane only)"
            );
            return;
        }
        let image = docker_gate::configured_sandbox_image();
        if !docker_gate::docker_image_available(&image) {
            eprintln!(
                "SKIP: sandbox worker image {image:?} is not built locally — requires a locally-built ironclaw-worker image (CI/hosted Docker lane only)"
            );
            return;
        }

        let docker = Docker::connect_with_local_defaults().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let config = docker_tests_config(temp.path());
        let tenant = ironclaw_host_api::ids::TenantId::new("ssl-cert-file-tenant").unwrap();
        let user = ironclaw_host_api::ids::UserId::new("ssl-cert-file-user").unwrap();
        let key = RebornSandboxUserKey::from_tenant_user(&tenant, &user);
        let workspace = key.workspace_path(temp.path());
        create_writable_workspace(&config, &workspace).await;

        let mut launch = user_container_launch_config(&config, &tenant, &user, &workspace)
            .await
            .expect("launch config builds");
        let mut env = launch.env.take().unwrap_or_default();
        // A real, readable file — the same CA bundle the base image already
        // installs via `ca-certificates` — so `[ -f "${SSL_CERT_FILE}" ]`
        // is true, exactly as it would be for W5's bind-mounted bundle.
        env.push("SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt".to_string());
        launch.env = Some(env);

        let container_name = format!("ironclaw-test-ssl-cert-file-{}", uuid::Uuid::new_v4());
        let created = docker
            .create_container(
                Some(CreateContainerOptions {
                    name: container_name,
                    platform: None,
                }),
                launch,
            )
            .await
            .expect("container create succeeds");
        docker
            .start_container(&created.id, None::<StartContainerOptions<String>>)
            .await
            .expect("container start succeeds");

        wait_until_running(&docker, &created.id)
            .await
            .expect("container reaches running state");

        // `wait_until_running`'s first successful poll can land in the
        // narrow window where Docker already reports `running: true` but a
        // failing entrypoint (e.g. `cp` into a read-only rootfs) is about to
        // exit the container milliseconds later via `set -eu` — a bare
        // single inspect right after start is not enough to distinguish
        // "started and stayed up" from "started and immediately aborted".
        // Give the entrypoint's synchronous setup work time to finish (or
        // fail) before re-checking that the container is still up.
        tokio::time::sleep(Duration::from_secs(1)).await;

        let inspected = docker
            .inspect_container(&created.id, None::<InspectContainerOptions>)
            .await
            .expect("inspect succeeds");
        let running = inspected
            .state
            .as_ref()
            .and_then(|state| state.running)
            .unwrap_or(false);
        assert!(
            running,
            "container with SSL_CERT_FILE set must still be running a second after the \
             entrypoint has run (regression: if the entrypoint ever grows a CA-install step \
             gated on SSL_CERT_FILE alone, `update-ca-certificates` under uid 1000 + readonly \
             rootfs would fail and `set -eu` would abort the entrypoint before it could exec \
             `sleep infinity`): {:?}",
            inspected.state
        );

        best_effort_remove(&docker, &created.id).await;
    }

    /// The container-side analogue of the egress-network posture tests
    /// above (W1.5's `ensure_egress_network_fails_closed_on_posture_
    /// mismatch`), but for the opposite outcome: a container is per-user and
    /// disposable, so `ensure_container` must recycle-and-recreate on a
    /// stale stamp rather than fail closed. Covers both halves of
    /// `ensure_container`'s label-driven branch in one flow: a container
    /// manually created with the old no-PID-limit `security_posture` is
    /// destroyed and replaced by a freshly stamped one (asserting the
    /// container ID changes, the stale container is actually gone, and the
    /// new one carries today's stamp); a second `ensure_container` call
    /// against that same, now-matching container reuses it untouched
    /// (asserting the ID does NOT change).
    #[tokio::test]
    async fn ensure_container_recycles_stale_stamp_then_reuses_matching_stamp() {
        if !docker_gate::docker_available() {
            eprintln!(
                "SKIP: no docker daemon reachable — ensure_container_recycles_stale_stamp_then_reuses_matching_stamp requires a real Docker daemon (CI/hosted Docker lane only)"
            );
            return;
        }
        let image = docker_gate::configured_sandbox_image();
        if !docker_gate::docker_image_available(&image) {
            eprintln!(
                "SKIP: sandbox worker image {image:?} is not built locally — requires a locally-built ironclaw-worker image (CI/hosted Docker lane only)"
            );
            return;
        }

        let docker = Docker::connect_with_local_defaults().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let config = docker_tests_config(temp.path());
        let tenant = ironclaw_host_api::ids::TenantId::new("posture-tenant").unwrap();
        let user = ironclaw_host_api::ids::UserId::new("posture-user").unwrap();
        // See `remove_labeled_test_containers`'s doc — this test also
        // creates a container under a deterministic name (`key.container_
        // name()` below), so a leftover from a prior run would additionally
        // fail this test's own `create_container` call with "name already
        // in use" on top of the stale-bind-mount defect.
        remove_labeled_test_containers(&docker, &tenant, &user).await;
        let key = RebornSandboxUserKey::from_tenant_user(&tenant, &user);
        let workspace = key.workspace_path(temp.path());
        create_writable_workspace(&config, &workspace).await;

        // Manually build and start a container carrying the right
        // tenant/user labels and a self-consistent pre-limit posture: both
        // HostConfig.pids_limit and its stamped posture omit the finite
        // limit. Docker has no
        // "update labels on an existing container" API, so a stale
        // container can only be simulated by creating one directly like
        // this, not by mutating a real one after the fact.
        let mut stale_launch = user_container_launch_config(&config, &tenant, &user, &workspace)
            .await
            .expect("launch config builds");
        stale_launch
            .host_config
            .as_mut()
            .expect("launch config has host config")
            .pids_limit = None;
        let mut stale_posture = security_posture_fields(&config);
        stale_posture.pids_limit = None;
        let mut stale_labels = stale_launch.labels.take().unwrap_or_default();
        stale_labels.insert(
            registry::label_security_posture(LABEL_PREFIX),
            security_posture_stamp(&stale_posture),
        );
        stale_launch.labels = Some(stale_labels);
        let stale_created = docker
            .create_container(
                Some(CreateContainerOptions {
                    name: key.container_name(),
                    platform: None,
                }),
                stale_launch,
            )
            .await
            .expect("stale-stamped container create succeeds");
        docker
            .start_container(&stale_created.id, None::<StartContainerOptions<String>>)
            .await
            .expect("stale-stamped container start succeeds");
        wait_until_running(&docker, &stale_created.id)
            .await
            .expect("stale-stamped container reaches running state");

        let network_ready = tokio::sync::OnceCell::new();
        let recreated_id = ensure_container(
            &docker,
            EnsureContainerRequest {
                config: &config,
                key: &key,
                tenant_id: &tenant,
                user_id: &user,
                workspace: &workspace,
                network_ready: &network_ready,
                attribution: None,
            },
        )
        .await
        .expect("ensure_container succeeds despite the stale stamp");

        assert_ne!(
            recreated_id, stale_created.id,
            "a container with a stale security-posture stamp must be recycled, not reused"
        );
        let stale_still_exists = docker
            .inspect_container(&stale_created.id, None::<InspectContainerOptions>)
            .await
            .is_ok();
        assert!(
            !stale_still_exists,
            "the stale-stamped container must have been destroyed, not left running alongside \
             the recreated one"
        );

        let recreated_inspect = docker
            .inspect_container(&recreated_id, None::<InspectContainerOptions>)
            .await
            .expect("recreated container inspects");
        let recreated_stamp = recreated_inspect
            .config
            .as_ref()
            .and_then(|c| c.labels.as_ref())
            .and_then(|labels| labels.get(&registry::label_security_posture(LABEL_PREFIX)))
            .cloned()
            .expect("recreated container must carry a security-posture label");
        assert_eq!(
            recreated_stamp,
            security_posture_stamp(&security_posture_fields(&config)),
            "the recreated container must carry today's expected posture stamp"
        );
        assert_eq!(
            recreated_inspect
                .host_config
                .as_ref()
                .and_then(|host_config| host_config.pids_limit),
            Some(SANDBOX_PIDS_LIMIT),
            "the container replacing the no-limit posture must apply the finite PID limit"
        );

        // Second call: the recreated container's stamp now matches, so it
        // must be reused untouched — no recycle, same container ID.
        let reused_id = ensure_container(
            &docker,
            EnsureContainerRequest {
                config: &config,
                key: &key,
                tenant_id: &tenant,
                user_id: &user,
                workspace: &workspace,
                network_ready: &network_ready,
                attribution: None,
            },
        )
        .await
        .expect("ensure_container succeeds on the matching-stamp path");
        assert_eq!(
            reused_id, recreated_id,
            "a container whose stamp already matches must be reused, not recreated"
        );

        best_effort_remove(&docker, &recreated_id).await;
    }

    /// RUN-001: a persistent container created while the sandbox egress
    /// proxy trusted CA-A must NOT be reused once the live config's CA
    /// bundle rotates to CA-B (the exact shape of a host-process restart:
    /// `ca.rs`'s root is regenerated fresh in memory on every process
    /// start, but `ensure_container` is designed to find and reuse the
    /// container that already exists for this `{tenant, user}` pair).
    /// Drives the real `ensure_container` caller with two configs that
    /// differ only in `ca_bundle_pem` — not a hand-forged label — so this
    /// pins the production posture-stamp comparison, not a helper in
    /// isolation. Before the fix, `SecurityPostureFields` carried no CA
    /// identity, so the second call would reuse the CA-A container
    /// unchanged and every intercepted bound-host request inside it would
    /// then fail TLS verification against the new CA-B leaf certificates.
    #[tokio::test]
    async fn ensure_container_recycles_when_ca_bundle_rotates() {
        if !docker_gate::docker_available() {
            eprintln!(
                "SKIP: no docker daemon reachable — ensure_container_recycles_when_ca_bundle_rotates requires a real Docker daemon (CI/hosted Docker lane only)"
            );
            return;
        }
        let image = docker_gate::configured_sandbox_image();
        if !docker_gate::docker_image_available(&image) {
            eprintln!(
                "SKIP: sandbox worker image {image:?} is not built locally — requires a locally-built ironclaw-worker image (CI/hosted Docker lane only)"
            );
            return;
        }

        let docker = Docker::connect_with_local_defaults().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let tenant = ironclaw_host_api::ids::TenantId::new("ca-rotate-tenant").unwrap();
        let user = ironclaw_host_api::ids::UserId::new("ca-rotate-user").unwrap();
        remove_labeled_test_containers(&docker, &tenant, &user).await;
        let key = RebornSandboxUserKey::from_tenant_user(&tenant, &user);
        let workspace = key.workspace_path(temp.path());

        let config_ca_a = docker_tests_config(temp.path()).with_ca_bundle_pem(
            "-----BEGIN CERTIFICATE-----\nfake-ca-a-bundle\n-----END CERTIFICATE-----\n",
        );
        create_writable_workspace(&config_ca_a, &workspace).await;

        let network_ready = tokio::sync::OnceCell::new();
        let container_under_ca_a = ensure_container(
            &docker,
            EnsureContainerRequest {
                config: &config_ca_a,
                key: &key,
                tenant_id: &tenant,
                user_id: &user,
                workspace: &workspace,
                network_ready: &network_ready,
                attribution: None,
            },
        )
        .await
        .expect("ensure_container succeeds under CA-A");

        // Sanity: an unrelated second call under the SAME config (the
        // steady-state case — no proxy restart) must reuse the container.
        let reused_under_ca_a = ensure_container(
            &docker,
            EnsureContainerRequest {
                config: &config_ca_a,
                key: &key,
                tenant_id: &tenant,
                user_id: &user,
                workspace: &workspace,
                network_ready: &network_ready,
                attribution: None,
            },
        )
        .await
        .expect("ensure_container succeeds on the repeat CA-A call");
        assert_eq!(
            reused_under_ca_a, container_under_ca_a,
            "same CA, same posture: the container must be reused, not recreated"
        );

        // Simulates a host-process restart: same tenant/user/workspace, but
        // the egress proxy minted a brand-new CA root this time.
        let config_ca_b = docker_tests_config(temp.path()).with_ca_bundle_pem(
            "-----BEGIN CERTIFICATE-----\nfake-ca-b-bundle\n-----END CERTIFICATE-----\n",
        );
        let container_under_ca_b = ensure_container(
            &docker,
            EnsureContainerRequest {
                config: &config_ca_b,
                key: &key,
                tenant_id: &tenant,
                user_id: &user,
                workspace: &workspace,
                network_ready: &network_ready,
                attribution: None,
            },
        )
        .await
        .expect("ensure_container succeeds under CA-B");

        assert_ne!(
            container_under_ca_b, container_under_ca_a,
            "a container created under CA-A must be recycled, not reused, once the live \
             config's CA bundle rotates to CA-B — otherwise it keeps trusting the old root \
             while the proxy signs with the new one and every bound-host TLS request inside \
             it fails verification"
        );
        let ca_a_container_still_exists = docker
            .inspect_container(&container_under_ca_a, None::<InspectContainerOptions>)
            .await
            .is_ok();
        assert!(
            !ca_a_container_still_exists,
            "the CA-A container must have been destroyed on rotation, not left running \
             alongside the recreated one"
        );

        best_effort_remove(&docker, &container_under_ca_b).await;
    }

    /// Creates and starts a plain `busybox` container on `network_name`,
    /// pinned to a static `ipv4_address` and carrying `labels` — a
    /// deterministic stand-in for "Docker reassigns a torn-down container's
    /// IP to a different container." Real Docker IP reuse is real (it's the
    /// exact mechanism `attribution`'s module doc names as the reason the
    /// cache needs bounded TTL + invalidation), but which address gets
    /// reused depends on subnet-pool state; pinning both the torn-down and
    /// the reassigned container to the same address makes the scenario
    /// reproducible without depending on exhausting the /24 pool. Mirrors
    /// `start_probe_container` above (plain busybox — these tests don't
    /// need the sandbox worker image's exec/workdir conventions), plus an
    /// explicit `NetworkingConfig` endpoint pin and labels.
    async fn create_ip_pinned_labeled_container(
        docker: &Docker,
        network_name: &str,
        ipv4_address: &str,
        name: &str,
        labels: HashMap<String, String>,
    ) -> String {
        let mut endpoints_config = HashMap::new();
        endpoints_config.insert(
            network_name.to_string(),
            EndpointSettings {
                ipam_config: Some(EndpointIpamConfig {
                    ipv4_address: Some(ipv4_address.to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let created = docker
            .create_container(
                Some(CreateContainerOptions {
                    name: name.to_string(),
                    platform: None,
                }),
                Config {
                    image: Some("busybox:1.36".to_string()),
                    cmd: Some(vec!["sleep".to_string(), "60".to_string()]),
                    labels: Some(labels),
                    host_config: Some(HostConfig {
                        network_mode: Some(network_name.to_string()),
                        auto_remove: Some(false),
                        ..Default::default()
                    }),
                    networking_config: Some(NetworkingConfig { endpoints_config }),
                    ..Default::default()
                },
            )
            .await
            .expect("ip-pinned container create succeeds");
        docker
            .start_container(&created.id, None::<StartContainerOptions<String>>)
            .await
            .expect("ip-pinned container start succeeds");
        created.id
    }

    /// **The W17 deliverable.** Proves the actual defect is closed: an IP
    /// whose container was torn down through the real, wired teardown call
    /// site (`recycle_stale_container`, called from `ensure_container`'s
    /// posture-mismatch branch) and reassigned to a *different* user's
    /// container does NOT resolve to the previous owner. Before W17's fix,
    /// `recycle_stale_container` removed the container but never told the
    /// attribution cache, so `attributed_after_recycle` below would still
    /// equal container A's tenant/user for up to
    /// `DEFAULT_ATTRIBUTION_CACHE_TTL` (5s) — exactly the cross-user
    /// credential-leak window this closes ahead of W6.
    #[tokio::test]
    async fn recycle_stale_container_invalidates_attribution_for_the_released_ip() {
        if !docker_gate::docker_available() {
            eprintln!(
                "SKIP: no docker daemon reachable — recycle_stale_container_invalidates_attribution_for_the_released_ip requires a real Docker daemon (CI/hosted Docker lane only)"
            );
            return;
        }

        let _network_guard = EGRESS_NETWORK_TEST_LOCK.lock().await;
        let docker = Docker::connect_with_local_defaults().unwrap();
        recreate_real_egress_network(&docker).await;

        // Fixed rather than Docker-chosen — see
        // `create_ip_pinned_labeled_container`'s doc comment.
        let pinned_ip = "10.200.0.222";
        let ip: IpAddr = pinned_ip.parse().unwrap();

        let tenant_a = TenantId::new("attribution-recycle-tenant-a").unwrap();
        let user_a = UserId::new("attribution-recycle-user-a").unwrap();
        let tenant_b = TenantId::new("attribution-recycle-tenant-b").unwrap();
        let user_b = UserId::new("attribution-recycle-user-b").unwrap();

        let container_a = create_ip_pinned_labeled_container(
            &docker,
            SANDBOX_EGRESS_NETWORK_NAME,
            pinned_ip,
            &format!("ironclaw-test-recycle-a-{}", uuid::Uuid::new_v4()),
            registry::build_user_container_labels(
                LABEL_PREFIX,
                &tenant_a,
                &user_a,
                "w17-test-posture-stamp",
            ),
        )
        .await;

        let resolver = attribution::ConnectionAttributionResolver::new(
            docker.clone(),
            SANDBOX_EGRESS_NETWORK_NAME.to_string(),
            LABEL_PREFIX.to_string(),
        );

        let attributed_a = resolver.resolve(ip).await;
        assert_eq!(
            attributed_a,
            attribution::ConnectionAttribution::Attributed {
                tenant_id: tenant_a.clone(),
                user_id: user_a.clone(),
            },
            "sanity: container A must resolve to tenant-a/user-a before teardown, or the rest \
             of this test proves nothing"
        );

        // The real teardown call site under test: with attribution wired,
        // tearing down container A must invalidate the cache entry for the
        // IP it releases, not just remove the container.
        recycle_stale_container(&docker, &container_a, Some(ip), Some(&resolver))
            .await
            .expect("recycle succeeds");

        // Simulate Docker handing the just-released IP to a DIFFERENT
        // user's container.
        let container_b = create_ip_pinned_labeled_container(
            &docker,
            SANDBOX_EGRESS_NETWORK_NAME,
            pinned_ip,
            &format!("ironclaw-test-recycle-b-{}", uuid::Uuid::new_v4()),
            registry::build_user_container_labels(
                LABEL_PREFIX,
                &tenant_b,
                &user_b,
                "w17-test-posture-stamp",
            ),
        )
        .await;

        let attributed_after_recycle = resolver.resolve(ip).await;

        best_effort_remove(&docker, &container_b).await;

        assert_eq!(
            attributed_after_recycle,
            attribution::ConnectionAttribution::Attributed {
                tenant_id: tenant_b,
                user_id: user_b,
            },
            "regression: a torn-down container's cached attribution must not survive to serve \
             a different user's container that Docker reassigns the same IP to — this is the \
             cross-user credential-leak window W17 closes"
        );
    }
}
