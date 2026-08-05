//! Reborn-native user sandbox command transport.
//!
//! The transport derives host workspace and container identity from the full
//! [`ResourceScope`]. It deliberately avoids the legacy project-only sandbox
//! lifecycle so hosted tenants with matching user/project strings cannot share
//! command state.

use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bollard::Docker;
use ironclaw_host_api::{ids::InvocationId, mount::MountView, resource::ResourceScope};

use crate::{
    CommandExecutionOutput, CommandExecutionRequest, RuntimeProcessError, SandboxCommandTransport,
    UserSandboxProcessPort, process_output::sanitize_command_output_bytes,
};

mod attribution;
mod broker;
mod ca;
mod connect;
mod container_identity;
mod credential_firewall;
#[cfg(test)]
pub(crate) use credential_firewall::SandboxCredentialConnectionIdentity;
mod credential_swap;
mod egress_proxy;
mod exec_transport;
mod key_codec;
mod mounts;
mod network_allowlist;
mod railway;
mod reaper;
mod registry;
mod scope_key;
pub(crate) mod shell_limits;
mod tls_intercept;
mod user_key;
mod worker_spec;

use shell_limits::{clamp_shell_output_limit_bytes, clamp_shell_timeout_secs};

pub use attribution::ConnectionAttributionResolver;
pub use broker::RebornSandboxNetworkBroker;
pub use connect::{SandboxDockerReadiness, connect_docker_with_retry, sandbox_docker_readiness};
pub use container_identity::{RebornSandboxContainerIdentity, RebornSandboxWorkspaceMode};
pub use credential_swap::SandboxCredentialRuntime;
pub(crate) use credential_swap::SandboxStaticCredentialGrant;
pub use egress_proxy::{
    BoundEgressAllowlistProxy, EgressAllowlistProxy, EgressProxyError, SandboxEgressProxyBinding,
    bind_sandbox_egress_proxy_with_tls_intercept,
};
pub use network_allowlist::{
    DEFAULT_SANDBOX_ALLOWED_DOMAINS, DEFAULT_SANDBOX_MAX_EGRESS_BYTES,
    SANDBOX_EXTRA_ALLOWED_DOMAINS_ENV, SANDBOX_MAX_EGRESS_BYTES_ENV, sandbox_allowed_domains,
    sandbox_extra_allowed_domains, sandbox_max_egress_bytes, sandbox_network_policy,
};
pub use railway::{RailwayPreviewSandboxConfig, RailwayPreviewSandboxTransport};
pub use reaper::{ReapSummary, SandboxReaper, SandboxReaperConfig};
pub use registry::SandboxActivityRegistry;
pub use scope_key::RebornSandboxScopeKey;
pub use user_key::RebornSandboxUserKey;

/// Creates or verifies the internal Docker network used by brokered sandbox
/// egress. This initializes shared sandbox infrastructure only; it does not
/// create or start a per-user sandbox container.
pub async fn prepare_sandbox_egress_network() -> Result<(), RuntimeProcessError> {
    let docker = connect_docker_with_retry().await?;
    exec_transport::ensure_default_egress_network(&docker).await
}

/// Address on which the host-side proxy must listen to be reachable from the
/// production internal sandbox network.
pub fn sandbox_egress_proxy_bind_addr() -> String {
    broker::sandbox_egress_proxy_bind_addr()
}

/// Docker label prefix for container metadata attached by
/// [`RebornScopedSandboxCommandTransport`] — shared with [`reaper`] so the
/// reaper's container-listing filter and this transport's container-creation
/// labels never drift apart.
const LABEL_PREFIX: &str = "ironclaw";

const DEFAULT_IMAGE: &str = "ironclaw-worker:latest";
// Sourced from `shell_limits` so the config-level default and the per-call
// clamp default (used when the model omits `timeout`/`output_limit`) can
// never drift apart. The per-call ceilings (`SHELL_TIMEOUT_MAX_SECS`,
// `SHELL_OUTPUT_LIMIT_MAX_BYTES`) are applied in `execute_in_container`.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(shell_limits::SHELL_TIMEOUT_DEFAULT_SECS);
const DEFAULT_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_CPU_SHARES: u32 = 1024;
const DEFAULT_MAX_OUTPUT_BYTES: usize = shell_limits::SHELL_OUTPUT_LIMIT_DEFAULT_BYTES as usize;
const CONTAINER_WORKSPACE_ROOT: &str = "/workspace";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContainerWorkdir(String);

impl ContainerWorkdir {
    fn workspace_root() -> Self {
        Self(CONTAINER_WORKSPACE_ROOT.to_string())
    }

    fn from_relative(relative: impl AsRef<Path>) -> Self {
        let relative = relative.as_ref().to_string_lossy();
        if relative.is_empty() || relative == "." {
            return Self::workspace_root();
        }
        Self(format!(
            "{CONTAINER_WORKSPACE_ROOT}/{}",
            relative.trim_start_matches('/')
        ))
    }

    fn into_string(self) -> String {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct RebornSandboxConfig {
    workspace_root: PathBuf,
    image: String,
    default_timeout: Duration,
    memory_bytes: u64,
    cpu_shares: u32,
    max_output_bytes: usize,
    disable_network: bool,
    network_broker: Option<RebornSandboxNetworkBroker>,
    container_identity: RebornSandboxContainerIdentity,
    /// PEM container trust bundle (system roots + the sandbox egress
    /// proxy's CA public root certificate — see
    /// `ca::SandboxCertificateAuthority::build_container_trust_bundle_pem`,
    /// no private key material) to bind-mount read-only into every
    /// container this config launches. `None` means no TLS interception is
    /// configured for this transport (e.g. direct construction in a test)
    /// — `exec_transport::user_container_launch_config` then adds neither
    /// the bind nor the `SSL_CERT_FILE`-family env vars, exactly
    /// reproducing pre-W5 behavior. Set via [`Self::with_ca_bundle_pem`].
    ca_bundle_pem: Option<String>,
}

impl RebornSandboxConfig {
    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            image: std::env::var("IRONCLAW_REBORN_SANDBOX_IMAGE")
                .or_else(|_| std::env::var("IRONCLAW_SANDBOX_IMAGE"))
                .unwrap_or_else(|_| DEFAULT_IMAGE.to_string()),
            default_timeout: DEFAULT_TIMEOUT,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            cpu_shares: DEFAULT_CPU_SHARES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            disable_network: true,
            network_broker: None,
            container_identity: RebornSandboxContainerIdentity::image_default(),
            ca_bundle_pem: None,
        }
    }

    pub fn with_image(mut self, image: impl Into<String>) -> Self {
        self.image = image.into();
        self
    }

    pub fn with_default_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    pub fn with_network_enabled(mut self) -> Self {
        self.disable_network = false;
        self
    }

    pub fn with_network_broker_port(mut self, port: u16) -> Self {
        self.network_broker = Some(RebornSandboxNetworkBroker::from_port(port));
        self
    }

    /// Wires the sandbox egress proxy's container trust bundle (system
    /// roots plus its CA's public root certificate — see
    /// [`SandboxEgressProxyBinding::ca_bundle_pem`](super::egress_proxy::SandboxEgressProxyBinding))
    /// into every container this config launches. `exec_transport::
    /// user_container_launch_config` materializes `ca_bundle_pem` to a host
    /// file under this config's `workspace_root`, bind-mounts it read-only,
    /// and points `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`/
    /// `GIT_SSL_CAINFO`/`NODE_EXTRA_CA_CERTS` at it — this is W5's CA
    /// trust-distribution wiring
    /// (`crates/ironclaw_host_runtime/src/sandbox_process/ca.rs`'s module
    /// doc). Composition
    /// (`ironclaw_reborn_composition::sandbox_boot::user_sandbox_process_binding`)
    /// is the only production caller, threading the SAME bundle the egress
    /// proxy's `TlsInterceptConfig` mints leaf certificates from — a
    /// mismatched bundle here would make every bound-host CONNECT fail
    /// certificate verification inside the container.
    pub fn with_ca_bundle_pem(mut self, ca_bundle_pem: impl Into<String>) -> Self {
        self.ca_bundle_pem = Some(ca_bundle_pem.into());
        self
    }

    pub fn with_container_identity(mut self, identity: RebornSandboxContainerIdentity) -> Self {
        self.container_identity = identity;
        self
    }

    pub fn with_container_user(
        mut self,
        user: impl Into<String>,
        workspace_mode: RebornSandboxWorkspaceMode,
    ) -> Self {
        self.container_identity =
            RebornSandboxContainerIdentity::configured_user(user, workspace_mode);
        self
    }

    /// Docker `--network` value for the sandbox container.
    ///
    /// - `disable_network: false` (`with_network_enabled`, unused in
    ///   production today): `None` (Docker default bridge) — a deliberate
    ///   fully-open mode, unrelated to the brokered-egress case below.
    /// - `disable_network: true` with no broker: `Some("none")` — no network
    ///   interfaces at all.
    /// - `disable_network: true` with a network broker configured: joins the
    ///   pinned internal network (`broker::SANDBOX_EGRESS_NETWORK_NAME`)
    ///   instead of the default bridge. **E1**: the default bridge NATs to
    ///   the internet, so a container there could dial out directly and
    ///   ignore the proxy env — "proxy-allowlist egress" would be advisory,
    ///   not enforced. The internal network has no route off-host except
    ///   back to its own gateway, where the proxy is reached (see
    ///   `broker::SANDBOX_EGRESS_NETWORK_GATEWAY` and
    ///   `exec_transport::ensure_egress_network`, which creates the network
    ///   idempotently before a container joins it).
    fn container_network_mode(&self) -> Option<String> {
        if !self.disable_network {
            return None;
        }
        if self.network_broker.is_some() {
            Some(broker::SANDBOX_EGRESS_NETWORK_NAME.to_string())
        } else {
            Some("none".to_string())
        }
    }

    fn command_env(
        &self,
        extra_env: HashMap<String, String>,
    ) -> Result<Vec<String>, RuntimeProcessError> {
        let mut env = validate_env(extra_env)?;
        broker::push_broker_env(self.network_broker.as_ref(), &mut env)?;
        Ok(env)
    }

    fn command_env_for_invocation(
        &self,
        extra_env: HashMap<String, String>,
        invocation_id: InvocationId,
    ) -> Result<Vec<String>, RuntimeProcessError> {
        if !extra_env.is_empty() {
            return Err(RuntimeProcessError::ExecutionFailed(
                "user sandbox does not accept caller-provided environment variables".to_string(),
            ));
        }
        let mut env = Vec::new();
        broker::push_broker_env_for_invocation(
            self.network_broker.as_ref(),
            &mut env,
            invocation_id,
        )?;
        Ok(env)
    }
}

#[derive(Clone)]
pub struct RebornScopedSandboxCommandTransport {
    docker: Docker,
    config: RebornSandboxConfig,
    activity: Arc<SandboxActivityRegistry>,
    /// Gates the egress network's idempotent-but-not-free create attempt
    /// (see `exec_transport::ensure_egress_network_once`) to once per
    /// process instead of once per command dispatch.
    network_ready: Arc<tokio::sync::OnceCell<()>>,
    /// Wired so `exec_transport::ensure_container`'s posture-mismatch
    /// recycle collapses the egress-proxy attribution cache's staleness
    /// window to zero for the IP the recycled container releases (see
    /// `attribution`'s module doc, "W17"). Production composition always
    /// wires this via [`Self::with_attribution_resolver`]
    /// (`ironclaw_reborn_composition::sandbox_boot::user_sandbox_process_binding`);
    /// `None` only for callers that construct a transport directly (tests,
    /// or a future non-sandboxed caller that has no attribution cache to
    /// invalidate).
    ///
    /// Concrete type, not `Arc<dyn AttributionInvalidator>`: that trait had
    /// exactly one impl and zero callers of the dyn-erased path, so it was
    /// collapsed (see `attribution`'s module doc).
    attribution: Option<Arc<attribution::ConnectionAttributionResolver>>,
}

impl std::fmt::Debug for RebornScopedSandboxCommandTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RebornScopedSandboxCommandTransport")
            .field("workspace_root", &self.config.workspace_root)
            .field("image", &self.config.image)
            .field("disable_network", &self.config.disable_network)
            .field("network_broker", &self.config.network_broker)
            .field("container_identity", &self.config.container_identity)
            .finish_non_exhaustive()
    }
}

impl RebornScopedSandboxCommandTransport {
    pub async fn connect(config: RebornSandboxConfig) -> Result<Self, RuntimeProcessError> {
        let docker = connect_docker_with_retry().await?;
        Ok(Self::new(docker, config))
    }

    pub fn new(docker: Docker, config: RebornSandboxConfig) -> Self {
        Self {
            docker,
            config,
            activity: Arc::new(SandboxActivityRegistry::new()),
            network_ready: Arc::new(tokio::sync::OnceCell::new()),
            attribution: None,
        }
    }

    /// Overrides the default activity registry with one shared elsewhere
    /// (e.g. with a [`SandboxReaper`] instance), so both observe the same
    /// per-user last-activity timestamps. Composition wiring is the
    /// expected caller.
    pub fn with_activity_registry(mut self, activity: Arc<SandboxActivityRegistry>) -> Self {
        self.activity = activity;
        self
    }

    /// Wires a shared attribution-cache invalidator (see
    /// [`Self::attribution`]'s doc). Composition
    /// (`ironclaw_reborn_composition::sandbox_boot::user_sandbox_process_binding`)
    /// is the production caller: it builds one
    /// [`attribution::ConnectionAttributionResolver::for_sandbox_egress`]
    /// instance and wires the SAME `Arc` here and into
    /// [`super::reaper::SandboxReaper::with_attribution_resolver`].
    pub fn with_attribution_resolver(
        mut self,
        resolver: Arc<attribution::ConnectionAttributionResolver>,
    ) -> Self {
        self.attribution = Some(resolver);
        self
    }

    pub fn into_process_port(self) -> UserSandboxProcessPort {
        UserSandboxProcessPort::new(Arc::new(self))
    }

    /// Initializes (and returns) the per-user host workspace directory that
    /// backs the persistent container's flat `/workspace` bind — every
    /// thread/project/agent for the same `{tenant, user}` pair shares this
    /// one directory, matching the container reuse in `exec_transport`. Also
    /// seeds `.home` (owner-only) so `HOME=/workspace/.home` (set in
    /// `exec_transport::user_container_launch_config`) always resolves to a
    /// real, private directory.
    async fn prepare_workspace(
        &self,
        scope: &ResourceScope,
    ) -> Result<PathBuf, RuntimeProcessError> {
        let key = RebornSandboxUserKey::from_scope(scope);
        let workspace = key.workspace_path(&self.config.workspace_root);
        #[cfg(unix)]
        {
            let workspace_root = self.config.workspace_root.clone();
            let workspace_mode = self.config.container_identity.workspace_mode();
            tokio::task::spawn_blocking(move || {
                prepare_workspace_unix(&workspace_root, &workspace, workspace_mode)
            })
            .await
            .map_err(|error| {
                RuntimeProcessError::ExecutionFailed(format!(
                    "sandbox workspace initialization task did not complete: {error}"
                ))
            })?
        }

        // Non-Unix hosts do not expose the dirfd-relative APIs used above.
        // Preserve their existing directory-creation behavior explicitly;
        // Unix ownership and mode changes have never applied on these hosts.
        #[cfg(not(unix))]
        {
            tokio::fs::create_dir_all(&workspace)
                .await
                .map_err(|error| {
                    RuntimeProcessError::ExecutionFailed(format!(
                        "sandbox workspace could not be initialized: {error}"
                    ))
                })?;
            let home = workspace.join(".home");
            tokio::fs::create_dir_all(&home).await.map_err(|error| {
                RuntimeProcessError::ExecutionFailed(format!(
                    "sandbox workspace HOME could not be initialized: {error}"
                ))
            })?;
            tokio::fs::canonicalize(&workspace).await.map_err(|error| {
                RuntimeProcessError::ExecutionFailed(format!(
                    "sandbox workspace could not be resolved: {error}"
                ))
            })
        }
    }

    fn resolve_container_workdir(
        workdir: Option<&str>,
    ) -> Result<ContainerWorkdir, RuntimeProcessError> {
        let Some(workdir) = workdir.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(ContainerWorkdir::workspace_root());
        };
        reject_nul("sandbox working directory", workdir)?;
        if workdir == CONTAINER_WORKSPACE_ROOT {
            return Ok(ContainerWorkdir::workspace_root());
        }
        if let Some(relative) = workdir.strip_prefix("/workspace/") {
            validate_relative_workdir(Path::new(relative))?;
            return Ok(ContainerWorkdir::from_relative(relative));
        }

        let requested = Path::new(workdir);
        if requested.is_absolute() {
            Err(RuntimeProcessError::ExecutionFailed(
                "sandbox working directory must be workspace-relative or under /workspace"
                    .to_string(),
            ))
        } else {
            validate_relative_workdir(requested)?;
            Ok(ContainerWorkdir::from_relative(requested))
        }
    }
}

#[cfg(unix)]
fn prepare_workspace_unix(
    workspace_root: &Path,
    workspace: &Path,
    workspace_mode: u32,
) -> Result<PathBuf, RuntimeProcessError> {
    use std::{
        ffi::{CString, OsStr},
        fs::OpenOptions,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        },
    };

    fn execution_failed(context: &str, error: impl std::fmt::Display) -> RuntimeProcessError {
        RuntimeProcessError::ExecutionFailed(format!("{context}: {error}"))
    }

    fn directory_name(name: &OsStr, context: &str) -> Result<CString, RuntimeProcessError> {
        CString::new(name.as_bytes()).map_err(|error| execution_failed(context, error))
    }

    fn create_or_open_directory_at(
        parent: &OwnedFd,
        name: &OsStr,
        create_mode: u32,
        context: &str,
    ) -> Result<OwnedFd, RuntimeProcessError> {
        let name = directory_name(name, context)?;
        // SAFETY: `parent` is a live directory descriptor and `name` is a
        // NUL-terminated, single path component. Failure is checked below.
        let mkdir_result = unsafe {
            libc::mkdirat(
                parent.as_raw_fd(),
                name.as_ptr(),
                create_mode as libc::mode_t,
            )
        };
        if mkdir_result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(execution_failed(context, error));
            }
        }

        // SAFETY: the same valid dirfd and CString are used for `openat`.
        // O_NOFOLLOW rejects a symlink occupying this component, while the
        // returned descriptor pins the verified directory against renames.
        let raw_fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw_fd < 0 {
            return Err(execution_failed(context, std::io::Error::last_os_error()));
        }
        // SAFETY: `openat` returned a new owned descriptor on success.
        Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
    }

    fn set_sandbox_writable_permissions_fd(
        directory: &OwnedFd,
        mode: u32,
        context: &str,
    ) -> Result<(), RuntimeProcessError> {
        // SAFETY: `directory` is an owned descriptor returned by an
        // O_DIRECTORY|O_NOFOLLOW open. `fchown` cannot traverse a path.
        let chowned = unsafe {
            libc::fchown(
                directory.as_raw_fd(),
                exec_transport::SANDBOX_EXEC_UID,
                exec_transport::SANDBOX_EXEC_GID,
            )
        } == 0;
        // Preserve the existing local-development fallback when the host
        // lacks permission to chown to the fixed sandbox uid/gid.
        let effective_mode = if chowned { mode } else { mode | 0o007 };
        // SAFETY: `directory` remains live and verified as a directory.
        if unsafe { libc::fchmod(directory.as_raw_fd(), effective_mode as libc::mode_t) } != 0 {
            return Err(execution_failed(context, std::io::Error::last_os_error()));
        }
        Ok(())
    }

    std::fs::create_dir_all(workspace_root).map_err(|error| {
        execution_failed("sandbox workspace root could not be initialized", error)
    })?;
    let canonical_root = std::fs::canonicalize(workspace_root)
        .map_err(|error| execution_failed("sandbox workspace root could not be resolved", error))?;
    let root_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&canonical_root)
        .map_err(|error| execution_failed("sandbox workspace root could not be opened", error))?;
    let mut directory = OwnedFd::from(root_file);
    let relative_workspace = workspace.strip_prefix(workspace_root).map_err(|error| {
        execution_failed("sandbox workspace escaped its configured root", error)
    })?;
    for component in relative_workspace.components() {
        let Component::Normal(name) = component else {
            return Err(RuntimeProcessError::ExecutionFailed(
                "sandbox workspace path contains an invalid component".to_string(),
            ));
        };
        directory = create_or_open_directory_at(
            &directory,
            name,
            0o777,
            "sandbox workspace child could not be initialized",
        )?;
    }
    set_sandbox_writable_permissions_fd(
        &directory,
        workspace_mode,
        "sandbox workspace permissions could not be set",
    )?;

    let home = create_or_open_directory_at(
        &directory,
        OsStr::new(".home"),
        0o700,
        "sandbox workspace HOME could not be initialized",
    )?;
    set_sandbox_writable_permissions_fd(
        &home,
        0o700,
        "sandbox workspace HOME permissions could not be set",
    )?;

    Ok(canonical_root.join(relative_workspace))
}

/// Redact secret-shaped content out of a sandboxed command's raw combined
/// stdout/stderr before it becomes model-visible.
///
/// Docker exec output reaches [`RebornScopedSandboxCommandTransport::run_command`]
/// as a raw string with no pass through `LeakDetector` at all — unlike
/// [`crate::process_port::HostProcessPort`], which routes every command's
/// output through `capture_command_output` -> `sanitize_command_output_bytes`
/// before it becomes model-visible. Without this, a sandboxed shell command
/// that echoes a `.env` value or an API-key-shaped token would reach the
/// model verbatim. This reuses the exact same chokepoint the host path uses
/// (`sanitize_command_output_bytes`) rather than threading the sandbox path
/// through the `StreamCapture`/saved-output-file machinery
/// `capture_command_output` also does — that machinery is shaped for
/// `AsyncRead` child-process pipes and does not fit the already-materialized
/// Docker log-stream string this transport produces.
fn redact_sandbox_command_output(raw_output: &str) -> String {
    sanitize_command_output_bytes(raw_output.as_bytes(), raw_output.to_string()).preview
}

#[cfg(any(test, feature = "test-support"))]
mod test_support {
    use super::*;

    impl RebornScopedSandboxCommandTransport {
        /// Test-only introspection for the production attribution wiring.
        pub fn attribution_for_test(
            &self,
        ) -> Option<Arc<attribution::ConnectionAttributionResolver>> {
            self.attribution.clone()
        }
    }
}

#[async_trait]
impl SandboxCommandTransport for RebornScopedSandboxCommandTransport {
    async fn run_command(
        &self,
        request: CommandExecutionRequest,
    ) -> Result<CommandExecutionOutput, RuntimeProcessError> {
        reject_nul("sandbox command", &request.command)?;
        reject_background_request(request.background)?;
        // Phase A scope narrowing: a persistent container's binds are fixed
        // at creation time from the flat per-user `/workspace` bind only
        // (`exec_transport::user_container_launch_config` always resolves
        // binds with `mounts: None`) — a later request naming a scoped
        // `MountView` grant can never be retrofitted onto an already-running
        // container, so it is rejected up front rather than silently
        // ignored.
        reject_non_workspace_mount_grants(request.mounts.as_ref())?;
        // Reject caller-controlled environment before touching per-user state
        // or provisioning a container. PR1 exposes no environment injection
        // surface; only the fixed worker environment is permitted.
        let env = self
            .config
            .command_env_for_invocation(request.extra_env, request.scope.invocation_id)?;

        let key = RebornSandboxUserKey::from_scope(&request.scope);
        // Lifecycle mutation is serialized per user. Mark the invocation
        // active while holding the same gate the reaper uses, then retain the
        // RAII lease across container setup and exec. This closes both the
        // concurrent-first-create race and reaper-vs-invocation teardown race
        // without making unrelated users wait on each other.
        let lifecycle_guard = self.activity.lock_user_lifecycle(&key).await;
        let _invocation_lease = self.activity.begin_invocation(&key);
        let workspace = self.prepare_workspace(&request.scope).await?;
        let workdir = Self::resolve_container_workdir(request.workdir.as_deref())?;
        // Clamp to `[SHELL_TIMEOUT_MIN_SECS, SHELL_TIMEOUT_MAX_SECS]` — the
        // model-adjustable `timeout` field is bounded by the operator
        // ceiling here rather than rejected when it overshoots.
        let requested_secs = request
            .timeout_secs
            .unwrap_or(self.config.default_timeout.as_secs());
        let timeout = clamp_shell_timeout_secs(Some(requested_secs));
        // Clamp to `[SHELL_OUTPUT_LIMIT_MIN_BYTES, SHELL_OUTPUT_LIMIT_MAX_BYTES]`,
        // falling back to the configured default when the model omits
        // `output_limit`.
        let output_limit = clamp_shell_output_limit_bytes(Some(
            request
                .output_limit_bytes
                .unwrap_or(self.config.max_output_bytes as u64),
        ));
        let container_id = exec_transport::ensure_container(
            &self.docker,
            exec_transport::EnsureContainerRequest {
                config: &self.config,
                key: &key,
                tenant_id: &request.scope.tenant_id,
                user_id: &request.scope.user_id,
                workspace: &workspace,
                network_ready: &self.network_ready,
                attribution: self.attribution.as_deref(),
            },
        )
        .await?;
        let execution = exec_transport::exec_in_container(
            &self.docker,
            &container_id,
            workdir,
            env,
            request.command,
            timeout,
            output_limit,
        )
        .await;
        let stopped =
            exec_transport::stop_container_after_command(&self.docker, &container_id).await;
        drop(lifecycle_guard);
        self.activity.touch(&key);

        if let Err(stop_error) = stopped {
            return Err(match execution {
                Ok(_) => stop_error,
                Err(execution_error) => RuntimeProcessError::ExecutionFailed(format!(
                    "sandbox command failed ({execution_error}); container cleanup also failed ({stop_error})"
                )),
            });
        }

        let mut output = execution?;
        output.output = redact_sandbox_command_output(&output.output);
        Ok(output)
    }
}

fn reject_background_request(background: bool) -> Result<(), RuntimeProcessError> {
    if background {
        return Err(RuntimeProcessError::ExecutionFailed(
            "user sandbox does not support background commands in this release".into(),
        ));
    }
    Ok(())
}

/// Phase A scope-narrowing guard: persistent per-user containers only
/// support the default `/workspace` bind (see `run_command` above), so any
/// caller-supplied `MountView` grant — scoped or not — is rejected before
/// the container is ever touched, with a clear error, rather than being
/// silently dropped by `exec_transport::user_container_launch_config`'s
/// hardcoded `mounts: None`.
fn reject_non_workspace_mount_grants(
    mounts: Option<&MountView>,
) -> Result<(), RuntimeProcessError> {
    let Some(mounts) = mounts else {
        return Ok(());
    };
    if mounts.mounts.is_empty() {
        return Ok(());
    }
    Err(RuntimeProcessError::ExecutionFailed(
        "sandbox command rejected: persistent per-user sandbox containers only support the \
         default /workspace bind in Phase A; scoped mount grants are not supported"
            .to_string(),
    ))
}

pub(super) fn append_with_limit(buffer: &mut String, text: &str, limit: usize) {
    if buffer.len() >= limit {
        return;
    }
    let remaining = limit - buffer.len();
    if text.len() <= remaining {
        buffer.push_str(text);
        return;
    }
    let end = floor_char_boundary(text, remaining);
    buffer.push_str(&text[..end]);
}

fn floor_char_boundary(value: &str, index: usize) -> usize {
    if index >= value.len() {
        return value.len();
    }
    let mut index = index;
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn reject_nul(label: &str, value: &str) -> Result<(), RuntimeProcessError> {
    if value.as_bytes().contains(&0) {
        return Err(RuntimeProcessError::ExecutionFailed(format!(
            "{label} contains null bytes"
        )));
    }
    Ok(())
}

fn validate_env(env: HashMap<String, String>) -> Result<Vec<String>, RuntimeProcessError> {
    env.into_iter()
        .map(|(key, value)| {
            reject_nul("environment variable name", &key)?;
            reject_nul("environment variable value", &value)?;
            if key.contains('=') || key.is_empty() {
                return Err(RuntimeProcessError::ExecutionFailed(
                    "environment variable names must be non-empty and cannot contain '='"
                        .to_string(),
                ));
            }
            Ok(format!("{key}={value}"))
        })
        .collect()
}

fn validate_relative_workdir(path: &Path) -> Result<(), RuntimeProcessError> {
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(RuntimeProcessError::ExecutionFailed(
                    "sandbox working directory must stay inside the scoped workspace".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Wraps `value` in single quotes, escaping any embedded single quote so the
/// result is safe to interpolate into a `sh -c '...'` argument. The one
/// shell-quoting implementation in this crate — `exec_transport`'s
/// pgid-isolation wrapper calls this instead of hand-rolling its own.
pub(crate) fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod shell_quote_tests {
    use super::*;

    #[test]
    fn shell_single_quote_escapes_embedded_single_quotes() {
        assert_eq!(shell_single_quote("echo hi"), "'echo hi'");
        assert_eq!(shell_single_quote("it's"), "'it'\\''s'");
    }
}

#[cfg(test)]
mod pr1_request_tests {
    use super::*;

    #[test]
    fn background_execution_is_rejected_hermetically() {
        let error = reject_background_request(true).expect_err("background must fail closed");
        assert!(format!("{error}").contains("does not support background commands"));
        assert!(reject_background_request(false).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_host_api::{
        mount::{MountGrant, MountPermissions, MountView},
        path::{MountAlias, VirtualPath},
    };

    #[test]
    fn relative_workdir_rejects_escape() {
        let error = RebornScopedSandboxCommandTransport::resolve_container_workdir(Some("../x"))
            .unwrap_err();

        assert!(format!("{error}").contains("scoped workspace"));
    }

    #[test]
    fn container_workdir_rejects_host_absolute_paths() {
        let error = RebornScopedSandboxCommandTransport::resolve_container_workdir(Some(
            "/tmp/reborn-sandbox/tenant/user/app",
        ))
        .unwrap_err();

        assert!(format!("{error}").contains("workspace-relative"));
    }

    #[test]
    fn container_workdir_accepts_typed_container_paths() {
        let workdir =
            RebornScopedSandboxCommandTransport::resolve_container_workdir(Some("/workspace/app"))
                .unwrap();

        assert_eq!(workdir.into_string(), "/workspace/app");
    }

    #[test]
    fn configured_workspace_modes_are_explicit_shapes() {
        let private = RebornSandboxConfig::new("/tmp/reborn-sandbox")
            .with_container_user("1000:1000", RebornSandboxWorkspaceMode::Private);
        let group_shared = RebornSandboxConfig::new("/tmp/reborn-sandbox")
            .with_container_user("1000:1000", RebornSandboxWorkspaceMode::GroupShared);

        assert_eq!(private.container_identity.workspace_mode(), 0o700);
        assert_eq!(group_shared.container_identity.workspace_mode(), 0o770);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepare_workspace_rejects_symlinked_home_without_touching_target() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        let temp = tempfile::tempdir().unwrap();
        let workspace_root = temp.path().join("workspaces");
        let scope = ResourceScope::system();
        let workspace = RebornSandboxUserKey::from_scope(&scope).workspace_path(&workspace_root);
        std::fs::create_dir_all(&workspace).unwrap();

        let target = temp.path().join("host-target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o751)).unwrap();
        let before = std::fs::metadata(&target).unwrap();
        symlink(&target, workspace.join(".home")).unwrap();

        let docker =
            Docker::connect_with_http("http://127.0.0.1:0", 120, bollard::API_DEFAULT_VERSION)
                .expect("HTTP-transport client construction performs no I/O");
        let transport = RebornScopedSandboxCommandTransport::new(
            docker,
            RebornSandboxConfig::new(&workspace_root),
        );

        let error = transport.prepare_workspace(&scope).await.unwrap_err();
        let after = std::fs::metadata(&target).unwrap();

        assert!(
            format!("{error}").contains("HOME could not be initialized"),
            "unexpected error: {error}"
        );
        assert_eq!(after.uid(), before.uid(), "target owner uid changed");
        assert_eq!(after.gid(), before.gid(), "target owner gid changed");
        assert_eq!(
            after.permissions().mode() & 0o7777,
            before.permissions().mode() & 0o7777,
            "target mode changed"
        );
        assert!(
            std::fs::symlink_metadata(workspace.join(".home"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the rejected symlink should not be replaced"
        );
    }

    #[test]
    fn default_sandbox_disables_ambient_network() {
        let config = RebornSandboxConfig::new("/tmp/reborn-sandbox");
        let env = config.command_env(HashMap::new()).unwrap();

        assert_eq!(config.container_network_mode(), Some("none".to_string()));
        assert!(env.contains(&"IRONCLAW_REBORN_NETWORK_MODE=disabled".to_string()));
    }

    #[test]
    fn validate_env_rejects_empty_equals_and_nul_values() {
        for (key, value) in [
            ("", "value"),
            ("BAD=KEY", "value"),
            ("BAD\0KEY", "value"),
            ("GOOD_KEY", "bad\0value"),
        ] {
            let error = validate_env(HashMap::from([(key.to_string(), value.to_string())]))
                .expect_err("invalid env should be rejected");
            assert!(matches!(error, RuntimeProcessError::ExecutionFailed(_)));
        }
    }

    #[test]
    fn network_broker_port_uses_pinned_internal_network_gateway_proxy_url() {
        let config = RebornSandboxConfig::new("/tmp/reborn-sandbox").with_network_broker_port(8181);
        let env = config.command_env(HashMap::new()).unwrap();
        let proxy_url = format!("http://{}:8181", broker::SANDBOX_EGRESS_NETWORK_GATEWAY);

        // E1: the default-port broker's proxy URL must point at the pinned
        // internal network's gateway (reachable once the container joins
        // `SANDBOX_EGRESS_NETWORK_NAME`), not the Docker default-bridge
        // host-gateway address — that was the E1 hole (default bridge NATs
        // to the internet).
        assert!(env.contains(&"IRONCLAW_REBORN_NETWORK_MODE=brokered".to_string()));
        assert!(env.contains(&format!("IRONCLAW_REBORN_HTTP_PROXY={proxy_url}")));
        assert!(env.contains(&format!("http_proxy={proxy_url}")));
        assert!(env.contains(&format!("https_proxy={proxy_url}")));
        assert!(env.contains(&format!("HTTP_PROXY={proxy_url}")));
        assert!(env.contains(&format!("HTTPS_PROXY={proxy_url}")));
        assert_eq!(
            config.container_network_mode(),
            Some(broker::SANDBOX_EGRESS_NETWORK_NAME.to_string())
        );
    }

    #[test]
    fn reserved_broker_env_keys_match_the_full_fail_closed_list() {
        // Fail-closed guarantee: a caller must never be able to inject any of
        // these names into the sandboxed container's environment, regardless
        // of whether a broker implementation for that name currently exists.
        // `broker_env_rejects_all_reserved_user_overrides` iterates over
        // `RESERVED_BROKER_ENV_KEYS` itself, so shrinking the const keeps
        // that test green while testing fewer keys — pin the expected list
        // here, independent of the const, so a future shrink fails loudly.
        let expected: &[&str] = &[
            "IRONCLAW_REBORN_NETWORK_MODE",
            "IRONCLAW_REBORN_HTTP_PROXY",
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "IRONCLAW_REBORN_HTTP_BROKER_SOCKET",
            "IRONCLAW_REBORN_HTTP_BROKER_URL",
            "IRONCLAW_REBORN_SECRET_MODE",
            "IRONCLAW_REBORN_SECRET_BROKER_URL",
            "IRONCLAW_REBORN_SECRET_BROKER_SOCKET",
        ];

        assert_eq!(
            broker::RESERVED_BROKER_ENV_KEYS.len(),
            expected.len(),
            "RESERVED_BROKER_ENV_KEYS length drifted from the expected fail-closed list"
        );
        for key in expected {
            assert!(
                broker::RESERVED_BROKER_ENV_KEYS.contains(key),
                "{key} must remain reserved even without a live broker implementation"
            );
        }
    }

    #[test]
    fn broker_env_rejects_all_reserved_user_overrides() {
        let config = RebornSandboxConfig::new("/tmp/reborn-sandbox").with_network_broker_port(8181);
        for key in broker::RESERVED_BROKER_ENV_KEYS {
            let error = config
                .command_env(HashMap::from([(
                    (*key).to_string(),
                    "caller-controlled".to_string(),
                )]))
                .unwrap_err();

            assert!(format!("{error}").contains("reserved"), "{key}");
        }
    }

    #[test]
    fn invocation_env_rejects_every_caller_provided_value() {
        let config = RebornSandboxConfig::new("/tmp/reborn-sandbox");
        let error = config
            .command_env_for_invocation(
                HashMap::from([(
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                    "must-remain-host-side".to_string(),
                )]),
                InvocationId::new(),
            )
            .expect_err("caller environment must never enter a sandbox invocation");

        assert!(
            format!("{error}").contains("does not accept caller-provided environment variables")
        );
    }

    #[tokio::test]
    async fn user_container_launch_config_applies_http_proxy_broker_env_and_joins_internal_egress_network()
     {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let config =
            RebornSandboxConfig::new(temp.path().join("workspaces")).with_network_broker_port(8181);
        let tenant = ironclaw_host_api::ids::TenantId::new("tenant-a").unwrap();
        let user = ironclaw_host_api::ids::UserId::new("user-a").unwrap();
        let proxy_url = format!("http://{}:8181", broker::SANDBOX_EGRESS_NETWORK_GATEWAY);

        let launch =
            exec_transport::user_container_launch_config(&config, &tenant, &user, &workspace)
                .await
                .unwrap();
        let host_config = launch.host_config.unwrap();
        let binds = host_config.binds.unwrap();
        let env = launch.env.unwrap();

        // E1: the applied Docker HostConfig must attach to the pinned
        // internal egress network, never silently fall back to the default
        // bridge (which would NAT to the internet and defeat the proxy
        // allowlist).
        assert_eq!(
            host_config.network_mode,
            Some(broker::SANDBOX_EGRESS_NETWORK_NAME.to_string())
        );
        assert!(env.contains(&"IRONCLAW_REBORN_NETWORK_MODE=brokered".to_string()));
        assert!(env.contains(&format!("http_proxy={proxy_url}")));
        assert!(env.contains(&format!("HTTPS_PROXY={proxy_url}")));
        assert!(binds.contains(&format!("{}:/workspace:rw", workspace.display())));
    }

    #[test]
    fn reject_non_workspace_mount_grants_allows_none_and_empty_but_rejects_any_grant() {
        assert!(reject_non_workspace_mount_grants(None).is_ok());
        assert!(reject_non_workspace_mount_grants(Some(&MountView::default())).is_ok());

        let mounts = MountView::new(vec![MountGrant::new(
            MountAlias::new("/workspace").unwrap(),
            VirtualPath::new("/projects/app").unwrap(),
            process_read_only_permissions(),
        )])
        .unwrap();
        let error = reject_non_workspace_mount_grants(Some(&mounts)).unwrap_err();

        assert!(format!("{error}").contains("scoped mount grants are not supported"));
    }

    #[tokio::test]
    async fn run_command_rejects_any_scoped_mount_grant_before_container_touch() {
        let temp = tempfile::tempdir().unwrap();
        // `run_command` must reject a scoped `MountView` grant as a pure
        // precondition, before any Docker client use — so this test must
        // not require a live daemon either. `connect_with_local_defaults`
        // stats the Unix socket at construction and fails immediately
        // without one; the HTTP-transport client performs no I/O until a
        // request is sent (see `ensure_egress_network_is_a_no_op_for_none_
        // network_configs` in `exec_transport.rs` for the same pattern).
        let docker =
            Docker::connect_with_http("http://127.0.0.1:0", 120, bollard::API_DEFAULT_VERSION)
                .expect("HTTP-transport client construction performs no I/O");
        let transport = RebornScopedSandboxCommandTransport::new(
            docker,
            RebornSandboxConfig::new(temp.path().join("workspaces")),
        );
        let mounts = MountView::new(vec![MountGrant::new(
            MountAlias::new("/workspace").unwrap(),
            VirtualPath::new("/projects/app").unwrap(),
            process_read_only_permissions(),
        )])
        .unwrap();

        let error = transport
            .run_command(CommandExecutionRequest {
                scope: ResourceScope::system(),
                mounts: Some(mounts),
                command: "true".to_string(),
                workdir: None,
                timeout_secs: Some(1),
                extra_env: HashMap::new(),
                output_limit_bytes: None,
                background: false,
            })
            .await
            .unwrap_err();

        assert!(format!("{error}").contains("scoped mount grants are not supported"));
    }

    /// Regression for the sandbox output leak: pre-fix, `run_command`
    /// assigned Docker's raw stdout/stderr straight to
    /// `CommandExecutionOutput::output` with no pass through
    /// `LeakDetector` at all — unlike `HostProcessPort`'s
    /// `capture_command_output` path, which redacts every command's output
    /// before it becomes model-visible. Drives the exact helper
    /// `run_command` calls (`redact_sandbox_command_output`) rather than
    /// requiring a live Docker daemon, and asserts parity against the same
    /// `COMMAND_OUTPUT_BLOCKED_MARKER` the host path's own
    /// `capture_command_output_blocks_secret_like_small_preview` test
    /// (`process_output.rs`) pins for the identical secret shape.
    #[test]
    fn redact_sandbox_command_output_blocks_secret_like_content() {
        let secret_output = "sk-proj-test1234567890abcdefghij";

        let redacted = redact_sandbox_command_output(secret_output);

        assert_eq!(
            redacted,
            crate::process_output::COMMAND_OUTPUT_BLOCKED_MARKER
        );
        assert!(
            !redacted.contains("sk-proj-test1234567890abcdefghij"),
            "the secret-shaped token must never reach the model verbatim"
        );
    }

    #[test]
    fn redact_sandbox_command_output_leaves_clean_output_untouched() {
        let clean_output = "hello from the sandboxed container\n";

        let redacted = redact_sandbox_command_output(clean_output);

        assert_eq!(redacted, clean_output);
    }

    fn process_read_only_permissions() -> MountPermissions {
        MountPermissions {
            execute: true,
            ..MountPermissions::read_only()
        }
    }
}
