//! Provider factory and opaque runtime-bundle construction for
//! composition profiles that request it (today: only
//! `hosted-single-tenant-volume-sandboxed`).
//!
//! This is the one place composition reaches into
//! `ironclaw_host_runtime`'s sandbox transport to produce a
//! [`RebornRuntimeProcessBinding`]. Callers above composition — notably the
//! `ironclaw` CLI binary crate — enter Reborn only through this crate's
//! public surface and must never depend on `ironclaw_host_runtime` directly
//! (enforced by
//! `ironclaw_architecture::reborn_cli_binary_crate_stays_separate_from_v1_root`),
//! so the Docker connect + transport construction lives here rather than at
//! the CLI boot-input assembly call site.

use std::path::PathBuf;
use std::sync::Arc;

use ironclaw_host_runtime::{
    RailwayPreviewSandboxConfig, RailwayPreviewSandboxTransport, RebornSandboxConfig,
    RebornScopedSandboxCommandTransport, SandboxActivityRegistry, UserSandboxProcessPort,
};

use crate::RebornBuildError;
use crate::input::RebornRuntimeProcessBinding;

/// Single construction boundary for every user-sandbox provider.
///
/// Callers select a provider here and receive one opaque runtime bundle;
/// generic composition must not assemble Docker/Railway handles field by
/// field.
pub struct UserSandboxFactory;

impl UserSandboxFactory {
    pub async fn local_docker(
        sandbox_workspaces_root: PathBuf,
    ) -> Result<UserSandboxRuntimeBundle, RebornBuildError> {
        user_sandbox_process_binding(sandbox_workspaces_root).await
    }

    pub fn railway_preview(config: RailwayPreviewSandboxConfig) -> UserSandboxRuntimeBundle {
        railway_user_sandbox_process_binding(config)
    }
}

#[cfg(any(test, feature = "test-support"))]
mod test_support {
    use super::*;

    impl UserSandboxFactory {
        #[cfg(test)]
        pub(crate) fn recording_for_test(
            process_port: Arc<ironclaw_host_runtime::UserSandboxProcessPort>,
            sandbox_workspaces_root: PathBuf,
        ) -> UserSandboxRuntimeBundle {
            UserSandboxRuntimeBundle {
                process_port,
                lifecycle: UserSandboxLifecycle::HostManaged {
                    activity: Arc::new(SandboxActivityRegistry::new()),
                },
                workspace: UserSandboxWorkspace::HostDirectory(sandbox_workspaces_root),
            }
        }

        pub(crate) fn transport_managed_recording_for_test(
            process_port: Arc<ironclaw_host_runtime::UserSandboxProcessPort>,
            sandbox_workspaces_root: PathBuf,
        ) -> UserSandboxRuntimeBundle {
            UserSandboxRuntimeBundle {
                process_port,
                lifecycle: UserSandboxLifecycle::TransportManaged,
                workspace: UserSandboxWorkspace::HostDirectory(sandbox_workspaces_root),
            }
        }
    }
}

/// Connect to the Docker daemon and build a `UserSandbox` process-port
/// binding rooted at `sandbox_workspaces_root`. Fails closed: any Docker
/// connect failure returns `Err`, never a silent
/// `RebornRuntimeProcessBinding::none()` fallback (which would mean running
/// sandbox-profile shell commands unsandboxed on the host) — see
/// `docs/safety-and-sandbox.md`.
///
/// PR1 intentionally retains `RebornSandboxConfig`'s default `--network none`
/// posture. Egress mediation, CA distribution, and credential presentation
/// are follow-up layers and are not booted by this factory.
async fn user_sandbox_process_binding(
    sandbox_workspaces_root: PathBuf,
) -> Result<UserSandboxRuntimeBundle, RebornBuildError> {
    let config = RebornSandboxConfig::new(sandbox_workspaces_root.clone());
    let activity = Arc::new(SandboxActivityRegistry::new());
    let transport = RebornScopedSandboxCommandTransport::connect(config)
        .await
        .map_err(|error| RebornBuildError::InvalidConfig {
            reason: format!(
                "user-sandbox process backend requires a reachable Docker daemon: {error}"
            ),
        })?
        .with_activity_registry(Arc::clone(&activity));
    let process_port = Arc::new(transport.into_process_port());
    Ok(UserSandboxRuntimeBundle {
        process_port,
        lifecycle: UserSandboxLifecycle::HostManaged { activity },
        workspace: UserSandboxWorkspace::HostDirectory(sandbox_workspaces_root),
    })
}

/// Build the transport-managed Railway preview binding without starting a VM.
///
/// The first model shell command lazily creates the per-user Railway sandbox;
/// profile boot only installs this host-owned transport. Railway owns VM
/// retirement and checkpoint recovery, while the inner Docker worker has no
/// egress or credential runtime in this first slice.
fn railway_user_sandbox_process_binding(
    config: RailwayPreviewSandboxConfig,
) -> UserSandboxRuntimeBundle {
    let transport = Arc::new(RailwayPreviewSandboxTransport::new(config));
    let process_port = Arc::new(UserSandboxProcessPort::new(transport));
    UserSandboxRuntimeBundle::managed(process_port)
}

/// Declares which layer owns sandbox lifecycle services around the generic
/// user-sandbox process port.
///
/// The distinction records lifecycle ownership, not a different worker kind:
/// both paths launch a hardened Docker worker. A directly reached daemon uses
/// host-owned reaping; a transport-managed daemon owns its own VM retirement
/// and persistence behavior.
pub(crate) enum UserSandboxLifecycle {
    HostManaged {
        activity: Arc<SandboxActivityRegistry>,
    },
    TransportManaged,
}

/// Return value of [`user_sandbox_process_binding`]: the process-port
/// binding plus the SAME [`SandboxActivityRegistry`] instance the exec
/// transport now writes activity into, so a caller that also spawns
/// `SandboxReaper` (via `sandbox::lifecycle`/`factory.rs`) reads the exact
/// timestamps the transport is recording — never a second, independently
/// constructed registry.
pub struct UserSandboxRuntimeBundle {
    process_port: Arc<ironclaw_host_runtime::UserSandboxProcessPort>,
    lifecycle: UserSandboxLifecycle,
    workspace: UserSandboxWorkspace,
}

enum UserSandboxWorkspace {
    HostDirectory(PathBuf),
    RemoteOnly,
}

impl UserSandboxRuntimeBundle {
    fn managed(process_port: Arc<ironclaw_host_runtime::UserSandboxProcessPort>) -> Self {
        Self {
            process_port,
            lifecycle: UserSandboxLifecycle::TransportManaged,
            workspace: UserSandboxWorkspace::RemoteOnly,
        }
    }

    pub(crate) fn process_binding(&self) -> RebornRuntimeProcessBinding {
        RebornRuntimeProcessBinding::user_sandbox(Arc::clone(&self.process_port))
    }

    pub(crate) fn process_binding_matches(&self, binding: &RebornRuntimeProcessBinding) -> bool {
        match binding {
            RebornRuntimeProcessBinding::UserSandbox { process_port } => {
                Arc::ptr_eq(&self.process_port, process_port)
            }
            RebornRuntimeProcessBinding::None => false,
        }
    }

    pub(crate) fn host_workspace_root(&self) -> Option<&std::path::Path> {
        match &self.workspace {
            UserSandboxWorkspace::HostDirectory(root) => Some(root),
            UserSandboxWorkspace::RemoteOnly => None,
        }
    }

    pub(crate) fn replace_workspace_root(&mut self, root: PathBuf) {
        if matches!(self.workspace, UserSandboxWorkspace::HostDirectory(_)) {
            self.workspace = UserSandboxWorkspace::HostDirectory(root);
        }
    }

    pub(crate) fn has_remote_workspace(&self) -> bool {
        matches!(self.workspace, UserSandboxWorkspace::RemoteOnly)
    }

    pub(crate) fn into_lifecycle(self) -> UserSandboxLifecycle {
        self.lifecycle
    }
}

#[cfg(any(test, feature = "test-support"))]
impl UserSandboxRuntimeBundle {
    /// Returns the process port used by black-box Docker tests while keeping
    /// the rest of the sandbox substrate opaque.
    pub fn process_port_for_test(
        &self,
    ) -> Result<Arc<ironclaw_host_runtime::UserSandboxProcessPort>, RebornBuildError> {
        Ok(Arc::clone(&self.process_port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn railway_bundle_is_remote_only_and_transport_managed() {
        let config = RailwayPreviewSandboxConfig::new("project-id", "environment-id")
            .expect("static Railway config is valid");
        let bundle = UserSandboxFactory::railway_preview(config);

        assert!(bundle.host_workspace_root().is_none());
        assert!(bundle.has_remote_workspace());
        assert!(matches!(
            bundle.lifecycle,
            UserSandboxLifecycle::TransportManaged
        ));
    }
}
