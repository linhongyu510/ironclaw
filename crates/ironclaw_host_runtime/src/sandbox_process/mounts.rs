use std::path::{Path, PathBuf};

use crate::RuntimeProcessError;

use super::CONTAINER_WORKSPACE_ROOT;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ContainerBind {
    source: PathBuf,
    target: String,
    read_only: bool,
}

impl ContainerBind {
    fn new(
        source: PathBuf,
        target: impl Into<String>,
        read_only: bool,
    ) -> Result<Self, RuntimeProcessError> {
        let target = target.into();
        reject_nul("sandbox bind source", &source.to_string_lossy())?;
        reject_nul("sandbox bind target", &target)?;
        if source.to_string_lossy().contains(':') || target.contains(':') {
            return Err(RuntimeProcessError::ExecutionFailed(
                "sandbox bind paths cannot contain ':'".to_string(),
            ));
        }
        Ok(Self {
            source,
            target,
            read_only,
        })
    }

    pub(super) fn into_docker_bind(self) -> String {
        let mode = if self.read_only { "ro" } else { "rw" };
        format!("{}:{}:{mode}", self.source.display(), self.target)
    }
}

/// The sandbox container's primary bind mount: the per-invocation workspace,
/// read-write, at `/workspace`.
///
/// Scoped/virtual mount grants (`MountView`) used to be resolvable here
/// against a caller-configured set of trusted local sources, but
/// `reject_non_workspace_mount_grants` (`sandbox_process.rs`) already
/// rejects any such grant before a container is ever touched, and nothing
/// in production ever configured a trusted source to resolve against. That
/// grant-resolution path was deleted as dead code; this and
/// [`ca_bundle_bind`] are the only binds any production sandbox container
/// receives.
pub(super) fn workspace_bind(workspace: &Path) -> Result<ContainerBind, RuntimeProcessError> {
    ContainerBind::new(workspace.to_path_buf(), CONTAINER_WORKSPACE_ROOT, false)
}

/// Container-side path the sandbox CA trust bundle (this CA instance's
/// public root certificate plus the host's system root certificates — see
/// `ca::SandboxCertificateAuthority::build_container_trust_bundle_pem`, no
/// private key material) is bind-mounted to, read-only. Fixed and stable so
/// `exec_transport::user_container_launch_config`'s `SSL_CERT_FILE` and
/// sibling env vars always point at the same path regardless of the host
/// path the bundle was materialized under.
pub(super) const CONTAINER_CA_BUNDLE_PATH: &str = "/ironclaw/sandbox-ca/ca-bundle.pem";

/// Read-only bind for the CA trust bundle at [`CONTAINER_CA_BUNDLE_PATH`].
/// `bundle_path` is a single regular file on the host (see
/// `exec_transport`'s CA-bundle materialization), never a directory —
/// mirrors [`workspace_bind`]'s shape but read-only, since a container must
/// never be able to write back into its own trust anchor.
pub(super) fn ca_bundle_bind(bundle_path: &Path) -> Result<ContainerBind, RuntimeProcessError> {
    ContainerBind::new(bundle_path.to_path_buf(), CONTAINER_CA_BUNDLE_PATH, true)
}

fn reject_nul(label: &str, value: &str) -> Result<(), RuntimeProcessError> {
    if value.as_bytes().contains(&0) {
        return Err(RuntimeProcessError::ExecutionFailed(format!(
            "{label} contains null bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_bind_produces_read_write_docker_bind() {
        let temp = tempfile::tempdir().unwrap();

        let bind = workspace_bind(temp.path()).unwrap();

        assert_eq!(
            bind.into_docker_bind(),
            format!("{}:/workspace:rw", temp.path().display())
        );
    }

    #[test]
    fn workspace_bind_rejects_paths_containing_colon() {
        let error = workspace_bind(Path::new("/tmp/has:colon")).unwrap_err();

        assert!(format!("{error}").contains("cannot contain"));
    }

    #[test]
    fn ca_bundle_bind_produces_read_only_docker_bind() {
        let temp = tempfile::tempdir().unwrap();
        let bundle_path = temp.path().join("ca-bundle.pem");

        let bind = ca_bundle_bind(&bundle_path).unwrap();

        assert_eq!(
            bind.into_docker_bind(),
            format!(
                "{}:{CONTAINER_CA_BUNDLE_PATH}:ro",
                bundle_path.display()
            )
        );
    }

    #[test]
    fn ca_bundle_bind_rejects_paths_containing_colon() {
        let error = ca_bundle_bind(Path::new("/tmp/has:colon/ca-bundle.pem")).unwrap_err();

        assert!(format!("{error}").contains("cannot contain"));
    }
}
