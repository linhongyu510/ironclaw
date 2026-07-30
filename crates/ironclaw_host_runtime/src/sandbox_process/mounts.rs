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

/// Writes `ca_bundle_pem` (the sandbox egress proxy's container trust
/// bundle — system roots plus its CA's public root certificate, no private
/// key material; see `ca::SandboxCertificateAuthority::
/// build_container_trust_bundle_pem`) to a stable host-side path under
/// `workspace_root` and returns the canonicalized path, ready for
/// [`ca_bundle_bind`].
///
/// One shared file per `workspace_root` (NOT per-user): every sandbox
/// container in a given deployment is served by the SAME egress proxy
/// instance and therefore must trust the SAME CA, so there is nothing
/// tenant/user-scoped about this content — it is public certificate
/// material, safe to be world-readable. Rewritten on every call (cheap: a
/// few KiB, only at container-creation time, never per-exec) rather than
/// written once behind a guard, so a proxy restart with a freshly
/// regenerated CA (the root is regenerated fresh in memory on every process
/// start — see `ca.rs`'s module doc) is always reflected the next time a
/// container is created or recycled, without this transport needing to
/// track whether the bundle is stale.
pub(super) async fn materialize_ca_bundle(
    workspace_root: &Path,
    ca_bundle_pem: &str,
) -> Result<PathBuf, RuntimeProcessError> {
    let bundle_dir = workspace_root.join(".sandbox-ca");
    tokio::fs::create_dir_all(&bundle_dir)
        .await
        .map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!(
                "sandbox CA trust bundle directory could not be initialized: {error}"
            ))
        })?;
    let bundle_path = bundle_dir.join("ca-bundle.pem");
    tokio::fs::write(&bundle_path, ca_bundle_pem)
        .await
        .map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!(
                "sandbox CA trust bundle could not be written: {error}"
            ))
        })?;
    tokio::fs::canonicalize(&bundle_path)
        .await
        .map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!(
                "sandbox CA trust bundle path could not be resolved: {error}"
            ))
        })
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
            format!("{}:{CONTAINER_CA_BUNDLE_PATH}:ro", bundle_path.display())
        );
    }

    #[test]
    fn ca_bundle_bind_rejects_paths_containing_colon() {
        let error = ca_bundle_bind(Path::new("/tmp/has:colon/ca-bundle.pem")).unwrap_err();

        assert!(format!("{error}").contains("cannot contain"));
    }
}
