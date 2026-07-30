use std::path::{Path, PathBuf};

use crate::RuntimeProcessError;

use super::CONTAINER_WORKSPACE_ROOT;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ContainerBind {
    source: PathBuf,
    target: String,
}

impl ContainerBind {
    fn new(source: PathBuf, target: impl Into<String>) -> Result<Self, RuntimeProcessError> {
        let target = target.into();
        reject_nul("sandbox bind source", &source.to_string_lossy())?;
        reject_nul("sandbox bind target", &target)?;
        if source.to_string_lossy().contains(':') || target.contains(':') {
            return Err(RuntimeProcessError::ExecutionFailed(
                "sandbox bind paths cannot contain ':'".to_string(),
            ));
        }
        Ok(Self { source, target })
    }

    pub(super) fn into_docker_bind(self) -> String {
        format!("{}:{}:rw", self.source.display(), self.target)
    }
}

/// The sandbox container's sole bind mount: the per-invocation workspace,
/// read-write, at `/workspace`.
///
/// Scoped/virtual mount grants (`MountView`) used to be resolvable here
/// against a caller-configured set of trusted local sources, but
/// `reject_non_workspace_mount_grants` (`sandbox_process.rs`) already
/// rejects any such grant before a container is ever touched, and nothing
/// in production ever configured a trusted source to resolve against. That
/// grant-resolution path was deleted as dead code; this is the only bind
/// any production sandbox container receives.
pub(super) fn workspace_bind(workspace: &Path) -> Result<ContainerBind, RuntimeProcessError> {
    ContainerBind::new(workspace.to_path_buf(), CONTAINER_WORKSPACE_ROOT)
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
}
