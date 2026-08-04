use std::path::{Path, PathBuf};

use crate::RuntimeProcessError;

use super::CONTAINER_WORKSPACE_ROOT;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ContainerBind {
    source: PathBuf,
    target: String,
    mode: DockerBindMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DockerBindMode {
    ReadOnly,
    ReadWrite,
}

impl ContainerBind {
    fn new(
        source: PathBuf,
        target: impl Into<String>,
        mode: DockerBindMode,
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
            mode,
        })
    }

    pub(super) fn into_docker_bind(self) -> String {
        let mode = match self.mode {
            DockerBindMode::ReadOnly => "ro",
            DockerBindMode::ReadWrite => "rw",
        };
        format!("{}:{}:{mode}", self.source.display(), self.target)
    }
}

/// Builds the sandbox container's primary read-write `/workspace` bind.
///
/// Persistent per-user sandbox containers construct this bind directly.
pub(super) fn workspace_bind(workspace: &Path) -> Result<ContainerBind, RuntimeProcessError> {
    ContainerBind::new(
        workspace.to_path_buf(),
        CONTAINER_WORKSPACE_ROOT,
        DockerBindMode::ReadWrite,
    )
}

/// Container-side path for the host-owned public CA bundle used by the
/// sandbox egress proxy. The file contains no private key material and is
/// mounted read-only.
pub(super) const CONTAINER_CA_BUNDLE_PATH: &str = "/ironclaw/sandbox-ca/ca-bundle.pem";

pub(super) fn ca_bundle_bind(bundle_path: &Path) -> Result<ContainerBind, RuntimeProcessError> {
    ContainerBind::new(
        bundle_path.to_path_buf(),
        CONTAINER_CA_BUNDLE_PATH,
        DockerBindMode::ReadOnly,
    )
}

/// Atomically publishes the shared public CA bundle so concurrently running
/// containers never observe a truncated trust file during proxy restart.
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
    let tmp_path = bundle_dir.join(format!("ca-bundle.pem.tmp-{}", uuid::Uuid::new_v4()));
    if let Err(error) = tokio::fs::write(&tmp_path, ca_bundle_pem).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(RuntimeProcessError::ExecutionFailed(format!(
            "sandbox CA trust bundle could not be written: {error}"
        )));
    }
    if let Err(error) = tokio::fs::rename(&tmp_path, &bundle_path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(RuntimeProcessError::ExecutionFailed(format!(
            "sandbox CA trust bundle could not be published: {error}"
        )));
    }
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
    fn ca_bundle_bind_produces_read_only_docker_bind() {
        let temp = tempfile::tempdir().unwrap();
        let bundle_path = temp.path().join("ca-bundle.pem");

        let bind = ca_bundle_bind(&bundle_path).unwrap();

        assert_eq!(
            bind.into_docker_bind(),
            format!("{}:{CONTAINER_CA_BUNDLE_PATH}:ro", bundle_path.display())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn materialize_ca_bundle_never_exposes_a_torn_read_to_concurrent_readers() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let temp = tempfile::tempdir().expect("tempdir");
        let workspace_root = temp.path().to_path_buf();
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            "A".repeat(64).repeat(4096)
        );
        let bundle_path = materialize_ca_bundle(&workspace_root, &pem)
            .await
            .expect("initial write should succeed");

        let stop = Arc::new(AtomicBool::new(false));
        let reader_stop = Arc::clone(&stop);
        let expected = pem.clone().into_bytes();
        let reader = tokio::spawn(async move {
            let mut torn_reads = 0usize;
            while !reader_stop.load(Ordering::Relaxed) {
                if let Ok(bytes) = tokio::fs::read(&bundle_path).await
                    && bytes != expected
                {
                    torn_reads += 1;
                }
            }
            torn_reads
        });

        let writer_root = workspace_root.clone();
        let writer = tokio::spawn(async move {
            for _ in 0..500 {
                materialize_ca_bundle(&writer_root, &pem)
                    .await
                    .expect("write should succeed");
            }
        });

        writer.await.expect("writer task should not panic");
        stop.store(true, Ordering::Relaxed);
        assert_eq!(
            reader.await.expect("reader task should not panic"),
            0,
            "concurrent readers must never observe a partial CA bundle"
        );
    }
}
