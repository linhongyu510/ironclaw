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
    // Write-then-rename instead of a direct `tokio::fs::write` (open +
    // truncate + write): this file is bind-mounted read-only into every
    // sandbox container in the deployment (see the doc above) and rewritten
    // on every container create/recycle for ANY user, so a direct write
    // leaves a window where a concurrent reader in an unrelated,
    // already-running container observes a truncated/empty PEM mid-write.
    // `rename` is atomic within a filesystem, so a concurrent reader always
    // sees either the complete old file or the complete new one, never a
    // partial one. The temp file lives in the same directory so the rename
    // stays on the same filesystem.
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

    /// RUN-001 regression: `materialize_ca_bundle` is shared across every
    /// container in the deployment (see its doc above) and is rewritten on
    /// every container create/recycle for ANY user. A non-atomic
    /// open+truncate+write leaves a window where a concurrent reader
    /// (another, already-running container bind-mounting this exact host
    /// path read-only) can observe an empty or partial PEM. This test
    /// starts one task hammering `materialize_ca_bundle` on a shared
    /// `workspace_root` while another task repeatedly reads the same path,
    /// and asserts every successful read is the complete, byte-exact PEM —
    /// never a short/torn read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn materialize_ca_bundle_never_exposes_a_torn_read_to_concurrent_readers() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let temp = tempfile::tempdir().expect("tempdir");
        let workspace_root = temp.path().to_path_buf();
        // Large enough (~256 KiB) that a torn write has a realistically
        // observable window even on a fast filesystem/tmpfs.
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            "A".repeat(64).repeat(4096)
        );

        // Create the file once before racing, so the reader can distinguish
        // "not created yet" (fine — still setting up) from "was created,
        // then observed incomplete" (the bug under test).
        let bundle_path = materialize_ca_bundle(&workspace_root, &pem)
            .await
            .expect("initial write should succeed");

        let stop = Arc::new(AtomicBool::new(false));
        let reader_stop = Arc::clone(&stop);
        let reader_path = bundle_path.clone();
        let expected = pem.clone().into_bytes();
        let reader = tokio::spawn(async move {
            let mut torn_reads = 0usize;
            let mut total_reads = 0usize;
            while !reader_stop.load(Ordering::Relaxed) {
                if let Ok(bytes) = tokio::fs::read(&reader_path).await {
                    total_reads += 1;
                    if bytes != expected {
                        torn_reads += 1;
                    }
                }
            }
            (torn_reads, total_reads)
        });

        let writer_root = workspace_root.clone();
        let writer_pem = pem.clone();
        let writer = tokio::spawn(async move {
            for _ in 0..500 {
                materialize_ca_bundle(&writer_root, &writer_pem)
                    .await
                    .expect("write should succeed");
            }
        });

        writer.await.expect("writer task should not panic");
        stop.store(true, Ordering::Relaxed);
        let (torn_reads, total_reads) = reader.await.expect("reader task should not panic");

        assert_eq!(
            torn_reads, 0,
            "observed {torn_reads} torn/incomplete reads out of {total_reads} total reads of \
             the CA bundle while materialize_ca_bundle concurrently rewrote it in place — every \
             concurrent reader must always see either the complete old file or the complete new \
             one, never a partial one"
        );
    }
}
