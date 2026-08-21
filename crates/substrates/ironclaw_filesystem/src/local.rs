use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use async_trait::async_trait;
use ironclaw_host_api::path::{HostPath, VirtualPath};
use ironclaw_safety::sensitive_paths::is_sensitive_path;
use tokio::io::AsyncReadExt;

use crate::{
    AtomicSubtreeEntry, CasExpectation, DirEntry, Entry, FileStat, FileType, FilesystemError,
    FilesystemOperation, RecordVersion, RootFilesystem, VersionedEntry,
    local_capability::{CapabilityWriteError, DiskDirectoryCapability, run_capability_blocking},
    path_prefix_matches,
    root::validate_atomic_subtree_entries,
};

static LOCAL_WRITE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The on-disk `RootFilesystem` backend, mounted into the virtual namespace.
///
/// The name states the **storage medium** — disk, a peer of `InMemoryBackend`,
/// `LibSqlRootFilesystem`, and `PostgresRootFilesystem` — not a deployment mode.
/// Renamed from `LocalFilesystem` because `Local` read like a deployment tier
/// while this is simply the disk backend a `DeploymentConfig` may select
/// (arch-simplification §4.4 Bucket 2).
#[derive(Debug, Default)]
pub struct DiskFilesystem {
    mounts: Vec<LocalMount>,
}

#[derive(Debug, Clone)]
struct LocalMount {
    virtual_root: VirtualPath,
    host_root: PathBuf,
    capability: DiskDirectoryCapability,
    /// When `true`, this mount is shared by many callers who are each only
    /// ever granted a single leaf subtree of it (one [`MountGrant`] target
    /// per caller, narrowed by the composition-layer `MountView` resolver —
    /// e.g. the sandboxed-profile `/workspace` mount, where every user's
    /// `MountView` target is `/workspace/<digest>`). Containment for such a
    /// mount is pinned to `host_root/<first-tail-segment>` rather than the
    /// full `host_root`: the physical [`DiskFilesystem`] mount table is
    /// boot-time-fixed and cannot register a distinct `host_root` per caller,
    /// but the first path segment after `virtual_root` is never
    /// caller-controlled — it comes from the server-computed `MountGrant`
    /// target, not from the caller's tail — so pinning containment to it
    /// closes a same-mount cross-leaf symlink escape (one caller's symlink
    /// resolving into a sibling leaf) without weakening containment for any
    /// other mount. See `ensure_contained`.
    leaf_scoped: bool,
}

impl DiskFilesystem {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mounts a host directory during trusted setup.
    ///
    /// This API is intentionally synchronous because it mutates in-memory mount
    /// configuration and is not part of the async runtime operation path. Async
    /// file operations after mount setup use `tokio::fs`.
    pub fn mount_local(
        &mut self,
        virtual_root: VirtualPath,
        host_root: HostPath,
    ) -> Result<(), FilesystemError> {
        self.mount_local_impl(virtual_root, host_root, false)
    }

    /// Creates and admits a local mount without following path components,
    /// retaining the opened directory capability for all later writes.
    pub async fn mount_local_create(
        &mut self,
        virtual_root: VirtualPath,
        host_root: HostPath,
    ) -> Result<(), FilesystemError> {
        if self
            .mounts
            .iter()
            .any(|mount| mount.virtual_root.as_str() == virtual_root.as_str())
        {
            return Err(FilesystemError::MountConflict { path: virtual_root });
        }
        let host_path = host_root.as_path().to_path_buf();
        let capability =
            run_capability_blocking(move || DiskDirectoryCapability::admit_or_create(&host_path))
                .await
                .map_err(|error| {
                    local_capability_error(
                        virtual_root.clone(),
                        FilesystemOperation::MountLocal,
                        error,
                    )
                })?;
        self.mounts.push(LocalMount {
            virtual_root,
            host_root: host_root.as_path().to_path_buf(),
            capability,
            leaf_scoped: false,
        });
        Ok(())
    }

    /// Mounts a host directory shared across many callers, each of whom is
    /// only ever granted (via their own `MountView`) a single leaf subtree
    /// of it — e.g. the `HostedSingleTenantVolumeSandboxed` profile's
    /// `/workspace` mount, whose shared parent holds every user's leaf
    /// sandbox-workspace directory. Containment for paths resolved through
    /// this mount is pinned per-request to `host_root/<leaf>`, where `<leaf>`
    /// is the first path segment after `virtual_root` — closing a symlink
    /// planted inside one caller's leaf from resolving into a sibling leaf,
    /// which a plain [`mount_local`](Self::mount_local) mount (containment at
    /// the full shared `host_root`) would not catch. See [`LocalMount::leaf_scoped`].
    pub fn mount_local_per_leaf(
        &mut self,
        virtual_root: VirtualPath,
        host_root: HostPath,
    ) -> Result<(), FilesystemError> {
        self.mount_local_impl(virtual_root, host_root, true)
    }

    fn mount_local_impl(
        &mut self,
        virtual_root: VirtualPath,
        host_root: HostPath,
        leaf_scoped: bool,
    ) -> Result<(), FilesystemError> {
        if self
            .mounts
            .iter()
            .any(|mount| mount.virtual_root.as_str() == virtual_root.as_str())
        {
            return Err(FilesystemError::MountConflict { path: virtual_root });
        }

        let canonical_root = std::fs::canonicalize(host_root.as_path()).map_err(|error| {
            FilesystemError::Backend {
                path: virtual_root.clone(),
                operation: FilesystemOperation::MountLocal,
                reason: io_reason(error),
            }
        })?;

        if !canonical_root.is_dir() {
            return Err(FilesystemError::Backend {
                path: virtual_root,
                operation: FilesystemOperation::MountLocal,
                reason: "host root is not a directory".to_string(),
            });
        }
        let capability =
            DiskDirectoryCapability::from_existing(&canonical_root).map_err(|error| {
                local_capability_error(virtual_root.clone(), FilesystemOperation::MountLocal, error)
            })?;

        self.mounts.push(LocalMount {
            virtual_root,
            host_root: canonical_root,
            capability,
            leaf_scoped,
        });
        Ok(())
    }

    async fn resolve_existing(
        &self,
        path: &VirtualPath,
        operation: FilesystemOperation,
    ) -> Result<PathBuf, FilesystemError> {
        let resolved = self.resolve_joined(path)?;
        let canonical = tokio::fs::canonicalize(&resolved.joined)
            .await
            .map_err(|error| io_error(path.clone(), operation, error))?;
        ensure_contained(path, &resolved.containment_root, &canonical, true)?;
        Ok(canonical)
    }

    /// Resolves `path` to its host-side join point plus the containment
    /// invariant callers must enforce against it.
    ///
    /// Bundling the ambient read path and retained write capability prevents
    /// callers from resolving those two sides against different mounts.
    fn resolve_joined(&self, path: &VirtualPath) -> Result<ResolvedMountPath, FilesystemError> {
        let mount = self
            .mounts
            .iter()
            .filter(|mount| path_prefix_matches(mount.virtual_root.as_str(), path.as_str()))
            .max_by_key(|mount| mount.virtual_root.as_str().len())
            .ok_or_else(|| FilesystemError::MountNotFound { path: path.clone() })?;

        let tail = path
            .as_str()
            .strip_prefix(mount.virtual_root.as_str())
            .unwrap_or_default()
            .trim_start_matches('/');

        let mut joined = mount.host_root.clone();
        let mut relative = PathBuf::new();
        let mut containment_root = mount.host_root.clone();
        if tail.is_empty() {
            // A leaf-scoped mount has no safe containment root for the bare
            // mount path itself — that would be "every caller's leaf", the
            // shared-parent boundary this mount kind exists to eliminate.
            // The composition-layer `MountView` always supplies a leaf, but
            // that invariant is enforced one layer up, so fail closed here.
            if mount.leaf_scoped {
                return Err(FilesystemError::PathOutsideMount { path: path.clone() });
            }
        } else {
            for (index, segment) in tail.split('/').enumerate() {
                joined.push(segment);
                relative.push(segment);
                if mount.leaf_scoped && index == 0 {
                    containment_root.push(segment);
                }
            }
        }
        Ok(ResolvedMountPath {
            joined,
            relative,
            capability: mount.capability.clone(),
            containment_root,
        })
    }
}

/// The host-side join point for a resolved `VirtualPath` plus the
/// containment invariant every write/read caller must enforce against it —
/// see [`DiskFilesystem::resolve_joined`] for why these three fields travel
/// together instead of as a positional tuple.
struct ResolvedMountPath {
    /// The host path `path` joins to under the mount's `host_root`,
    /// pre-canonicalization.
    joined: PathBuf,
    /// Capability-relative path, never containing parent or root components.
    relative: PathBuf,
    /// Retained mount-root handle used by mutating operations.
    capability: DiskDirectoryCapability,
    /// The boundary [`ensure_contained`] checks the canonicalized path
    /// against: `host_root` for an ordinary mount, or `host_root` plus the
    /// caller's own leaf segment for a [`LocalMount::leaf_scoped`] mount —
    /// see [`DiskFilesystem::resolve_joined`].
    containment_root: PathBuf,
}

#[async_trait]
impl RootFilesystem for DiskFilesystem {
    /// Native `put` for the byte-only local filesystem. Opaque-file entries
    /// (`kind = None`, empty `indexed`) support `CasExpectation::Any` and
    /// `CasExpectation::Absent`; record-shaped entries, populated indexed
    /// projections, and `Version(_)` are `Unsupported` because the local
    /// filesystem has no native metadata or version tracking (sidecar
    /// metadata is a future addition; see the reborn storage rework plan).
    /// We implement `put` here rather than relying on a trait default so that
    /// the put/write_file pair is non-recursive even when downstream consumers
    /// route through `put`.
    async fn put(
        &self,
        path: &VirtualPath,
        entry: Entry,
        cas: CasExpectation,
    ) -> Result<RecordVersion, FilesystemError> {
        if entry.kind.is_some() || !entry.indexed.is_empty() {
            return Err(FilesystemError::Unsupported {
                path: path.clone(),
                operation: FilesystemOperation::WriteFile,
            });
        }
        if matches!(cas, CasExpectation::Version(_)) {
            return Err(FilesystemError::Unsupported {
                path: path.clone(),
                operation: FilesystemOperation::WriteFile,
            });
        }
        self.write_file_with_cas(path, &entry.body, cas).await?;
        Ok(RecordVersion::from_backend(0))
    }

    /// Native `get` mirroring `put`: read the bytes and wrap as an opaque
    /// `Entry`. Version is always `0` because the local filesystem doesn't
    /// track per-path versions. Non-existent paths return `Ok(None)`;
    /// directories or symlinks return their respective `read_file` errors.
    async fn get(&self, path: &VirtualPath) -> Result<Option<VersionedEntry>, FilesystemError> {
        match self.read_file(path).await {
            Ok(body) => Ok(Some(VersionedEntry {
                path: path.clone(),
                entry: Entry::bytes(body),
                version: RecordVersion::from_backend(0),
            })),
            Err(FilesystemError::NotFound { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn create_subtree_atomic(
        &self,
        prefix: &VirtualPath,
        entries: Vec<AtomicSubtreeEntry>,
    ) -> Result<Vec<RecordVersion>, FilesystemError> {
        validate_local_atomic_subtree(prefix, &entries)?;
        let resolved = self.resolve_joined(prefix)?;
        let relative_prefix = resolved.relative;
        let capability = resolved.capability;
        let prefix_with_separator = format!("{}/", prefix.as_str().trim_end_matches('/'));
        let entry_count = entries.len();
        let mut relative_entries = Vec::with_capacity(entry_count);
        for item in entries {
            let relative = item
                .path
                .as_str()
                .strip_prefix(&prefix_with_separator)
                .ok_or_else(|| FilesystemError::PathOutsideMount {
                    path: item.path.clone(),
                })?;
            relative_entries.push((PathBuf::from(relative), item.entry.body));
        }
        let counter = LOCAL_WRITE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        match tokio::task::spawn_blocking(move || {
            capability.create_subtree_atomic(&relative_prefix, relative_entries, counter)
        })
        .await
        .map_err(|error| {
            local_capability_error(
                prefix.clone(),
                FilesystemOperation::CreateSubtreeAtomic,
                std::io::Error::other(error),
            )
        })? {
            Ok(()) => Ok(vec![RecordVersion::from_backend(0); entry_count]),
            Err(CapabilityWriteError::Io(error)) => Err(local_capability_error(
                prefix.clone(),
                FilesystemOperation::CreateSubtreeAtomic,
                error,
            )),
            Err(CapabilityWriteError::SymlinkEscape) => Err(FilesystemError::SymlinkEscape {
                path: prefix.clone(),
            }),
            Err(CapabilityWriteError::VersionMismatch) => Err(FilesystemError::VersionMismatch {
                path: prefix.clone(),
                expected: None,
                found: Some(RecordVersion::from_backend(0)),
            }),
            Err(CapabilityWriteError::UnsupportedVersion) => Err(FilesystemError::Unsupported {
                path: prefix.clone(),
                operation: FilesystemOperation::CreateSubtreeAtomic,
            }),
        }
    }

    async fn read_file(&self, path: &VirtualPath) -> Result<Vec<u8>, FilesystemError> {
        let resolved = self
            .resolve_existing(path, FilesystemOperation::ReadFile)
            .await?;
        tokio::fs::read(resolved)
            .await
            .map_err(|error| io_error(path.clone(), FilesystemOperation::ReadFile, error))
    }

    async fn read_file_bounded(
        &self,
        path: &VirtualPath,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, FilesystemError> {
        let resolved = self
            .resolve_existing(path, FilesystemOperation::ReadFile)
            .await?;
        let file = tokio::fs::File::open(&resolved)
            .await
            .map_err(|error| io_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        let metadata = file
            .metadata()
            .await
            .map_err(|error| io_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        if !metadata.is_file() {
            return Err(FilesystemError::Backend {
                path: path.clone(),
                operation: FilesystemOperation::ReadFile,
                reason: "not a file".to_string(),
            });
        }
        if metadata.len() > max_bytes as u64 {
            return Ok(None);
        }

        let mut bytes = Vec::with_capacity(max_bytes.min(metadata.len() as usize));
        file.take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| io_error(path.clone(), FilesystemOperation::ReadFile, error))?;
        if bytes.len() > max_bytes {
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    async fn write_file(&self, path: &VirtualPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        self.write_file_with_cas(path, bytes, CasExpectation::Any)
            .await
    }

    async fn append_file(&self, path: &VirtualPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        let resolved = self.resolve_joined(path)?;
        let relative = resolved.relative;
        let capability = resolved.capability;
        let bytes = bytes.to_vec();
        run_capability_blocking(move || capability.append(&relative, &bytes))
            .await
            .map_err(|error| {
                local_capability_error(path.clone(), FilesystemOperation::AppendFile, error)
            })
    }

    async fn list_dir(&self, path: &VirtualPath) -> Result<Vec<DirEntry>, FilesystemError> {
        self.list_dir_bounded(path, usize::MAX).await
    }

    async fn list_dir_bounded(
        &self,
        path: &VirtualPath,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>, FilesystemError> {
        let resolved = self
            .resolve_existing(path, FilesystemOperation::ListDir)
            .await?;
        let mut read_dir = tokio::fs::read_dir(resolved)
            .await
            .map_err(|error| io_error(path.clone(), FilesystemOperation::ListDir, error))?;
        let mut entries = Vec::new();
        while entries.len() < max_entries {
            let Some(entry) = read_dir
                .next_entry()
                .await
                .map_err(|error| io_error(path.clone(), FilesystemOperation::ListDir, error))?
            else {
                break;
            };
            let name = entry.file_name().to_string_lossy().to_string();
            let entry_path =
                VirtualPath::new(format!("{}/{}", path.as_str().trim_end_matches('/'), name))?;
            let metadata = entry
                .metadata()
                .await
                .map_err(|error| io_error(entry_path.clone(), FilesystemOperation::Stat, error))?;
            entries.push(DirEntry {
                name,
                path: entry_path,
                file_type: file_type_from_metadata(&metadata),
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    async fn list_dir_page(
        &self,
        path: &VirtualPath,
        after: Option<&str>,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>, FilesystemError> {
        if max_entries == 0 {
            return Ok(Vec::new());
        }
        let resolved = self
            .resolve_existing(path, FilesystemOperation::ListDir)
            .await?;
        let mut read_dir = tokio::fs::read_dir(resolved)
            .await
            .map_err(|error| io_error(path.clone(), FilesystemOperation::ListDir, error))?;
        let mut page = std::collections::BTreeMap::<String, DirEntry>::new();
        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|error| io_error(path.clone(), FilesystemOperation::ListDir, error))?
        {
            let name = entry.file_name().to_string_lossy().to_string();
            if after.is_some_and(|cursor| name.as_str() <= cursor) {
                continue;
            }
            let entry_path =
                VirtualPath::new(format!("{}/{}", path.as_str().trim_end_matches('/'), name))?;
            let metadata = entry
                .metadata()
                .await
                .map_err(|error| io_error(entry_path.clone(), FilesystemOperation::Stat, error))?;
            page.insert(
                name.clone(),
                DirEntry {
                    name,
                    path: entry_path,
                    file_type: file_type_from_metadata(&metadata),
                },
            );
            if page.len() > max_entries {
                page.pop_last();
            }
        }
        Ok(page.into_values().collect())
    }

    async fn stat(&self, path: &VirtualPath) -> Result<FileStat, FilesystemError> {
        let resolved = self
            .resolve_existing(path, FilesystemOperation::Stat)
            .await?;
        let metadata = tokio::fs::metadata(&resolved)
            .await
            .map_err(|error| io_error(path.clone(), FilesystemOperation::Stat, error))?;
        Ok(FileStat {
            path: path.clone(),
            file_type: file_type_from_metadata(&metadata),
            len: metadata.len(),
            modified: metadata.modified().ok(),
            sensitive: is_sensitive_path(&resolved),
        })
    }

    async fn delete(&self, path: &VirtualPath) -> Result<(), FilesystemError> {
        // `resolved` is the canonicalized, containment-checked path from
        // `resolve_existing`, but the check and the removal below are still
        // two syscalls: an ancestor symlink swapped in between them is the
        // same residual TOCTOU window documented on `resolve_for_write`
        // (local.rs) and not closed until descriptor/capability-rooted
        // traversal lands (PR #2996 review follow-up). `remove_dir_all` and
        // `remove_file` operate on the already-canonical `resolved` path
        // rather than re-walking `path`'s original components, which keeps
        // this in line with the other mutating operations in this file.
        let resolved = self
            .resolve_existing(path, FilesystemOperation::Delete)
            .await?;
        let metadata = tokio::fs::metadata(&resolved)
            .await
            .map_err(|error| io_error(path.clone(), FilesystemOperation::Delete, error))?;
        let result = if metadata.is_dir() {
            tokio::fs::remove_dir_all(resolved).await
        } else {
            tokio::fs::remove_file(resolved).await
        };
        result.map_err(|error| io_error(path.clone(), FilesystemOperation::Delete, error))
    }

    async fn create_dir_all(&self, path: &VirtualPath) -> Result<(), FilesystemError> {
        let resolved = self.resolve_joined(path)?;
        let relative = resolved.relative;
        let capability = resolved.capability;
        run_capability_blocking(move || capability.create_dir_all(&relative))
            .await
            .map_err(|error| {
                local_capability_error(path.clone(), FilesystemOperation::CreateDirAll, error)
            })
    }
}

impl DiskFilesystem {
    async fn write_file_with_cas(
        &self,
        path: &VirtualPath,
        bytes: &[u8],
        cas: CasExpectation,
    ) -> Result<(), FilesystemError> {
        let resolved = self.resolve_joined(path)?;
        let relative = resolved.relative;
        let capability = resolved.capability;
        let bytes = bytes.to_vec();
        let counter = LOCAL_WRITE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        match tokio::task::spawn_blocking(move || {
            capability.atomic_write(&relative, &bytes, cas, counter)
        })
        .await
        .map_err(|error| {
            local_capability_error(
                path.clone(),
                FilesystemOperation::WriteFile,
                std::io::Error::other(error),
            )
        })? {
            Ok(()) => Ok(()),
            Err(CapabilityWriteError::Io(error)) => Err(local_capability_error(
                path.clone(),
                FilesystemOperation::WriteFile,
                error,
            )),
            Err(CapabilityWriteError::SymlinkEscape) => {
                Err(FilesystemError::SymlinkEscape { path: path.clone() })
            }
            Err(CapabilityWriteError::VersionMismatch) => Err(FilesystemError::VersionMismatch {
                path: path.clone(),
                expected: None,
                found: Some(RecordVersion::from_backend(0)),
            }),
            Err(CapabilityWriteError::UnsupportedVersion) => Err(FilesystemError::Unsupported {
                path: path.clone(),
                operation: FilesystemOperation::WriteFile,
            }),
        }
    }
}

fn local_capability_error(
    path: VirtualPath,
    operation: FilesystemOperation,
    source: std::io::Error,
) -> FilesystemError {
    FilesystemError::LocalCapability {
        path,
        operation,
        source,
    }
}

fn validate_local_atomic_subtree(
    prefix: &VirtualPath,
    entries: &[AtomicSubtreeEntry],
) -> Result<(), FilesystemError> {
    validate_atomic_subtree_entries(prefix, entries)?;
    for item in entries {
        if item.entry.kind.is_some() || !item.entry.indexed.is_empty() {
            return Err(FilesystemError::Unsupported {
                path: item.path.clone(),
                operation: FilesystemOperation::CreateSubtreeAtomic,
            });
        }
    }
    Ok(())
}

/// Checks `candidate` (an already-canonicalized host path) is contained
/// within `containment_root`. For a plain mount, `containment_root` is the
/// mount's `host_root`; for a [`LocalMount::leaf_scoped`] mount it is the
/// caller's own leaf under `host_root` (see [`DiskFilesystem::resolve_joined`]),
/// so a symlink that escapes the caller's leaf — even while staying inside
/// the shared `host_root` — is rejected here exactly like an escape past
/// `host_root` itself.
fn ensure_contained(
    virtual_path: &VirtualPath,
    containment_root: &Path,
    candidate: &Path,
    existing_target: bool,
) -> Result<(), FilesystemError> {
    if candidate.starts_with(containment_root) {
        Ok(())
    } else if existing_target {
        Err(FilesystemError::SymlinkEscape {
            path: virtual_path.clone(),
        })
    } else {
        Err(FilesystemError::PathOutsideMount {
            path: virtual_path.clone(),
        })
    }
}

fn file_type_from_metadata(metadata: &std::fs::Metadata) -> FileType {
    let file_type = metadata.file_type();
    if file_type.is_file() {
        FileType::File
    } else if file_type.is_dir() {
        FileType::Directory
    } else if file_type.is_symlink() {
        FileType::Symlink
    } else {
        FileType::Other
    }
}

fn io_error(
    path: VirtualPath,
    operation: FilesystemOperation,
    error: std::io::Error,
) -> FilesystemError {
    if error.kind() == std::io::ErrorKind::NotFound {
        return FilesystemError::NotFound { path, operation };
    }

    tracing::debug!(
        virtual_path = path.as_str(),
        %operation,
        error = %error,
        "local filesystem backend error"
    );
    FilesystemError::Backend {
        path,
        operation,
        reason: error.kind().to_string(),
    }
}

fn io_reason(error: std::io::Error) -> String {
    error.kind().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn missing_local_paths_do_not_log_backend_error() {
        let storage = tempdir().unwrap();
        let mut root = DiskFilesystem::new();
        root.mount_local(
            VirtualPath::new("/projects").unwrap(),
            HostPath::from_path_buf(storage.path().to_path_buf()),
        )
        .unwrap();

        let read_error = root
            .read_file(&VirtualPath::new("/projects/missing.txt").unwrap())
            .await
            .unwrap_err();
        let stat_error = root
            .stat(&VirtualPath::new("/projects/also-missing.txt").unwrap())
            .await
            .unwrap_err();

        assert!(matches!(read_error, FilesystemError::NotFound { .. }));
        assert!(matches!(stat_error, FilesystemError::NotFound { .. }));
        assert!(!logs_contain("local filesystem backend error"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn non_not_found_io_error_logs_backend_error() {
        let error = io_error(
            VirtualPath::new("/projects/secret.txt").unwrap(),
            FilesystemOperation::ReadFile,
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );

        assert!(matches!(error, FilesystemError::Backend { .. }));
        assert!(logs_contain("local filesystem backend error"));
    }

    /// A `mount_local_per_leaf` mount's containment boundary is the caller's
    /// own leaf (`host_root/<first-tail-segment>`), derived from the tail —
    /// there is no safe containment root for the bare mount path itself
    /// (that would mean "every caller's leaf", the exact shared-parent
    /// boundary `mount_local_per_leaf` exists to eliminate). Today every
    /// legitimate grant against such a mount always resolves to a
    /// leaf-prefixed target (`sandbox_user_workspace_mount_view` in
    /// `ironclaw_composition`), but that is an invariant enforced one
    /// layer up, not by this crate — so a bare-root request must fail closed
    /// here rather than silently fall back to the full shared parent.
    #[tokio::test]
    async fn leaf_scoped_mount_rejects_bare_mount_root_request() {
        let storage = tempdir().unwrap();
        let mut root = DiskFilesystem::new();
        root.mount_local_per_leaf(
            VirtualPath::new("/tmp").unwrap(),
            HostPath::from_path_buf(storage.path().to_path_buf()),
        )
        .unwrap();

        let error = root
            .read_file(&VirtualPath::new("/tmp").unwrap())
            .await
            .unwrap_err();

        assert!(
            matches!(error, FilesystemError::PathOutsideMount { .. }),
            "expected PathOutsideMount, got: {error:?}"
        );
    }

    /// The actual escape `leaf_scoped` containment exists to close: two
    /// callers share one `mount_local_per_leaf` `host_root`, each confined to
    /// their own leaf (`leaf-a`, `leaf-b`). A symlink planted inside
    /// `leaf-a` pointing at `../leaf-b/secret.txt` stays within the shared
    /// `host_root` — a plain `mount_local` containment check (host_root
    /// only) would let it resolve — but leaves `leaf-a`'s own containment
    /// root, so it must be rejected here.
    #[cfg(unix)]
    #[tokio::test]
    async fn leaf_scoped_mount_rejects_cross_leaf_symlink_escape() {
        let storage = tempdir().unwrap();
        let host_root = storage.path();

        let leaf_a = host_root.join("leaf-a");
        let leaf_b = host_root.join("leaf-b");
        std::fs::create_dir_all(&leaf_a).unwrap();
        std::fs::create_dir_all(&leaf_b).unwrap();
        std::fs::write(leaf_b.join("secret.txt"), b"leaf-b secret").unwrap();
        std::os::unix::fs::symlink("../leaf-b/secret.txt", leaf_a.join("escape.txt")).unwrap();

        let mut root = DiskFilesystem::new();
        root.mount_local_per_leaf(
            VirtualPath::new("/tmp").unwrap(),
            HostPath::from_path_buf(host_root.to_path_buf()),
        )
        .unwrap();

        let error = root
            .read_file(&VirtualPath::new("/tmp/leaf-a/escape.txt").unwrap())
            .await
            .unwrap_err();

        assert!(
            matches!(error, FilesystemError::SymlinkEscape { .. }),
            "expected SymlinkEscape, got: {error:?}"
        );
    }

    /// A retained shared-root capability may safely create the caller's
    /// server-selected leaf without ambient-path bootstrap checks.
    #[tokio::test]
    async fn leaf_scoped_mount_creates_a_brand_new_leaf_on_first_write() {
        let storage = tempdir().unwrap();
        let host_root = storage.path();

        let mut root = DiskFilesystem::new();
        root.mount_local_per_leaf(
            VirtualPath::new("/tmp").unwrap(),
            HostPath::from_path_buf(host_root.to_path_buf()),
        )
        .unwrap();

        root.write_file(
            &VirtualPath::new("/tmp/new-leaf/file.txt").unwrap(),
            b"hello",
        )
        .await
        .unwrap();

        let bytes = root
            .read_file(&VirtualPath::new("/tmp/new-leaf/file.txt").unwrap())
            .await
            .unwrap();
        assert_eq!(bytes, b"hello");
    }

    /// Same first-use bootstrap through capability-relative `create_dir_all`.
    #[tokio::test]
    async fn leaf_scoped_mount_create_dir_all_bootstraps_a_brand_new_leaf() {
        let storage = tempdir().unwrap();
        let host_root = storage.path();

        let mut root = DiskFilesystem::new();
        root.mount_local_per_leaf(
            VirtualPath::new("/tmp").unwrap(),
            HostPath::from_path_buf(host_root.to_path_buf()),
        )
        .unwrap();

        root.create_dir_all(&VirtualPath::new("/tmp/new-leaf/nested").unwrap())
            .await
            .unwrap();

        assert!(host_root.join("new-leaf").join("nested").is_dir());
    }

    /// Bootstrapping a new leaf must not reopen the cross-leaf symlink
    /// escape the write path closes: a *pre-existing* sibling leaf's
    /// symlink must still be rejected by `resolve_for_write`
    /// (`append_file`/`write_file`), not just by `read_file`.
    #[cfg(unix)]
    #[tokio::test]
    async fn leaf_scoped_mount_rejects_cross_leaf_symlink_escape_on_write() {
        let storage = tempdir().unwrap();
        let host_root = storage.path();

        let leaf_a = host_root.join("leaf-a");
        let leaf_b = host_root.join("leaf-b");
        std::fs::create_dir_all(&leaf_a).unwrap();
        std::fs::create_dir_all(&leaf_b).unwrap();
        std::os::unix::fs::symlink("../leaf-b", leaf_a.join("escape")).unwrap();

        let mut root = DiskFilesystem::new();
        root.mount_local_per_leaf(
            VirtualPath::new("/tmp").unwrap(),
            HostPath::from_path_buf(host_root.to_path_buf()),
        )
        .unwrap();

        let error = root
            .write_file(
                &VirtualPath::new("/tmp/leaf-a/escape/planted.txt").unwrap(),
                b"planted",
            )
            .await
            .unwrap_err();

        assert!(
            matches!(error, FilesystemError::SymlinkEscape { .. }),
            "expected SymlinkEscape, got: {error:?}"
        );
        assert!(!leaf_b.join("planted.txt").exists());
    }

    /// A *dangling* final symlink — the entry exists but its target does
    /// not — must still be rejected. `tokio::fs::try_exists` follows
    /// symlinks and reports `false` for a target that doesn't exist yet, so
    /// naively treating "not exists" as "brand new file in this leaf" would
    /// let `write_file`/`append_file` open through the symlink (the OS
    /// creates the target on `O_CREAT`), writing into whatever sibling leaf
    /// (or worse) the symlink points at.
    #[cfg(unix)]
    #[tokio::test]
    async fn leaf_scoped_mount_rejects_dangling_final_symlink_escape_on_write() {
        let storage = tempdir().unwrap();
        let host_root = storage.path();

        let leaf_a = host_root.join("leaf-a");
        let leaf_b = host_root.join("leaf-b");
        std::fs::create_dir_all(&leaf_a).unwrap();
        std::fs::create_dir_all(&leaf_b).unwrap();
        std::os::unix::fs::symlink("../leaf-b/planted.txt", leaf_a.join("escape.txt")).unwrap();

        let mut root = DiskFilesystem::new();
        root.mount_local_per_leaf(
            VirtualPath::new("/tmp").unwrap(),
            HostPath::from_path_buf(host_root.to_path_buf()),
        )
        .unwrap();

        let error = root
            .write_file(
                &VirtualPath::new("/tmp/leaf-a/escape.txt").unwrap(),
                b"planted",
            )
            .await
            .unwrap_err();

        assert!(
            matches!(error, FilesystemError::SymlinkEscape { .. }),
            "expected SymlinkEscape, got: {error:?}"
        );
        assert!(!leaf_b.join("planted.txt").exists());
    }
}
