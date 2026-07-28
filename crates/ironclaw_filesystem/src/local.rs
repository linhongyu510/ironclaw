use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
};

use async_trait::async_trait;
use ironclaw_host_api::{HostPath, VirtualPath};
use ironclaw_safety::sensitive_paths::is_sensitive_path_str;
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::{
    CasExpectation, DirEntry, Entry, FileStat, FileType, FilesystemError, FilesystemOperation,
    RecordVersion, RootFilesystem, VersionedEntry, path_prefix_matches,
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
    /// An open directory descriptor on the mount's canonical host root,
    /// opened once at mount time. Every request resolves *from this fd*,
    /// component by component, with `O_NOFOLLOW` (or the single-syscall
    /// `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` equivalent on
    /// Linux) — so a symlink swapped in after any earlier check is never
    /// followed, closing the pathname-check-then-separate-syscall TOCTOU
    /// window `resolve_existing` / `resolve_for_write` /
    /// `resolve_for_create_dir_all` used to leave open. See [`open_one`].
    ///
    /// Wrapped in `Arc` (not re-opened per request): cloning an `Arc<OwnedFd>`
    /// shares the same underlying open file description rather than
    /// `dup`-ing a new fd, which is exactly what we want here — directory
    /// fds used only for relative `openat`/`mkdirat`/`unlinkat`/`fstatat`
    /// lookups carry no mutable per-fd state (no seek offset, no O_APPEND
    /// cursor) that a concurrent "clone" could corrupt, so many callers
    /// reading `self.mounts` concurrently and cloning this `Arc` is safe
    /// without any lock. `LocalMount` derives `Clone` for the same reason
    /// this crate never needed a lock around `mounts: Vec<LocalMount>`
    /// before: nothing here ever mutates a mount after `mount_local`/
    /// `mount_local_per_leaf` pushes it, so concurrent readers only ever see
    /// a fully-constructed, immutable `LocalMount` — cloning is cheap
    /// (refcount bump) and never races.
    root_fd: Arc<OwnedFd>,
    /// When `true`, this mount is shared by many callers who are each only
    /// ever granted a single leaf subtree of it (one [`MountGrant`] target
    /// per caller, narrowed by the composition-layer `MountView` resolver —
    /// e.g. the sandboxed-profile `/workspace` mount, where every user's
    /// `MountView` target is `/workspace/<digest>`).
    ///
    /// Containment no longer needs a *narrower* boundary for this mount kind
    /// than for an ordinary one: because [`open_one`] refuses to traverse
    /// **any** symlink anywhere in a resolved path (not just one that would
    /// land outside the mount), a symlink planted in one caller's leaf can
    /// never be followed into a sibling leaf either — the whole attack class
    /// this flag used to need a bespoke `containment_root`/
    /// `ensure_existing_ancestor_contained` bootstrap-boundary calculation
    /// for is closed by the same no-symlink-traversal rule that protects
    /// ordinary mounts. `leaf_scoped` now exists purely to preserve one
    /// policy decision: a request against the bare mount root (no leaf
    /// segment at all) must still fail closed rather than resolving to the
    /// shared parent every caller's leaf lives under. See
    /// [`DiskFilesystem::resolve_mount_target`].
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
    /// file operations after mount setup use fd-relative syscalls (see
    /// [`open_one`]) run on the blocking pool.
    pub fn mount_local(
        &mut self,
        virtual_root: VirtualPath,
        host_root: HostPath,
    ) -> Result<(), FilesystemError> {
        self.mount_local_impl(virtual_root, host_root, false)
    }

    /// Mounts a host directory shared across many callers, each of whom is
    /// only ever granted (via their own `MountView`) a single leaf subtree
    /// of it — e.g. the `HostedSingleTenantVolumeSandboxed` profile's
    /// `/workspace` mount, whose shared parent holds every user's leaf
    /// sandbox-workspace directory. See [`LocalMount::leaf_scoped`] for why
    /// this no longer needs a distinct containment boundary from
    /// [`mount_local`](Self::mount_local).
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

        let root_fd = rustix::fs::open(
            &canonical_root,
            OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|errno| FilesystemError::Backend {
            path: virtual_root.clone(),
            operation: FilesystemOperation::MountLocal,
            reason: io_reason(errno.into()),
        })?;

        self.mounts.push(LocalMount {
            virtual_root,
            root_fd: Arc::new(root_fd),
            leaf_scoped,
        });
        Ok(())
    }

    /// Routes `path` to its mount and splits the tail into path components
    /// under that mount's `root_fd`. No filesystem access happens here —
    /// this is pure string/virtual-path routing, unchanged in shape from
    /// before this fix, and is not part of the TOCTOU surface: the actual
    /// containment enforcement now happens fd-relatively in [`open_one`] as
    /// each returned component is walked.
    fn resolve_mount_target(&self, path: &VirtualPath) -> Result<MountTarget, FilesystemError> {
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

        if tail.is_empty() && mount.leaf_scoped {
            // A leaf-scoped mount has no safe target for the bare mount path
            // itself — that would be "every caller's leaf", the shared-parent
            // boundary this mount kind exists to eliminate. The
            // composition-layer `MountView` always supplies a leaf, but that
            // invariant is enforced one layer up, so fail closed here.
            return Err(FilesystemError::PathOutsideMount { path: path.clone() });
        }

        let mut components = Vec::new();
        for segment in tail.split('/').filter(|segment| !segment.is_empty()) {
            // The virtual-path layer (`ScopedPath::new`) already rejects
            // literal `..` segments before a caller-controlled path ever
            // reaches this crate, but `VirtualPath` itself does not enforce
            // that (this crate's own tests construct arbitrary
            // `VirtualPath` values), and every component below is handed
            // directly to `openat`/`mkdirat` — which *do* interpret a `..`
            // component as "go to the parent directory". Reject it here,
            // defensively, before any fd work: this is the one place a
            // literal `..` could turn into a real directory-fd escape.
            if segment == ".." {
                return Err(FilesystemError::PathOutsideMount { path: path.clone() });
            }
            if segment == "." {
                continue;
            }
            components.push(OsString::from(segment));
        }

        Ok(MountTarget {
            root_fd: Arc::clone(&mount.root_fd),
            components,
        })
    }
}

/// A mount plus the path components to walk under its `root_fd`. Carries no
/// host path — every subsequent step is fd-relative.
struct MountTarget {
    root_fd: Arc<OwnedFd>,
    components: Vec<OsString>,
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

    async fn read_file(&self, path: &VirtualPath) -> Result<Vec<u8>, FilesystemError> {
        let target = self.resolve_mount_target(path)?;
        let path = path.clone();
        run_blocking(path.clone(), FilesystemOperation::ReadFile, move || {
            let (fd, _parent) = resolve_walk(
                target.root_fd.as_fd(),
                &target.components,
                OFlags::RDONLY,
            )
            .map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::ReadFile, error)
            })?;
            let stat = rustix::fs::fstat(&fd).map_err(|errno| {
                io_error(path.clone(), FilesystemOperation::ReadFile, errno.into())
            })?;
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                != rustix::fs::FileType::RegularFile
            {
                return Err(FilesystemError::Backend {
                    path: path.clone(),
                    operation: FilesystemOperation::ReadFile,
                    reason: "not a file".to_string(),
                });
            }
            read_all(fd)
                .map_err(|error| io_error(path.clone(), FilesystemOperation::ReadFile, error))
        })
        .await
    }

    async fn read_file_bounded(
        &self,
        path: &VirtualPath,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, FilesystemError> {
        let target = self.resolve_mount_target(path)?;
        let path = path.clone();
        run_blocking(path.clone(), FilesystemOperation::ReadFile, move || {
            let (fd, _parent) = resolve_walk(
                target.root_fd.as_fd(),
                &target.components,
                OFlags::RDONLY,
            )
            .map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::ReadFile, error)
            })?;
            let stat = rustix::fs::fstat(&fd).map_err(|errno| {
                io_error(path.clone(), FilesystemOperation::ReadFile, errno.into())
            })?;
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                != rustix::fs::FileType::RegularFile
            {
                return Err(FilesystemError::Backend {
                    path: path.clone(),
                    operation: FilesystemOperation::ReadFile,
                    reason: "not a file".to_string(),
                });
            }
            if stat.st_size < 0 || stat.st_size as u64 > max_bytes as u64 {
                return Ok(None);
            }
            let bytes = read_all(fd)
                .map_err(|error| io_error(path.clone(), FilesystemOperation::ReadFile, error))?;
            if bytes.len() > max_bytes {
                return Ok(None);
            }
            Ok(Some(bytes))
        })
        .await
    }

    async fn write_file(&self, path: &VirtualPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        self.write_file_with_cas(path, bytes, CasExpectation::Any)
            .await
    }

    async fn append_file(&self, path: &VirtualPath, bytes: &[u8]) -> Result<(), FilesystemError> {
        let target = self.resolve_mount_target(path)?;
        let (parent_components, leaf) = split_leaf(&target.components, path)?;
        let bytes = bytes.to_vec();
        let path = path.clone();
        run_blocking(path.clone(), FilesystemOperation::AppendFile, move || {
            let parent_fd =
                descend_creating(target.root_fd.as_fd(), &parent_components).map_err(|error| {
                    resolve_error_to_filesystem_error(&path, FilesystemOperation::AppendFile, error)
                })?;
            let fd = open_one(
                parent_fd.as_fd(),
                &leaf,
                OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE,
                new_file_mode(),
            )
            .map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::AppendFile, error)
            })?;
            write_all(fd, &bytes)
                .map_err(|error| io_error(path.clone(), FilesystemOperation::AppendFile, error))
        })
        .await
    }

    async fn list_dir(&self, path: &VirtualPath) -> Result<Vec<DirEntry>, FilesystemError> {
        self.list_dir_bounded(path, usize::MAX).await
    }

    async fn list_dir_bounded(
        &self,
        path: &VirtualPath,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>, FilesystemError> {
        let target = self.resolve_mount_target(path)?;
        let path = path.clone();
        run_blocking(path.clone(), FilesystemOperation::ListDir, move || {
            let (fd, _parent) = resolve_walk(
                target.root_fd.as_fd(),
                &target.components,
                OFlags::RDONLY,
            )
            .map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::ListDir, error)
            })?;
            let mut listing = rustix::fs::Dir::read_from(fd.as_fd()).map_err(|errno| {
                io_error(path.clone(), FilesystemOperation::ListDir, errno.into())
            })?;
            let mut entries = Vec::new();
            while entries.len() < max_entries {
                let Some(raw_entry) = listing.next() else {
                    break;
                };
                let raw_entry = raw_entry.map_err(|errno| {
                    io_error(path.clone(), FilesystemOperation::ListDir, errno.into())
                })?;
                let name_bytes = raw_entry.file_name().to_bytes();
                if name_bytes == b"." || name_bytes == b".." {
                    continue;
                }
                let name = OsStr::from_bytes(name_bytes);
                let name_str = name.to_string_lossy().to_string();
                let entry_path = VirtualPath::new(format!(
                    "{}/{}",
                    path.as_str().trim_end_matches('/'),
                    name_str
                ))?;
                // `AT_SYMLINK_NOFOLLOW`: report a symlink child as a symlink,
                // never resolve through it to describe whatever it points
                // at (which may be outside the mount entirely).
                let stat = rustix::fs::statat(fd.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|errno| {
                        io_error(entry_path.clone(), FilesystemOperation::Stat, errno.into())
                    })?;
                entries.push(DirEntry {
                    name: name_str,
                    path: entry_path,
                    file_type: map_file_type(rustix::fs::FileType::from_raw_mode(stat.st_mode)),
                });
            }
            entries.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(entries)
        })
        .await
    }

    async fn stat(&self, path: &VirtualPath) -> Result<FileStat, FilesystemError> {
        let target = self.resolve_mount_target(path)?;
        let path = path.clone();
        run_blocking(path.clone(), FilesystemOperation::Stat, move || {
            let (fd, _parent) =
                resolve_walk(target.root_fd.as_fd(), &target.components, OFlags::RDONLY).map_err(
                    |error| {
                        resolve_error_to_filesystem_error(&path, FilesystemOperation::Stat, error)
                    },
                )?;
            let stat = rustix::fs::fstat(&fd)
                .map_err(|errno| io_error(path.clone(), FilesystemOperation::Stat, errno.into()))?;
            let len = if stat.st_size < 0 {
                0
            } else {
                stat.st_size as u64
            };
            Ok(FileStat {
                path: path.clone(),
                file_type: map_file_type(rustix::fs::FileType::from_raw_mode(stat.st_mode)),
                len,
                modified: stat_modified(stat.st_mtime, stat.st_mtime_nsec),
                // No host path to check anymore (by design — see the module
                // doc): the string-only, filesystem-access-free
                // `is_sensitive_path_str` checks the same filename patterns
                // (`.env`, `.pem`, …) against the virtual path's leaf
                // component, which is identical to the host path's leaf
                // component for every mount (mounting only ever renames the
                // path *prefix*).
                sensitive: is_sensitive_path_str(path.as_str()),
            })
        })
        .await
    }

    async fn delete(&self, path: &VirtualPath) -> Result<(), FilesystemError> {
        let target = self.resolve_mount_target(path)?;
        if target.components.is_empty() {
            // Removing an entire mount's root by virtual-path traversal was
            // never an intentional capability (the old path-based
            // implementation happened to allow it as a side effect of
            // `resolve_existing` resolving the bare mount root). The
            // fd-rooted resolver has no parent fd for the mount root itself
            // — by design, it never holds an fd outside `root_fd` — so this
            // fails closed instead.
            return Err(FilesystemError::PathOutsideMount { path: path.clone() });
        }
        let path = path.clone();
        run_blocking(path.clone(), FilesystemOperation::Delete, move || {
            let (fd, parent) =
                resolve_walk(target.root_fd.as_fd(), &target.components, OFlags::RDONLY).map_err(
                    |error| {
                        resolve_error_to_filesystem_error(&path, FilesystemOperation::Delete, error)
                    },
                )?;
            let Some((parent_fd, name)) = parent else {
                return Err(FilesystemError::PathOutsideMount { path: path.clone() });
            };
            let stat = rustix::fs::fstat(&fd).map_err(|errno| {
                io_error(path.clone(), FilesystemOperation::Delete, errno.into())
            })?;
            drop(fd);
            if rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory
            {
                remove_dir_all_fd(parent_fd.as_fd(), &name)
                    .map_err(|error| io_error(path.clone(), FilesystemOperation::Delete, error))
            } else {
                rustix::fs::unlinkat(parent_fd.as_fd(), &name, AtFlags::empty()).map_err(|errno| {
                    io_error(path.clone(), FilesystemOperation::Delete, errno.into())
                })
            }
        })
        .await
    }

    async fn create_dir_all(&self, path: &VirtualPath) -> Result<(), FilesystemError> {
        let target = self.resolve_mount_target(path)?;
        let path = path.clone();
        run_blocking(path.clone(), FilesystemOperation::CreateDirAll, move || {
            descend_creating(target.root_fd.as_fd(), &target.components)
                .map(|_fd| ())
                .map_err(|error| {
                    resolve_error_to_filesystem_error(
                        &path,
                        FilesystemOperation::CreateDirAll,
                        error,
                    )
                })
        })
        .await
    }
}

impl DiskFilesystem {
    async fn write_file_with_cas(
        &self,
        path: &VirtualPath,
        bytes: &[u8],
        cas: CasExpectation,
    ) -> Result<(), FilesystemError> {
        let target = self.resolve_mount_target(path)?;
        let (parent_components, leaf) = split_leaf(&target.components, path)?;
        let bytes = bytes.to_vec();
        let path = path.clone();
        run_blocking(path.clone(), FilesystemOperation::WriteFile, move || {
            let parent_fd =
                descend_creating(target.root_fd.as_fd(), &parent_components).map_err(|error| {
                    resolve_error_to_filesystem_error(&path, FilesystemOperation::WriteFile, error)
                })?;
            atomic_write_file(&path, parent_fd.as_fd(), &leaf, &bytes, cas)
        })
        .await
    }
}

/// Splits `components` into its parent directory components and its final
/// (leaf) component, for operations that create or open a specific file —
/// distinct from [`resolve_walk`], which is used by read-only operations
/// that may legitimately target the bare mount root.
fn split_leaf(
    components: &[OsString],
    path: &VirtualPath,
) -> Result<(Vec<OsString>, OsString), FilesystemError> {
    match components.split_last() {
        Some((leaf, parent)) => Ok((parent.to_vec(), leaf.clone())),
        None => Err(FilesystemError::PathOutsideMount { path: path.clone() }),
    }
}

/// Runs a synchronous, fd-rooted resolve-and-act closure on the blocking
/// pool, and flattens the `JoinError` case into a `FilesystemError`.
///
/// This is the structural fix's shape: everything inside `body` — walking
/// component-by-component from the mount's open root fd, and then acting on
/// the fd that walk produced — runs without ever crossing back through the
/// async scheduler. There is no `.await` between "resolve" and "act" for a
/// TOCTOU race to land in, because there is no longer a separate "resolve"
/// step that hands back a path string for a later, independent syscall to
/// re-resolve. The resolved fd itself, not a path, is what every subsequent
/// operation in `body` touches.
async fn run_blocking<T, F>(
    path: VirtualPath,
    operation: FilesystemOperation,
    body: F,
) -> Result<T, FilesystemError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, FilesystemError> + Send + 'static,
{
    match tokio::task::spawn_blocking(body).await {
        Ok(result) => result,
        Err(join_error) => Err(FilesystemError::Backend {
            path,
            operation,
            reason: format!("local filesystem blocking task panicked: {join_error}"),
        }),
    }
}

// ---------------------------------------------------------------------
// fd-rooted, symlink-free traversal primitives
// ---------------------------------------------------------------------
//
// Every function below operates purely on file descriptors and path
// *components* (never a joined host path string). `open_one` is the one
// place a directory-entry lookup happens, and it refuses to follow a
// symlink anywhere in the walk. Because resolution never hands back a path
// for a later, independent syscall to re-open, there is no window between
// "checked" and "acted on" for an attacker to swap the entry in.

/// The outcome of a failed fd-relative resolution step: either a genuine I/O
/// error (propagated as-is), or a symlink/`..`-past-root escape attempt.
enum ResolveError {
    Escape,
    Io(std::io::Error),
}

fn resolve_error_to_filesystem_error(
    path: &VirtualPath,
    operation: FilesystemOperation,
    error: ResolveError,
) -> FilesystemError {
    match error {
        ResolveError::Escape => FilesystemError::SymlinkEscape { path: path.clone() },
        ResolveError::Io(io_err) => io_error(path.clone(), operation, io_err),
    }
}

/// Opens exactly one path component beneath `dir`, refusing to follow a
/// symlink at that component.
///
/// On Linux, this is one syscall via `openat2(RESOLVE_BENEATH |
/// RESOLVE_NO_SYMLINKS)` when the kernel supports it (falling back below on
/// `ENOSYS` — an older kernel, or a container/seccomp profile that denies
/// `openat2` outright). Everywhere else, including macOS (which has no
/// `openat2` at all), a plain `openat` with `O_NOFOLLOW`.
///
/// **macOS asymmetry, documented rather than silent:** both paths reject the
/// same attack class — a symlink at any resolved path component, ancestor or
/// leaf — because `O_NOFOLLOW` and `RESOLVE_NO_SYMLINKS` both refuse to
/// traverse a symlink; the security property (no symlink traversal escapes
/// the mount root) holds identically on both platforms. What macOS's
/// fallback does *not* get is `RESOLVE_BENEATH`'s single-syscall,
/// kernel-enforced resolution step: each `open_one` call is independently
/// safe (it either opens the real, non-symlink entry or fails), but the
/// *sequence* of `open_one` calls that make up a full path walk on macOS is
/// coordinated by this module's own loop (`walk`/`resolve_walk`/
/// `descend_creating`), not by one kernel-verified decision the way
/// `RESOLVE_BENEATH` verifies a whole relative path in a single syscall on
/// Linux. Both close the same escape; only the mechanism differs.
fn open_one(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    oflags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, ResolveError> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{ResolveFlags, openat2};

        // `openat2(2)` documents `EAGAIN` for "a resolution restart was
        // necessary, e.g. because of concurrent rename or unlink of a path
        // component" — a *legitimate* concurrent mutation (an editor's
        // atomic save, `git checkout`, a parallel build touching the same
        // subtree), not an attack. Without a retry, a real, benign rename
        // racing an unrelated open makes `openat2` spuriously fail and the
        // caller sees an opaque `Backend` error for an operation that would
        // have succeeded a moment later. Retry a small, fixed number of
        // times — each retry is a fresh kernel-side resolution, not a busy
        // spin on our own state, so the bound only needs to outlast one
        // rename's duration, not any unbounded contention; the loop always
        // terminates within `MAX_AGAIN_RETRIES + 1` attempts, never spins
        // unbounded. What happens when the bound is exhausted is documented
        // at the `Err(Errno::AGAIN) => break` arm below.
        const MAX_AGAIN_RETRIES: u8 = 4;
        let mut retries = 0;
        loop {
            match openat2(
                dir,
                name,
                oflags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                mode,
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            ) {
                Ok(fd) => return Ok(fd),
                // Kernel predates openat2 (< 5.6), or a seccomp/container
                // policy denies the syscall outright. Fall through to the
                // portable per-component path below rather than failing
                // closed on a syscall the fallback doesn't need.
                Err(Errno::NOSYS) => break,
                Err(Errno::AGAIN) if retries < MAX_AGAIN_RETRIES => {
                    retries += 1;
                    continue;
                }
                // Retries exhausted (a pathological, sustained-rename case
                // rather than one atomic swap): fall through to the
                // portable per-component path below instead of surfacing an
                // opaque `Backend` error, since that path does not share
                // `openat2`'s whole-path-restart-on-`EAGAIN` failure mode.
                Err(Errno::AGAIN) => break,
                Err(Errno::LOOP) | Err(Errno::XDEV) => return Err(ResolveError::Escape),
                Err(errno) => return Err(ResolveError::Io(errno.into())),
            }
        }
    }
    match rustix::fs::openat(dir, name, oflags | OFlags::NOFOLLOW | OFlags::CLOEXEC, mode) {
        Ok(fd) => Ok(fd),
        Err(Errno::LOOP) => Err(ResolveError::Escape),
        // Some platforms (observed on macOS) report `ENOTDIR` rather than
        // `ELOOP` when `O_DIRECTORY | O_NOFOLLOW` hits a symlink — the
        // kernel checks "is this a directory" before "did NOFOLLOW block
        // it", and a symlink is never a directory itself. `ENOTDIR` is
        // ambiguous on its own (a plain non-directory file blocking descent
        // hits it too), so disambiguate with one `AT_SYMLINK_NOFOLLOW`
        // `fstatat` rather than guessing either way.
        Err(Errno::NOTDIR) if oflags.contains(OFlags::DIRECTORY) => {
            match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat)
                    if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                        == rustix::fs::FileType::Symlink =>
                {
                    Err(ResolveError::Escape)
                }
                _ => Err(ResolveError::Io(Errno::NOTDIR.into())),
            }
        }
        Err(errno) => Err(ResolveError::Io(errno.into())),
    }
}

fn dup_fd(fd: BorrowedFd<'_>) -> Result<OwnedFd, ResolveError> {
    rustix::io::dup(fd).map_err(|errno| ResolveError::Io(errno.into()))
}

/// Walks `components` from `root`, refusing every symlink along the way, and
/// returns the final entry's fd plus — when `components` is non-empty — the
/// fd of its immediate parent directory and its own name (needed by callers
/// that must act on the parent, e.g. `unlinkat`/`renameat`, rather than on
/// the entry itself, which POSIX has no "act on this fd regardless of its
/// name" primitive for).
///
/// `components` empty resolves to the mount root itself (`root` duplicated),
/// with no parent — the mount root has no fd-relative parent inside this
/// mount's sandbox, by design (see [`DiskFilesystem::delete`]).
fn resolve_walk(
    root: BorrowedFd<'_>,
    components: &[OsString],
    final_oflags: OFlags,
) -> Result<(OwnedFd, Option<(OwnedFd, OsString)>), ResolveError> {
    let Some((leaf, ancestors)) = components.split_last() else {
        return Ok((dup_fd(root)?, None));
    };
    let mut cur = dup_fd(root)?;
    for component in ancestors {
        cur = open_one(cur.as_fd(), component, OFlags::DIRECTORY, Mode::empty())?;
    }
    let fd = open_one(cur.as_fd(), leaf, final_oflags, Mode::empty())?;
    Ok((fd, Some((cur, leaf.clone()))))
}

/// Walks `components` from `root`, creating any missing directory along the
/// way (`mkdir -p` semantics), and returns the final directory's fd. Used
/// by `write_file`/`append_file` (parent-only — matching the previous
/// implementation's "always create the parent chain" behavior) and by
/// `create_dir_all` (full path, leaf included).
///
/// Each level is still resolved through [`open_one`], so a symlink swapped
/// into any not-yet-existing ancestor between one level's `mkdirat` and the
/// next level's `open_one` is rejected exactly like any other symlink in the
/// walk — there is no separate "check ancestor, then mkdir, then check
/// again" gap here, because creation and the next level's containment check
/// are the same `open_one` call the next loop iteration makes.
fn descend_creating(
    root: BorrowedFd<'_>,
    components: &[OsString],
) -> Result<OwnedFd, ResolveError> {
    let mut cur = dup_fd(root)?;
    for component in components {
        cur = match open_one(cur.as_fd(), component, OFlags::DIRECTORY, Mode::empty()) {
            Ok(fd) => fd,
            Err(ResolveError::Io(io_err)) if io_err.kind() == std::io::ErrorKind::NotFound => {
                match rustix::fs::mkdirat(cur.as_fd(), component.as_os_str(), new_dir_mode()) {
                    Ok(()) => {}
                    Err(Errno::EXIST) => {}
                    Err(errno) => return Err(ResolveError::Io(errno.into())),
                }
                open_one(cur.as_fd(), component, OFlags::DIRECTORY, Mode::empty())?
            }
            Err(other) => return Err(other),
        };
    }
    Ok(cur)
}

/// Recursively removes `name` (found directly under `parent`) and everything
/// beneath it, never following a symlink into whatever it points at — a
/// symlinked child is unlinked as itself, exactly like `std::fs::remove_dir_all`,
/// never traversed into.
fn remove_dir_all_fd(parent: BorrowedFd<'_>, name: &OsStr) -> Result<(), std::io::Error> {
    let dir_fd =
        open_one(parent, name, OFlags::DIRECTORY, Mode::empty()).map_err(resolve_error_to_io)?;
    remove_dir_contents(dir_fd.as_fd())?;
    rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR).map_err(std::io::Error::from)
}

fn remove_dir_contents(dir: BorrowedFd<'_>) -> Result<(), std::io::Error> {
    let mut entries = Vec::new();
    {
        let listing = rustix::fs::Dir::read_from(dir)?;
        for entry in listing {
            let entry = entry?;
            let name_bytes = entry.file_name().to_bytes();
            if name_bytes == b"." || name_bytes == b".." {
                continue;
            }
            let name = OsStr::from_bytes(name_bytes).to_os_string();
            let stat = rustix::fs::statat(dir, &name, AtFlags::SYMLINK_NOFOLLOW)?;
            let is_dir = rustix::fs::FileType::from_raw_mode(stat.st_mode)
                == rustix::fs::FileType::Directory;
            entries.push((name, is_dir));
        }
    }
    for (name, is_dir) in entries {
        if is_dir {
            remove_dir_all_fd(dir, &name)?;
        } else {
            rustix::fs::unlinkat(dir, &name, AtFlags::empty())?;
        }
    }
    Ok(())
}

fn resolve_error_to_io(error: ResolveError) -> std::io::Error {
    match error {
        ResolveError::Escape => std::io::Error::other("symlink escape"),
        ResolveError::Io(io_err) => io_err,
    }
}

fn read_all(fd: OwnedFd) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    let mut file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn write_all(fd: OwnedFd, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes)?;
    file.flush()
}

fn new_file_mode() -> Mode {
    Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH
}

fn new_dir_mode() -> Mode {
    Mode::RWXU | Mode::RWXG | Mode::RWXO
}

fn map_file_type(kind: rustix::fs::FileType) -> FileType {
    match kind {
        rustix::fs::FileType::RegularFile => FileType::File,
        rustix::fs::FileType::Directory => FileType::Directory,
        rustix::fs::FileType::Symlink => FileType::Symlink,
        _ => FileType::Other,
    }
}

fn stat_modified(secs: i64, nanos: impl TryInto<u32>) -> Option<std::time::SystemTime> {
    let nanos = nanos.try_into().unwrap_or(0);
    if secs >= 0 {
        std::time::SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::new(secs as u64, nanos))
    } else {
        std::time::SystemTime::UNIX_EPOCH.checked_sub(std::time::Duration::new((-secs) as u64, 0))
    }
}

/// Atomically installs `bytes` as `leaf` under `parent`, via a temp file
/// created in the same directory and then renamed (`CasExpectation::Any`) or
/// hard-linked into place (`CasExpectation::Absent`) — unchanged in
/// approach from before this fix, just fd-relative (`renameat`/`linkat`
/// against `parent`, an already fd-resolved, already-verified directory)
/// instead of path-relative. `rename`/`link` never follow a symlink at the
/// destination name (they replace/create the directory entry itself), so
/// this step was never part of the TOCTOU surface `resolve_for_write` left
/// open; only `append_file`'s direct `open` of the leaf was.
fn atomic_write_file(
    virtual_path: &VirtualPath,
    parent: BorrowedFd<'_>,
    leaf: &OsStr,
    bytes: &[u8],
    cas: CasExpectation,
) -> Result<(), FilesystemError> {
    // `rename`/`link` never follow a symlink at the destination name (see
    // the function doc), so the install step below can never be tricked
    // into writing through one — but silently *replacing* a symlink entry
    // that's still sitting at the leaf (dangling or not) is a real content
    // loss surprise for whatever legitimately created it, and this crate's
    // steady-state contract is "reject a pre-existing symlink at a write
    // target", not "clobber it". Probe with the same `O_NOFOLLOW` primitive
    // every other lookup in this module uses, immediately before the
    // install below — both run inside the same non-yielding blocking
    // closure, so there is no `.await` for a swap to land between the probe
    // and the install.
    match open_one(parent, leaf, OFlags::RDONLY, Mode::empty()) {
        Ok(_existing) => {}
        Err(ResolveError::Escape) => {
            return Err(FilesystemError::SymlinkEscape {
                path: virtual_path.clone(),
            });
        }
        Err(ResolveError::Io(io_err)) if io_err.kind() == std::io::ErrorKind::NotFound => {}
        Err(ResolveError::Io(io_err)) => {
            return Err(io_error(
                virtual_path.clone(),
                FilesystemOperation::WriteFile,
                io_err,
            ));
        }
    }

    let counter = LOCAL_WRITE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut temp_name = OsString::from(".");
    temp_name.push(leaf);
    temp_name.push(format!(".tmp.{counter}"));

    let temp_fd = open_one(
        parent,
        &temp_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        new_file_mode(),
    )
    .map_err(|error| {
        resolve_error_to_filesystem_error(virtual_path, FilesystemOperation::WriteFile, error)
    })?;

    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::File::from(temp_fd);
        file.write_all(bytes)?;
        file.sync_all()
    })();
    if let Err(error) = write_result {
        let _ = rustix::fs::unlinkat(parent, &temp_name, AtFlags::empty());
        return Err(io_error(
            virtual_path.clone(),
            FilesystemOperation::WriteFile,
            error,
        ));
    }

    let install_result = match cas {
        CasExpectation::Any => {
            rustix::fs::renameat(parent, &temp_name, parent, leaf).map_err(|errno| {
                io_error(
                    virtual_path.clone(),
                    FilesystemOperation::WriteFile,
                    errno.into(),
                )
            })
        }
        CasExpectation::Absent => {
            match rustix::fs::linkat(parent, &temp_name, parent, leaf, AtFlags::empty()) {
                Ok(()) => {
                    let _ = rustix::fs::unlinkat(parent, &temp_name, AtFlags::empty());
                    Ok(())
                }
                Err(Errno::EXIST) => {
                    let _ = rustix::fs::unlinkat(parent, &temp_name, AtFlags::empty());
                    Err(FilesystemError::VersionMismatch {
                        path: virtual_path.clone(),
                        expected: None,
                        found: Some(RecordVersion::from_backend(0)),
                    })
                }
                Err(errno) => {
                    let _ = rustix::fs::unlinkat(parent, &temp_name, AtFlags::empty());
                    Err(io_error(
                        virtual_path.clone(),
                        FilesystemOperation::WriteFile,
                        errno.into(),
                    ))
                }
            }
        }
        CasExpectation::Version(_) => Err(FilesystemError::Unsupported {
            path: virtual_path.clone(),
            operation: FilesystemOperation::WriteFile,
        }),
    };

    install_result?;

    // Best-effort durability: fsync the parent directory so the rename/link
    // above survives a crash. Not part of the containment/TOCTOU surface —
    // failure here is reported but the write itself already succeeded.
    let parent_file = std::fs::File::from(
        dup_fd(parent)
            .map_err(resolve_error_to_io)
            .map_err(|error| {
                io_error(virtual_path.clone(), FilesystemOperation::WriteFile, error)
            })?,
    );
    parent_file
        .sync_all()
        .map_err(|error| io_error(virtual_path.clone(), FilesystemOperation::WriteFile, error))
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
    /// `ironclaw_reborn_composition`), but that is an invariant enforced one
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

    /// First-use path for a brand-new leaf: nothing under `host_root` exists
    /// yet for this caller, so the nearest *existing* ancestor of the target
    /// is the shared `host_root` itself, not the (not-yet-created)
    /// containment root `host_root/<leaf>`. Regression for the bug where
    /// `ensure_existing_ancestor_contained` rejected that shared root as an
    /// escape, permanently blocking every new leaf's first write.
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

    /// Same first-use bootstrap, but through `create_dir_all` rather than
    /// `write_file` — the two callers of `ensure_existing_ancestor_contained`
    /// must both accept the shared `host_root` as a bootstrap ancestor.
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
    /// not — must still be rejected. Naively treating "target doesn't
    /// resolve" as "brand new file in this leaf" would let `write_file`/
    /// `append_file` open through the symlink (the OS creates the target on
    /// `O_CREAT`), writing into whatever sibling leaf (or worse) the symlink
    /// points at. `atomic_write_file`'s pre-install probe (`open_one` with
    /// `O_NOFOLLOW`) is what catches this now: it never resolves the
    /// dangling target at all, so "does the target exist" never comes up.
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
