mod fd_resolve;

use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    sync::Arc,
};

use async_trait::async_trait;
use ironclaw_host_api::{HostPath, VirtualPath};
use ironclaw_safety::sensitive_paths::is_sensitive_path_str;
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{AtFlags, Mode, OFlags};

use self::fd_resolve::{
    ResolveError, atomic_write_file, descend_creating, map_file_type, new_file_mode, open_one,
    read_all, remove_dir_all_fd, resolve_error_to_filesystem_error, resolve_walk,
    resolve_write_leaf, write_all,
};
use crate::{
    CasExpectation, DirEntry, Entry, FileStat, FilesystemError, FilesystemOperation, RecordVersion,
    RootFilesystem, VersionedEntry, path_prefix_matches,
};

/// The on-disk `RootFilesystem` backend, mounted into the virtual namespace.
///
/// The name states the **storage medium** — disk, a peer of `InMemoryBackend`,
/// `LibSqlRootFilesystem`, and `PostgresRootFilesystem` — not a deployment mode.
/// Renamed from `LocalFilesystem` because `Local` read like a deployment tier
/// while this is simply the disk backend a `DeploymentConfig` may select
/// (arch-simplification §4.4 Bucket 2).
#[derive(Debug, Default)]
pub struct DiskFilesystem {
    mounts: std::sync::RwLock<Vec<LocalMount>>,
}

#[derive(Debug, Clone)]
struct LocalMount {
    virtual_root: VirtualPath,
    /// An open directory descriptor on the mount's canonical host root,
    /// opened once at mount time. Every request resolves *from this fd*
    /// (or, for a `leaf_scoped` mount, from a fresh per-call anchor fd
    /// opened beneath it — see [`anchor_for_target`]), component by
    /// component, following an in-bounds symlink and refusing an escaping
    /// one atomically — via the single-syscall `openat2(RESOLVE_BENEATH)`
    /// on Linux, or this crate's own bounded fd-anchored walk everywhere
    /// else. A symlink swapped in after any earlier check is never handed
    /// to a later, independent path-based syscall, closing the
    /// pathname-check-then-separate-syscall TOCTOU window `resolve_existing`
    /// / `resolve_for_write` / `resolve_for_create_dir_all` used to leave
    /// open. See [`open_one`].
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
    /// `leaf_scoped` still needs a *narrower* containment boundary than an
    /// ordinary mount: now that [`open_one`] follows an in-bounds symlink
    /// instead of rejecting every symlink outright, a symlink planted in one
    /// caller's leaf that resolves into a sibling leaf would stay "beneath"
    /// the wide, shared mount root and pass containment there. So for a
    /// `leaf_scoped` mount, every request is anchored not at `root_fd` but
    /// at a fresh fd opened *at the caller's own leaf directory* (see
    /// [`anchor_for_target`]) before any further walking happens —
    /// `RESOLVE_BENEATH` (or the portable fallback's escape check) then
    /// enforces containment against that narrower anchor, so a symlink can
    /// never step from one caller's leaf into a sibling leaf. `leaf_scoped`
    /// additionally still preserves the original policy that a request
    /// against the bare mount root (no leaf segment at all) must fail closed
    /// rather than resolving to the shared parent every caller's leaf lives
    /// under. See [`DiskFilesystem::resolve_mount_target`].
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
        // `&mut self`, so `get_mut` never actually contends a lock — this
        // still goes through the same `RwLock<Vec<LocalMount>>` storage
        // `ensure_scoped_mount` uses for its `&self` dynamic registration,
        // rather than keeping two separate storage shapes in sync.
        let mounts = self
            .mounts
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if mounts
            .iter()
            .any(|mount| mount.virtual_root.as_str() == virtual_root.as_str())
        {
            return Err(FilesystemError::MountConflict { path: virtual_root });
        }

        let (canonical_root, root_fd) = open_mount_root(&virtual_root, &host_root)?;
        let _ = canonical_root;

        mounts.push(LocalMount {
            virtual_root,
            root_fd: Arc::new(root_fd),
            leaf_scoped,
        });
        Ok(())
    }

    /// Dynamically registers a mount rooted exactly *at* `virtual_root`, if
    /// one is not already registered there — idempotent, so a repeated call
    /// for the same `virtual_root` (the usual shape: called on every request
    /// for a given scope) is a cheap no-op after the first. Unlike
    /// [`mount_local`](Self::mount_local) (boot-time only, exclusive
    /// `&mut self`), this takes `&self` so it can be called per request from
    /// behind a shared `Arc<DiskFilesystem>`.
    ///
    /// This is the mechanism that closes a same-storage-root cross-tenant/
    /// cross-user symlink escape for a mount whose containment root is wider
    /// than the subtree a specific caller is actually granted (e.g. `/projects`
    /// mounted once over the whole local-dev storage root, while a caller's
    /// `/skills` grant only authorizes `/projects/tenants/<t>/users/<u>/skills`).
    /// The composition layer already knows that exact boundary — it is the
    /// `MountGrant::target` a scope-aware `MountView` builder computes from
    /// typed `ResourceScope` fields, not something this crate derives by
    /// counting path segments. Registering a *second*, narrower mount at that
    /// literal target makes [`resolve_mount_target`]'s existing
    /// longest-prefix-wins matching pick it over the wide mount for anything
    /// under it, so `RESOLVE_BENEATH` (or the portable fallback) enforces
    /// containment against the caller's own subtree — exactly that subtree,
    /// no more — rather than the shared parent every caller's subtree lives
    /// under.
    ///
    /// No host path is taken as input: `virtual_root` is resolved through the
    /// *existing* (necessarily wider) mount that already covers it, via the
    /// same fd-rooted [`descend_creating`] every other write path in this
    /// crate uses (creating the directory if this is a brand-new leaf's first
    /// access, exactly like `descend_creating`'s other callers) — never a
    /// second, independently-resolved `std::fs` path lookup. The resulting,
    /// already-open fd becomes the new mount's `root_fd` directly.
    pub async fn ensure_scoped_mount(
        &self,
        virtual_root: VirtualPath,
    ) -> Result<(), FilesystemError> {
        if self.has_mount(&virtual_root) {
            return Ok(());
        }
        let target = self.resolve_mount_target(&virtual_root)?;
        let path = virtual_root.clone();
        let anchor_fd = run_blocking(path.clone(), FilesystemOperation::MountLocal, move || {
            descend_creating(target.root_fd.as_fd(), &target.components).map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::MountLocal, error)
            })
        })
        .await?;

        let mut mounts = self
            .mounts
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Re-check under the write lock: two concurrent first-callers for
        // the same scope must not both push a mount for the same
        // `virtual_root` (that would leave two entries with the same
        // longest-prefix key — harmless for correctness since both point at
        // the same host directory, but wasteful and worth avoiding).
        if mounts
            .iter()
            .any(|mount| mount.virtual_root.as_str() == virtual_root.as_str())
        {
            return Ok(());
        }
        mounts.push(LocalMount {
            virtual_root,
            root_fd: Arc::new(anchor_fd),
            leaf_scoped: false,
        });
        Ok(())
    }

    fn has_mount(&self, virtual_root: &VirtualPath) -> bool {
        let mounts = self
            .mounts
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        mounts
            .iter()
            .any(|mount| mount.virtual_root.as_str() == virtual_root.as_str())
    }

    /// Routes `path` to its mount and splits the tail into path components
    /// under that mount's `root_fd`. No filesystem access happens here —
    /// this is pure string/virtual-path routing, unchanged in shape from
    /// before this fix, and is not part of the TOCTOU surface: the actual
    /// containment enforcement now happens fd-relatively in [`open_one`] as
    /// each returned component is walked.
    fn resolve_mount_target(&self, path: &VirtualPath) -> Result<MountTarget, FilesystemError> {
        let mounts = self
            .mounts
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mount = mounts
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
            leaf_scoped: mount.leaf_scoped,
        })
    }
}

fn dup_owned_fd(fd: rustix::fd::BorrowedFd<'_>) -> Result<OwnedFd, ResolveError> {
    rustix::io::dup(fd).map_err(|errno| ResolveError::Io(errno.into()))
}

/// A mount plus the path components to walk under its `root_fd`. Carries no
/// host path — every subsequent step is fd-relative.
struct MountTarget {
    root_fd: Arc<OwnedFd>,
    components: Vec<OsString>,
    /// Mirrors [`LocalMount::leaf_scoped`] — carried through so the blocking
    /// closures below can anchor containment at the caller's own leaf (see
    /// [`anchor_for_target`]) instead of the shared mount root now that
    /// [`open_one`] follows in-bounds symlinks. Without this, a symlink
    /// planted inside one caller's leaf that resolves into a sibling leaf
    /// would pass containment (both stay "beneath" the wide, shared mount
    /// root) even though it must not.
    leaf_scoped: bool,
}

/// For a `leaf_scoped` mount, opens the caller's own leaf directory
/// (`target.components[0]`) as a fresh anchor fd and returns it alongside
/// the remaining tail components: every subsequent walk resolves
/// `RESOLVE_BENEATH` *this* anchor, not the wide, shared mount root, so an
/// in-bounds symlink can never step from one caller's leaf into a sibling
/// leaf. Non-leaf-scoped mounts pass the mount root straight through,
/// unchanged.
///
/// `create_if_missing` mirrors [`descend_creating`]'s bootstrap semantics —
/// a brand-new leaf's directory does not exist yet on its first write, so
/// write paths must create it as they anchor; read paths must not (a read
/// against a leaf that has never been written must still report
/// `NotFound`/`MountNotFound`, not silently fabricate the directory).
fn anchor_for_target(
    target: &MountTarget,
    create_if_missing: bool,
) -> Result<(OwnedFd, Vec<OsString>), ResolveError> {
    if !target.leaf_scoped {
        return Ok((
            dup_owned_fd(target.root_fd.as_fd())?,
            target.components.clone(),
        ));
    }
    let Some((leaf, rest)) = target.components.split_first() else {
        // `resolve_mount_target` already fails a leaf-scoped mount closed on
        // an empty tail (`PathOutsideMount`) before a `MountTarget` is ever
        // built, so this arm is unreachable in practice; handled without
        // `.unwrap()`/`.expect()` regardless, matching the rest of this
        // module's no-panic discipline.
        return Ok((dup_owned_fd(target.root_fd.as_fd())?, Vec::new()));
    };
    let leaf_components = std::slice::from_ref(leaf);
    let anchor = if create_if_missing {
        descend_creating(target.root_fd.as_fd(), leaf_components)?
    } else {
        open_one(
            target.root_fd.as_fd(),
            target.root_fd.as_fd(),
            leaf,
            OFlags::DIRECTORY,
            Mode::empty(),
        )?
    };
    Ok((anchor, rest.to_vec()))
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
            let (anchor, rest) = anchor_for_target(&target, false).map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::ReadFile, error)
            })?;
            let (fd, _parent) =
                resolve_walk(anchor.as_fd(), &rest, OFlags::RDONLY).map_err(|error| {
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
            let (anchor, rest) = anchor_for_target(&target, false).map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::ReadFile, error)
            })?;
            let (fd, _parent) =
                resolve_walk(anchor.as_fd(), &rest, OFlags::RDONLY).map_err(|error| {
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
        let bytes = bytes.to_vec();
        let path = path.clone();
        run_blocking(path.clone(), FilesystemOperation::AppendFile, move || {
            let (anchor, rest) = anchor_for_target(&target, true).map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::AppendFile, error)
            })?;
            let (parent_components, leaf) = split_leaf(&rest, &path)?;
            let parent_fd =
                descend_creating(anchor.as_fd(), &parent_components).map_err(|error| {
                    resolve_error_to_filesystem_error(&path, FilesystemOperation::AppendFile, error)
                })?;
            // `open_one` already follows an in-bounds symlink at `leaf`
            // transparently (unlike `write_file`'s rename-based atomic
            // install, a plain `open`-and-append writes straight through
            // one), so no separate `resolve_write_leaf` chase is needed here.
            let fd = open_one(
                anchor.as_fd(),
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
            let (anchor, rest) = anchor_for_target(&target, false).map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::ListDir, error)
            })?;
            let (fd, _parent) =
                resolve_walk(anchor.as_fd(), &rest, OFlags::RDONLY).map_err(|error| {
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
            let (anchor, rest) = anchor_for_target(&target, false).map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::Stat, error)
            })?;
            let (fd, _parent) =
                resolve_walk(anchor.as_fd(), &rest, OFlags::RDONLY).map_err(|error| {
                    resolve_error_to_filesystem_error(&path, FilesystemOperation::Stat, error)
                })?;
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
            let (anchor, rest) = anchor_for_target(&target, false).map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::Delete, error)
            })?;
            if rest.is_empty() {
                // Same "cannot delete the resolution root" policy as the
                // bare-mount-root check above, restated post-anchor: for a
                // leaf-scoped mount, `rest` empty means the request named
                // the caller's own leaf directory itself (anchoring already
                // consumed it as `target.components[0]`), which has no
                // fd-relative parent inside this resolution either.
                return Err(FilesystemError::PathOutsideMount { path: path.clone() });
            }
            let (fd, parent) =
                resolve_walk(anchor.as_fd(), &rest, OFlags::RDONLY).map_err(|error| {
                    resolve_error_to_filesystem_error(&path, FilesystemOperation::Delete, error)
                })?;
            let Some((parent_fd, name)) = parent else {
                return Err(FilesystemError::PathOutsideMount { path: path.clone() });
            };
            drop(fd);
            // Determine the *entry's own* type via an `AT_SYMLINK_NOFOLLOW`
            // stat against `parent_fd`/`name` — not `fstat` of `fd` (which,
            // now that `open_one` follows in-bounds symlinks, may have
            // opened straight through a symlink to a directory target).
            // `std::fs::remove_dir_all`/`remove_file` never follow a
            // symlink at the entry being removed — a symlink is always
            // unlinked as itself, never traversed into — and this module
            // promises the same contract; using `fd`'s (possibly-followed)
            // type here would recurse into and delete the *target*
            // directory's contents before failing on the final
            // `unlinkat(..., REMOVEDIR)` (which POSIX refuses on a symlink).
            let entry_stat =
                rustix::fs::statat(parent_fd.as_fd(), &name, AtFlags::SYMLINK_NOFOLLOW).map_err(
                    |errno| io_error(path.clone(), FilesystemOperation::Delete, errno.into()),
                )?;
            if rustix::fs::FileType::from_raw_mode(entry_stat.st_mode)
                == rustix::fs::FileType::Directory
            {
                remove_dir_all_fd(anchor.as_fd(), parent_fd.as_fd(), &name)
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
            let (anchor, rest) = anchor_for_target(&target, true).map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::CreateDirAll, error)
            })?;
            descend_creating(anchor.as_fd(), &rest)
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
        let bytes = bytes.to_vec();
        let path = path.clone();
        run_blocking(path.clone(), FilesystemOperation::WriteFile, move || {
            let (anchor, rest) = anchor_for_target(&target, true).map_err(|error| {
                resolve_error_to_filesystem_error(&path, FilesystemOperation::WriteFile, error)
            })?;
            let (parent_components, leaf) = split_leaf(&rest, &path)?;
            let parent_fd =
                descend_creating(anchor.as_fd(), &parent_components).map_err(|error| {
                    resolve_error_to_filesystem_error(&path, FilesystemOperation::WriteFile, error)
                })?;
            // `rename`/`link` (how `atomic_write_file` installs bytes) never
            // follow a symlink at the destination name — resolve any
            // in-bounds symlink chain at `leaf` ourselves first so the
            // install lands at the symlink's ultimate target, not over the
            // symlink entry itself.
            let (write_parent_fd, write_leaf) =
                resolve_write_leaf(anchor.as_fd(), parent_fd.as_fd(), &leaf).map_err(|error| {
                    resolve_error_to_filesystem_error(&path, FilesystemOperation::WriteFile, error)
                })?;
            atomic_write_file(&path, write_parent_fd.as_fd(), &write_leaf, &bytes, cas)
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

/// `pub(super)`: also called from the [`fd_resolve`] submodule, which has no
/// dependency on `DiskFilesystem` itself but does need this shared
/// `io::Error -> FilesystemError` mapping (the majority of call sites are
/// still here, in the `RootFilesystem` impl above).
pub(super) fn io_error(
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

/// Canonicalizes `host_root` and opens it `O_DIRECTORY | O_NOFOLLOW`, the
/// shared "turn a host path into a verified mount root fd" step both
/// `mount_local_impl` (boot-time, static mounts) and `ensure_scoped_mount`
/// (per-request, dynamic mounts) need. The returned canonical `PathBuf` is
/// not retained by either caller — only the fd is; this crate never
/// re-resolves a path string against anything after mount time (see the
/// `fd_resolve` module doc).
fn open_mount_root(
    virtual_root: &VirtualPath,
    host_root: &HostPath,
) -> Result<(std::path::PathBuf, OwnedFd), FilesystemError> {
    let canonical_root =
        std::fs::canonicalize(host_root.as_path()).map_err(|error| FilesystemError::Backend {
            path: virtual_root.clone(),
            operation: FilesystemOperation::MountLocal,
            reason: io_reason(error),
        })?;

    if !canonical_root.is_dir() {
        return Err(FilesystemError::Backend {
            path: virtual_root.clone(),
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

    Ok((canonical_root, root_fd))
}

fn stat_modified(secs: i64, nanos: impl TryInto<u32>) -> Option<std::time::SystemTime> {
    let nanos = nanos.try_into().unwrap_or(0);
    if secs >= 0 {
        std::time::SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::new(secs as u64, nanos))
    } else {
        std::time::SystemTime::UNIX_EPOCH.checked_sub(std::time::Duration::new((-secs) as u64, 0))
    }
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
