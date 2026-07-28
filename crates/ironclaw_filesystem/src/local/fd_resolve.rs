//! fd-rooted, symlink-free traversal primitives for the local disk backend.
//!
//! Every function below operates purely on file descriptors and path
//! *components* (never a joined host path string). `open_one` is the one
//! place a directory-entry lookup happens, and it refuses to follow a
//! symlink anywhere in the walk. Because resolution never hands back a path
//! for a later, independent syscall to re-open, there is no window between
//! "checked" and "acted on" for an attacker to swap the entry in.
//!
//! This module is deliberately self-contained: nothing here depends on
//! `DiskFilesystem`/`LocalMount`/the `RootFilesystem` impl in the parent
//! `local` module — every function operates on `BorrowedFd`/`OwnedFd` and
//! `OsStr`/`OsString` only, plus the crate's error/path vocabulary
//! (`FilesystemError`, `FilesystemOperation`, `VirtualPath`). That is also
//! why this module has no reason to ever import `tokio::fs` (or any other
//! path-based filesystem API): its whole job is to be the fd-relative
//! alternative to one.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, Ordering};

use ironclaw_host_api::VirtualPath;
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use crate::{CasExpectation, FileType, FilesystemError, FilesystemOperation, RecordVersion};

static LOCAL_WRITE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The outcome of a failed fd-relative resolution step: either a genuine I/O
/// error (propagated as-is), or a symlink/`..`-past-root escape attempt.
pub(super) enum ResolveError {
    Escape,
    Io(std::io::Error),
}

pub(super) fn resolve_error_to_filesystem_error(
    path: &VirtualPath,
    operation: FilesystemOperation,
    error: ResolveError,
) -> FilesystemError {
    match error {
        ResolveError::Escape => FilesystemError::SymlinkEscape { path: path.clone() },
        ResolveError::Io(io_err) => super::io_error(path.clone(), operation, io_err),
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
pub(super) fn open_one(
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
/// mount's sandbox, by design (see `DiskFilesystem::delete`).
pub(super) fn resolve_walk(
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
pub(super) fn descend_creating(
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

/// Maximum nesting depth [`remove_dir_all_fd`] will descend into before
/// failing closed, rather than recursing without limit.
///
/// This is genuinely recursive Rust code running on a tokio blocking-pool
/// thread — not a regression (`std::fs::remove_dir_all` is also recursive
/// and has no cap of its own), but a deep tree can now be created entirely
/// inside a sandboxed shell's own writable mount, i.e. by someone who will
/// deliberately try to break it. 512 levels comfortably survives on a
/// default thread stack (each frame here is a handful of small locals, no
/// large stack arrays) while still failing far short of any real stack
/// limit if a caller does manage to create a tree this deep. `remove_dir_contents`
/// only `unlinkat`s a symlink entry directly (`AtFlags::empty()`, never
/// following it) and never recurses through one, so cycles via symlinks are
/// not a concern here — depth is bounded purely by real, non-symlink
/// directory nesting.
const MAX_REMOVE_DIR_DEPTH: usize = 512;

/// Recursively removes `name` (found directly under `parent`) and everything
/// beneath it, never following a symlink into whatever it points at — a
/// symlinked child is unlinked as itself, exactly like `std::fs::remove_dir_all`,
/// never traversed into.
pub(super) fn remove_dir_all_fd(
    parent: BorrowedFd<'_>,
    name: &OsStr,
) -> Result<(), std::io::Error> {
    remove_dir_all_fd_bounded(parent, name, 0)
}

fn remove_dir_all_fd_bounded(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    depth: usize,
) -> Result<(), std::io::Error> {
    if depth >= MAX_REMOVE_DIR_DEPTH {
        return Err(std::io::Error::other(format!(
            "directory tree exceeds maximum removal depth of {MAX_REMOVE_DIR_DEPTH} levels; refusing to delete"
        )));
    }
    let dir_fd =
        open_one(parent, name, OFlags::DIRECTORY, Mode::empty()).map_err(resolve_error_to_io)?;
    remove_dir_contents(dir_fd.as_fd(), depth + 1)?;
    rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR).map_err(std::io::Error::from)
}

fn remove_dir_contents(dir: BorrowedFd<'_>, depth: usize) -> Result<(), std::io::Error> {
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
            remove_dir_all_fd_bounded(dir, &name, depth)?;
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

pub(super) fn read_all(fd: OwnedFd) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    let mut file = std::fs::File::from(fd);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(super) fn write_all(fd: OwnedFd, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes)?;
    file.flush()
}

pub(super) fn new_file_mode() -> Mode {
    Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH
}

fn new_dir_mode() -> Mode {
    Mode::RWXU | Mode::RWXG | Mode::RWXO
}

pub(super) fn map_file_type(kind: rustix::fs::FileType) -> FileType {
    match kind {
        rustix::fs::FileType::RegularFile => FileType::File,
        rustix::fs::FileType::Directory => FileType::Directory,
        rustix::fs::FileType::Symlink => FileType::Symlink,
        _ => FileType::Other,
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
pub(super) fn atomic_write_file(
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
            return Err(super::io_error(
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
        return Err(super::io_error(
            virtual_path.clone(),
            FilesystemOperation::WriteFile,
            error,
        ));
    }

    let install_result = match cas {
        CasExpectation::Any => {
            rustix::fs::renameat(parent, &temp_name, parent, leaf).map_err(|errno| {
                super::io_error(
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
                    Err(super::io_error(
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
    let parent_file = std::fs::File::from(dup_fd(parent).map_err(resolve_error_to_io).map_err(
        |error| super::io_error(virtual_path.clone(), FilesystemOperation::WriteFile, error),
    )?);
    parent_file.sync_all().map_err(|error| {
        super::io_error(virtual_path.clone(), FilesystemOperation::WriteFile, error)
    })
}
