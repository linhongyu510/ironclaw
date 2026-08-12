//! Advisory locks that serialize startup cutover and journal recovery.

use super::*;
use super::{filesystem::*, model::*};

pub(super) struct AdoptionLock {
    #[cfg(any(unix, windows))]
    _file: File,
}

pub(super) fn acquire_adoption_lock(adoption_root: &Path) -> anyhow::Result<AdoptionLock> {
    acquire_named_lock(adoption_root, ADOPTION_LOCK_FILE, "storage adoption")
}

pub(super) fn acquire_named_lock(
    directory: &Path,
    file_name: &str,
    operation: &str,
) -> anyhow::Result<AdoptionLock> {
    #[cfg(not(any(unix, windows)))]
    {
        bail!(
            "descriptor-backed advisory locks are unsupported on this platform; refusing {operation} at {}",
            directory.display()
        );
    }

    #[cfg(any(unix, windows))]
    {
        let path = directory.join(file_name);
        require_ordinary_directory(directory)?;
        let mut file = open_adoption_lock_file(&path)?;
        fs2::FileExt::try_lock_exclusive(&file).with_context(|| {
        format!(
            "another {operation} is holding advisory lock {}; wait for it to finish before retrying",
            path.display()
        )
    })?;
        file.set_len(0)
            .with_context(|| format!("clear advisory lock {}", path.display()))?;
        writeln!(file, "pid={}", std::process::id())
            .with_context(|| format!("write advisory lock {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync advisory lock {}", path.display()))?;
        sync_directory(directory)?;
        Ok(AdoptionLock { _file: file })
    }
}

#[cfg(unix)]
pub(super) fn open_adoption_lock_file(path: &Path) -> anyhow::Result<File> {
    if path.exists() {
        require_ordinary_file(path)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).with_context(|| {
        format!(
            "open advisory lock without following links {}",
            path.display()
        )
    })?;
    if !file
        .metadata()
        .with_context(|| format!("inspect opened advisory lock {}", path.display()))?
        .is_file()
    {
        bail!("expected an ordinary file at {}", path.display());
    }
    Ok(file)
}

#[cfg(windows)]
pub(super) fn open_adoption_lock_file(path: &Path) -> anyhow::Result<File> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).with_context(|| {
        format!(
            "open advisory lock without following links {}",
            path.display()
        )
    })?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect opened advisory lock {}", path.display()))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_file() {
        bail!(
            "expected an ordinary non-reparse-point file at {}",
            path.display()
        );
    }
    Ok(file)
}

pub(super) fn acquire_existing_adoption_lock(adoption_root: &Path) -> anyhow::Result<AdoptionLock> {
    if !adoption_root.is_dir() {
        bail!(
            "adoption journal parent is not an ordinary directory at {}; refusing recovery",
            adoption_root.display()
        );
    }
    acquire_adoption_lock(adoption_root)
}
