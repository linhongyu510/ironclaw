//! Advisory locks that serialize startup cutover and journal recovery.

use super::*;
use super::{filesystem::*, model::*};

pub(super) struct AdoptionLock {
    #[cfg(unix)]
    _file: File,
    #[cfg(not(unix))]
    path: PathBuf,
}

#[cfg(not(unix))]
impl Drop for AdoptionLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub(super) fn acquire_adoption_lock(adoption_root: &Path) -> anyhow::Result<AdoptionLock> {
    acquire_named_lock(adoption_root, ADOPTION_LOCK_FILE, "storage adoption")
}

pub(super) fn acquire_named_lock(
    directory: &Path,
    file_name: &str,
    operation: &str,
) -> anyhow::Result<AdoptionLock> {
    let path = directory.join(file_name);
    require_ordinary_directory(directory)?;
    #[cfg(unix)]
    let mut file = open_adoption_lock_file(&path)?;
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| {
            format!(
                "another {operation} may already be running; advisory lock {} exists",
                path.display()
            )
        })?;
    #[cfg(unix)]
    file.try_lock_exclusive().with_context(|| {
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
    Ok(AdoptionLock {
        #[cfg(unix)]
        _file: file,
        #[cfg(not(unix))]
        path,
    })
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
    options.open(path).with_context(|| {
        format!(
            "open advisory lock without following links {}",
            path.display()
        )
    })
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
