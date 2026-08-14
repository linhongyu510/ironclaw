use super::*;

pub(in super::super) fn copy_system_tree(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let source_handle = open_directory_no_follow(source)?;
    for entry in
        fs::read_dir(source).with_context(|| format!("read system source {}", source.display()))?
    {
        let entry = entry
            .with_context(|| format!("read system source entry under {}", source.display()))?;
        let destination = destination.join(entry.file_name());
        copy_ordinary_tree(&entry.path(), &destination)?;
    }
    ensure_directory_path_matches_handle(source, &source_handle)?;
    Ok(())
}

/// Maximum nesting accepted from an operator-controlled adoption source.
///
/// This is a structural safety bound, independent of file count: every
/// recursive adoption walk shares it so validation cannot approve a tree that
/// copying or content detection would traverse without limit.
pub(in super::super) const MAX_ADOPTION_TREE_DEPTH: usize = 64;

pub(in super::super) fn copy_ordinary_tree(
    source: &Path,
    destination: &Path,
) -> anyhow::Result<()> {
    copy_ordinary_tree_at_depth(source, destination, 0)
}

fn copy_ordinary_tree_at_depth(
    source: &Path,
    destination: &Path,
    depth: usize,
) -> anyhow::Result<()> {
    ensure_adoption_tree_depth(source, depth)?;
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("inspect source {}", source.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing symbolic link in adoption source: {}",
            source.display()
        );
    }
    if metadata.is_file() {
        return copy_ordinary_file(source, destination);
    }
    if !metadata.is_dir() {
        bail!("refusing non-ordinary source entry: {}", source.display());
    }
    let source_handle = open_directory_no_follow(source)?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| anyhow!("destination has no parent: {}", destination.display()))?;
    require_ordinary_directory(destination_parent)?;
    fs::create_dir(destination)
        .with_context(|| format!("create destination directory {}", destination.display()))?;
    for entry in fs::read_dir(source)
        .with_context(|| format!("read source directory {}", source.display()))?
    {
        let entry =
            entry.with_context(|| format!("read source entry under {}", source.display()))?;
        copy_ordinary_tree_at_depth(
            &entry.path(),
            &destination.join(entry.file_name()),
            depth + 1,
        )?;
    }
    ensure_directory_path_matches_handle(source, &source_handle)?;
    sync_directory(destination)
}

pub(in super::super) fn copy_ordinary_file(
    source: &Path,
    destination: &Path,
) -> anyhow::Result<()> {
    require_ordinary_file(source)?;
    let mut input = open_file_no_follow(source)?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| anyhow!("destination has no parent: {}", destination.display()))?;
    require_ordinary_directory(destination_parent)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    let source_mode = {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        let mode = input
            .metadata()
            .with_context(|| format!("read opened source mode {}", source.display()))?
            .mode()
            & 0o777;
        options.mode(mode);
        mode
    };
    let mut output = options
        .open(destination)
        .with_context(|| format!("create destination file {}", destination.display()))?;
    std::io::copy(&mut input, &mut output)
        .with_context(|| format!("copy {} -> {}", source.display(), destination.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync copied file {}", destination.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(destination, fs::Permissions::from_mode(source_mode))
            .with_context(|| format!("preserve mode on {}", destination.display()))?;
        output
            .sync_all()
            .with_context(|| format!("sync preserved mode on {}", destination.display()))?;
    }
    Ok(())
}

/// Copy the cached secrets master key under the owner-only policy. The output
/// is created with mode 0600 before any bytes are written and that policy is
/// re-established and verified after the synced copy. On Unix the mode is the
/// POSIX ACL mask, so it denies group and other access for the entire copy.
pub(in super::super) fn copy_master_key(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let mut input = validate_master_key_source(source)?;
    let destination_parent = destination.parent().ok_or_else(|| {
        anyhow!(
            "master key destination has no parent: {}",
            destination.display()
        )
    })?;
    require_ordinary_directory(destination_parent)?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = options
        .open(destination)
        .with_context(|| format!("create owner-only master key {}", destination.display()))?;
    std::io::copy(&mut input, &mut output).with_context(|| {
        format!(
            "copy master key {} -> {}",
            source.display(),
            destination.display()
        )
    })?;
    output
        .sync_all()
        .with_context(|| format!("sync copied master key {}", destination.display()))?;
    establish_and_verify_master_key_policy(destination)
}

pub(in super::super) fn validate_master_key_source(path: &Path) -> anyhow::Result<File> {
    require_ordinary_file(path)?;
    let file = open_file_no_follow(path)?;
    verify_master_key_policy(&file, path, "source")?;
    Ok(file)
}

pub(in super::super) fn establish_and_verify_master_key_policy(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "re-establish owner-only master key mode at {}",
                path.display()
            )
        })?;
    }
    let file = open_file_no_follow(path)?;
    verify_master_key_policy(&file, path, "destination")?;
    file.sync_all()
        .with_context(|| format!("sync restored master key mode at {}", path.display()))
}

pub(in super::super) fn verify_master_key_policy(
    file: &File,
    path: &Path,
    location: &str,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let mode = file
            .metadata()
            .with_context(|| format!("read {location} master key metadata at {}", path.display()))?
            .mode()
            & 0o777;
        if mode != 0o600 {
            bail!(
                "{location} master key at {} must have owner-only mode 0600; found {mode:03o}",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path, location);
    }
    Ok(())
}

pub(in super::super) fn open_file_no_follow(path: &Path) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).with_context(|| {
        format!(
            "open ordinary source file without following links {}",
            path.display()
        )
    })
}

pub(in super::super) fn open_directory_no_follow(path: &Path) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    options.open(path).with_context(|| {
        format!(
            "open ordinary directory without following links {}",
            path.display()
        )
    })
}

pub(in super::super) fn ensure_directory_path_matches_handle(
    path: &Path,
    handle: &File,
) -> anyhow::Result<()> {
    let reopened = open_directory_no_follow(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let original = handle
            .metadata()
            .with_context(|| format!("read opened directory metadata {}", path.display()))?;
        let current = reopened
            .metadata()
            .with_context(|| format!("read reopened directory metadata {}", path.display()))?;
        if original.dev() != current.dev() || original.ino() != current.ino() {
            bail!(
                "directory {} changed while adoption was traversing it; refusing to continue with a raced path",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (handle, reopened);
    }
    Ok(())
}

pub(in super::super) fn read_utf8_file_no_follow(path: &Path) -> anyhow::Result<String> {
    require_ordinary_file(path)?;
    let mut file = open_file_no_follow(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("read UTF-8 text file {}", path.display()))?;
    Ok(contents)
}

pub(in super::super) fn validate_ordinary_tree(path: &Path) -> anyhow::Result<()> {
    validate_ordinary_tree_at_depth(path, 0)
}

fn validate_ordinary_tree_at_depth(path: &Path, depth: usize) -> anyhow::Result<()> {
    ensure_adoption_tree_depth(path, depth)?;
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing symbolic link in adoption source: {}",
            path.display()
        );
    }
    if metadata.is_file() {
        return Ok(());
    }
    if !metadata.is_dir() {
        bail!("refusing non-ordinary source entry: {}", path.display());
    }
    let directory_handle = open_directory_no_follow(path)?;
    for entry in
        fs::read_dir(path).with_context(|| format!("read source directory {}", path.display()))?
    {
        let entry = entry.with_context(|| format!("read source entry under {}", path.display()))?;
        validate_ordinary_tree_at_depth(&entry.path(), depth + 1)?;
    }
    ensure_directory_path_matches_handle(path, &directory_handle)
}

pub(in super::super) fn require_ordinary_file(path: &Path) -> anyhow::Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "expected an ordinary non-symlink file at {}",
            path.display()
        );
    }
    Ok(())
}

pub(in super::super) fn require_ordinary_directory(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "expected an ordinary non-symlink directory at {}",
            path.display()
        );
    }
    let handle = open_directory_no_follow(path)?;
    if !handle
        .metadata()
        .with_context(|| format!("read opened directory metadata {}", path.display()))?
        .is_dir()
    {
        bail!(
            "expected an ordinary non-symlink directory at {}",
            path.display()
        );
    }
    Ok(())
}

pub(in super::super) fn directory_is_empty(path: &Path) -> anyhow::Result<bool> {
    require_ordinary_directory(path)?;
    Ok(fs::read_dir(path)
        .with_context(|| format!("read directory {}", path.display()))?
        .next()
        .is_none())
}

pub(in super::super) fn directory_has_content(path: &Path) -> anyhow::Result<bool> {
    directory_has_content_at_depth(path, 0)
}

fn directory_has_content_at_depth(path: &Path, depth: usize) -> anyhow::Result<bool> {
    ensure_adoption_tree_depth(path, depth)?;
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing symbolic link in adoption candidate: {}",
            path.display()
        );
    }
    if metadata.is_file() {
        return Ok(true);
    }
    if !metadata.is_dir() {
        bail!(
            "refusing non-ordinary adoption candidate entry: {}",
            path.display()
        );
    }
    for entry in fs::read_dir(path).with_context(|| format!("read directory {}", path.display()))? {
        let entry = entry.with_context(|| format!("read entry under {}", path.display()))?;
        if directory_has_content_at_depth(&entry.path(), depth + 1)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(in super::super) fn ensure_adoption_tree_depth(
    path: &Path,
    depth: usize,
) -> anyhow::Result<()> {
    if depth > MAX_ADOPTION_TREE_DEPTH {
        bail!(
            "adoption source tree exceeds maximum depth {MAX_ADOPTION_TREE_DEPTH} at {}",
            path.display()
        );
    }
    Ok(())
}

pub(in super::super) fn sync_directory(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        open_directory_no_follow(path)?
            .sync_all()
            .with_context(|| format!("sync directory {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
