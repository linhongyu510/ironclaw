use super::*;
use ironclaw_filesystem::{CasExpectation, DiskDirectoryCapability};

pub(in super::super) fn write_manifest_last(
    home: &Path,
    manifest: &LayoutManifest,
) -> anyhow::Result<()> {
    let manifest_path = home.join(LAYOUT_MANIFEST_FILE);
    if manifest_path.exists() {
        let existing = read_manifest(&manifest_path)?;
        if existing == *manifest {
            return Ok(());
        }
        bail!(
            "refusing to replace existing layout manifest at {}",
            manifest_path.display()
        );
    }
    let contents = toml::to_string(manifest).context("serialize durable layout manifest")?;
    match write_atomic_synced(&manifest_path, &contents, false) {
        Ok(()) => Ok(()),
        Err(create_error) => match read_manifest(&manifest_path) {
            Ok(existing) if existing == *manifest => Ok(()),
            _ => Err(create_error),
        },
    }
}

pub(in super::super) fn read_manifest(path: &Path) -> anyhow::Result<LayoutManifest> {
    let contents = read_utf8_file_no_follow(path)?;
    toml::from_str(&contents)
        .map_err(|error| anyhow!("parse durable layout manifest {}: {error}", path.display()))
}

pub(in super::super) fn admit_manifest(
    manifest: &LayoutManifest,
    requirement: LayoutRequirement,
) -> anyhow::Result<()> {
    match manifest.admit(requirement) {
        ProfileTransitionAdmission::Allowed => Ok(()),
        ProfileTransitionAdmission::Rejected { reason } => {
            bail!("stored durable layout rejects this profile transition: {reason}")
        }
    }
}

pub(in super::super) fn write_atomic_synced(
    path: &Path,
    contents: &str,
    replace: bool,
) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("path has no file name: {}", path.display()))?;
    let capability = DiskDirectoryCapability::admit_existing(parent)
        .with_context(|| format!("admit parent directory for {}", path.display()))?;
    write_atomic_synced_at(&capability, Path::new(file_name), path, contents, replace)
}

pub(in super::super) fn write_atomic_synced_at(
    parent: &DiskDirectoryCapability,
    relative: &Path,
    display_path: &Path,
    contents: &str,
    replace: bool,
) -> anyhow::Result<()> {
    let cas = if replace {
        CasExpectation::Any
    } else {
        CasExpectation::Absent
    };
    parent
        .write_file_atomic_synced(relative, contents.as_bytes(), cas)
        .with_context(|| format!("atomically publish {}", display_path.display()))
}
