use super::*;

pub(in super::super) fn initialize_disposable_namespaces(
    home: &Path,
    paths: &RebornStoragePaths,
) -> anyhow::Result<()> {
    for path in [paths.logs_root(), paths.cache_root(), paths.temp_root()] {
        create_or_validate_direct_child(home, path)?;
        sync_directory(path)?;
    }
    Ok(())
}

pub(in super::super) fn canonical_layout_is_empty(
    paths: &RebornStoragePaths,
) -> anyhow::Result<bool> {
    for path in [
        paths.state_root(),
        paths.system_root(),
        paths.workspace_root(),
        paths.runtime_root(),
        paths.logs_root(),
        paths.cache_root(),
        paths.temp_root(),
    ] {
        if path.exists() && !directory_is_empty(path)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(in super::super) fn ensure_canonical_install_targets_empty(
    paths: &RebornStoragePaths,
) -> anyhow::Result<()> {
    for path in [paths.state_root(), paths.system_root()] {
        if path.exists() && !directory_is_empty(path)? {
            bail!(
                "canonical destination {} already contains data; adoption never overwrites or merges canonical state",
                path.display()
            );
        }
        if path.exists() {
            fs::remove_dir(path).with_context(|| {
                format!("remove empty canonical placeholder {}", path.display())
            })?;
        }
    }
    Ok(())
}

pub(in super::super) fn ensure_initial_adoption_namespaces_empty(
    paths: &RebornStoragePaths,
) -> anyhow::Result<()> {
    ensure_canonical_install_targets_empty(paths)?;
    for path in [
        paths.workspace_root(),
        paths.runtime_root(),
        paths.logs_root(),
        paths.cache_root(),
        paths.temp_root(),
    ] {
        if path.exists() && !directory_is_empty(path)? {
            bail!(
                "canonical namespace {} contains unexplained data; initial adoption only permits an empty workspace/runtime namespace and never infers ownership or runtime provenance",
                path.display()
            );
        }
    }
    Ok(())
}

pub(in super::super) fn validate_initial_adoption_namespaces_empty(
    paths: &RebornStoragePaths,
) -> anyhow::Result<()> {
    for path in [
        paths.state_root(),
        paths.system_root(),
        paths.workspace_root(),
        paths.runtime_root(),
        paths.logs_root(),
        paths.cache_root(),
        paths.temp_root(),
    ] {
        if path.exists() && !directory_is_empty(path)? {
            bail!(
                "canonical namespace {} contains unexplained data; automatic adoption never overwrites, merges, or infers ownership",
                path.display()
            );
        }
    }
    Ok(())
}

pub(in super::super) fn validate_adoption_ancestors(
    home: &Path,
    paths: &RebornStoragePaths,
    adoption_root: &Path,
) -> anyhow::Result<()> {
    require_ordinary_directory(home)?;
    if paths.runtime_root().exists() {
        require_ordinary_directory(paths.runtime_root())?;
    }
    if adoption_root.exists() {
        require_ordinary_directory(adoption_root)?;
    }
    Ok(())
}

pub(in super::super) fn create_adoption_root(
    home: &Path,
    paths: &RebornStoragePaths,
    adoption_root: &Path,
) -> anyhow::Result<()> {
    create_or_validate_direct_child(home, paths.runtime_root())?;
    create_or_validate_direct_child(paths.runtime_root(), adoption_root)
}

pub(in super::super) fn validate_journal_owned_runtime(
    paths: &RebornStoragePaths,
    adoption_root: &Path,
) -> anyhow::Result<()> {
    require_ordinary_directory(paths.runtime_root())?;
    let runtime_entries = fs::read_dir(paths.runtime_root())
        .with_context(|| format!("read runtime namespace {}", paths.runtime_root().display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "enumerate runtime namespace {}",
                paths.runtime_root().display()
            )
        })?;
    if runtime_entries.len() != 1 || runtime_entries[0].file_name() != ADOPTION_DIR {
        bail!(
            "runtime namespace {} contains unexplained data; recovery permits only the journal-owned layout-adoption directory",
            paths.runtime_root().display()
        );
    }
    require_ordinary_directory(adoption_root)?;
    for entry in fs::read_dir(adoption_root)
        .with_context(|| format!("read adoption root {}", adoption_root.display()))?
    {
        let entry =
            entry.with_context(|| format!("read entry under {}", adoption_root.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let path = entry.path();
        match name.as_ref() {
            JOURNAL_FILE | ADOPTION_LOCK_FILE => require_ordinary_file(&path)?,
            SNAPSHOT_DIR | STAGING_DIR => require_ordinary_directory(&path)?,
            _ => bail!(
                "adoption root {} contains unexplained recovery artifact `{name}`",
                adoption_root.display()
            ),
        }
    }
    Ok(())
}

pub(in super::super) fn create_or_validate_direct_child(
    parent: &Path,
    child: &Path,
) -> anyhow::Result<()> {
    if child.parent() != Some(parent) {
        bail!(
            "refusing to create non-direct child {} beneath {}",
            child.display(),
            parent.display()
        );
    }
    require_ordinary_directory(parent)?;
    if child.exists() {
        return require_ordinary_directory(child);
    }
    fs::create_dir(child)
        .with_context(|| format!("create adoption directory {}", child.display()))?;
    sync_directory(parent)
}

pub(in super::super) fn create_or_validate_directory(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        return require_ordinary_directory(path);
    }
    fs::create_dir(path)
        .with_context(|| format!("create canonical directory {}", path.display()))?;
    sync_directory(
        path.parent()
            .ok_or_else(|| anyhow!("canonical directory has no parent: {}", path.display()))?,
    )
}
