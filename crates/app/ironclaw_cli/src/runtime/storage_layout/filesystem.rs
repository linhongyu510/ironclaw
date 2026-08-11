use super::model::*;
use super::*;

pub(super) fn initialize_disposable_namespaces(
    home: &Path,
    paths: &RebornStoragePaths,
) -> anyhow::Result<()> {
    for path in [paths.logs_root(), paths.cache_root(), paths.temp_root()] {
        create_or_validate_direct_child(home, path)?;
        sync_directory(path)?;
    }
    Ok(())
}

pub(super) fn write_manifest_last(home: &Path, manifest: &LayoutManifest) -> anyhow::Result<()> {
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

pub(super) fn read_manifest(path: &Path) -> anyhow::Result<LayoutManifest> {
    let contents = read_utf8_file_no_follow(path)?;
    toml::from_str(&contents)
        .map_err(|error| anyhow!("parse durable layout manifest {}: {error}", path.display()))
}

pub(super) fn admit_manifest(
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

pub(super) fn read_journal(path: &Path) -> anyhow::Result<AdoptionJournal> {
    let contents = read_utf8_file_no_follow(path)?;
    let journal: AdoptionJournal = toml::from_str(&contents)
        .map_err(|error| anyhow!("parse adoption journal {}: {error}", path.display()))?;
    if journal.schema_version != JOURNAL_SCHEMA_VERSION {
        bail!(
            "unsupported layout adoption journal schema_version {}; expected {}",
            journal.schema_version,
            JOURNAL_SCHEMA_VERSION
        );
    }
    journal.validate_source_requirement()?;
    let _ = journal.validated_workspace()?;
    Ok(journal)
}

pub(super) fn write_journal(path: &Path, journal: &AdoptionJournal) -> anyhow::Result<()> {
    let contents = toml::to_string(journal).context("serialize adoption journal")?;
    write_atomic_synced(path, &contents, true)
}

pub(super) fn write_atomic_synced(
    path: &Path,
    contents: &str,
    replace: bool,
) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;
    require_ordinary_directory(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary file beside {}", path.display()))?;
    temp.write_all(contents.as_bytes())
        .with_context(|| format!("write temporary file for {}", path.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("sync temporary file for {}", path.display()))?;
    if replace {
        temp.persist(path).map_err(|error| {
            anyhow!(
                "atomically replace {} with {}: {}",
                path.display(),
                error.file.path().display(),
                error.error
            )
        })?;
    } else {
        temp.persist_noclobber(path).map_err(|error| {
            anyhow!(
                "atomically create {} from {}: {}",
                path.display(),
                error.file.path().display(),
                error.error
            )
        })?;
    }
    sync_directory(parent)
}

pub(super) fn inspect_legacy_candidates(home: &Path) -> anyhow::Result<Vec<LegacyCandidate>> {
    let sandbox_root = home.join("hosted-single-tenant-volume-sandboxed");
    if unreleased_sandbox_is_populated(&sandbox_root)? {
        bail!(
            "unreleased sandbox legacy root is populated at {}; inspect or archive it explicitly before adoption. IronClaw will not auto-adopt sandbox state or workspaces",
            sandbox_root.display()
        );
    }

    let mut candidates = Vec::new();
    for kind in [
        LegacySourceKind::LocalDev,
        LegacySourceKind::HostedSingleTenant,
        LegacySourceKind::HostedSingleTenantVolume,
    ] {
        let candidate = inspect_profile_root(home, kind)?;
        if let Some(candidate) = candidate {
            candidates.push(candidate);
        }
    }
    if let Some(candidate) = inspect_bare_home(home)? {
        candidates.push(candidate);
    }
    Ok(candidates)
}

pub(super) fn inspect_profile_root(
    home: &Path,
    kind: LegacySourceKind,
) -> anyhow::Result<Option<LegacyCandidate>> {
    let directory = kind
        .profile_directory()
        .ok_or_else(|| anyhow!("bare home is not a profile root"))?;
    let root = home.join(directory);
    if !root.exists() {
        return Ok(None);
    }
    require_ordinary_directory(&root)?;
    let mut db_files = Vec::new();
    let mut has_master_key = false;
    let mut has_system_content = false;
    let mut has_legacy_skills = false;
    for entry in
        fs::read_dir(&root).with_context(|| format!("read legacy root {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("read entry under {}", root.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let path = entry.path();
        if LIBSQL_DB_UNIT.contains(&name.as_ref()) {
            require_ordinary_file(&path)?;
            db_files.push(name.into_owned());
        } else if name == MASTER_KEY_FILE {
            require_ordinary_file(&path)?;
            validate_master_key_source(&path)?;
            has_master_key = true;
        } else if name == "system" {
            require_ordinary_directory(&path)?;
            has_system_content = system_tree_has_content(&path)?;
            validate_system_tree(&path)?;
        } else if name == "skills" {
            require_ordinary_directory(&path)?;
            validate_ordinary_tree(&path)?;
            has_legacy_skills |= directory_has_content(&path)?;
        } else if name == "tenants" {
            require_ordinary_directory(&path)?;
            has_legacy_skills |= validate_legacy_tenant_skill_tree(&path)?;
        } else if path.is_dir() && directory_is_empty(&path)? {
            // Empty directory entries are not state and cannot be inferred as
            // workspaces or ownership. Leave them in the preserved snapshot.
        } else {
            bail!(
                "unknown entry `{name}` in populated legacy root {}; adoption will not discard or reinterpret it",
                root.display()
            );
        }
    }

    db_files.sort();
    if db_files.iter().any(|file| file != DB_FILE) && !db_files.iter().any(|file| file == DB_FILE) {
        bail!(
            "legacy root {} has libSQL sidecars without {DB_FILE}",
            root.display()
        );
    }
    let populated =
        !db_files.is_empty() || has_master_key || has_system_content || has_legacy_skills;
    if !populated {
        return Ok(None);
    }
    if kind == LegacySourceKind::HostedSingleTenant {
        if !db_files.is_empty() || has_master_key {
            bail!(
                "{} is a PostgreSQL/system-content legacy source but contains embedded DB/key files; inspect it manually",
                root.display()
            );
        }
    } else if !db_files.is_empty() && !has_master_key {
        bail!(
            "legacy embedded state at {} lacks its cached secrets master key; refusing adoption that could make encrypted secrets unreadable",
            root.display()
        );
    }

    Ok(Some(LegacyCandidate {
        kind,
        source_root: root,
        db_files,
        has_master_key,
        has_system_content,
        has_legacy_skills,
    }))
}

pub(super) fn inspect_bare_home(home: &Path) -> anyhow::Result<Option<LegacyCandidate>> {
    let mut db_files = Vec::new();
    for file in LIBSQL_DB_UNIT {
        let path = home.join(file);
        if path.exists() {
            require_ordinary_file(&path)?;
            db_files.push((*file).to_string());
        }
    }
    let key_path = home.join(MASTER_KEY_FILE);
    let has_master_key = key_path.exists();
    if has_master_key {
        require_ordinary_file(&key_path)?;
        validate_master_key_source(&key_path)?;
    }
    if db_files.is_empty() && !has_master_key {
        return Ok(None);
    }
    if db_files.iter().any(|file| file != DB_FILE) && !db_files.iter().any(|file| file == DB_FILE) {
        bail!(
            "bare Reborn home {} has libSQL sidecars without {DB_FILE}",
            home.display()
        );
    }
    if !db_files.is_empty() && !has_master_key {
        bail!(
            "bare Reborn home {} has embedded state without its cached secrets master key; refusing adoption",
            home.display()
        );
    }
    Ok(Some(LegacyCandidate {
        kind: LegacySourceKind::BareHome,
        source_root: home.to_path_buf(),
        db_files,
        has_master_key,
        has_system_content: false,
        has_legacy_skills: false,
    }))
}

pub(super) fn unreleased_sandbox_is_populated(path: &Path) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    require_ordinary_directory(path)?;
    directory_has_content(path)
}

pub(super) fn canonical_layout_is_empty(paths: &RebornStoragePaths) -> anyhow::Result<bool> {
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

pub(super) fn ensure_canonical_install_targets_empty(
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

pub(super) fn ensure_initial_adoption_namespaces_empty(
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

pub(super) fn validate_initial_adoption_namespaces_empty(
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

pub(super) fn validate_adoption_ancestors(
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

pub(super) fn create_adoption_root(
    home: &Path,
    paths: &RebornStoragePaths,
    adoption_root: &Path,
) -> anyhow::Result<()> {
    create_or_validate_direct_child(home, paths.runtime_root())?;
    create_or_validate_direct_child(paths.runtime_root(), adoption_root)
}

pub(super) fn validate_journal_owned_runtime(
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

pub(super) fn create_or_validate_direct_child(parent: &Path, child: &Path) -> anyhow::Result<()> {
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

pub(super) fn prepare_workspace_import(
    options: Option<&WorkspaceImportOptions>,
    paths: &RebornStoragePaths,
) -> anyhow::Result<Option<WorkspaceImportDecision>> {
    let Some(options) = options else {
        return Ok(None);
    };
    if !options.source.is_absolute() {
        bail!(
            "--workspace-source must be an absolute path; IronClaw never infers an ambient working directory as a workspace"
        );
    }
    require_ordinary_directory(&options.source)?;
    validate_ordinary_tree(&options.source)?;
    let decision = WorkspaceImportDecision {
        source: options.source.clone(),
        tenant: options.tenant.as_str().to_string(),
        user: options.user.as_str().to_string(),
        digest: TenantUserWorkspaceKey::from_tenant_user(&options.tenant, &options.user)
            .digest_segment()
            .to_string(),
    };
    let destination = workspace_leaf_path(paths, &decision.validate()?);
    if destination.exists() {
        bail!(
            "workspace import destination {} already exists; refusing to merge or overwrite a tenant/user workspace leaf",
            destination.display()
        );
    }
    if !options.confirmed {
        bail!(
            "workspace import preview: {} -> {} for tenant `{}` user `{}`; rerun with --confirm-workspace-import to copy without deleting the source",
            decision.source.display(),
            destination.display(),
            decision.tenant,
            decision.user
        );
    }
    Ok(Some(decision))
}

pub(super) fn is_single_path_segment(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

pub(super) fn workspace_leaf_path(
    paths: &RebornStoragePaths,
    workspace: &ValidatedWorkspaceImportDecision,
) -> PathBuf {
    paths.workspace_root().join("users").join(&workspace.digest)
}

pub(super) fn install_workspace_leaf(
    paths: &RebornStoragePaths,
    workspace: &ValidatedWorkspaceImportDecision,
    staged_leaf: &Path,
) -> anyhow::Result<()> {
    let workspace_root = paths.workspace_root();
    create_or_validate_directory(workspace_root)?;
    let users_root = workspace_root.join("users");
    create_or_validate_directory(&users_root)?;
    let destination = workspace_leaf_path(paths, workspace);
    if destination.exists() {
        bail!(
            "workspace import destination {} already exists; refusing to merge or overwrite a tenant/user workspace leaf",
            destination.display()
        );
    }
    fs::rename(staged_leaf, &destination).with_context(|| {
        format!(
            "install tenant/user workspace leaf {} -> {}",
            staged_leaf.display(),
            destination.display()
        )
    })?;
    sync_directory(&users_root)
}

pub(super) fn create_or_validate_directory(path: &Path) -> anyhow::Result<()> {
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

pub(super) fn candidate_paths(candidates: &[LegacyCandidate]) -> String {
    candidates
        .iter()
        .map(|candidate| candidate.source_root.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn validate_system_tree(root: &Path) -> anyhow::Result<()> {
    require_ordinary_directory(root)?;
    for entry in
        fs::read_dir(root).with_context(|| format!("read system content {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("read system entry under {}", root.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !SYSTEM_CONTENT_DIRS.contains(&name.as_ref()) {
            bail!(
                "unknown system entry `{name}` under {}; adoption will not reinterpret it",
                root.display()
            );
        }
        validate_ordinary_tree(&entry.path())?;
    }
    Ok(())
}

/// Validate the one released host-disk user-skill grammar without accepting
/// arbitrary tenant content as a migration source.
pub(super) fn validate_legacy_tenant_skill_tree(tenants_root: &Path) -> anyhow::Result<bool> {
    let mut has_content = false;
    for tenant in fs::read_dir(tenants_root)
        .with_context(|| format!("read legacy tenants tree {}", tenants_root.display()))?
    {
        let tenant = tenant
            .with_context(|| format!("read tenant entry under {}", tenants_root.display()))?;
        let tenant_path = tenant.path();
        require_ordinary_directory(&tenant_path)?;
        let tenant_name = tenant.file_name().to_string_lossy().into_owned();
        TenantId::new(tenant_name.clone())
            .map_err(|error| anyhow!("invalid legacy skill tenant `{tenant_name}`: {error}"))?;
        let users_root = tenant_path.join("users");
        for entry in fs::read_dir(&tenant_path)
            .with_context(|| format!("read legacy tenant {}", tenant_path.display()))?
        {
            let entry = entry.with_context(|| {
                format!("read entry under legacy tenant {}", tenant_path.display())
            })?;
            if entry.file_name() != "users" {
                bail!(
                    "unknown entry `{}` under legacy tenant {}; only users/<user>/skills is adoptable",
                    entry.file_name().to_string_lossy(),
                    tenant_path.display()
                );
            }
            require_ordinary_directory(&entry.path())?;
        }
        if !users_root.exists() {
            continue;
        }
        for user in fs::read_dir(&users_root)
            .with_context(|| format!("read legacy users tree {}", users_root.display()))?
        {
            let user =
                user.with_context(|| format!("read user entry under {}", users_root.display()))?;
            let user_path = user.path();
            require_ordinary_directory(&user_path)?;
            let user_name = user.file_name().to_string_lossy().into_owned();
            UserId::new(user_name.clone())
                .map_err(|error| anyhow!("invalid legacy skill user `{user_name}`: {error}"))?;
            let skills_root = user_path.join("skills");
            for entry in fs::read_dir(&user_path)
                .with_context(|| format!("read legacy user {}", user_path.display()))?
            {
                let entry = entry.with_context(|| {
                    format!("read entry under legacy user {}", user_path.display())
                })?;
                if entry.file_name() != "skills" {
                    bail!(
                        "unknown entry `{}` under legacy user {}; only the skills tree is adoptable",
                        entry.file_name().to_string_lossy(),
                        user_path.display()
                    );
                }
                require_ordinary_directory(&entry.path())?;
            }
            if skills_root.exists() {
                validate_ordinary_tree(&skills_root)?;
                has_content |= directory_has_content(&skills_root)?;
            }
        }
    }
    Ok(has_content)
}

pub(super) fn system_tree_has_content(root: &Path) -> anyhow::Result<bool> {
    for entry in
        fs::read_dir(root).with_context(|| format!("read system content {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("read system entry under {}", root.display()))?;
        if directory_has_content(&entry.path())? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn copy_system_tree(source: &Path, destination: &Path) -> anyhow::Result<()> {
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
pub(super) const MAX_ADOPTION_TREE_DEPTH: usize = 64;

pub(super) fn copy_ordinary_tree(source: &Path, destination: &Path) -> anyhow::Result<()> {
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

pub(super) fn copy_ordinary_file(source: &Path, destination: &Path) -> anyhow::Result<()> {
    require_ordinary_file(source)?;
    let mut input = open_file_no_follow(source)?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| anyhow!("destination has no parent: {}", destination.display()))?;
    require_ordinary_directory(destination_parent)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
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
        let mode = fs::metadata(source)
            .with_context(|| format!("read source mode {}", source.display()))?
            .permissions()
            .mode();
        fs::set_permissions(destination, fs::Permissions::from_mode(mode))
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
pub(super) fn copy_master_key(source: &Path, destination: &Path) -> anyhow::Result<()> {
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

pub(super) fn validate_master_key_source(path: &Path) -> anyhow::Result<File> {
    require_ordinary_file(path)?;
    let file = open_file_no_follow(path)?;
    verify_master_key_policy(&file, path, "source")?;
    Ok(file)
}

pub(super) fn establish_and_verify_master_key_policy(path: &Path) -> anyhow::Result<()> {
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

pub(super) fn verify_master_key_policy(
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

pub(super) fn open_file_no_follow(path: &Path) -> anyhow::Result<File> {
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

pub(super) fn open_directory_no_follow(path: &Path) -> anyhow::Result<File> {
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

pub(super) fn ensure_directory_path_matches_handle(
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

pub(super) fn read_utf8_file_no_follow(path: &Path) -> anyhow::Result<String> {
    require_ordinary_file(path)?;
    let mut file = open_file_no_follow(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("read UTF-8 text file {}", path.display()))?;
    Ok(contents)
}

pub(super) fn validate_ordinary_tree(path: &Path) -> anyhow::Result<()> {
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

pub(super) fn require_ordinary_file(path: &Path) -> anyhow::Result<()> {
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

pub(super) fn require_ordinary_directory(path: &Path) -> anyhow::Result<()> {
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

pub(super) fn directory_is_empty(path: &Path) -> anyhow::Result<bool> {
    require_ordinary_directory(path)?;
    Ok(fs::read_dir(path)
        .with_context(|| format!("read directory {}", path.display()))?
        .next()
        .is_none())
}

pub(super) fn directory_has_content(path: &Path) -> anyhow::Result<bool> {
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

fn ensure_adoption_tree_depth(path: &Path, depth: usize) -> anyhow::Result<()> {
    if depth > MAX_ADOPTION_TREE_DEPTH {
        bail!(
            "adoption source tree exceeds maximum depth {MAX_ADOPTION_TREE_DEPTH} at {}",
            path.display()
        );
    }
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> anyhow::Result<()> {
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
