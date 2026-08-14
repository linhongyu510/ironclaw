use super::*;

pub(in super::super) fn prepare_workspace_import(
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

pub(in super::super) fn is_single_path_segment(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

pub(in super::super) fn workspace_leaf_path(
    paths: &RebornStoragePaths,
    workspace: &ValidatedWorkspaceImportDecision,
) -> PathBuf {
    paths.workspace_root().join("users").join(&workspace.digest)
}

pub(in super::super) fn install_workspace_leaf(
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
