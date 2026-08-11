use std::path::{Path, PathBuf};

use ironclaw_host_api::{
    ids::TenantUserWorkspaceKey,
    mount::{MountGrant, MountView},
    resource::ResourceScope,
};

use ironclaw_host_api::process::RuntimeProcessError;

use super::CONTAINER_WORKSPACE_ROOT;

const MANDATORY_WORKSPACE_TARGET_ROOT: &str = "/projects/workspace";

#[derive(Debug, Clone)]
pub(super) struct RebornSandboxMountSources;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ContainerBind {
    source: PathBuf,
    target: String,
    mode: DockerBindMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DockerBindMode {
    ReadOnly,
    ReadWrite,
}

impl RebornSandboxMountSources {
    pub(super) async fn prepare_container_binds(
        &self,
        workspace_root: &Path,
        workspace: &Path,
        scope: &ResourceScope,
        mounts: Option<&MountView>,
    ) -> Result<Vec<ContainerBind>, RuntimeProcessError> {
        validate_mandatory_workspace_mount_view(scope, mounts)?;
        let workspace_root = tokio::fs::canonicalize(workspace_root)
            .await
            .map_err(|error| {
                RuntimeProcessError::ExecutionFailed(format!(
                    "sandbox workspace root could not be resolved: {error}"
                ))
            })?;
        if !workspace_root.is_dir() {
            return Err(RuntimeProcessError::ExecutionFailed(
                "sandbox workspace root must be a directory".to_string(),
            ));
        }
        let users_root = tokio::fs::canonicalize(workspace_root.join("users"))
            .await
            .map_err(|error| {
                RuntimeProcessError::ExecutionFailed(format!(
                    "sandbox workspace users root could not be resolved: {error}"
                ))
            })?;
        if !users_root.is_dir() {
            return Err(RuntimeProcessError::ExecutionFailed(
                "sandbox workspace users root must be a directory".to_string(),
            ));
        }
        if users_root.parent() != Some(workspace_root.as_path()) {
            return Err(RuntimeProcessError::ExecutionFailed(
                "sandbox workspace users root escapes the configured workspace root".to_string(),
            ));
        }
        let workspace = tokio::fs::canonicalize(workspace).await.map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!(
                "sandbox caller workspace could not be resolved: {error}"
            ))
        })?;
        if !workspace.is_dir() {
            return Err(RuntimeProcessError::ExecutionFailed(
                "sandbox caller workspace must be a directory".to_string(),
            ));
        }
        validate_prepared_workspace_leaf(&users_root, &workspace, scope)?;

        let workspace_bind = mounts
            .and_then(|mounts| mounts.mounts.first())
            .map(|grant| resolve_mandatory_workspace_grant(&workspace, scope, grant))
            .unwrap_or_else(|| {
                ContainerBind::new(
                    workspace,
                    CONTAINER_WORKSPACE_ROOT,
                    DockerBindMode::ReadWrite,
                )
            })?;
        Ok(vec![workspace_bind])
    }
}

/// Admit the sole virtual workspace grant both sandbox transports understand.
/// The transport never resolves this virtual target to a caller-selected host
/// path; Docker binds the already-prepared leaf and Railway keeps its own
/// provider-owned leaf. Validating the common authority shape here prevents a
/// public, manually constructed `MountView` from changing either transport's
/// selection semantics.
pub(super) fn validate_mandatory_workspace_mount_view(
    scope: &ResourceScope,
    mounts: Option<&MountView>,
) -> Result<(), RuntimeProcessError> {
    let Some(mounts) = mounts else {
        return Ok(());
    };
    mounts.validate().map_err(|error| {
        RuntimeProcessError::ExecutionFailed(format!("sandbox mount view is invalid: {error}"))
    })?;
    let Some(grant) = mounts.mounts.first() else {
        return Ok(());
    };
    if mounts.mounts.len() != 1 || grant.alias.as_str() != CONTAINER_WORKSPACE_ROOT {
        return Err(RuntimeProcessError::ExecutionFailed(
            "sandbox accepts only the mandatory /workspace caller workspace leaf and no extra mounts"
                .to_string(),
        ));
    }
    let key = TenantUserWorkspaceKey::from_scope(scope);
    let expected_target = format!(
        "{MANDATORY_WORKSPACE_TARGET_ROOT}/users/{}",
        key.digest_segment()
    );
    if grant.target.as_str() != expected_target {
        return Err(RuntimeProcessError::ExecutionFailed(
            "sandbox /workspace mount must target the current caller workspace leaf".to_string(),
        ));
    }
    DockerBindMode::from_grant(grant)?;
    Ok(())
}

fn validate_prepared_workspace_leaf(
    users_root: &Path,
    workspace: &Path,
    scope: &ResourceScope,
) -> Result<(), RuntimeProcessError> {
    let key = TenantUserWorkspaceKey::from_scope(scope);
    let expected = users_root.join(key.digest_segment());
    if workspace != expected {
        return Err(RuntimeProcessError::ExecutionFailed(
            "sandbox caller workspace leaf must be the prepared tenant/user workspace".to_string(),
        ));
    }
    Ok(())
}

fn resolve_mandatory_workspace_grant(
    workspace: &Path,
    scope: &ResourceScope,
    grant: &MountGrant,
) -> Result<ContainerBind, RuntimeProcessError> {
    let key = TenantUserWorkspaceKey::from_scope(scope);
    let expected_target = format!(
        "{MANDATORY_WORKSPACE_TARGET_ROOT}/users/{}",
        key.digest_segment()
    );
    if grant.target.as_str() != expected_target {
        return Err(RuntimeProcessError::ExecutionFailed(
            "sandbox /workspace mount must target the current caller workspace leaf".to_string(),
        ));
    }
    ContainerBind::new(
        workspace.to_path_buf(),
        CONTAINER_WORKSPACE_ROOT,
        DockerBindMode::from_grant(grant)?,
    )
}

impl ContainerBind {
    fn new(
        source: PathBuf,
        target: impl Into<String>,
        mode: DockerBindMode,
    ) -> Result<Self, RuntimeProcessError> {
        let target = target.into();
        reject_nul("sandbox bind source", &source.to_string_lossy())?;
        reject_nul("sandbox bind target", &target)?;
        if source.to_string_lossy().contains(':') || target.contains(':') {
            return Err(RuntimeProcessError::ExecutionFailed(
                "sandbox bind paths cannot contain ':'".to_string(),
            ));
        }
        Ok(Self {
            source,
            target,
            mode,
        })
    }

    pub(super) fn into_docker_bind(self) -> String {
        let mode = match self.mode {
            DockerBindMode::ReadOnly => "ro",
            DockerBindMode::ReadWrite => "rw",
        };
        format!("{}:{}:{mode}", self.source.display(), self.target)
    }
}

impl DockerBindMode {
    fn from_grant(grant: &MountGrant) -> Result<Self, RuntimeProcessError> {
        let permissions = &grant.permissions;
        let readonly = permissions.read
            && permissions.list
            && permissions.execute
            && !permissions.write
            && !permissions.delete;
        let read_write = permissions.read
            && permissions.list
            && permissions.execute
            && permissions.write
            && permissions.delete;
        match (readonly, read_write) {
            (true, false) => Ok(Self::ReadOnly),
            (false, true) => Ok(Self::ReadWrite),
            _ => Err(RuntimeProcessError::ExecutionFailed(format!(
                "sandbox mount {} permissions cannot be enforced by Docker bind mounts",
                grant.alias
            ))),
        }
    }
}

fn reject_nul(label: &str, value: &str) -> Result<(), RuntimeProcessError> {
    if value.as_bytes().contains(&0) {
        return Err(RuntimeProcessError::ExecutionFailed(format!(
            "{label} contains null bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ironclaw_host_api::{
        ids::{AgentId, InvocationId, TenantId, TenantUserWorkspaceKey, UserId},
        mount::MountPermissions,
        path::{MountAlias, VirtualPath},
        resource::ResourceScope,
    };

    use super::*;

    fn caller_scope() -> ResourceScope {
        ResourceScope {
            tenant_id: TenantId::new("acme").expect("tenant"),
            user_id: UserId::new("alice").expect("user"),
            agent_id: Some(AgentId::new("agent").expect("agent")),
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        }
    }

    fn caller_workspace_target(scope: &ResourceScope) -> VirtualPath {
        let key = TenantUserWorkspaceKey::from_scope(scope);
        VirtualPath::new(format!(
            "/projects/workspace/users/{}",
            key.digest_segment()
        ))
        .expect("workspace target")
    }

    #[tokio::test]
    async fn scoped_workspace_mount_replaces_default_workspace_bind() {
        let temp = tempfile::tempdir().unwrap();
        let scope = caller_scope();
        let workspace_root = temp.path().join("workspace");
        let scoped_workspace = workspace_root
            .join("users")
            .join(TenantUserWorkspaceKey::from_scope(&scope).digest_segment());
        tokio::fs::create_dir_all(&scoped_workspace).await.unwrap();
        let sources = RebornSandboxMountSources;
        let mounts = MountView::new(vec![MountGrant::new(
            MountAlias::new("/workspace").unwrap(),
            caller_workspace_target(&scope),
            process_read_only_permissions(),
        )])
        .unwrap();

        let binds = sources
            .prepare_container_binds(&workspace_root, &scoped_workspace, &scope, Some(&mounts))
            .await
            .unwrap();

        assert_eq!(binds.len(), 1);
        assert!(
            binds[0]
                .clone()
                .into_docker_bind()
                .ends_with(":/workspace:ro")
        );
        assert!(
            binds[0].clone().into_docker_bind().starts_with(
                tokio::fs::canonicalize(&scoped_workspace)
                    .await
                    .expect("workspace canonical path")
                    .to_str()
                    .expect("workspace path utf-8")
            )
        );
    }

    /// Under a per-caller workspace policy the `/workspace` grant target is a
    /// nested path (`/projects/workspace/users/<tenant-user-digest>`) rather
    /// than a request-resolvable source root. The prepared caller leaf is the
    /// only host path that can be bound at `/workspace`.
    #[tokio::test]
    async fn per_caller_workspace_grant_binds_the_callers_subdirectory() {
        let temp = tempfile::tempdir().unwrap();
        let scope = caller_scope();
        let default_workspace = temp
            .path()
            .join("workspace/users")
            .join(TenantUserWorkspaceKey::from_scope(&scope).digest_segment());
        tokio::fs::create_dir_all(&default_workspace).await.unwrap();
        let sources = RebornSandboxMountSources;
        let mounts = MountView::new(vec![MountGrant::new(
            MountAlias::new("/workspace").unwrap(),
            caller_workspace_target(&scope),
            process_read_write_permissions(),
        )])
        .unwrap();

        let binds = sources
            .prepare_container_binds(
                &temp.path().join("workspace"),
                &default_workspace,
                &scope,
                Some(&mounts),
            )
            .await
            .unwrap();

        assert_eq!(
            binds.len(),
            1,
            "the /workspace grant replaces the default bind"
        );
        let bind = binds[0].clone().into_docker_bind();
        let expected_host_dir = tokio::fs::canonicalize(&default_workspace)
            .await
            .expect("the prepared caller workspace is canonicalized");
        assert!(
            bind.starts_with(expected_host_dir.to_str().unwrap()),
            "bind should map the caller subdirectory, got {bind}"
        );
        assert!(
            bind.ends_with(":/workspace:rw"),
            "bind should mount it read-write at /workspace, got {bind}"
        );
    }

    /// `/workspace` is a mandatory caller leaf, not a generic alias into the
    /// trusted mount catalog. A sibling's virtual target must never replace
    /// the prepared leaf, even when it is below the configured workspace root.
    #[tokio::test]
    async fn workspace_grant_rejects_a_sibling_user_leaf() {
        let temp = tempfile::tempdir().unwrap();
        let workspace_root = temp.path().join("workspace");
        let scope = caller_scope();
        let caller_leaf = workspace_root
            .join("users")
            .join("c711caa52fd730885e365ba866cb387c38357e3a82dc675071d1bb9ac834fd22");
        tokio::fs::create_dir_all(&caller_leaf).await.unwrap();
        let sources = RebornSandboxMountSources;
        let mounts = MountView::new(vec![MountGrant::new(
            MountAlias::new("/workspace").unwrap(),
            VirtualPath::new(
                "/projects/workspace/users/0d8e2f80d9d679685b37a5e5eff4eb3ffe78bcf3e69cf027b51d3b5ccd1f06f0",
            )
            .unwrap(),
            process_read_write_permissions(),
        )])
        .unwrap();

        let error = sources
            .prepare_container_binds(&workspace_root, &caller_leaf, &scope, Some(&mounts))
            .await
            .expect_err("a sibling workspace target must be rejected");

        assert!(format!("{error}").contains("caller workspace"));
    }

    #[tokio::test]
    async fn workspace_grant_rejects_every_noncanonical_caller_target() {
        let temp = tempfile::tempdir().unwrap();
        let scope = caller_scope();
        let key = TenantUserWorkspaceKey::from_scope(&scope);
        let caller_leaf = temp
            .path()
            .join("workspace/users")
            .join(key.digest_segment());
        let workspace_root = temp.path().join("workspace");
        tokio::fs::create_dir_all(&caller_leaf).await.unwrap();
        let sources = RebornSandboxMountSources;
        let targets = [
            "/projects/workspace".to_string(),
            "/projects/workspace/users".to_string(),
            format!("/projects/workspace/users/{}/child", key.digest_segment()),
            "/projects/workspace/not-users/not-a-digest".to_string(),
        ];

        for target in targets {
            let mounts = MountView::new(vec![MountGrant::new(
                MountAlias::new("/workspace").unwrap(),
                VirtualPath::new(target.clone()).unwrap(),
                process_read_write_permissions(),
            )])
            .unwrap();

            let error = sources
                .prepare_container_binds(&workspace_root, &caller_leaf, &scope, Some(&mounts))
                .await
                .expect_err("only the exact caller workspace target is admitted");
            assert!(
                format!("{error}").contains("caller workspace"),
                "target {target} must be rejected: {error}"
            );
        }
    }

    #[test]
    fn workspace_virtual_path_rejects_a_bare_root_before_resolver_admission() {
        let error = VirtualPath::new("/").expect_err("a sandbox workspace target may not be root");

        assert!(format!("{error}").contains("root path is not valid here"));
    }

    #[tokio::test]
    async fn workspace_grant_rejects_a_host_directory_other_than_the_caller_leaf() {
        let temp = tempfile::tempdir().unwrap();
        let scope = caller_scope();
        let workspace_root = temp.path().join("workspaces");
        let arbitrary_directory = workspace_root.join("not-the-caller-leaf");
        tokio::fs::create_dir_all(&arbitrary_directory)
            .await
            .unwrap();
        tokio::fs::create_dir(workspace_root.join("users"))
            .await
            .unwrap();
        let sources = RebornSandboxMountSources;
        let mounts = MountView::new(vec![MountGrant::new(
            MountAlias::new("/workspace").unwrap(),
            caller_workspace_target(&scope),
            process_read_write_permissions(),
        )])
        .unwrap();

        let error = sources
            .prepare_container_binds(&workspace_root, &arbitrary_directory, &scope, Some(&mounts))
            .await
            .expect_err("only the prepared caller leaf may bind at /workspace");

        assert!(format!("{error}").contains("caller workspace leaf"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn container_bind_rejects_a_users_root_that_escapes_the_workspace_root() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let scope = caller_scope();
        let workspace_root = temp.path().join("workspace");
        let outside = temp.path().join("outside");
        let key = TenantUserWorkspaceKey::from_scope(&scope);
        tokio::fs::create_dir(&workspace_root).await.unwrap();
        tokio::fs::create_dir(&outside).await.unwrap();
        tokio::fs::create_dir(outside.join(key.digest_segment()))
            .await
            .unwrap();
        symlink(&outside, workspace_root.join("users")).unwrap();

        let error = RebornSandboxMountSources
            .prepare_container_binds(
                &workspace_root,
                &outside.join(key.digest_segment()),
                &scope,
                None,
            )
            .await
            .expect_err("bind construction must retain workspace-root containment");

        assert!(
            format!("{error}").contains("users root escapes"),
            "users symlink escape must fail at bind construction: {error}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn container_bind_rejects_a_caller_leaf_symlink_that_escapes_users_root() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let scope = caller_scope();
        let workspace_root = temp.path().join("workspace");
        let outside = temp.path().join("outside");
        let key = TenantUserWorkspaceKey::from_scope(&scope);
        tokio::fs::create_dir_all(workspace_root.join("users"))
            .await
            .unwrap();
        tokio::fs::create_dir(&outside).await.unwrap();
        symlink(
            &outside,
            workspace_root.join("users").join(key.digest_segment()),
        )
        .unwrap();

        let error = RebornSandboxMountSources
            .prepare_container_binds(
                &workspace_root,
                &workspace_root.join("users").join(key.digest_segment()),
                &scope,
                None,
            )
            .await
            .expect_err("a caller workspace leaf may not escape through a symlink");

        assert!(
            format!("{error}").contains("caller workspace leaf"),
            "caller leaf symlink escape must fail at bind construction: {error}"
        );
    }

    #[tokio::test]
    async fn none_mounts_use_default_workspace_bind() {
        let temp = tempfile::tempdir().unwrap();
        let sources = RebornSandboxMountSources;
        let scope = caller_scope();
        let (workspace_root, workspace) = prepared_workspace(&temp, &scope).await;

        let binds = sources
            .prepare_container_binds(&workspace_root, &workspace, &scope, None)
            .await
            .unwrap();

        assert_eq!(binds.len(), 1);
        assert_eq!(
            binds[0].clone().into_docker_bind(),
            format!(
                "{}:/workspace:rw",
                tokio::fs::canonicalize(&workspace)
                    .await
                    .expect("workspace canonical path")
                    .display()
            )
        );
    }

    #[tokio::test]
    async fn sandbox_rejects_extra_mount_without_initializing_a_host_directory() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("source");
        let project_root = source_root.join("app");
        tokio::fs::create_dir_all(&source_root).await.unwrap();
        let sources = RebornSandboxMountSources;
        let scope = caller_scope();
        let (workspace_root, workspace) = prepared_workspace(&temp, &scope).await;
        let mounts = MountView::new(vec![
            MountGrant::new(
                MountAlias::new("/workspace").unwrap(),
                caller_workspace_target(&scope),
                process_read_write_permissions(),
            ),
            MountGrant::new(
                MountAlias::new("/project").unwrap(),
                VirtualPath::new("/artifacts/test-fixture/app").unwrap(),
                process_read_write_permissions(),
            ),
        ])
        .unwrap();

        let error = sources
            .prepare_container_binds(&workspace_root, &workspace, &scope, Some(&mounts))
            .await
            .expect_err("the sandbox must receive only the mandatory caller workspace leaf");

        assert!(format!("{error}").contains("only the mandatory /workspace"));
        assert!(
            !project_root.exists(),
            "the rejected extra mount must not initialize a host directory"
        );
    }

    #[test]
    fn mount_catalog_rejects_a_duplicate_workspace_mount_override() {
        let scope = caller_scope();
        let error = MountView::new(vec![
            MountGrant::new(
                MountAlias::new("/workspace").unwrap(),
                caller_workspace_target(&scope),
                process_read_write_permissions(),
            ),
            MountGrant::new(
                MountAlias::new("/workspace").unwrap(),
                caller_workspace_target(&scope),
                process_read_write_permissions(),
            ),
        ])
        .expect_err("a sandbox admits exactly one mandatory workspace mount");

        assert!(format!("{error}").contains("duplicate mount alias"));
    }

    #[tokio::test]
    async fn container_bind_rejects_a_manually_constructed_duplicate_workspace_override() {
        let temp = tempfile::tempdir().unwrap();
        let scope = caller_scope();
        let (workspace_root, workspace) = prepared_workspace(&temp, &scope).await;
        let mounts = MountView {
            mounts: vec![
                MountGrant::new(
                    MountAlias::new("/workspace").unwrap(),
                    caller_workspace_target(&scope),
                    process_read_write_permissions(),
                ),
                MountGrant::new(
                    MountAlias::new("/workspace").unwrap(),
                    caller_workspace_target(&scope),
                    process_read_only_permissions(),
                ),
            ],
        };

        let error = RebornSandboxMountSources
            .prepare_container_binds(&workspace_root, &workspace, &scope, Some(&mounts))
            .await
            .expect_err("public MountView construction must not permit a last-wins workspace bind");

        assert!(format!("{error}").contains("duplicate mount alias"));
    }

    #[tokio::test]
    async fn scoped_mount_rejects_unconfigured_virtual_target() {
        let temp = tempfile::tempdir().unwrap();
        let sources = RebornSandboxMountSources;
        let scope = caller_scope();
        let (workspace_root, workspace) = prepared_workspace(&temp, &scope).await;
        let mounts = MountView::new(vec![MountGrant::new(
            MountAlias::new("/workspace").unwrap(),
            VirtualPath::new("/memory/app").unwrap(),
            process_read_only_permissions(),
        )])
        .unwrap();

        let error = sources
            .prepare_container_binds(&workspace_root, &workspace, &scope, Some(&mounts))
            .await
            .unwrap_err();

        assert!(format!("{error}").contains("caller workspace"));
    }

    #[tokio::test]
    async fn scoped_mount_rejects_permissions_docker_cannot_enforce() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("source");
        let project_root = source_root.join("app");
        tokio::fs::create_dir_all(&project_root).await.unwrap();
        let sources = RebornSandboxMountSources;
        let scope = caller_scope();
        let (workspace_root, workspace) = prepared_workspace(&temp, &scope).await;
        let mut permissions = MountPermissions::read_write();
        permissions.execute = true;
        let mounts = MountView::new(vec![MountGrant::new(
            MountAlias::new("/workspace").unwrap(),
            caller_workspace_target(&scope),
            permissions,
        )])
        .unwrap();

        let error = sources
            .prepare_container_binds(&workspace_root, &workspace, &scope, Some(&mounts))
            .await
            .unwrap_err();

        assert!(format!("{error}").contains("permissions cannot be enforced"));
    }

    async fn prepared_workspace(
        temp: &tempfile::TempDir,
        scope: &ResourceScope,
    ) -> (PathBuf, PathBuf) {
        let workspace_root = temp.path().join("workspaces");
        let workspace = workspace_root
            .join("users")
            .join(TenantUserWorkspaceKey::from_scope(scope).digest_segment());
        tokio::fs::create_dir_all(&workspace)
            .await
            .expect("prepared caller workspace");
        (workspace_root, workspace)
    }

    fn process_read_only_permissions() -> MountPermissions {
        MountPermissions {
            execute: true,
            ..MountPermissions::read_only()
        }
    }

    fn process_read_write_permissions() -> MountPermissions {
        MountPermissions {
            execute: true,
            ..MountPermissions::read_write_list_delete()
        }
    }
}
