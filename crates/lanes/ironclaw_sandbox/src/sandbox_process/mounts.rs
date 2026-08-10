use std::path::{Path, PathBuf};

use ironclaw_host_api::{
    ids::TenantUserWorkspaceKey,
    mount::{MountGrant, MountView},
    path::VirtualPath,
    resource::ResourceScope,
};

use ironclaw_host_api::process::RuntimeProcessError;

use super::CONTAINER_WORKSPACE_ROOT;

const MANDATORY_WORKSPACE_TARGET_ROOT: &str = "/projects/workspace";

#[derive(Debug, Clone, Default)]
pub(super) struct RebornSandboxMountSources {
    sources: Vec<RebornSandboxMountSource>,
}

#[derive(Debug, Clone)]
struct RebornSandboxMountSource {
    virtual_root: VirtualPath,
    host_root: PathBuf,
}

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
    pub(super) fn add_local_source(
        &mut self,
        virtual_root: VirtualPath,
        host_root: impl Into<PathBuf>,
    ) -> Result<(), RuntimeProcessError> {
        if virtual_path_prefix_matches(virtual_root.as_str(), MANDATORY_WORKSPACE_TARGET_ROOT) {
            return Err(RuntimeProcessError::ExecutionFailed(
                "the caller workspace root is mandatory and cannot be a request-resolvable trusted sandbox mount source".to_string(),
            ));
        }
        if self
            .sources
            .iter()
            .any(|source| source.virtual_root == virtual_root)
        {
            return Err(RuntimeProcessError::ExecutionFailed(format!(
                "trusted sandbox mount source for {virtual_root} is already configured"
            )));
        }

        let host_root = std::fs::canonicalize(host_root.into()).map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!(
                "trusted sandbox mount source for {virtual_root} could not be resolved: {error}"
            ))
        })?;
        if !host_root.is_dir() {
            return Err(RuntimeProcessError::ExecutionFailed(format!(
                "trusted sandbox mount source for {virtual_root} is not a directory"
            )));
        }

        self.sources.push(RebornSandboxMountSource {
            virtual_root,
            host_root,
        });
        Ok(())
    }

    pub(super) async fn prepare_container_binds(
        &self,
        workspace_root: &Path,
        workspace: &Path,
        scope: &ResourceScope,
        mounts: Option<&MountView>,
    ) -> Result<Vec<ContainerBind>, RuntimeProcessError> {
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
        validate_prepared_workspace_leaf(&workspace_root, &workspace, scope)?;

        let Some(mounts) = mounts else {
            return Ok(vec![ContainerBind::new(
                workspace,
                CONTAINER_WORKSPACE_ROOT,
                DockerBindMode::ReadWrite,
            )?]);
        };

        let mut workspace_bind = None;
        let mut request_binds = Vec::new();
        for grant in &mounts.mounts {
            if grant.alias.as_str() == CONTAINER_WORKSPACE_ROOT {
                workspace_bind = Some(resolve_mandatory_workspace_grant(&workspace, scope, grant)?);
            } else {
                request_binds.push(self.resolve_grant(grant).await?);
            }
        }
        request_binds.sort_by_key(|bind| bind.target.len());
        let mut binds = vec![workspace_bind.unwrap_or(ContainerBind::new(
            workspace,
            CONTAINER_WORKSPACE_ROOT,
            DockerBindMode::ReadWrite,
        )?)];
        binds.extend(request_binds);

        Ok(binds)
    }

    async fn resolve_grant(
        &self,
        grant: &MountGrant,
    ) -> Result<ContainerBind, RuntimeProcessError> {
        validate_container_mount_target(grant.alias.as_str())?;
        let mode = DockerBindMode::from_grant(grant)?;
        let source = self
            .sources
            .iter()
            .filter(|source| {
                virtual_path_prefix_matches(source.virtual_root.as_str(), grant.target.as_str())
            })
            .max_by_key(|source| source.virtual_root.as_str().len())
            .ok_or_else(|| {
                RuntimeProcessError::ExecutionFailed(format!(
                    "no trusted sandbox mount source is configured for virtual path {}",
                    grant.target
                ))
            })?;

        let mut joined = source.host_root.clone();
        let tail = grant
            .target
            .as_str()
            .strip_prefix(source.virtual_root.as_str())
            .unwrap_or_default()
            .trim_start_matches('/');
        if !tail.is_empty() {
            for segment in tail.split('/') {
                joined.push(segment);
            }
        }

        if mode == DockerBindMode::ReadWrite {
            tokio::fs::create_dir_all(&joined).await.map_err(|error| {
                RuntimeProcessError::ExecutionFailed(format!(
                    "sandbox mount target {} could not be initialized: {error}",
                    grant.target
                ))
            })?;
        }
        let canonical = tokio::fs::canonicalize(&joined).await.map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!(
                "sandbox mount target {} could not be resolved: {error}",
                grant.target
            ))
        })?;
        if !canonical.starts_with(&source.host_root) {
            return Err(RuntimeProcessError::ExecutionFailed(format!(
                "sandbox mount target {} escapes its trusted source",
                grant.target
            )));
        }
        if !canonical.is_dir() {
            return Err(RuntimeProcessError::ExecutionFailed(format!(
                "sandbox mount target {} is not a directory",
                grant.target
            )));
        }

        ContainerBind::new(canonical, grant.alias.as_str(), mode)
    }
}

fn validate_prepared_workspace_leaf(
    workspace_root: &Path,
    workspace: &Path,
    scope: &ResourceScope,
) -> Result<(), RuntimeProcessError> {
    let key = TenantUserWorkspaceKey::from_scope(scope);
    let expected = workspace_root.join("users").join(key.digest_segment());
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

fn validate_container_mount_target(target: &str) -> Result<(), RuntimeProcessError> {
    const FORBIDDEN_TARGETS: &[&str] = &[
        "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root",
        "/run", "/sbin", "/sys", "/usr", "/var",
    ];
    if FORBIDDEN_TARGETS
        .iter()
        .any(|forbidden| target == *forbidden || target.starts_with(&format!("{forbidden}/")))
    {
        return Err(RuntimeProcessError::ExecutionFailed(
            "sandbox mount target collides with the container system filesystem".to_string(),
        ));
    }
    Ok(())
}

fn virtual_path_prefix_matches(prefix: &str, path: &str) -> bool {
    Path::new(path).starts_with(Path::new(prefix))
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
        path::MountAlias,
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

    #[test]
    fn trusted_mount_source_validates_host_root_during_config() {
        let mut sources = RebornSandboxMountSources::default();
        let error = sources
            .add_local_source(
                VirtualPath::new("/artifacts/test-fixture").unwrap(),
                PathBuf::from("/path/that/does/not/exist"),
            )
            .unwrap_err();

        assert!(format!("{error}").contains("could not be resolved"));
    }

    #[test]
    fn trusted_mount_source_rejects_duplicate_virtual_roots() {
        let temp = tempfile::tempdir().unwrap();
        let mut sources = sources_with(
            VirtualPath::new("/artifacts/test-fixture").unwrap(),
            temp.path(),
        );

        let error = sources
            .add_local_source(
                VirtualPath::new("/artifacts/test-fixture").unwrap(),
                temp.path(),
            )
            .unwrap_err();

        assert!(format!("{error}").contains("already configured"));
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
        let sources = RebornSandboxMountSources::default();
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
        let sources = RebornSandboxMountSources::default();
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
        let sources = RebornSandboxMountSources::default();
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
        let sources = RebornSandboxMountSources::default();
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

    #[tokio::test]
    async fn workspace_grant_rejects_a_host_directory_other_than_the_caller_leaf() {
        let temp = tempfile::tempdir().unwrap();
        let scope = caller_scope();
        let workspace_root = temp.path().join("workspaces");
        let arbitrary_directory = workspace_root.join("not-the-caller-leaf");
        tokio::fs::create_dir_all(&arbitrary_directory)
            .await
            .unwrap();
        let sources = RebornSandboxMountSources::default();
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

    #[test]
    fn mandatory_workspace_parent_cannot_be_registered_as_a_trusted_source() {
        let temp = tempfile::tempdir().unwrap();
        for virtual_root in ["/projects", "/projects/workspace"] {
            let mut sources = RebornSandboxMountSources::default();
            let error = sources
                .add_local_source(VirtualPath::new(virtual_root).unwrap(), temp.path())
                .expect_err("the caller workspace root must not be request-resolvable");
            assert!(
                format!("{error}").contains("mandatory"),
                "{virtual_root}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn none_mounts_use_default_workspace_bind() {
        let temp = tempfile::tempdir().unwrap();
        let sources = RebornSandboxMountSources::default();
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
    async fn read_write_scoped_mount_initializes_target_directory() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("source");
        tokio::fs::create_dir_all(&source_root).await.unwrap();
        let sources = sources_with(
            VirtualPath::new("/artifacts/test-fixture").unwrap(),
            &source_root,
        );
        let scope = caller_scope();
        let (workspace_root, workspace) = prepared_workspace(&temp, &scope).await;
        let mounts = MountView::new(vec![MountGrant::new(
            MountAlias::new("/project").unwrap(),
            VirtualPath::new("/artifacts/test-fixture/new-task").unwrap(),
            process_read_write_permissions(),
        )])
        .unwrap();

        let binds = sources
            .prepare_container_binds(&workspace_root, &workspace, &scope, Some(&mounts))
            .await
            .unwrap();

        assert!(source_root.join("new-task").is_dir());
        assert!(
            binds
                .into_iter()
                .any(|bind| bind.into_docker_bind().ends_with(":/project:rw"))
        );
    }

    #[tokio::test]
    async fn scoped_mount_rejects_unconfigured_virtual_target() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("source");
        tokio::fs::create_dir_all(&source_root).await.unwrap();
        let sources = sources_with(
            VirtualPath::new("/artifacts/test-fixture").unwrap(),
            source_root,
        );
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
        let sources = RebornSandboxMountSources::default();
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

    #[tokio::test]
    async fn scoped_mount_rejects_container_system_targets() {
        let temp = tempfile::tempdir().unwrap();
        let source_root = temp.path().join("source");
        let project_root = source_root.join("app");
        tokio::fs::create_dir_all(&project_root).await.unwrap();
        let sources = sources_with(
            VirtualPath::new("/artifacts/test-fixture").unwrap(),
            source_root,
        );
        let scope = caller_scope();
        let (workspace_root, workspace) = prepared_workspace(&temp, &scope).await;
        let mounts = MountView::new(vec![MountGrant::new(
            MountAlias::new("/etc").unwrap(),
            VirtualPath::new("/artifacts/test-fixture/app").unwrap(),
            process_read_only_permissions(),
        )])
        .unwrap();

        let error = sources
            .prepare_container_binds(&workspace_root, &workspace, &scope, Some(&mounts))
            .await
            .unwrap_err();

        assert!(format!("{error}").contains("container system filesystem"));
    }

    fn sources_with(
        virtual_root: VirtualPath,
        host_root: impl Into<PathBuf>,
    ) -> RebornSandboxMountSources {
        let mut sources = RebornSandboxMountSources::default();
        sources
            .add_local_source(virtual_root, host_root.into())
            .unwrap();
        sources
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
