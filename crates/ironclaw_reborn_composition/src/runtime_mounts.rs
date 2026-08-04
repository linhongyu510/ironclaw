//! Runtime mount views selected from the resolved filesystem configuration.

use std::{collections::HashSet, path::Path, sync::Arc};

use ironclaw_filesystem::{CompositeRootFilesystem, ScopedFilesystem};
use ironclaw_host_api::{
    error::HostApiError,
    mount::{MountGrant, MountPermissions, MountView},
    path::{MountAlias, VirtualPath},
    resource::ResourceScope,
};
use ironclaw_memory::MemoryDocumentScope;

// One owner for the workspace mount alias: `ironclaw_attachments` also uses it
// to decide which model-text references become egress attachments.
pub(crate) use ironclaw_attachments::WORKSPACE_ALIAS;

const WORKSPACE_TARGET: &str = "/projects/workspace";
const HOST_ALIAS: &str = "/host";
const HOST_TARGET: &str = "/projects/host";
const MEMORY_ALIAS: &str = "/memory";
const MEMORY_TARGET: &str = "/memory";

pub(crate) fn workspace_mount_view(
    permissions: MountPermissions,
    host_home_aliases: &[&Path],
) -> Result<MountView, HostApiError> {
    ambient_workspace_mount_view(permissions, &[], host_home_aliases)
}

/// Build the workspace mount view used by capability grants.
///
/// `workspace_aliases` is load-bearing for ambient host coding tools:
/// callers must pass it only under a policy that grants ambient host access. Other
/// profiles must pass an empty slice so raw host workspace paths stay denied.
pub(crate) fn ambient_workspace_mount_view(
    permissions: MountPermissions,
    workspace_aliases: &[&Path],
    host_home_aliases: &[&Path],
) -> Result<MountView, HostApiError> {
    let mut mounts = vec![grant(
        WORKSPACE_ALIAS,
        WORKSPACE_TARGET,
        permissions.clone(),
    )?];
    push_raw_alias_mounts(
        &mut mounts,
        workspace_aliases,
        WORKSPACE_TARGET,
        permissions.clone(),
        "workspace alias",
    )?;
    if !host_home_aliases.is_empty() {
        mounts.push(grant(HOST_ALIAS, HOST_TARGET, permissions.clone())?);
        push_raw_alias_mounts(
            &mut mounts,
            host_home_aliases,
            HOST_TARGET,
            permissions.clone(),
            "confirmed host-home alias",
        )?;
    }
    MountView::new(mounts)
}

/// Virtual root the `HostedSingleTenantVolumeSandboxed` profile's per-user
/// sandbox-workspace disk mount is registered at
/// (`mount_sandbox_user_workspace_root` in `factory.rs` mounts the shared
/// PARENT directory — every user's leaf workspace directory — here, ONCE, at
/// boot). Grants built by [`sandbox_user_workspace_mount_view`] narrow
/// `/workspace` down to the calling scope's own child directory under this
/// root, so the disk mount itself never needs to change per user.
const SANDBOX_WORKSPACE_ROOT: &str = "/workspace";

/// Per-invocation workspace `MountView` for the `HostedSingleTenantVolumeSandboxed`
/// profile: resolves `/workspace` to the CALLING scope's own subtree under the
/// shared sandbox-workspace-users disk mount, using the SAME canonical
/// `RebornSandboxUserKey::from_scope` key the sandbox container bind uses
/// (`sandbox_process.rs`'s `prepare_workspace`) — so abstract-FS
/// `read_file`/`write_file` and the shell container agree on the identical
/// host directory PER USER. Mirrors [`scoped_skill_context_mount_view`]'s
/// per-scope resolver shape: unlike the old fixed view (baked once from the
/// boot owner), this must be re-resolved for every invocation — never cached
/// or reused across scopes.
pub(crate) fn sandbox_user_workspace_mount_view(
    scope: &ResourceScope,
    permissions: MountPermissions,
) -> Result<MountView, HostApiError> {
    let workspace_path = ironclaw_host_runtime::RebornSandboxUserKey::from_scope(scope)
        .workspace_path(Path::new(""));
    // `RebornSandboxUserKey::workspace_path` always yields `"users/<digest>"`
    // relative to whatever root it is given; the disk mount registered by
    // `mount_sandbox_user_workspace_root` is rooted at that same "users"
    // parent, so strip the (structurally constant) "users" prefix to get the
    // segment relative to the mount.
    let digest = workspace_path
        .strip_prefix("users")
        .map_err(|_| HostApiError::InvalidMount {
            value: WORKSPACE_ALIAS.to_string(),
            reason: "sandbox workspace key produced an unexpected path shape".to_string(),
        })?
        .to_str()
        .ok_or_else(|| HostApiError::InvalidMount {
            value: WORKSPACE_ALIAS.to_string(),
            reason: "sandbox workspace path is not valid UTF-8".to_string(),
        })?;
    MountView::new(vec![grant(
        WORKSPACE_ALIAS,
        &format!("{SANDBOX_WORKSPACE_ROOT}/{digest}"),
        permissions,
    )?])
}

pub(crate) fn scoped_skill_context_mount_view(
    scope: &ResourceScope,
) -> Result<MountView, HostApiError> {
    MountView::new(vec![
        grant(
            "/skills",
            &format!(
                "/projects/tenants/{}/users/{}/skills",
                scope.tenant_id.as_str(),
                scope.user_id.as_str()
            ),
            MountPermissions::read_only(),
        )?,
        grant(
            "/tenant-shared/skills",
            "/projects/tenant-shared/skills",
            MountPermissions::read_only(),
        )?,
        grant(
            "/system/skills",
            "/projects/system/skills",
            MountPermissions::read_only(),
        )?,
    ])
}

pub(crate) fn skill_management_mount_view() -> Result<MountView, HostApiError> {
    MountView::new(vec![
        grant(
            "/skills",
            "/projects/skills",
            MountPermissions::read_write_list_delete(),
        )?,
        grant(
            "/system/skills",
            "/projects/system/skills",
            MountPermissions::read_only(),
        )?,
    ])
}

pub(crate) fn scoped_skill_management_mount_view(
    scope: &ResourceScope,
) -> Result<MountView, HostApiError> {
    MountView::new(vec![
        grant(
            "/skills",
            &format!(
                "/projects/tenants/{}/users/{}/skills",
                scope.tenant_id.as_str(),
                scope.user_id.as_str()
            ),
            MountPermissions::read_write_list_delete(),
        )?,
        grant(
            "/system/skills",
            "/projects/system/skills",
            MountPermissions::read_only(),
        )?,
    ])
}

pub(crate) fn memory_mount_view(permissions: MountPermissions) -> Result<MountView, HostApiError> {
    MountView::new(vec![grant(MEMORY_ALIAS, MEMORY_TARGET, permissions)?])
}

#[cfg(test)]
pub(crate) fn system_extensions_lifecycle_mount_view() -> Result<MountView, HostApiError> {
    MountView::new(vec![grant(
        "/system/extensions",
        "/system/extensions",
        MountPermissions::read_write_list_delete(),
    )?])
}

/// Read-only mount view backing the standalone WebUI filesystem viewer.
///
/// Spans every mount the read-only browser can navigate — the workspace
/// (project working files + landed attachments) and the persistent memory store
/// — over the same targets the agent's own tools resolve through, so the viewer
/// shows exactly what the agent sees. Read-only by construction: the viewer is a
/// navigation + preview/download surface, never a write path. The aliases here
/// are the contract the browse reader confines against; keep them aligned with
/// [`BROWSE_MEMORY_ALIAS`]/[`WORKSPACE_ALIAS`].
pub(crate) const BROWSE_MEMORY_ALIAS: &str = MEMORY_ALIAS;

/// Per-caller workspace mount view for agent read/write filesystem access.
/// Maps `WORKSPACE_ALIAS` to the caller's own subtree under
/// `/projects/workspace/tenants/{tenant}/users/{user}`, mirroring memory's
/// per-caller scoping, so agent tool/attachment writes land in the caller's
/// private subtree and the WebUI browser (which reads the same subtree) can
/// surface them. A missing subtree renders empty on read rather than falling
/// back to the shared root.
pub(crate) fn scoped_workspace_mount_view(
    scope: &ResourceScope,
    permissions: MountPermissions,
) -> Result<MountView, HostApiError> {
    MountView::new(vec![grant(
        WORKSPACE_ALIAS,
        &format!(
            "{WORKSPACE_TARGET}/tenants/{}/users/{}",
            scope.tenant_id.as_str(),
            scope.user_id.as_str()
        ),
        permissions,
    )?])
}

/// How a deployment keys the workspace mount, resolved once at composition
/// from [`crate::deployment::DeploymentConfig::workspace_scoped_per_caller`].
///
/// Every workspace *write* lane reads this one value — capability grant
/// minting, approval lease terms, the WebUI attachment handle, and the
/// channel-inbound attachment lander — so the agent and the WebUI browser can
/// never address different subtrees. Under [`Self::PerCaller`] there is no
/// shared view to reach for: the shared `/projects/workspace` root is simply
/// not representable.
#[derive(Clone, Debug)]
pub(crate) enum WorkspaceMountPolicy {
    /// One ambient workspace view for the whole deployment, including any raw
    /// host aliases the runtime policy granted. Local single-user coding
    /// profiles depend on those aliases, so this view is never scoped.
    Shared(MountView),
    /// Workspace mounts key the caller's own subtree under
    /// `/projects/workspace/tenants/{tenant}/users/{user}`.
    PerCaller,
    /// The sandbox profile keys `/workspace` by the same hashed
    /// `{tenant_id,user_id}` leaf used by the process backend.
    SandboxPerCaller,
}

impl WorkspaceMountPolicy {
    /// The deployment's single workspace scoping decision, turned into the
    /// policy every write lane reads.
    ///
    /// One constructor so the `PerCaller` / `Shared` branch cannot drift
    /// between assembly sites: a deployment that scopes per caller must never
    /// end up with an ambient shared view on one lane and a scoped view on
    /// another. `workspace_aliases` / `host_home_aliases` are the raw host
    /// aliases only ambient-access profiles may carry; a per-caller deployment
    /// gets no ambient view at all, so they are ignored on that branch.
    pub(crate) fn resolve(
        scoped_per_caller: bool,
        workspace_aliases: &[&Path],
        host_home_aliases: &[&Path],
    ) -> Result<Self, HostApiError> {
        if scoped_per_caller {
            return Ok(Self::PerCaller);
        }
        Ok(Self::Shared(ambient_workspace_mount_view(
            MountPermissions::read_write(),
            workspace_aliases,
            host_home_aliases,
        )?))
    }

    /// The workspace view used to mint capability grants and approval lease
    /// terms for a run/gate resolved to `scope`.
    ///
    /// The per-caller permissions match the ambient grant view's
    /// (`read_write`), so turning scoping on narrows *where* a grant points,
    /// never what it may do.
    pub(crate) fn capability_grant_view(
        &self,
        scope: &ResourceScope,
    ) -> Result<MountView, HostApiError> {
        match self {
            Self::Shared(view) => Ok(view.clone()),
            Self::PerCaller => scoped_workspace_mount_view(scope, MountPermissions::read_write()),
            Self::SandboxPerCaller => {
                sandbox_user_workspace_mount_view(scope, MountPermissions::read_write())
            }
        }
    }
}

/// The read-write workspace handle every write lane that lands *bytes* uses:
/// the WebUI attachment/upload seam, the channel-inbound attachment lander, and
/// the C-ATTACH test seam.
///
/// Single owner of this recipe, so the handles cannot drift. Deliberately not
/// the read-only `workspace_filesystem` handle, which backs setup-marker reads
/// and fails closed with `PermissionDenied` on write.
pub(crate) fn read_write_workspace_filesystem(
    extension_filesystem: &Arc<CompositeRootFilesystem>,
    policy: &WorkspaceMountPolicy,
) -> Option<Arc<ScopedFilesystem<CompositeRootFilesystem>>> {
    let permissions = MountPermissions::read_write_list_delete();
    match policy {
        // Per-caller: the resolver runs on every call, so each authenticated
        // caller keys its own `tenants/{tenant}/users/{user}` subtree and the
        // shared `/projects/workspace` root is never exposed for writes.
        WorkspaceMountPolicy::PerCaller => Some(Arc::new(ScopedFilesystem::new(
            Arc::clone(extension_filesystem),
            move |scope| scoped_workspace_mount_view(scope, permissions.clone()),
        ))),
        WorkspaceMountPolicy::SandboxPerCaller => Some(Arc::new(ScopedFilesystem::new(
            Arc::clone(extension_filesystem),
            move |scope| sandbox_user_workspace_mount_view(scope, permissions.clone()),
        ))),
        WorkspaceMountPolicy::Shared(_) => Some(Arc::new(ScopedFilesystem::with_fixed_view(
            Arc::clone(extension_filesystem),
            // silent-ok: the alias-free workspace mount view is built from
            // compile-time constants with no caller input, so the only failure
            // mode is a malformed constant that every other call site would
            // reject at startup. `None` here disables the write lane rather
            // than serving an unscoped one.
            workspace_mount_view(permissions, &[]).ok()?,
        ))),
    }
}

pub(crate) fn scoped_browse_mount_view(scope: &ResourceScope) -> Result<MountView, HostApiError> {
    let memory_target = scoped_memory_target(scope)?;
    MountView::new(vec![
        grant(
            WORKSPACE_ALIAS,
            WORKSPACE_TARGET,
            MountPermissions::read_only(),
        )?,
        grant(
            MEMORY_ALIAS,
            memory_target.as_str(),
            MountPermissions::read_only(),
        )?,
    ])
}

fn scoped_memory_target(scope: &ResourceScope) -> Result<VirtualPath, HostApiError> {
    MemoryDocumentScope::new_with_agent(
        scope.tenant_id.as_str(),
        scope.user_id.as_str(),
        scope.agent_id.as_ref().map(|id| id.as_str()),
        scope.project_id.as_ref().map(|id| id.as_str()),
    )?
    .virtual_prefix()
}

fn grant(
    alias: &str,
    target: &str,
    permissions: MountPermissions,
) -> Result<MountGrant, HostApiError> {
    Ok(MountGrant::new(
        MountAlias::new(alias)?,
        VirtualPath::new(target)?,
        permissions,
    ))
}

fn push_raw_alias_mounts(
    mounts: &mut Vec<MountGrant>,
    aliases: &[&Path],
    target: &str,
    permissions: MountPermissions,
    label: &str,
) -> Result<(), HostApiError> {
    let mut seen_aliases = mounts
        .iter()
        .map(|mount| mount.alias.as_str().to_string())
        .collect::<HashSet<_>>();
    for alias in aliases {
        let Some(alias) = alias.to_str() else {
            return Err(HostApiError::InvalidPath {
                value: format!("<non-utf8-{label}>"),
                reason: format!("{label} must be valid UTF-8"),
            });
        };
        let raw_alias = MountAlias::new(alias.to_string())?;
        if !seen_aliases.insert(raw_alias.as_str().to_string()) {
            continue;
        }
        mounts.push(MountGrant::new(
            raw_alias,
            VirtualPath::new(target)?,
            permissions.clone(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One owner backs every lane that lands workspace *bytes*: the WebUI
    /// attachment handle (`RebornRuntime::webui_workspace_filesystem`), the
    /// production channel-inbound lander in `channel_host_source`, and the
    /// C-ATTACH test seam. Pin that its two branches address different roots,
    /// so no lane can be wired to a shared root while its sibling is scoped.
    #[test]
    fn read_write_workspace_handle_follows_the_deployment_policy() {
        use ironclaw_host_api::{
            ids::{InvocationId, TenantId, UserId},
            path::ScopedPath,
        };

        let scope = ResourceScope {
            tenant_id: TenantId::new("acme").expect("tenant id"),
            user_id: UserId::new("alice").expect("user id"),
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        };
        let path = ScopedPath::new("/workspace/landed.txt").expect("scoped path");
        let backend = Arc::new(CompositeRootFilesystem::default());

        let per_caller =
            read_write_workspace_filesystem(&backend, &WorkspaceMountPolicy::PerCaller)
                .expect("per-caller handle builds");
        let shared = read_write_workspace_filesystem(
            &backend,
            &WorkspaceMountPolicy::Shared(
                workspace_mount_view(MountPermissions::read_write(), &[])
                    .expect("shared view builds"),
            ),
        )
        .expect("shared handle builds");

        assert_eq!(
            per_caller
                .resolve(&scope, &path)
                .expect("per-caller resolve")
                .as_str(),
            "/projects/workspace/tenants/acme/users/alice/landed.txt"
        );
        assert_eq!(
            shared
                .resolve(&scope, &path)
                .expect("shared resolve")
                .as_str(),
            "/projects/workspace/landed.txt"
        );
    }

    #[test]
    fn ambient_workspace_mount_rejects_invalid_workspace_alias() {
        let err = ambient_workspace_mount_view(
            MountPermissions::read_write(),
            &[Path::new(r"C:\Users\alice\project")],
            &[],
        )
        .expect_err("invalid workspace alias should fail loudly");

        assert!(
            err.to_string().contains("backslashes are not allowed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn workspace_mount_rejects_host_home_alias_that_is_not_mount_shaped() {
        let err = workspace_mount_view(
            MountPermissions::read_write(),
            &[Path::new(r"C:\Users\alice")],
        )
        .expect_err("invalid raw alias should fail loudly");

        assert!(
            err.to_string().contains("backslashes are not allowed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn ambient_workspace_mount_deduplicates_workspace_alias_against_canonical_workspace() {
        let mounts = ambient_workspace_mount_view(
            MountPermissions::read_write(),
            &[Path::new(WORKSPACE_ALIAS)],
            &[],
        )
        .expect("mount view builds");

        assert_eq!(
            mounts
                .mounts
                .iter()
                .filter(|mount| mount.alias.as_str() == WORKSPACE_ALIAS)
                .count(),
            1
        );
    }

    #[test]
    fn workspace_mount_deduplicates_normalized_host_home_aliases() {
        let mounts = workspace_mount_view(
            MountPermissions::read_write(),
            &[
                Path::new("/Users/alice"),
                Path::new("/Users/alice/"),
                Path::new("/Users/alice/."),
            ],
        )
        .expect("mount view builds");

        assert_eq!(
            mounts
                .mounts
                .iter()
                .filter(|mount| mount.alias.as_str() == "/Users/alice")
                .count(),
            1
        );
    }

    #[test]
    fn ambient_workspace_mount_includes_raw_workspace_alias() {
        let mounts = ambient_workspace_mount_view(
            MountPermissions::read_write(),
            &[Path::new("/Users/alice/project")],
            &[Path::new("/Users/alice")],
        )
        .expect("mount view builds");

        let mount_for = |alias: &str| {
            mounts
                .mounts
                .iter()
                .find(|mount| mount.alias.as_str() == alias)
                .unwrap_or_else(|| panic!("missing mount alias {alias}"))
        };
        assert_eq!(
            mount_for("/Users/alice/project").target.as_str(),
            WORKSPACE_TARGET
        );
        assert_eq!(mount_for("/Users/alice").target.as_str(), HOST_TARGET);
    }
}
