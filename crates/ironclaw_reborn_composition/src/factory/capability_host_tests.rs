//! Capability-host factory tests.

use ironclaw_host_api::mount::MountPermissions;

use super::*;
use crate::filesystem_assembly::mount_sandbox_user_workspace_root;

mod approval_gates;

#[tokio::test]
async fn local_yolo_policy_mounts_confirmed_host_home_as_host() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage_root = dir.path().join("standalone");
    let host_home = dir.path().join("home");
    std::fs::create_dir_all(&host_home).expect("host home root");

    let services = build_runtime_substrate(
        crate::deployment::local_filesystem_build_input_with_profile(
            RebornCompositionProfile::StandaloneUnrestricted,
            "standalone-unrestricted-host-owner",
            storage_root,
        )
        .with_runtime_policy(local_yolo_policy())
        .with_local_runtime_confirmed_host_home_root(host_home.clone()),
    )
    .await
    .expect("standalone-unrestricted services build");
    let runtime_surfaces = services
        .local_runtime_for_test()
        .expect("standalone runtime substrate");

    let host_mount = crate::factory::test_support::workspace_mounts_for_test(runtime_surfaces)
        .mounts
        .iter()
        .find(|mount| mount.alias.as_str() == "/host")
        .expect("host mount exists");
    assert_eq!(host_mount.target.as_str(), "/projects/host");
    assert_eq!(host_mount.permissions, MountPermissions::read_write());

    let raw_host_home_alias = host_home
        .canonicalize()
        .expect("canonical host home")
        .to_string_lossy()
        .into_owned();
    let raw_host_home_mount =
        crate::factory::test_support::workspace_mounts_for_test(runtime_surfaces)
            .mounts
            .iter()
            .find(|mount| mount.alias.as_str() == raw_host_home_alias)
            .expect("raw host home mount exists");
    assert_eq!(raw_host_home_mount.target.as_str(), "/projects/host");
    assert_eq!(
        raw_host_home_mount.permissions,
        MountPermissions::read_write()
    );
}

#[tokio::test]
async fn local_yolo_policy_allows_workspace_under_confirmed_host_home() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage_root = dir.path().join("standalone");
    let host_home = dir.path().join("home");
    let workspace_root = host_home.join("repo");
    std::fs::create_dir_all(&workspace_root).expect("workspace root");

    let services = build_runtime_substrate(
        crate::deployment::local_filesystem_build_input_with_profile(
            RebornCompositionProfile::StandaloneUnrestricted,
            "standalone-unrestricted-host-owner",
            storage_root,
        )
        .with_runtime_policy(local_yolo_policy())
        .with_local_runtime_workspace_root(workspace_root)
        .with_local_runtime_confirmed_host_home_root(host_home),
    )
    .await
    .expect("standalone-unrestricted services build");
    let runtime_surfaces = services
        .local_runtime_for_test()
        .expect("standalone runtime substrate");

    let workspace_mount = crate::factory::test_support::workspace_mounts_for_test(runtime_surfaces)
        .mounts
        .iter()
        .find(|mount| mount.alias.as_str() == "/workspace")
        .expect("workspace mount exists");
    assert_eq!(workspace_mount.target.as_str(), "/projects/workspace");
    assert_eq!(workspace_mount.permissions, MountPermissions::read_write());

    let host_mount = crate::factory::test_support::workspace_mounts_for_test(runtime_surfaces)
        .mounts
        .iter()
        .find(|mount| mount.alias.as_str() == "/host")
        .expect("host mount exists");
    assert_eq!(host_mount.target.as_str(), "/projects/host");
    assert_eq!(host_mount.permissions, MountPermissions::read_write());
}

#[cfg(unix)]
#[tokio::test]
async fn local_yolo_policy_keeps_symlinked_host_home_raw_alias() {
    let dir = tempfile::tempdir().expect("tempdir"); // safety: test-only setup in #[cfg(test)] module.
    let storage_root = dir.path().join("standalone");
    let host_home = dir.path().join("home");
    let host_home_link = dir.path().join("home-link");
    std::fs::create_dir_all(&host_home).expect("host home root"); // safety: test-only setup in #[cfg(test)] module.
    std::os::unix::fs::symlink(&host_home, &host_home_link).expect("host home symlink"); // safety: test-only setup in #[cfg(test)] module.

    let services = build_runtime_substrate(
        crate::deployment::local_filesystem_build_input_with_profile(
            RebornCompositionProfile::StandaloneUnrestricted,
            "standalone-unrestricted-host-owner",
            storage_root,
        )
        .with_runtime_policy(local_yolo_policy())
        .with_local_runtime_confirmed_host_home_root(host_home_link.clone()),
    )
    .await
    .expect("standalone-unrestricted services build"); // safety: test-only assertion in #[cfg(test)] module.
    let runtime_surfaces = services
        .local_runtime_for_test()
        .expect("standalone runtime substrate"); // safety: test-only assertion in #[cfg(test)] module.

    let raw_aliases = crate::factory::test_support::workspace_mounts_for_test(runtime_surfaces)
        .mounts
        .iter()
        .map(|mount| mount.alias.as_str())
        .collect::<Vec<_>>();
    let raw_alias_includes_original =
        raw_aliases.contains(&host_home_link.to_str().expect("utf-8 link path")); // safety: temp paths are test-owned.
    assert!(raw_alias_includes_original); // safety: test-only assertion in #[cfg(test)] module.
    let canonical_host_home = host_home
        .canonicalize()
        .expect("canonical home") // safety: test setup created this path.
        .to_str()
        .expect("utf-8 canonical path") // safety: temp paths are test-owned.
        .to_string();
    let raw_alias_includes_canonical = raw_aliases.contains(&canonical_host_home.as_str());
    assert!(raw_alias_includes_canonical); // safety: test-only assertion in #[cfg(test)] module.
}

#[tokio::test]
async fn local_yolo_policy_requires_confirmed_host_home_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let error = build_runtime_substrate(
        crate::deployment::local_filesystem_build_input_with_profile(
            RebornCompositionProfile::StandaloneUnrestricted,
            "standalone-unrestricted-host-owner",
            dir.path().join("standalone"),
        )
        .with_runtime_policy(local_yolo_policy()),
    )
    .await
    .expect_err("host home policy needs confirmed root");

    assert!(format!("{error}").contains("confirmed host home root"));
}

#[tokio::test]
async fn confirmed_host_home_root_is_rejected_without_matching_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let host_home = dir.path().join("home");
    std::fs::create_dir_all(&host_home).expect("host home root");

    let error = build_runtime_substrate(
        crate::deployment::local_filesystem_build_input(
            "standalone-host-owner",
            dir.path().join("standalone"),
        )
        .with_runtime_policy(local_host_policy())
        .with_local_runtime_confirmed_host_home_root(host_home),
    )
    .await
    .expect_err("host home root needs matching policy");

    assert!(format!("{error}").contains("does not allow host home access"));
}

#[tokio::test]
async fn local_yolo_policy_rejects_confirmed_host_home_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let host_home_file = dir.path().join("home-file");
    std::fs::write(&host_home_file, "not a directory").expect("host home file");

    let error = build_runtime_substrate(
        crate::deployment::local_filesystem_build_input_with_profile(
            RebornCompositionProfile::StandaloneUnrestricted,
            "standalone-unrestricted-host-owner",
            dir.path().join("standalone"),
        )
        .with_runtime_policy(local_yolo_policy())
        .with_local_runtime_confirmed_host_home_root(host_home_file),
    )
    .await
    .expect_err("host home root must be a directory");

    assert!(format!("{error}").contains("must be an existing directory"));
}

#[tokio::test]
async fn local_yolo_policy_rejects_confirmed_host_home_filesystem_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let error = build_runtime_substrate(
        crate::deployment::local_filesystem_build_input_with_profile(
            RebornCompositionProfile::StandaloneUnrestricted,
            "standalone-unrestricted-host-owner",
            dir.path().join("standalone"),
        )
        .with_runtime_policy(local_yolo_policy())
        .with_local_runtime_confirmed_host_home_root(filesystem_root()),
    )
    .await
    .expect_err("host home root must not be a filesystem root");

    assert!(format!("{error}").contains("must not be a filesystem root"));
}

fn local_yolo_policy() -> ironclaw_host_api::runtime_policy::EffectiveRuntimePolicy {
    crate::standalone_unrestricted_runtime_policy(true).expect("local-yolo policy resolves") // safety: test-only helper in #[cfg(test)] module.
}

fn local_host_policy() -> ironclaw_host_api::runtime_policy::EffectiveRuntimePolicy {
    crate::standalone_runtime_policy().expect("standalone policy resolves") // safety: test-only helper in #[cfg(test)] module.
}

fn filesystem_root() -> std::path::PathBuf {
    let mut path = std::env::current_dir().expect("current dir"); // safety: test-only helper in #[cfg(test)] module.
    while let Some(parent) = path.parent() {
        path = parent.to_path_buf();
    }
    path
}

/// Stub `SandboxCommandTransport` for sandbox-profile filesystem tests — mirrors
/// `approval_gates::RecordingSandboxTransport`, never invoked here since
/// these tests exercise the filesystem mount, not shell execution.
#[derive(Debug, Default)]
struct NoopSandboxTransport;

#[async_trait::async_trait]
impl ironclaw_host_runtime::SandboxCommandTransport for NoopSandboxTransport {
    async fn run_command(
        &self,
        _request: ironclaw_host_runtime::CommandExecutionRequest,
    ) -> Result<
        ironclaw_host_runtime::CommandExecutionOutput,
        ironclaw_host_runtime::RuntimeProcessError,
    > {
        unimplemented!("workspace-mount tests never execute shell commands")
    }
}

fn user_sandbox_process_binding_for_test() -> RebornRuntimeProcessBinding {
    let process_port = Arc::new(ironclaw_host_runtime::UserSandboxProcessPort::new(
        Arc::new(NoopSandboxTransport),
    ));
    RebornRuntimeProcessBinding::user_sandbox(process_port)
}

#[tokio::test]
async fn sandboxed_profile_workspace_mount_is_per_user_and_shares_bytes_with_host_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage_root = dir.path().join("hosted-sandboxed");

    let services = build_runtime_substrate(
        crate::deployment::local_filesystem_build_input_with_profile(
            RebornCompositionProfile::HostedSingleTenantVolumeSandboxed,
            "sandbox-owner",
            storage_root.clone(),
        )
        .with_runtime_policy(
            crate::hosted_single_tenant_volume_sandboxed_runtime_policy()
                .expect("sandboxed policy resolves"),
        )
        .with_runtime_process_binding(user_sandbox_process_binding_for_test())
        // This test deliberately shares one root for both the plain LocalDev
        // storage and the sandbox-workspaces root (unlike the CLI, which
        // uses `<root>/sandbox-workspaces` for the latter — see
        // `sandboxed_profile_workspace_mount_resolves_the_container_bind_root_not_the_plain_storage_root`
        // below for the CLI-realistic divergent-roots case).
        .with_sandbox_runtime_support_for_test(storage_root.clone()),
    )
    .await
    .expect("hosted-single-tenant-volume-sandboxed services build");
    let local_runtime = services
        .local_runtime_for_test()
        .expect("local-dev runtime substrate");

    let owner_scope_for_grant = default_runtime_owner_scope(
        ironclaw_host_api::ids::UserId::new("sandbox-owner").expect("owner id"),
    )
    .expect("owner scope resolves");
    let workspace_grants = local_runtime
        .workspace_mounts
        .capability_grant_view(&owner_scope_for_grant)
        .expect("sandbox workspace grant resolves for owner");
    let workspace_grant = workspace_grants
        .mounts
        .iter()
        .find(|mount| mount.alias.as_str() == "/workspace")
        .expect("/workspace grant exists for the sandboxed profile");
    // `sandbox_user_workspace_mount_view` deliberately narrows the alias
    // down to the calling scope's own child directory under the shared
    // `/workspace` disk mount `mount_sandbox_user_workspace_root` registers
    // once at boot — not a bare "/workspace" passthrough — so distinct
    // owners' per-invocation grants can never resolve to the same target
    // even though they share one underlying disk mount. The digest-write
    // and digest-read round trip below is exactly what depends on this
    // narrowing actually happening.
    let workspace_digest =
        ironclaw_host_runtime::RebornSandboxUserKey::from_scope(&owner_scope_for_grant)
            .workspace_path(std::path::Path::new(""))
            .strip_prefix("users")
            .expect("workspace_path is always users/<digest>")
            .to_str()
            .expect("digest is valid UTF-8")
            .to_string();
    assert_eq!(
        workspace_grant.target.as_str(),
        format!("/workspace/{workspace_digest}")
    );
    assert_eq!(workspace_grant.permissions, MountPermissions::read_write());

    // `local_runtime.extension_filesystem` is the raw composite root
    // filesystem — the SAME one `mount_sandbox_user_workspace_root` mounts
    // at `/workspace` -> the shared `users` parent, unnarrowed. The
    // per-invocation narrowing down to the caller's own digest subtree
    // happens one layer up, in the `MountView` alias translation
    // `sandbox_user_workspace_mount_view` returns (exercised by the
    // `workspace_grant.target` assertion above and by
    // `hosted_single_tenant_volume_sandboxed_workspace_resolves_per_invocation_scope`
    // in `runtime/local_dev/tests.rs`). Exercising the same alias
    // translation here means writing/reading through the digest-prefixed
    // path directly, matching exactly what the capability dispatch path
    // resolves `/workspace/f.txt` to for this owner.
    // Production never reaches the raw composite mount without first
    // provisioning the caller's own leaf directory —
    // `RefreshingLoopCapabilityPortFactory::create_capability_port`
    // (`runtime/local_dev.rs`) `create_dir_all`s the digest leaf before
    // handing back the narrowed `MountView`. This test drives
    // `extension_filesystem` directly (bypassing that narrowing to exercise
    // the raw mount, per the comment above), so it must reproduce that same
    // provisioning step rather than relying on the pre-fix shared-parent
    // containment root, which happened to tolerate a not-yet-created leaf.
    let owner_scope = default_runtime_owner_scope(
        ironclaw_host_api::ids::UserId::new("sandbox-owner").expect("owner id"),
    )
    .expect("owner scope resolves");
    let canonical_root = storage_root.canonicalize().expect("canonical storage root");
    let host_workspace_dir = ironclaw_host_runtime::RebornSandboxUserKey::from_scope(&owner_scope)
        .workspace_path(&canonical_root);
    std::fs::create_dir_all(&host_workspace_dir).expect("provision caller's own leaf directory");

    let path =
        ironclaw_host_api::path::VirtualPath::new(format!("/workspace/{workspace_digest}/f.txt"))
            .expect("virtual path");
    local_runtime
        .extension_filesystem
        .write_file(&path, b"from-fs-tools")
        .await
        .expect("write through composite /workspace mount");

    assert_eq!(
        std::fs::read(host_workspace_dir.join("f.txt")).expect("host file exists"),
        b"from-fs-tools"
    );

    // reverse: write directly on the host dir (what a shell `echo` inside the
    // container does), read back through the abstract FS /workspace mount
    // via the same digest-prefixed virtual path.
    std::fs::write(host_workspace_dir.join("g.txt"), b"from-shell").expect("host write");
    let bytes = local_runtime
        .extension_filesystem
        .read_file(
            &ironclaw_host_api::path::VirtualPath::new(format!(
                "/workspace/{workspace_digest}/g.txt"
            ))
            .expect("virtual path"),
        )
        .await
        .expect("read through composite /workspace mount");
    assert_eq!(bytes, b"from-shell");
}

/// Pins the CLI-level divergence a hand-constructed-both-sides test cannot
/// catch: `sandboxed_profile_workspace_mount_is_per_user_and_shares_bytes_with_host_dir`
/// above builds the abstract-FS mount AND derives the "host workspace dir"
/// it compares against from the SAME `storage_root` parameter, so it can
/// never observe a real CLI where the `UserSandbox` container bind is
/// rooted at a *different* directory
/// (`<local runtime root>/sandbox-workspaces`,
/// `ironclaw_reborn_cli::runtime::build_sandboxed_local_runtime_services_input`)
/// than the plain LocalDev storage root
/// (`<local runtime root>`) composition's `/workspace` mount used to
/// re-derive `users/` from. This test drives the two roots apart exactly
/// the way the CLI does (`with_sandbox_workspaces_root` set to a `..
/// /sandbox-workspaces` child of the storage root, mirroring
/// `SANDBOX_WORKSPACES_SUBDIR`) and asserts the abstract-FS write lands
/// under the SANDBOX workspaces root (what the container bind uses), never
/// under the plain storage root's `users/` subtree.
#[tokio::test]
async fn sandboxed_profile_workspace_mount_resolves_the_container_bind_root_not_the_plain_storage_root()
 {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage_root = dir.path().join("hosted-sandboxed");
    let sandbox_workspaces_root = storage_root.join("sandbox-workspaces");

    let services = build_runtime_substrate(
        crate::deployment::local_filesystem_build_input_with_profile(
            RebornCompositionProfile::HostedSingleTenantVolumeSandboxed,
            "sandbox-owner",
            storage_root.clone(),
        )
        .with_runtime_policy(
            crate::hosted_single_tenant_volume_sandboxed_runtime_policy()
                .expect("sandboxed policy resolves"),
        )
        .with_runtime_process_binding(user_sandbox_process_binding_for_test())
        .with_sandbox_runtime_support_for_test(sandbox_workspaces_root.clone()),
    )
    .await
    .expect("hosted-single-tenant-volume-sandboxed services build");
    let local_runtime = services
        .local_runtime_for_test()
        .expect("local-dev runtime substrate");

    let owner_scope = default_runtime_owner_scope(
        ironclaw_host_api::ids::UserId::new("sandbox-owner").expect("owner id"),
    )
    .expect("owner scope resolves");
    let workspace_digest = ironclaw_host_runtime::RebornSandboxUserKey::from_scope(&owner_scope)
        .workspace_path(std::path::Path::new(""))
        .strip_prefix("users")
        .expect("workspace_path is always users/<digest>")
        .to_str()
        .expect("digest is valid UTF-8")
        .to_string();

    // Production never reaches the raw composite mount without first
    // provisioning the caller's own leaf directory —
    // `RefreshingLoopCapabilityPortFactory::create_capability_port`
    // (`runtime/local_dev.rs`) `create_dir_all`s the digest leaf before
    // handing back the narrowed `MountView`. This test drives
    // `extension_filesystem` directly (bypassing that narrowing), so it must
    // reproduce that same provisioning step.
    let canonical_sandbox_workspaces_root_for_provisioning = sandbox_workspaces_root
        .canonicalize()
        .expect("canonical sandbox workspaces root (created by the build)");
    let host_workspace_dir_for_provisioning =
        ironclaw_host_runtime::RebornSandboxUserKey::from_scope(&owner_scope)
            .workspace_path(&canonical_sandbox_workspaces_root_for_provisioning);
    std::fs::create_dir_all(&host_workspace_dir_for_provisioning)
        .expect("provision caller's own leaf directory");

    let path =
        ironclaw_host_api::path::VirtualPath::new(format!("/workspace/{workspace_digest}/f.txt"))
            .expect("virtual path");
    local_runtime
        .extension_filesystem
        .write_file(&path, b"from-fs-tools")
        .await
        .expect("write through composite /workspace mount");

    // Must land under the sandbox-workspaces root — the same host tree the
    // `UserSandbox` container bind is rooted at
    // (`RebornSandboxConfig::new(sandbox_workspaces_root)`) — not under
    // `<storage_root>/users`, which is what re-deriving from the plain
    // LocalDev storage root gave before this fix.
    let canonical_sandbox_workspaces_root = sandbox_workspaces_root
        .canonicalize()
        .expect("canonical sandbox workspaces root (created by the build)");
    let container_bind_workspace_dir =
        ironclaw_host_runtime::RebornSandboxUserKey::from_scope(&owner_scope)
            .workspace_path(&canonical_sandbox_workspaces_root);
    assert_eq!(
        std::fs::read(container_bind_workspace_dir.join("f.txt"))
            .expect("file exists under the sandbox-workspaces root the container binds"),
        b"from-fs-tools"
    );

    // And it must NOT have leaked into the plain storage root's `users/`
    // subtree — the divergence this test pins.
    let canonical_storage_root = storage_root
        .canonicalize()
        .expect("canonical storage root (created by the build)");
    let plain_root_workspace_dir =
        ironclaw_host_runtime::RebornSandboxUserKey::from_scope(&owner_scope)
            .workspace_path(&canonical_storage_root);
    assert!(
        !plain_root_workspace_dir.join("f.txt").exists(),
        "abstract-FS write must not leak into the plain storage root's users/ subtree \
         (container bind and abstract-FS mount must resolve the SAME host tree)"
    );
}

#[tokio::test]
async fn sandbox_user_workspace_directories_do_not_overlap_across_owners() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    std::fs::create_dir_all(&root).expect("root");
    let canonical_root = root.canonicalize().expect("canonical root");

    let scope_a = default_runtime_owner_scope(
        ironclaw_host_api::ids::UserId::new("user-a").expect("user id"),
    )
    .expect("owner scope resolves");
    let scope_b = default_runtime_owner_scope(
        ironclaw_host_api::ids::UserId::new("user-b").expect("user id"),
    )
    .expect("owner scope resolves");

    let path_a = ironclaw_host_runtime::RebornSandboxUserKey::from_scope(&scope_a)
        .workspace_path(&canonical_root);
    let path_b = ironclaw_host_runtime::RebornSandboxUserKey::from_scope(&scope_b)
        .workspace_path(&canonical_root);

    assert_ne!(
        path_a, path_b,
        "different owners must not share a workspace directory"
    );
    assert!(
        !path_a.starts_with(&path_b) && !path_b.starts_with(&path_a),
        "one user's workspace directory must not nest inside another's: {path_a:?} vs {path_b:?}"
    );

    // The mount registration itself must fail closed if it were ever pointed
    // at a shared parent instead of the digest leaf: assert mounting user A's
    // path denies access to a file only present under user B's path.
    std::fs::create_dir_all(&path_a).expect("user a dir");
    std::fs::create_dir_all(&path_b).expect("user b dir");
    std::fs::write(path_b.join("secret.txt"), b"user-b-only").expect("user b file");

    let mut composite = CompositeRootFilesystem::new();
    mount_sandbox_user_workspace_root(&mut composite, &path_a).expect("mount user a workspace");
    let escape = composite
        .read_file(
            &ironclaw_host_api::path::VirtualPath::new("/workspace/secret.txt")
                .expect("virtual path"),
        )
        .await;
    assert!(
        escape.is_err(),
        "user A's /workspace mount must not see user B's file"
    );
}

/// Sets up the SHARED-mount shape production actually uses (unlike
/// `sandbox_user_workspace_directories_do_not_overlap_across_owners` above,
/// which mounts each user's own leaf directly): one `mount_sandbox_user_workspace_root`
/// mount at the `users` PARENT, narrowed per invocation to the caller's own
/// digest leaf via `sandbox_user_workspace_mount_view` — exactly what
/// `RefreshingLoopCapabilityPortFactory::create_capability_port`
/// (`runtime/local_dev.rs`) resolves for every capability call. Returns
/// `(TempDir, CompositeRootFilesystem, digest_a, digest_b, path_a, path_b)`
/// with both users' leaf directories created and user B's `secret.txt`
/// written. The `TempDir` must be kept alive by the caller (bind it to a
/// named variable, not `_`) — dropping it deletes the whole backing tree.
async fn shared_sandbox_workspace_mount_with_two_users() -> (
    tempfile::TempDir,
    CompositeRootFilesystem,
    String,
    String,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    std::fs::create_dir_all(&root).expect("root");
    let canonical_root = root.canonicalize().expect("canonical root");
    let users_root = canonical_root.join("users");

    let scope_a = default_runtime_owner_scope(
        ironclaw_host_api::ids::UserId::new("user-a").expect("user id"),
    )
    .expect("owner scope resolves");
    let scope_b = default_runtime_owner_scope(
        ironclaw_host_api::ids::UserId::new("user-b").expect("user id"),
    )
    .expect("owner scope resolves");

    let path_a = ironclaw_host_runtime::RebornSandboxUserKey::from_scope(&scope_a)
        .workspace_path(&canonical_root);
    let path_b = ironclaw_host_runtime::RebornSandboxUserKey::from_scope(&scope_b)
        .workspace_path(&canonical_root);
    std::fs::create_dir_all(&path_a).expect("user a dir");
    std::fs::create_dir_all(&path_b).expect("user b dir");
    std::fs::write(path_b.join("secret.txt"), b"user-b-only").expect("user b secret file");

    let digest_of = |scope: &ironclaw_host_api::resource::ResourceScope| {
        ironclaw_host_runtime::RebornSandboxUserKey::from_scope(scope)
            .workspace_path(std::path::Path::new(""))
            .strip_prefix("users")
            .expect("workspace_path is always users/<digest>")
            .to_str()
            .expect("digest is valid UTF-8")
            .to_string()
    };
    let digest_a = digest_of(&scope_a);
    let digest_b = digest_of(&scope_b);

    let mut composite = CompositeRootFilesystem::new();
    mount_sandbox_user_workspace_root(&mut composite, &users_root)
        .expect("mount shared sandbox users root, production shape");

    (dir, composite, digest_a, digest_b, path_a, path_b)
}

/// THE cross-tenant read escape this module closes: a symlink planted
/// inside user A's own leaf directory (something A's sandboxed shell can do
/// unassisted — `ln -s`) pointing at user B's file. Before the
/// `mount_local_per_leaf` containment fix, `ensure_contained` pinned to the
/// shared `users` parent (`mount.host_root`), so the canonicalized symlink
/// target — which lands inside user B's leaf but still starts with the
/// shared parent — passed containment and the read succeeded with user B's
/// bytes. RED on pre-fix `local.rs` (`ensure_contained` checking
/// `mount.host_root`): this assertion fails because the read returns
/// `Ok(b"user-b-only")` instead of erroring.
#[tokio::test]
async fn sandbox_workspace_shared_mount_rejects_cross_user_symlink_read() {
    let (_dir, composite, digest_a, _digest_b, path_a, path_b) =
        shared_sandbox_workspace_mount_with_two_users().await;

    #[cfg(unix)]
    std::os::unix::fs::symlink(path_b.join("secret.txt"), path_a.join("evil-read"))
        .expect("plant cross-user symlink inside user A's own leaf");

    let escape = composite
        .read_file(
            &ironclaw_host_api::path::VirtualPath::new(format!("/workspace/{digest_a}/evil-read"))
                .expect("virtual path"),
        )
        .await;

    let error = escape.expect_err(
        "user A's per-leaf /workspace mount must reject a symlink resolving into user B's leaf",
    );
    assert!(
        matches!(
            error,
            ironclaw_filesystem::FilesystemError::SymlinkEscape { .. }
        ),
        "expected SymlinkEscape, got: {error:?}"
    );
}

/// Mirrors the read case for `write_file`: `resolve_for_write` is a
/// separate resolution path from `resolve_existing` (it branches on whether
/// the target already exists before canonicalizing), so it needs its own
/// coverage rather than relying on the read test alone. Plants the same
/// cross-user symlink and asserts a write through it is rejected rather than
/// silently overwriting (or reading through, for the CAS check) user B's
/// file.
#[tokio::test]
async fn sandbox_workspace_shared_mount_rejects_cross_user_symlink_write() {
    let (_dir, composite, digest_a, _digest_b, path_a, path_b) =
        shared_sandbox_workspace_mount_with_two_users().await;

    #[cfg(unix)]
    std::os::unix::fs::symlink(path_b.join("secret.txt"), path_a.join("evil-write"))
        .expect("plant cross-user symlink inside user A's own leaf");

    let escape = composite
        .write_file(
            &ironclaw_host_api::path::VirtualPath::new(format!("/workspace/{digest_a}/evil-write"))
                .expect("virtual path"),
            b"clobbered-by-user-a",
        )
        .await;

    let error = escape.expect_err(
        "user A's per-leaf /workspace mount must reject a write through a symlink resolving \
         into user B's leaf",
    );
    assert!(
        matches!(
            error,
            ironclaw_filesystem::FilesystemError::SymlinkEscape { .. }
        ),
        "expected SymlinkEscape, got: {error:?}"
    );
    assert_eq!(
        std::fs::read(path_b.join("secret.txt")).expect("user b file still readable"),
        b"user-b-only",
        "user B's file must be untouched by the rejected write"
    );
}

/// Regression guard for the fix's own containment boundary: an escape past
/// the mount entirely (not into a sibling leaf, but outside `users_root`
/// altogether) must still be rejected exactly as before. Not the bug this
/// module closes (that gap was always correctly caught — see the module
/// doc), but pinned here so the leaf-scoped containment change can't
/// accidentally narrow this case's coverage away.
#[tokio::test]
async fn sandbox_workspace_shared_mount_still_rejects_outside_root_escape() {
    let (_dir, composite, digest_a, _digest_b, path_a, _path_b) =
        shared_sandbox_workspace_mount_with_two_users().await;

    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", path_a.join("evil-outside"))
        .expect("plant outside-root symlink inside user A's own leaf");

    let escape = composite
        .read_file(
            &ironclaw_host_api::path::VirtualPath::new(format!(
                "/workspace/{digest_a}/evil-outside"
            ))
            .expect("virtual path"),
        )
        .await;

    let error = escape.expect_err("an outside-root escape must still be rejected");
    assert!(
        matches!(
            error,
            ironclaw_filesystem::FilesystemError::SymlinkEscape { .. }
        ),
        "expected SymlinkEscape, got: {error:?}"
    );
}
