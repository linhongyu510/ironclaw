use std::path::{Path, PathBuf};

use ironclaw_host_api::ids::UserId;

use crate::RebornBuildError;
use crate::root::default_system_prompt::seed_default_system_prompt;

const DEFAULT_SYSTEM_PROMPT_PATH: &str = "prompts/default-system.md";
#[cfg(all(test, unix))]
pub(crate) use ironclaw_extension_host::bundled_skills::LEGACY_SKILLS_BACKFILL_MARKER;
#[cfg(test)]
const STANDALONE_LEGACY_SKILL_TENANTS: [&str; 2] = ["default", "reborn-cli"];

/// Apply the legacy standalone skill-tree migration to every tenant identity
/// this standalone host profile supports.
#[cfg(test)]
pub(crate) fn backfill_legacy_user_skills(
    storage_root: &Path,
    owner_user_id: &UserId,
) -> Result<(), RebornBuildError> {
    let legacy_root = storage_root.join("skills");
    for tenant_id in STANDALONE_LEGACY_SKILL_TENANTS {
        let scoped_root = storage_root
            .join("tenants")
            .join(tenant_id)
            .join("users")
            .join(owner_user_id.as_str())
            .join("skills");
        ironclaw_extension_host::bundled_skills::backfill_legacy_skill_tree(
            &legacy_root,
            &scoped_root,
        )?;
    }
    Ok(())
}

/// Move host-disk user skills into the database-backed tree, which is the only tree skills are read
/// from now.
///
/// Two populations need this, and both are silent without it:
///
/// * The legacy backfill above writes to `storage_root/tenants/<t>/users/<u>/skills` on the HOST DISK.
///   Nothing reads that path any more, so a user upgrading with legacy skills would find them gone.
/// * Every skill an agent installed before this change also went to that disk path, because the
///   agent's in-run skill port wrote there while Settings → Skills listed the database — the mount
///   split that is nearai/ironclaw#7168. Those skills are real, the user created them, and an upgrade
///   must not silently drop them.
///
/// Copies rather than moves, so a downgrade is not destructive, and an existing database entry
/// always wins.
///
/// Runs once PER SKILL, gated on a marker under [`SKILL_DISK_IMPORT_MARKER_ROOT`]. "Existing entry
/// wins" is not enough on its own: the disk copy stays behind, so a skill the user REMOVED would be
/// absent at the next boot and get copied straight back. A marker makes this a migration rather than
/// a standing sync.
///
/// Keyed per skill, not once for the whole store. A single store-wide marker made the import a
/// one-time event, so a skill dropped into the store after the first boot was never copied across —
/// and since skills read only from the database, it stayed invisible permanently, the marker
/// outliving every restart. Per skill, one that appears later is picked up on the next boot while
/// migrated ones stay migrated.
///
/// Markers live under `/system/settings`, database-backed on every shape, so they travel with the
/// store rather than the boot directory.
const SKILL_DISK_IMPORT_MARKER_ROOT: &str = "/system/settings/skill-disk-import";

/// Record that one disk skill has been migrated. Never fatal: a missing marker costs one repeated
/// import attempt, which "existing entry wins" already absorbs; a failed boot costs the runtime.
async fn record_skill_disk_import(
    filesystem: &ironclaw_filesystem::CompositeRootFilesystem,
    marker: &ironclaw_host_api::path::VirtualPath,
) {
    use ironclaw_filesystem::RootFilesystem;
    if let Err(error) = RootFilesystem::write_file(filesystem, marker, b"1").await {
        tracing::debug!(
            %error,
            marker = marker.as_str(),
            "could not record a skill disk-import marker; the import will be retried next boot"
        );
    }
}

pub(crate) async fn import_host_disk_skills_into_database(
    storage_root: &Path,
    filesystem: &std::sync::Arc<ironclaw_filesystem::CompositeRootFilesystem>,
) -> Result<(), RebornBuildError> {
    use ironclaw_filesystem::RootFilesystem;
    use ironclaw_host_api::path::VirtualPath;

    validate_legacy_skill_snapshot_tree(storage_root)?;
    let tenants_root = storage_root.join("tenants");
    let mut imported = 0usize;
    for (host_path, virtual_path) in disk_skill_files(&tenants_root)? {
        let target = VirtualPath::new(&virtual_path)?;
        let marker = VirtualPath::new(format!("{SKILL_DISK_IMPORT_MARKER_ROOT}{virtual_path}"))?;
        // Already migrated. Re-reading the disk copy here resurrects a skill the user has deleted.
        if RootFilesystem::stat(filesystem.as_ref(), &marker)
            .await
            .is_ok()
        {
            continue;
        }
        // A database entry wins: it is either newer or the product of a previous import.
        if RootFilesystem::stat(filesystem.as_ref(), &target)
            .await
            .is_ok()
        {
            record_skill_disk_import(filesystem, &marker).await;
            continue;
        }
        let Ok(bytes) = std::fs::read(&host_path) else {
            continue;
        };
        if RootFilesystem::write_file(filesystem.as_ref(), &target, &bytes)
            .await
            .is_ok()
        {
            record_skill_disk_import(filesystem, &marker).await;
            imported += 1;
        }
    }
    if imported > 0 {
        tracing::info!(
            imported,
            "imported host-disk skills into the database-backed skill tree"
        );
    }
    Ok(())
}

/// Every file under `tenants/<tenant>/users/<user>/skills/**`, paired with its database path.
///
/// Walks only that shape, so nothing else under `tenants/` is copied into the skill tree.
fn disk_skill_files(tenants_root: &Path) -> Result<Vec<(PathBuf, String)>, RebornBuildError> {
    let mut found = Vec::new();
    let tenants = match std::fs::read_dir(tenants_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        Err(error) => {
            return Err(snapshot_io_error(
                "read tenants directory",
                tenants_root,
                error,
            ));
        }
    };
    for tenant in tenants {
        let tenant = tenant.map_err(|error| {
            snapshot_io_error("read tenant directory entry", tenants_root, error)
        })?;
        let tenant_id = tenant.file_name().to_string_lossy().to_string();
        let users_root = tenant.path().join("users");
        let users = match std::fs::read_dir(&users_root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(snapshot_io_error(
                    "read users directory",
                    &users_root,
                    error,
                ));
            }
        };
        for user in users {
            let user = user.map_err(|error| {
                snapshot_io_error("read user directory entry", &users_root, error)
            })?;
            let user_id = user.file_name().to_string_lossy().to_string();
            let skills_root = user.path().join("skills");
            collect_files_under(&skills_root, &skills_root, &mut |relative, host_path| {
                found.push((
                    host_path.to_path_buf(),
                    format!("/tenants/{tenant_id}/users/{user_id}/skills/{relative}"),
                ));
            })?;
        }
    }
    Ok(found)
}

fn collect_files_under(
    base: &Path,
    dir: &Path,
    visit: &mut impl FnMut(String, &Path),
) -> Result<(), RebornBuildError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(snapshot_io_error("read skill directory", dir, error)),
    };
    for entry in entries {
        let entry =
            entry.map_err(|error| snapshot_io_error("read skill directory entry", dir, error))?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| snapshot_io_error("inspect skill snapshot entry", &path, error))?;
        if metadata.file_type().is_symlink() {
            return Err(snapshot_symlink_error(&path));
        }
        if metadata.is_dir() {
            collect_files_under(base, &path, visit)?;
        } else if metadata.is_file()
            && let Ok(relative) = path.strip_prefix(base)
        {
            // Forward slashes: this becomes a VirtualPath, not a host path.
            let relative = relative
                .components()
                .map(|component| component.as_os_str().to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("/");
            visit(relative, &path);
        }
    }
    Ok(())
}

/// Rejects every symlink in a completed legacy snapshot before any host file is read.
///
/// The migration source is an operator-selected legacy tree, so following even one entry would
/// allow a snapshot to import data from outside that tree. The later shape-specific walker repeats
/// the no-follow check while it reads the selected `skills` paths.
fn validate_legacy_skill_snapshot_tree(storage_root: &Path) -> Result<(), RebornBuildError> {
    validate_legacy_skill_snapshot_entry(storage_root)
}

fn validate_legacy_skill_snapshot_entry(path: &Path) -> Result<(), RebornBuildError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| snapshot_io_error("inspect legacy skill snapshot", path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(snapshot_symlink_error(path));
    }
    if metadata.is_file() {
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(RebornBuildError::InvalidConfig {
            reason: format!(
                "legacy skill snapshot entry is neither a regular file nor directory: {}",
                path.display()
            ),
        });
    }
    let entries = std::fs::read_dir(path)
        .map_err(|error| snapshot_io_error("read legacy skill snapshot directory", path, error))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            snapshot_io_error("read legacy skill snapshot directory entry", path, error)
        })?;
        validate_legacy_skill_snapshot_entry(&entry.path())?;
    }
    Ok(())
}

fn snapshot_symlink_error(path: &Path) -> RebornBuildError {
    RebornBuildError::InvalidConfig {
        reason: format!(
            "legacy skill snapshot must not contain symlinks: {}",
            path.display()
        ),
    }
}

fn snapshot_io_error(context: &str, path: &Path, error: std::io::Error) -> RebornBuildError {
    RebornBuildError::InvalidConfig {
        reason: format!("failed to {context} at {}: {error}", path.display()),
    }
}

/// Initializes standalone host content after storage roots are prepared.
pub(crate) async fn bootstrap_standalone_host(
    system_root: &Path,
    _owner_user_id: &UserId,
) -> Result<PathBuf, RebornBuildError> {
    let default_system_prompt_path = system_root.join(DEFAULT_SYSTEM_PROMPT_PATH);
    seed_default_system_prompt(system_root, &default_system_prompt_path).map_err(|error| {
        RebornBuildError::InvalidConfig {
            reason: error.to_string(),
        }
    })?;
    ironclaw_extension_host::bundled_skills::ensure_bundled_reborn_skills_installed_at_system_skills_root(
        &system_root.join("skills"),
    )
    .await?;

    Ok(default_system_prompt_path)
}

#[cfg(test)]
mod bootstrap_tests {
    use ironclaw_host_api::ids::UserId;

    use super::bootstrap_standalone_host;

    #[tokio::test]
    async fn bundled_skills_install_at_the_exact_system_skills_root() {
        let root = tempfile::tempdir().expect("tempdir");
        let system_root = root.path().join("system");
        let owner = UserId::new("bootstrap-owner").expect("valid owner");
        std::fs::create_dir_all(system_root.join("prompts"))
            .expect("host-access system prompt root");

        bootstrap_standalone_host(&system_root, &owner)
            .await
            .expect("standalone bootstrap succeeds");

        assert!(
            system_root.join("skills/code-review/SKILL.md").is_file(),
            "bundled skills must be installed under system/skills"
        );
        assert!(
            !system_root.join("system").exists(),
            "an exact system root must never be interpreted as an installation root"
        );
    }
}

#[cfg(test)]
mod skill_disk_import_tests {
    use std::path::Path;
    use std::sync::Arc;

    use ironclaw_filesystem::{InMemoryBackend, RootFilesystem};
    use ironclaw_host_api::path::VirtualPath;

    use super::import_host_disk_skills_into_database;

    const TENANT: &str = "import-tenant";
    const USER: &str = "import-user";

    fn virtual_skill_path(name: &str) -> VirtualPath {
        VirtualPath::new(format!(
            "/tenants/{TENANT}/users/{USER}/skills/{name}/SKILL.md"
        ))
        .expect("virtual skill path")
    }

    fn seed_skill_on_disk(storage_root: &Path, name: &str) {
        let dir = storage_root
            .join("tenants")
            .join(TENANT)
            .join("users")
            .join(USER)
            .join("skills")
            .join(name);
        std::fs::create_dir_all(&dir).expect("skill dir");
        std::fs::write(
            dir.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: {name}\n---\n\nbody\n"),
        )
        .expect("skill body");
    }

    fn database_filesystem() -> Arc<ironclaw_filesystem::CompositeRootFilesystem> {
        crate::filesystem_assembly::production_database_root_filesystem(
            Arc::new(InMemoryBackend::new()),
            "skill-disk-import-test",
        )
        .expect("database root filesystem builds")
    }

    /// A skill dropped into the store AFTER the first boot must still be imported.
    ///
    /// The import was gated on one marker for the whole store, so it ran exactly once ever. Since
    /// skills now read only from the database, anything that appeared on disk later was never
    /// copied across and stayed invisible — permanently, because the marker survives restarts.
    #[tokio::test]
    async fn a_skill_appearing_on_disk_after_the_first_import_is_still_imported() {
        let storage = tempfile::tempdir().expect("temp storage root");
        let filesystem = database_filesystem();

        seed_skill_on_disk(storage.path(), "first");
        import_host_disk_skills_into_database(storage.path(), &filesystem)
            .await
            .expect("first import runs");

        seed_skill_on_disk(storage.path(), "second");
        import_host_disk_skills_into_database(storage.path(), &filesystem)
            .await
            .expect("second import runs");

        assert!(
            RootFilesystem::stat(filesystem.as_ref(), &virtual_skill_path("second"))
                .await
                .is_ok(),
            "a skill added to the store after the first import must be imported on the next boot; \
             leaving it on disk makes it unreachable, because skills are read only from the database"
        );
    }

    /// ...but re-running the import must NOT undo a deletion.
    ///
    /// This is the reason the marker existed. The disk copy stays behind when a user removes a
    /// skill through the product, so an import that only checks "is it already in the database?"
    /// copies it straight back. Per-skill markers keep the migration one-shot PER SKILL, which is
    /// what lets the test above pass without resurrecting anything.
    #[tokio::test]
    async fn an_imported_skill_deleted_from_the_database_is_not_resurrected() {
        let storage = tempfile::tempdir().expect("temp storage root");
        let filesystem = database_filesystem();

        seed_skill_on_disk(storage.path(), "removed-later");
        import_host_disk_skills_into_database(storage.path(), &filesystem)
            .await
            .expect("first import runs");

        let path = virtual_skill_path("removed-later");
        RootFilesystem::delete(filesystem.as_ref(), &path)
            .await
            .expect("user deletes the skill through the product");

        import_host_disk_skills_into_database(storage.path(), &filesystem)
            .await
            .expect("second import runs");

        assert!(
            RootFilesystem::stat(filesystem.as_ref(), &path)
                .await
                .is_err(),
            "a skill the user deleted must stay deleted; the disk copy outlives the deletion, so an \
             import that re-reads it resurrects a skill the user removed"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_skill_snapshot_import_rejects_a_symlinked_snapshot_root() {
        use std::os::unix::fs::symlink;

        let storage = tempfile::tempdir().expect("temp storage root");
        let outside = tempfile::tempdir().expect("outside snapshot root");
        let filesystem = database_filesystem();
        seed_skill_on_disk(outside.path(), "escaped-root");
        let snapshot_alias = storage.path().join("snapshot");
        symlink(outside.path(), &snapshot_alias).expect("snapshot alias");

        let error = import_host_disk_skills_into_database(&snapshot_alias, &filesystem)
            .await
            .expect_err("a legacy snapshot root symlink must fail closed");

        assert!(error.to_string().contains("symlink"), "{error}");
        assert!(
            RootFilesystem::stat(filesystem.as_ref(), &virtual_skill_path("escaped-root"))
                .await
                .is_err(),
            "a rejected snapshot must not import an outside skill"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_skill_snapshot_import_rejects_a_symlinked_subtree() {
        use std::os::unix::fs::symlink;

        let storage = tempfile::tempdir().expect("temp storage root");
        let outside = tempfile::tempdir().expect("outside skill subtree");
        let filesystem = database_filesystem();
        seed_skill_on_disk(outside.path(), "escaped-subtree");
        let skills_root = storage
            .path()
            .join("tenants")
            .join(TENANT)
            .join("users")
            .join(USER)
            .join("skills");
        std::fs::create_dir_all(&skills_root).expect("skills root");
        let outside_skill = outside
            .path()
            .join("tenants")
            .join(TENANT)
            .join("users")
            .join(USER)
            .join("skills")
            .join("escaped-subtree");
        symlink(&outside_skill, skills_root.join("linked")).expect("skill subtree symlink");

        let error = import_host_disk_skills_into_database(storage.path(), &filesystem)
            .await
            .expect_err("a legacy snapshot subtree symlink must fail closed");

        assert!(error.to_string().contains("symlink"), "{error}");
        assert!(
            RootFilesystem::stat(filesystem.as_ref(), &virtual_skill_path("linked"))
                .await
                .is_err(),
            "a rejected snapshot must not import an outside subtree"
        );
    }
}
