use std::{path::Path, sync::Arc};

use ironclaw_filesystem::{InMemoryBackend, RootFilesystem};
use ironclaw_host_api::{ids::UserId, path::VirtualPath};

use super::{
    MAX_INSTALL_BUNDLE_FILE_BYTES, SKILL_DISK_IMPORT_MARKER_ROOT, disk_skill_files,
    import_host_disk_skills_into_database, import_host_disk_skills_into_database_with_collector,
    validate_legacy_skill_snapshot_tree,
};

const TENANT: &str = "import-tenant";
const USER: &str = "import-user";

fn owner() -> UserId {
    UserId::new(USER).expect("owner user id")
}

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
    std::fs::write(dir.join("SKILL.md"), b"snapshot skill").expect("skill body");
}

fn database_filesystem() -> Arc<ironclaw_filesystem::CompositeRootFilesystem> {
    crate::filesystem_assembly::production_database_root_filesystem(
        Arc::new(InMemoryBackend::new()),
        "skill-disk-import-async-test",
    )
    .expect("database root filesystem builds")
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_collection_does_not_block_unrelated_executor_work() {
    let filesystem = database_filesystem();
    let (collection_started_tx, collection_started_rx) = tokio::sync::oneshot::channel();
    let (executor_progress_tx, executor_progress_rx) = std::sync::mpsc::sync_channel(1);
    let (release_collection_tx, release_collection_rx) = std::sync::mpsc::sync_channel(1);
    let coordinator = std::thread::spawn(move || {
        // Success is signal-driven. The generous timeout only releases a
        // broken inline implementation instead of deadlocking the suite.
        let executor_progressed = executor_progress_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .is_ok();
        release_collection_tx
            .send(())
            .expect("release snapshot collection");
        executor_progressed
    });
    let progress = tokio::spawn(async move {
        collection_started_rx
            .await
            .expect("snapshot collector reports it started");
        let _ = executor_progress_tx.send(());
    });

    import_host_disk_skills_into_database_with_collector(&filesystem, move |_events| {
        collection_started_tx
            .send(())
            .map_err(|_| crate::RebornBuildError::InvalidConfig {
                reason: "snapshot progress observer dropped".to_string(),
            })?;
        release_collection_rx
            .recv()
            .map_err(|error| crate::RebornBuildError::InvalidConfig {
                reason: format!("wait to release snapshot collection: {error}"),
            })?;
        Ok(())
    })
    .await
    .expect("empty snapshot import succeeds");
    progress.await.expect("executor progress task joins");

    assert!(
        coordinator.join().expect("progress coordinator joins"),
        "snapshot collection blocked the current-thread Tokio executor"
    );
}

#[tokio::test]
async fn snapshot_collection_join_failure_keeps_stage_context() {
    let filesystem = database_filesystem();

    let error = import_host_disk_skills_into_database_with_collector(&filesystem, |_events| {
        panic!("snapshot collector panic");
    })
    .await
    .expect_err("a panicked snapshot collection task must fail startup");

    assert!(
        matches!(
            error,
            crate::RebornBuildError::InvalidConfig { ref reason }
                if reason.contains("legacy skill snapshot collection task failed")
                    && reason.contains("panicked")
        ),
        "{error}"
    );
}

#[tokio::test]
async fn marked_snapshot_file_is_skipped_before_an_oversized_read() {
    let storage = tempfile::tempdir().expect("temp storage root");
    let filesystem = database_filesystem();
    seed_skill_on_disk(storage.path(), "already-marked");
    let selected = storage
        .path()
        .join("tenants")
        .join(TENANT)
        .join("users")
        .join(USER)
        .join("skills/already-marked/SKILL.md");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&selected)
        .expect("open marked snapshot file")
        .set_len((MAX_INSTALL_BUNDLE_FILE_BYTES as u64).saturating_add(1))
        .expect("make marked snapshot file oversized");
    let virtual_path = virtual_skill_path("already-marked");
    let marker = VirtualPath::new(format!(
        "{SKILL_DISK_IMPORT_MARKER_ROOT}{}",
        virtual_path.as_str()
    ))
    .expect("per-skill marker path");
    RootFilesystem::write_file(filesystem.as_ref(), &marker, b"1")
        .await
        .expect("seed per-skill marker");

    import_host_disk_skills_into_database(storage.path(), &owner(), &filesystem)
        .await
        .expect("marked oversized snapshot file is skipped before read");

    assert!(
        RootFilesystem::stat(filesystem.as_ref(), &virtual_path)
            .await
            .is_err(),
        "a marker-covered disk copy must not be re-imported"
    );
}

#[cfg(unix)]
#[test]
fn collected_skill_file_replaced_by_symlink_is_rejected_at_verified_read() {
    use std::os::unix::fs::symlink;

    let storage = tempfile::tempdir().expect("temp storage root");
    seed_skill_on_disk(storage.path(), "replace-before-read");
    let snapshot_root = validate_legacy_skill_snapshot_tree(storage.path())
        .expect("skill snapshot validation retains its root");
    let (selected, _) = disk_skill_files(&storage.path().join("tenants"))
        .expect("skill snapshot collection succeeds")
        .into_iter()
        .next()
        .expect("seeded skill file is collected");
    let outside = storage.path().join("outside.txt");
    std::fs::write(&outside, b"outside bytes").expect("outside file");
    std::fs::remove_file(&selected).expect("remove collected file");
    symlink(&outside, &selected).expect("replace collected file with symlink");

    let relative = selected
        .strip_prefix(storage.path())
        .expect("relative path");
    let error = ironclaw_filesystem::read_ordinary_host_file(
        &snapshot_root,
        relative,
        MAX_INSTALL_BUNDLE_FILE_BYTES,
    )
    .expect_err("verified read must reject the replacement symlink");
    assert!(error.to_string().contains("symlink"), "{error}");
}

#[cfg(unix)]
#[test]
fn collected_skill_directory_replaced_by_symlink_is_rejected_at_verified_read() {
    use std::os::unix::fs::symlink;

    let storage = tempfile::tempdir().expect("temp storage root");
    let outside = tempfile::tempdir().expect("outside snapshot root");
    seed_skill_on_disk(storage.path(), "replace-directory-before-read");
    seed_skill_on_disk(outside.path(), "replace-directory-before-read");
    let snapshot_root = validate_legacy_skill_snapshot_tree(storage.path())
        .expect("skill snapshot validation retains its root");
    let (selected, _) = disk_skill_files(&storage.path().join("tenants"))
        .expect("skill snapshot collection succeeds")
        .into_iter()
        .next()
        .expect("seeded skill file is collected");
    let selected_directory = selected.parent().expect("selected skill directory");
    std::fs::rename(
        selected_directory,
        storage.path().join("retired-skill-directory"),
    )
    .expect("retire validated skill directory");
    let outside_directory = outside
        .path()
        .join("tenants")
        .join(TENANT)
        .join("users")
        .join(USER)
        .join("skills/replace-directory-before-read");
    symlink(&outside_directory, selected_directory)
        .expect("replace validated skill directory with outside symlink");

    let relative = selected
        .strip_prefix(storage.path())
        .expect("relative path");
    let error = ironclaw_filesystem::read_ordinary_host_file(
        &snapshot_root,
        relative,
        MAX_INSTALL_BUNDLE_FILE_BYTES,
    )
    .expect_err("verified read must reject a replaced ancestor directory");
    assert!(
        error.to_string().contains("without following links"),
        "{error}"
    );
}
