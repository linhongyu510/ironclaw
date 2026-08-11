use super::*;

#[cfg(unix)]
#[test]
fn symlinked_legacy_database_is_rejected_without_source_mutation() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    fs::create_dir_all(&legacy).expect("legacy root");
    let external = temp.path().join("outside.db");
    fs::write(&external, b"outside").expect("external database");
    symlink(&external, legacy.join("reborn-local-dev.db")).expect("legacy symlink");

    let error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect_err("symlink must not be followed");

    assert!(error.to_string().contains("non-symlink file"));
    assert!(legacy.join("reborn-local-dev.db").is_symlink());
    assert!(
        !temp
            .path()
            .join("runtime/layout-adoption/journal.toml")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn adoption_rejects_a_symlinked_runtime_ancestor_before_any_write() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let outside = temp.path().join("outside-runtime");
    fs::create_dir(&outside).expect("outside runtime");
    symlink(&outside, temp.path().join("runtime")).expect("runtime symlink");

    let error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect_err("runtime symlink must not be followed");

    assert!(
        format!("{error:#}").contains("ordinary non-symlink directory"),
        "{error:#}"
    );
    assert!(legacy.join("reborn-local-dev.db").is_file());
    assert!(
        fs::read_dir(&outside)
            .expect("outside remains readable")
            .next()
            .is_none(),
        "adoption must not create runtime artifacts through a symlink"
    );
}

#[cfg(unix)]
#[test]
fn recovery_rejects_a_symlinked_snapshot_ancestor_before_source_mutation() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let paths = RebornStoragePaths::from_home(&home);
    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    fs::create_dir_all(&adoption_root).expect("adoption root");
    let candidates = inspect_legacy_candidates(temp.path()).expect("inspect source");
    let candidate = candidates.first().expect("one candidate");
    let journal = AdoptionJournal::new(candidate, requirement, None);
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal");
    let outside = temp.path().join("outside-snapshots");
    fs::create_dir(&outside).expect("outside snapshots");
    symlink(&outside, adoption_root.join("snapshot")).expect("snapshot symlink");

    let error = adopt_layout(&home, requirement, confirmed_options())
        .expect_err("snapshot symlink must not be followed during recovery");

    assert!(
        format!("{error:#}").contains("ordinary non-symlink directory"),
        "{error:#}"
    );
    assert!(legacy.join("reborn-local-dev.db").is_file());
    assert!(
        fs::read_dir(&outside)
            .expect("outside remains readable")
            .next()
            .is_none(),
        "recovery must not snapshot through a symlink"
    );
}

#[cfg(unix)]
#[test]
fn recovery_rejects_a_symlinked_snapshot_leaf_before_inventory_read() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let paths = RebornStoragePaths::from_home(&home);
    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    fs::create_dir_all(&adoption_root).expect("adoption root");
    let candidates = inspect_legacy_candidates(temp.path()).expect("inspect source");
    let candidate = candidates.first().expect("one candidate");
    let snapshot = candidate.snapshot_root(&adoption_root);
    snapshot_source(candidate, &snapshot).expect("snapshot source");
    let preserved_snapshot = temp.path().join("preserved-snapshot");
    fs::rename(&snapshot, &preserved_snapshot).expect("preserve real snapshot");
    let outside = temp.path().join("outside-snapshot");
    fs::create_dir(&outside).expect("outside snapshot");
    symlink(&outside, &snapshot).expect("snapshot leaf symlink");
    let mut journal = AdoptionJournal::new(candidate, requirement, None);
    journal.phase = AdoptionPhase::SnapshotOwned;
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal");

    let error = adopt_layout(&home, requirement, confirmed_options())
        .expect_err("snapshot leaf symlink must be rejected before inventory traversal");

    assert!(
        format!("{error:#}").contains("ordinary non-symlink directory"),
        "{error:#}"
    );
    assert!(
        fs::read_dir(&outside)
            .expect("outside remains readable")
            .next()
            .is_none(),
        "recovery must not traverse a symlinked snapshot leaf"
    );
    assert!(preserved_snapshot.join("reborn-local-dev.db").is_file());
}

#[cfg(unix)]
#[test]
fn replay_rejects_a_swapped_symlinked_staging_child_before_install() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let paths = RebornStoragePaths::from_home(&home);
    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    fs::create_dir_all(&adoption_root).expect("adoption root");
    let candidates = inspect_legacy_candidates(temp.path()).expect("inspect source");
    let candidate = candidates.first().expect("one candidate");
    let snapshot = candidate.snapshot_root(&adoption_root);
    snapshot_source(candidate, &snapshot).expect("snapshot source");
    let staging = adoption_root.join("staging");
    fs::create_dir(&staging).expect("staging root");
    let outside = temp.path().join("outside-state");
    fs::create_dir(&outside).expect("outside state");
    symlink(&outside, staging.join("state")).expect("swapped staging state");
    fs::create_dir(staging.join("system")).expect("staging system");
    let mut journal = AdoptionJournal::new(candidate, requirement, None);
    fs::write(staging.join(STAGING_OWNER_FILE), &journal.operation_id)
        .expect("journal-owned staging marker");
    journal.phase = AdoptionPhase::Staged;
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal");

    let error = adopt_layout(&home, requirement, confirmed_options())
        .expect_err("replay must reject a swapped symlink before rename");

    assert!(
        format!("{error:#}").contains("ordinary non-symlink directory"),
        "{error:#}"
    );
    assert!(
        fs::read_dir(&outside)
            .expect("outside remains readable")
            .next()
            .is_none(),
        "staged replay must not write through a swapped child"
    );
    assert!(!temp.path().join("state").exists());
    assert!(!temp.path().join("layout.toml").exists());
}
