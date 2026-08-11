use super::*;

#[test]
fn store_verified_replay_revalidates_exact_canonical_inventory_before_manifest() {
    for mutation in ["delete-db", "substitute-db"] {
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
        let mut journal = AdoptionJournal::new(candidate, requirement, None);
        snapshot_source(candidate, &snapshot).expect("snapshot source");
        stage_snapshot(
            candidate,
            &snapshot,
            &adoption_root,
            None,
            &journal.operation_id,
        )
        .expect("stage snapshot");
        install_staged(&paths, &adoption_root, None).expect("install staged content");
        verify_canonical_store(
            &paths,
            DurableStateKind::EmbeddedLibSql,
            CanonicalStoreVerification::EmbeddedLibSql,
        )
        .expect("verify canonical store");
        journal.phase = AdoptionPhase::StoreVerified;
        write_journal(&adoption_root.join("journal.toml"), &journal).expect("store verified");

        let database = temp.path().join("state/reborn-local-dev.db");
        match mutation {
            "delete-db" => fs::remove_file(&database).expect("delete canonical database"),
            "substitute-db" => fs::write(&database, b"substituted database")
                .expect("substitute canonical database"),
            _ => unreachable!("exhaustive mutation"),
        }

        let error = adopt_layout(&home, requirement, confirmed_options())
            .expect_err("a StoreVerified replay must not publish a stale manifest");

        let diagnostic = format!("{error:#}");
        match mutation {
            "delete-db" => assert!(
                diagnostic.contains("inspect file"),
                "{mutation}: {diagnostic}"
            ),
            "substitute-db" => assert!(
                diagnostic.contains("canonical") || diagnostic.contains("libSQL"),
                "{mutation}: {diagnostic}"
            ),
            _ => unreachable!("exhaustive mutation"),
        }
        assert!(
            !temp.path().join("layout.toml").exists(),
            "{mutation}: manifest remains unpublished"
        );
    }
}

#[test]
fn migration_pending_recovery_accepts_a_real_post_copy_libsql_write() {
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
    let journal = AdoptionJournal::new(candidate, requirement, None);
    snapshot_source(candidate, &snapshot).expect("snapshot source");
    stage_snapshot(
        candidate,
        &snapshot,
        &adoption_root,
        None,
        &journal.operation_id,
    )
    .expect("stage snapshot");
    install_staged(&paths, &adoption_root, None).expect("install staged content");

    crate::runtime::block_on_cli({
        let state_root = paths.state_root().to_path_buf();
        async move {
            let store = ironclaw_composition::open_standalone_secret_store(&state_root)
                .await
                .map_err(|error| anyhow::anyhow!(error))?;
            ironclaw_operator::LlmKeyStore::new(
                ironclaw_composition::RuntimeOperatorSecretValueStore::shared(store),
            )
            .put(
                "migration-proof",
                ironclaw_secrets::SecretMaterial::from("post-copy-write"),
            )
            .await
            .map_err(|error| anyhow::anyhow!(error))
        }
    })
    .expect("real post-copy store write");

    let journal = toml::to_string(&journal)
        .expect("serialize journal")
        .replace("phase = \"prepare\"", "phase = \"migration-pending\"");
    fs::write(adoption_root.join("journal.toml"), journal).expect("migration-pending journal");

    adopt_layout(&home, requirement, confirmed_options())
        .expect("post-copy store writes must not be byte-compared to the snapshot");

    assert!(temp.path().join("layout.toml").is_file());
}

#[test]
fn migration_pending_recovery_allows_a_pre_copy_sidecar_to_disappear() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let sidecar = legacy.join("reborn-local-dev.db-wal");
    fs::write(&sidecar, b"legacy sidecar").expect("legacy sidecar");
    let paths = RebornStoragePaths::from_home(&home);
    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    fs::create_dir_all(&adoption_root).expect("adoption root");
    let candidates = inspect_legacy_candidates(temp.path()).expect("inspect source");
    let candidate = candidates.first().expect("one candidate");
    let snapshot = candidate.snapshot_root(&adoption_root);
    let mut journal = AdoptionJournal::new(candidate, requirement, None);
    snapshot_source(candidate, &snapshot).expect("snapshot source");
    stage_snapshot(
        candidate,
        &snapshot,
        &adoption_root,
        None,
        &journal.operation_id,
    )
    .expect("stage snapshot");
    install_staged(&paths, &adoption_root, None).expect("install staged content");
    fs::remove_file(paths.state_root().join("reborn-local-dev.db-wal"))
        .expect("simulate checkpoint removing sidecar");
    journal.phase = AdoptionPhase::MigrationPending;
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("migration journal");

    adopt_layout(&home, requirement, confirmed_options())
        .expect("post-migration validation permits an optional sidecar to disappear");

    assert!(temp.path().join("state/reborn-local-dev.db").is_file());
    assert!(!temp.path().join("state/reborn-local-dev.db-wal").exists());
    assert!(temp.path().join("layout.toml").is_file());
}

#[test]
fn recovery_never_deletes_unproven_canonical_content() {
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
    let mut journal = AdoptionJournal::new(candidate, requirement, None);
    snapshot_source(candidate, &snapshot).expect("snapshot source");
    stage_snapshot(
        candidate,
        &snapshot,
        &adoption_root,
        None,
        &journal.operation_id,
    )
    .expect("stage snapshot");
    install_staged(&paths, &adoption_root, None).expect("install staged content");
    journal.phase = AdoptionPhase::CanonicalInstalled;
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal phase");
    let sentinel = temp.path().join("state/operator-sentinel");
    fs::write(&sentinel, b"never delete this").expect("sentinel");

    let error = adopt_layout(&home, requirement, confirmed_options())
        .expect_err("recovery must fail closed instead of deleting canonical content");

    assert!(error.to_string().contains("canonical"));
    assert_eq!(
        fs::read(&sentinel).expect("sentinel retained"),
        b"never delete this"
    );
    assert!(!temp.path().join("layout.toml").exists());
}

#[test]
fn staged_recovery_finishes_after_a_crash_between_state_and_system_renames() {
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
    let mut journal = AdoptionJournal::new(candidate, requirement, None);
    snapshot_source(candidate, &snapshot).expect("snapshot source");
    stage_snapshot(
        candidate,
        &snapshot,
        &adoption_root,
        None,
        &journal.operation_id,
    )
    .expect("stage snapshot");
    fs::rename(adoption_root.join("staging/state"), paths.state_root())
        .expect("simulate crash after state rename");
    journal.phase = AdoptionPhase::Staged;
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal");

    adopt_layout(&home, requirement, confirmed_options())
        .expect("recovery finishes the remaining system rename");

    assert!(temp.path().join("state/reborn-local-dev.db").is_file());
    assert!(temp.path().join("system").is_dir());
    assert!(temp.path().join("layout.toml").is_file());
}

#[test]
fn snapshot_owned_recovery_discards_only_marker_proven_partial_staging() {
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
    fs::write(
        staging.join(".adoption-owner"),
        b"00000000-0000-4000-8000-000000000001",
    )
    .expect("staging owner marker");
    fs::create_dir(staging.join("state")).expect("partial staged state");
    fs::copy(
        snapshot.join("reborn-local-dev.db"),
        staging.join("state/reborn-local-dev.db"),
    )
    .expect("first staged copy");
    let mut journal = AdoptionJournal::new(candidate, requirement, None);
    journal.phase = AdoptionPhase::SnapshotOwned;
    let journal_contents = toml::to_string(&journal).expect("serialize journal");
    let mut journal: toml::Value = toml::from_str(&journal_contents).expect("journal TOML");
    journal.as_table_mut().expect("journal table").insert(
        "operation_id".into(),
        toml::Value::String("00000000-0000-4000-8000-000000000001".into()),
    );
    fs::write(
        adoption_root.join("journal.toml"),
        toml::to_string(&journal).expect("journal with owner"),
    )
    .expect("journal");

    adopt_layout(&home, requirement, confirmed_options())
        .expect("proven partial staging is discarded and copied again");

    assert!(temp.path().join("state/reborn-local-dev.db").is_file());
    assert!(
        temp.path()
            .join("state/.reborn-local-dev-secrets-master-key")
            .is_file()
    );
    assert!(temp.path().join("layout.toml").is_file());
}

#[test]
fn snapshot_owned_recovery_discards_only_an_empty_premark_staging_root() {
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
    fs::create_dir(adoption_root.join("staging")).expect("empty pre-marker staging root");
    let mut journal = AdoptionJournal::new(candidate, requirement, None);
    journal.phase = AdoptionPhase::SnapshotOwned;
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal");

    adopt_layout(&home, requirement, confirmed_options())
        .expect("empty pre-marker staging root is safe to discard and recopy");

    assert!(temp.path().join("layout.toml").is_file());
}

#[test]
fn enospc_style_copy_failure_recovers_from_journal_proven_partial_staging() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);

    let fault = TestAdoptionFaultGuard::arm(TestAdoptionFaultPoint::FirstStateCopy);
    let error = adopt_layout(&home, requirement, confirmed_options())
        .expect_err("injected ENOSPC-style copy failure");
    drop(fault);

    assert!(format!("{error:#}").contains("ENOSPC-style"));
    assert!(
        temp.path()
            .join("runtime/layout-adoption/staging/.adoption-owner")
            .is_file()
    );
    assert!(!temp.path().join("state").exists());

    adopt_layout(&home, requirement, confirmed_options())
        .expect("recovery discards only the proven staging tree and recopies");
    assert!(temp.path().join("layout.toml").is_file());
}

#[test]
fn fault_after_staging_children_recovers_with_preexisting_owner_proof() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);

    let fault = TestAdoptionFaultGuard::arm(TestAdoptionFaultPoint::StagingChildrenCreated);
    let error = adopt_layout(&home, requirement, confirmed_options())
        .expect_err("injected crash after staging child creation");
    drop(fault);

    assert!(format!("{error:#}").contains("StagingChildrenCreated"));
    assert!(
        temp.path()
            .join("runtime/layout-adoption/staging/.adoption-owner")
            .is_file(),
        "ownership proof is durable before staging children exist"
    );
    assert!(
        temp.path()
            .join("runtime/layout-adoption/staging/state")
            .is_dir()
    );
    assert!(
        temp.path()
            .join("runtime/layout-adoption/staging/system")
            .is_dir()
    );

    adopt_layout(&home, requirement, confirmed_options())
        .expect("SnapshotOwned recovery discards the proven partial staging tree");
    assert!(temp.path().join("layout.toml").is_file());
}

#[test]
fn fault_after_post_phase_marker_removal_recovers_staging_cleanup() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);

    let fault = TestAdoptionFaultGuard::arm(
        TestAdoptionFaultPoint::MarkerRemovedBeforeStagingDirectoryRemoval,
    );
    let error = adopt_layout(&home, requirement, confirmed_options())
        .expect_err("injected crash after marker removal before staging directory cleanup");
    drop(fault);

    assert!(format!("{error:#}").contains("MarkerRemovedBeforeStagingDirectoryRemoval"));
    assert!(temp.path().join("state/reborn-local-dev.db").is_file());
    assert!(temp.path().join("system").is_dir());
    assert!(temp.path().join("runtime/layout-adoption/staging").is_dir());
    assert!(
        !temp
            .path()
            .join("runtime/layout-adoption/staging/.adoption-owner")
            .exists()
    );
    assert!(
        fs::read_to_string(temp.path().join("runtime/layout-adoption/journal.toml"))
            .expect("canonical-installed journal")
            .contains("phase = \"canonical-installed\""),
        "phase advancement is durable before post-phase staging cleanup"
    );

    adopt_layout(&home, requirement, confirmed_options())
        .expect("canonical recovery completes the interrupted staging cleanup");
    assert!(temp.path().join("layout.toml").is_file());
}

#[test]
fn fault_after_state_rename_resumes_the_remaining_install_boundary() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);

    let fault = TestAdoptionFaultGuard::arm(TestAdoptionFaultPoint::StateRename);
    let error = adopt_layout(&home, requirement, confirmed_options())
        .expect_err("injected crash after state rename");
    drop(fault);

    assert!(format!("{error:#}").contains("StateRename"));
    assert!(temp.path().join("state/reborn-local-dev.db").is_file());
    assert!(
        temp.path()
            .join("runtime/layout-adoption/staging/system")
            .is_dir()
    );

    let authority = StartupAdoptionAuthority::from_environment_value(Some(
        StartupAdoptionAuthority::LEGACY_LAYOUT_V1,
    ))
    .expect("cutover authority");
    let permit = prepare_automatic_adoption(&home, requirement, authority)
        .expect("automatic recovery preflight");
    automatically_adopt_layout_with_store_verification(
        &home,
        requirement,
        permit,
        CanonicalStoreVerification::EmbeddedLibSql,
    )
    .expect("automatic recovery completes the remaining system rename");
    assert!(temp.path().join("layout.toml").is_file());
}

#[test]
fn automatic_startup_resumes_every_persisted_phase_and_commits_manifest_last() {
    for phase in [
        AdoptionPhase::Prepare,
        AdoptionPhase::SnapshotOwned,
        AdoptionPhase::Staged,
        AdoptionPhase::CanonicalInstalled,
        AdoptionPhase::MigrationPending,
        AdoptionPhase::StoreVerified,
    ] {
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
        let mut journal = AdoptionJournal::new(candidate, requirement, None);

        if phase != AdoptionPhase::Prepare {
            snapshot_source(candidate, &snapshot).expect("snapshot source");
            journal.phase = AdoptionPhase::SnapshotOwned;
        }
        if matches!(
            phase,
            AdoptionPhase::Staged
                | AdoptionPhase::CanonicalInstalled
                | AdoptionPhase::MigrationPending
                | AdoptionPhase::StoreVerified
        ) {
            stage_snapshot(
                candidate,
                &snapshot,
                &adoption_root,
                None,
                &journal.operation_id,
            )
            .expect("stage snapshot");
            journal.phase = AdoptionPhase::Staged;
        }
        if matches!(
            phase,
            AdoptionPhase::CanonicalInstalled
                | AdoptionPhase::MigrationPending
                | AdoptionPhase::StoreVerified
        ) {
            install_staged(&paths, &adoption_root, None).expect("install staged content");
            journal.phase = AdoptionPhase::CanonicalInstalled;
        }
        if phase == AdoptionPhase::MigrationPending {
            journal.phase = AdoptionPhase::MigrationPending;
        }
        if phase == AdoptionPhase::StoreVerified {
            verify_canonical_store(
                &paths,
                DurableStateKind::EmbeddedLibSql,
                CanonicalStoreVerification::EmbeddedLibSql,
            )
            .expect("verify canonical store");
            journal.phase = AdoptionPhase::StoreVerified;
        }
        write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal phase");

        assert!(!temp.path().join("layout.toml").exists());
        let authority = StartupAdoptionAuthority::from_environment_value(Some(
            StartupAdoptionAuthority::LEGACY_LAYOUT_V1,
        ))
        .expect("cutover authority");
        let permit = prepare_automatic_adoption(&home, requirement, authority)
            .expect("automatic recovery preflight");
        automatically_adopt_layout_with_store_verification(
            &home,
            requirement,
            permit,
            CanonicalStoreVerification::EmbeddedLibSql,
        )
        .expect("resume exact persisted phase automatically");
        assert!(temp.path().join("layout.toml").is_file());
        assert!(temp.path().join("state/reborn-local-dev.db").is_file());
    }
}
