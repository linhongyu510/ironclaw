use super::*;

#[test]
fn external_workspace_requires_preview_confirmation_and_preserves_the_source() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let workspace_source = temp.path().join("legacy-workspace");
    fs::create_dir_all(&workspace_source).expect("workspace source");
    fs::write(workspace_source.join("keep.txt"), b"workspace data").expect("workspace file");

    let error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        AdoptOptions {
            workspace_import: Some(workspace_import(workspace_source.clone(), false)),
            ..confirmed_options()
        },
    )
    .expect_err("workspace import must require a second explicit confirmation");

    assert!(error.to_string().contains("workspace import preview"));
    assert!(workspace_source.join("keep.txt").exists());
    assert!(legacy.join("reborn-local-dev.db").exists());
    assert!(
        !temp
            .path()
            .join("runtime/layout-adoption/journal.toml")
            .exists()
    );

    adopt_layout(
        &home,
        embedded_single_user_requirement(),
        AdoptOptions {
            workspace_import: Some(workspace_import(workspace_source.clone(), true)),
            ..confirmed_options()
        },
    )
    .expect("confirmed external workspace import");

    let expected_digest = TenantUserWorkspaceKey::from_tenant_user(
        &TenantId::new("tenant-a").expect("tenant id"),
        &UserId::new("user-a").expect("user id"),
    )
    .digest_segment()
    .to_string();
    assert!(
        temp.path()
            .join("workspaces/users")
            .join(expected_digest)
            .join("keep.txt")
            .is_file()
    );
    assert_eq!(
        fs::read(workspace_source.join("keep.txt")).expect("workspace source"),
        b"workspace data"
    );
}

#[test]
fn workspace_mismatch_blocks_manifest_publication_and_preserves_source() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let workspace_source = temp.path().join("legacy-workspace");
    fs::create_dir_all(workspace_source.join("nested")).expect("workspace source");
    fs::write(workspace_source.join("nested/keep.txt"), b"workspace data").expect("workspace file");
    let paths = RebornStoragePaths::from_home(&home);
    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    fs::create_dir_all(&adoption_root).expect("adoption root");
    let candidates = inspect_legacy_candidates(temp.path()).expect("inspect source");
    let candidate = candidates.first().expect("one candidate");
    let workspace = prepare_workspace_import(
        Some(&workspace_import(workspace_source.clone(), true)),
        &paths,
    )
    .expect("workspace decision")
    .expect("workspace requested")
    .validate()
    .expect("validated workspace decision");
    let snapshot = candidate.snapshot_root(&adoption_root);
    let mut journal = AdoptionJournal::new(
        candidate,
        requirement,
        Some(WorkspaceImportDecision {
            source: workspace.source.clone(),
            tenant: workspace.tenant.to_string(),
            user: workspace.user.to_string(),
            digest: workspace.digest.clone(),
        }),
    );
    snapshot_source(candidate, &snapshot).expect("snapshot source");
    stage_snapshot(
        candidate,
        &snapshot,
        &adoption_root,
        Some(&workspace),
        &journal.operation_id,
    )
    .expect("stage snapshot");
    install_staged(&paths, &adoption_root, Some(&workspace)).expect("install staged content");
    fs::write(
        workspace_leaf_path(&paths, &workspace).join("nested/keep.txt"),
        b"tampered installed workspace",
    )
    .expect("tamper installed workspace");
    journal.phase = AdoptionPhase::CanonicalInstalled;
    write_journal(&adoption_root.join(JOURNAL_FILE), &journal).expect("canonical journal");

    let error = adopt_layout(&home, requirement, confirmed_options())
        .expect_err("workspace mismatch must block manifest publication");

    assert!(format!("{error:#}").contains("workspace"), "{error:#}");
    assert_eq!(
        fs::read(workspace_source.join("nested/keep.txt")).expect("source retained"),
        b"workspace data"
    );
    assert!(!temp.path().join(LAYOUT_MANIFEST_FILE).exists());
}

#[test]
fn automatic_startup_refuses_a_journaled_external_workspace_import() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let workspace_source = temp.path().join("legacy-workspace");
    fs::create_dir(&workspace_source).expect("workspace source");
    fs::write(workspace_source.join("keep.txt"), b"workspace data").expect("workspace file");
    let tenant = TenantId::new("tenant-a").expect("tenant");
    let user = UserId::new("user-a").expect("user");
    let paths = RebornStoragePaths::from_home(&home);
    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    fs::create_dir_all(&adoption_root).expect("adoption root");
    let candidates = inspect_legacy_candidates(temp.path()).expect("inspect source");
    let journal = AdoptionJournal::new(
        candidates.first().expect("one candidate"),
        requirement,
        Some(WorkspaceImportDecision {
            source: workspace_source.clone(),
            tenant: tenant.to_string(),
            user: user.to_string(),
            digest: TenantUserWorkspaceKey::from_tenant_user(&tenant, &user)
                .digest_segment()
                .to_string(),
        }),
    );
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal");

    let error = preflight_automatic_adoption(&home, requirement)
        .expect_err("automatic startup never assumes workspace migration authority");

    assert!(error.to_string().contains("external workspace import"));
    assert!(legacy.join("reborn-local-dev.db").is_file());
    assert!(workspace_source.join("keep.txt").is_file());
    assert!(!temp.path().join("layout.toml").exists());
}

#[test]
fn automatic_startup_rejects_an_impossible_journal_shape_before_store_verification() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = external_single_user_requirement();
    let legacy_prompt = temp
        .path()
        .join("hosted-single-tenant/system/prompts/operator.md");
    fs::create_dir_all(legacy_prompt.parent().expect("prompt parent")).expect("legacy system root");
    fs::write(&legacy_prompt, b"operator prompt").expect("legacy prompt");
    let paths = RebornStoragePaths::from_home(&home);
    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    fs::create_dir_all(&adoption_root).expect("adoption root");
    let candidates = inspect_legacy_candidates(temp.path()).expect("inspect source");
    let mut journal = AdoptionJournal::new(
        candidates.first().expect("one candidate"),
        requirement,
        None,
    );
    // SnapshotOwned requires the source to be absent and its exact snapshot
    // to exist. This impossible shape must fail before the caller can open
    // or migrate PostgreSQL.
    journal.phase = AdoptionPhase::SnapshotOwned;
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal");
    let authority = StartupAdoptionAuthority::from_environment_value(Some(
        StartupAdoptionAuthority::LEGACY_LAYOUT_V1,
    ))
    .expect("cutover authority");

    let error = match prepare_automatic_adoption(&home, requirement, authority) {
        Ok(_) => panic!("invalid journal shape must fail during read-only preflight"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("snapshot"), "{error:#}");
    assert!(legacy_prompt.is_file());
    assert!(!temp.path().join("layout.toml").exists());
    assert!(!temp.path().join(".reborn-storage-cutover.lock").exists());
}

#[test]
fn automatic_startup_rejects_prepare_journal_with_canonical_content() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = external_single_user_requirement();
    let legacy_prompt = temp
        .path()
        .join("hosted-single-tenant/system/prompts/operator.md");
    fs::create_dir_all(legacy_prompt.parent().expect("prompt parent")).expect("legacy system root");
    fs::write(&legacy_prompt, b"operator prompt").expect("legacy prompt");
    let paths = RebornStoragePaths::from_home(&home);
    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    fs::create_dir_all(&adoption_root).expect("adoption root");
    let candidates = inspect_legacy_candidates(temp.path()).expect("inspect source");
    let journal = AdoptionJournal::new(
        candidates.first().expect("one candidate"),
        requirement,
        None,
    );
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal");
    fs::create_dir_all(paths.state_root()).expect("conflicting canonical state");
    fs::write(paths.state_root().join("unowned.db"), b"conflict")
        .expect("conflicting canonical file");
    let authority = StartupAdoptionAuthority::from_environment_value(Some(
        StartupAdoptionAuthority::LEGACY_LAYOUT_V1,
    ))
    .expect("cutover authority");

    let error = match prepare_automatic_adoption(&home, requirement, authority) {
        Ok(_) => panic!("canonical conflict must fail during read-only preflight"),
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("canonical destination"),
        "{error:#}"
    );
    assert!(legacy_prompt.is_file());
    assert!(paths.state_root().join("unowned.db").is_file());
    assert!(!temp.path().join("layout.toml").exists());
    assert!(!temp.path().join(".reborn-storage-cutover.lock").exists());
}

#[cfg(unix)]
#[test]
fn automatic_startup_rejects_unowned_workspace_and_dangling_staged_child() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    seed_legacy_embedded_store(&temp.path().join("local-dev"));
    let paths = RebornStoragePaths::from_home(&home);
    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    fs::create_dir_all(&adoption_root).expect("adoption root");
    let candidates = inspect_legacy_candidates(temp.path()).expect("inspect source");
    let candidate = candidates.first().expect("one candidate");
    let mut journal = AdoptionJournal::new(candidate, requirement, None);
    let snapshot = candidate.snapshot_root(&adoption_root);
    snapshot_source(candidate, &snapshot).expect("snapshot source");
    stage_snapshot(
        candidate,
        &snapshot,
        &adoption_root,
        None,
        &journal.operation_id,
    )
    .expect("stage snapshot");
    journal.phase = AdoptionPhase::Staged;
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal");
    fs::create_dir_all(paths.workspace_root()).expect("workspace root");
    fs::write(paths.workspace_root().join("unowned.txt"), b"unowned")
        .expect("unowned workspace content");
    let authority = StartupAdoptionAuthority::from_environment_value(Some(
        StartupAdoptionAuthority::LEGACY_LAYOUT_V1,
    ))
    .expect("cutover authority");
    let workspace_error = match prepare_automatic_adoption(&home, requirement, authority) {
        Ok(_) => panic!("unowned workspace must fail during read-only preflight"),
        Err(error) => error,
    };
    assert!(
        workspace_error
            .to_string()
            .contains("has no workspace owner"),
        "{workspace_error:#}"
    );
    fs::remove_dir_all(paths.workspace_root()).expect("remove unowned workspace fixture");

    let staged_state = adoption_root.join("staging/state");
    fs::remove_dir_all(&staged_state).expect("remove staged state");
    symlink(adoption_root.join("missing-state"), &staged_state)
        .expect("dangling staged-state symlink");
    let authority = StartupAdoptionAuthority::from_environment_value(Some(
        StartupAdoptionAuthority::LEGACY_LAYOUT_V1,
    ))
    .expect("cutover authority");

    let error = match prepare_automatic_adoption(&home, requirement, authority) {
        Ok(_) => panic!("dangling staged child must fail during read-only preflight"),
        Err(error) => error,
    };

    assert!(
        format!("{error:#}").contains("ordinary non-symlink directory"),
        "{error:#}"
    );
    assert!(!temp.path().join("layout.toml").exists());
    assert!(!temp.path().join(".reborn-storage-cutover.lock").exists());
}

#[test]
fn tampered_workspace_journal_identity_is_rejected_before_snapshot_or_install() {
    for journal_digest in ["not-the-canonical-digest", "../escape"] {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = reborn_home(temp.path());
        let requirement = embedded_single_user_requirement();
        let legacy = temp.path().join("local-dev");
        seed_legacy_embedded_store(&legacy);
        let workspace_source = temp.path().join("workspace-source");
        fs::create_dir_all(&workspace_source).expect("workspace source");
        fs::write(workspace_source.join("keep.txt"), b"workspace data").expect("workspace file");
        let paths = RebornStoragePaths::from_home(&home);
        let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
        fs::create_dir_all(&adoption_root).expect("adoption root");
        let candidates = inspect_legacy_candidates(temp.path()).expect("inspect source");
        let candidate = candidates.first().expect("one candidate");
        let journal = AdoptionJournal::new(
            candidate,
            requirement,
            Some(WorkspaceImportDecision {
                source: workspace_source.clone(),
                tenant: "tenant-a".into(),
                user: "user-a".into(),
                digest: journal_digest.into(),
            }),
        );
        write_journal(&adoption_root.join("journal.toml"), &journal).expect("tampered journal");

        let error = adopt_layout(&home, requirement, confirmed_options())
            .expect_err("journal workspace identity must not be trusted");

        assert!(error.to_string().contains("workspace journal"));
        assert!(legacy.join("reborn-local-dev.db").is_file());
        assert!(workspace_source.join("keep.txt").is_file());
        assert!(!temp.path().join("state").exists());
        assert!(!temp.path().join("layout.toml").exists());
    }
}

#[test]
fn journal_workspace_source_must_be_absolute_before_snapshot() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let tenant = TenantId::new("tenant-a").expect("tenant id");
    let user = UserId::new("user-a").expect("user id");
    let paths = RebornStoragePaths::from_home(&home);
    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    fs::create_dir_all(&adoption_root).expect("adoption root");
    let candidates = inspect_legacy_candidates(temp.path()).expect("inspect source");
    let candidate = candidates.first().expect("one candidate");
    let journal = AdoptionJournal::new(
        candidate,
        requirement,
        Some(WorkspaceImportDecision {
            source: std::path::PathBuf::from("relative-workspace"),
            tenant: tenant.as_str().to_string(),
            user: user.as_str().to_string(),
            digest: TenantUserWorkspaceKey::from_tenant_user(&tenant, &user)
                .digest_segment()
                .to_string(),
        }),
    );
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal");

    let error = adopt_layout(&home, requirement, confirmed_options())
        .expect_err("relative workspace source must fail before snapshot");

    assert!(format!("{error:#}").contains("workspace journal source must be absolute"));
    assert!(legacy.join("reborn-local-dev.db").is_file());
    assert!(!temp.path().join("state").exists());
    assert!(!temp.path().join("layout.toml").exists());
}

#[cfg(unix)]
#[test]
fn journal_workspace_source_must_be_an_ordinary_tree_before_snapshot() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let outside = temp.path().join("outside-workspace");
    fs::create_dir(&outside).expect("outside workspace");
    let linked_workspace = temp.path().join("linked-workspace");
    symlink(&outside, &linked_workspace).expect("linked workspace");
    let tenant = TenantId::new("tenant-a").expect("tenant id");
    let user = UserId::new("user-a").expect("user id");
    let paths = RebornStoragePaths::from_home(&home);
    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    fs::create_dir_all(&adoption_root).expect("adoption root");
    let candidates = inspect_legacy_candidates(temp.path()).expect("inspect source");
    let candidate = candidates.first().expect("one candidate");
    let journal = AdoptionJournal::new(
        candidate,
        requirement,
        Some(WorkspaceImportDecision {
            source: linked_workspace,
            tenant: tenant.as_str().to_string(),
            user: user.as_str().to_string(),
            digest: TenantUserWorkspaceKey::from_tenant_user(&tenant, &user)
                .digest_segment()
                .to_string(),
        }),
    );
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("journal");

    let error = adopt_layout(&home, requirement, confirmed_options())
        .expect_err("symlinked workspace source must fail before snapshot");

    assert!(
        format!("{error:#}").contains("ordinary non-symlink directory"),
        "{error:#}"
    );
    assert!(legacy.join("reborn-local-dev.db").is_file());
    assert!(!temp.path().join("state").exists());
    assert!(!temp.path().join("layout.toml").exists());
}
