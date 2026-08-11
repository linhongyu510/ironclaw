use super::*;

#[test]
fn fresh_home_initializes_canonical_namespaces_and_commits_manifest_last() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());

    ensure_ready_layout(&home, embedded_single_user_requirement()).expect("fresh home initializes");

    assert!(temp.path().join("layout.toml").is_file());
    assert!(temp.path().join("state").is_dir());
    assert!(temp.path().join("system").is_dir());
    assert!(temp.path().join("workspaces").is_dir());
    assert!(temp.path().join("runtime").is_dir());
    assert!(temp.path().join("logs").is_dir());
    assert!(temp.path().join("cache").is_dir());
    assert!(temp.path().join("tmp").is_dir());
    let manifest = read_manifest(&temp.path().join(LAYOUT_MANIFEST_FILE)).expect("manifest");
    assert_eq!(
        manifest.memory_provider_app_id(),
        Some(ironclaw_config::canonical_memory_provider_app_id(temp.path()).as_str())
    );
}

#[test]
fn concurrent_fresh_initializers_admit_the_identical_manifest() {
    use std::sync::{Arc, Barrier};

    let temp = tempfile::tempdir().expect("tempdir");
    let home = Arc::new(temp.path().to_path_buf());
    let barrier = Arc::new(Barrier::new(16));
    let manifest = LayoutManifest::new(embedded_single_user_requirement());
    let mut workers = Vec::new();
    for _ in 0..16 {
        let home = Arc::clone(&home);
        let barrier = Arc::clone(&barrier);
        let manifest = manifest.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            write_manifest_last(&home, &manifest)
        }));
    }
    for worker in workers {
        worker
            .join()
            .expect("initializer thread")
            .expect("identical concurrent manifest is admitted");
    }
    assert_eq!(
        super::read_manifest(&home.join(LAYOUT_MANIFEST_FILE)).expect("manifest"),
        manifest
    );
}

#[test]
fn fresh_home_initialization_resumes_after_partial_empty_namespace_creation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    fs::create_dir(temp.path().join("state")).expect("interrupted state namespace");
    fs::create_dir(temp.path().join("system")).expect("interrupted system namespace");

    let paths = ensure_ready_layout(&home, embedded_single_user_requirement())
        .expect("fresh initialization resumes idempotently");

    for path in [
        paths.state_root(),
        paths.system_root(),
        paths.workspace_root(),
        paths.runtime_root(),
        paths.logs_root(),
        paths.cache_root(),
        paths.temp_root(),
    ] {
        assert!(
            path.is_dir(),
            "canonical namespace exists: {}",
            path.display()
        );
    }
    assert!(temp.path().join("layout.toml").is_file());
}

#[test]
fn dry_run_layout_admission_refuses_a_fresh_home_without_creating_namespaces() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());

    let error = inspect_ready_layout(&home, embedded_single_user_requirement())
        .expect_err("dry-run admission must not initialize a fresh layout");

    assert!(error.to_string().contains("not ready"));
    assert!(!temp.path().join("layout.toml").exists());
    assert!(!temp.path().join("state").exists());
    assert!(!temp.path().join("system").exists());
    assert!(!temp.path().join("workspaces").exists());
    assert!(!temp.path().join("runtime").exists());
    assert!(!temp.path().join("logs").exists());
    assert!(!temp.path().join("cache").exists());
    assert!(!temp.path().join("tmp").exists());
}

#[test]
fn ready_manifest_requires_every_canonical_namespace_to_remain_an_ordinary_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    admit_startup_layout(&home, requirement).expect("initialize fresh layout");
    fs::remove_dir_all(temp.path().join("state")).expect("remove state namespace");

    let error = admit_startup_layout(&home, requirement)
        .expect_err("a ready manifest without state must fail closed");

    assert!(error.to_string().contains("state"), "{error:#}");
}

#[test]
fn startup_classifies_one_legacy_root_for_adoption_without_mutating_it() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);

    let admission = admit_startup_layout(&home, embedded_single_user_requirement())
        .expect("one supported source has a typed automatic-adoption decision");

    assert!(matches!(
        admission,
        StartupLayoutAdmission::AdoptionRequired
    ));
    assert!(legacy.join("reborn-local-dev.db").exists());
    assert!(!temp.path().join("layout.toml").exists());
    assert!(!temp.path().join("state").exists());
}

#[test]
fn adoption_requires_explicit_quiescence_and_backup_confirmations() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);

    let error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        AdoptOptions {
            confirm_processes_stopped: false,
            confirm_backup_snapshot: false,
            workspace_import: None,
        },
    )
    .expect_err("operator confirmations are mandatory");

    assert!(error.to_string().contains("--confirm-processes-stopped"));
    assert!(legacy.join("reborn-local-dev.db").exists());
    assert!(
        !temp
            .path()
            .join("runtime/layout-adoption/journal.toml")
            .exists()
    );
}

#[test]
fn adoption_moves_one_legacy_root_to_snapshot_and_commits_manifest() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let legacy_memory_provider_app_id = ironclaw_config::legacy_memory_provider_app_id(&legacy);
    fs::create_dir_all(legacy.join("system/extensions")).expect("legacy system root");
    fs::write(legacy.join("system/extensions/example.toml"), b"extension").expect("extension");

    adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect("offline adoption succeeds");

    assert!(temp.path().join("layout.toml").is_file());
    let manifest = read_manifest(&temp.path().join(LAYOUT_MANIFEST_FILE)).expect("manifest");
    assert_eq!(
        manifest.memory_provider_app_id(),
        Some(legacy_memory_provider_app_id.as_str()),
        "legacy remote-memory namespace survives physical storage adoption"
    );
    assert_eq!(
        crate::runtime::memory_provider_app_id_for_runtime(&home, None)
            .expect("restart resolves persisted memory-provider namespace"),
        Some(legacy_memory_provider_app_id.clone()),
        "a restart without an environment override must reopen the released remote-memory partition"
    );
    assert_eq!(
        crate::runtime::memory_provider_app_id_for_runtime(
            &home,
            Some("operator-override".to_string()),
        )
        .expect("explicit namespace resolves"),
        Some("operator-override".to_string()),
        "an explicit operator override must retain precedence over the persisted namespace"
    );
    assert!(!legacy.exists());
    assert!(
        temp.path()
            .join("runtime/layout-adoption/snapshot/local-dev/reborn-local-dev.db")
            .is_file()
    );
    assert!(temp.path().join("state/reborn-local-dev.db").is_file());
    assert!(
        temp.path()
            .join("state/.reborn-local-dev-secrets-master-key")
            .is_file()
    );
    assert!(temp.path().join("system/extensions/example.toml").is_file());
    assert_eq!(
        ready_legacy_skill_snapshot_source(&home).expect("ready snapshot source"),
        None,
        "copied system content does not require the database skill importer"
    );
}

#[test]
fn ready_layout_rejects_a_new_workspace_import_request() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect("adopt state before a later workspace request");
    let workspace_source = temp.path().join("legacy-workspace");
    fs::create_dir(&workspace_source).expect("workspace source");

    let error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        AdoptOptions {
            confirm_processes_stopped: true,
            confirm_backup_snapshot: true,
            workspace_import: Some(WorkspaceImportOptions {
                source: workspace_source,
                tenant: TenantId::new("tenant-a").expect("tenant"),
                user: UserId::new("user-a").expect("user"),
                confirmed: true,
            }),
        },
    )
    .expect_err("a ready layout cannot silently ignore a workspace import");

    assert!(error.to_string().contains("workspace import"), "{error:#}");
}

#[test]
fn adoption_preserves_a_legacy_user_skill_tree_and_nominates_its_snapshot() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    let skill = legacy.join("tenants/tenant-a/users/user-a/skills/preserved/SKILL.md");
    fs::create_dir_all(skill.parent().expect("skill parent")).expect("skill tree");
    fs::write(&skill, b"---\nname: preserved\n---\n").expect("legacy skill");
    let key = legacy.join(ironclaw_composition::STANDALONE_SECRETS_MASTER_KEY_PATH);
    fs::write(&key, ironclaw_secrets::keychain::generate_master_key_hex())
        .expect("legacy cached key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))
            .expect("owner-only legacy key");
    }

    adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect("skill-bearing legacy root is adopted");

    let snapshot_skill = temp
        .path()
        .join("runtime/layout-adoption/snapshot/local-dev")
        .join("tenants/tenant-a/users/user-a/skills/preserved/SKILL.md");
    assert_eq!(
        fs::read(snapshot_skill).expect("preserved snapshot skill"),
        b"---\nname: preserved\n---\n"
    );
    assert_eq!(
        ready_legacy_skill_snapshot_source(&home).expect("ready snapshot source"),
        Some(LegacySkillSnapshotSource::LocalDev)
    );
    assert!(temp.path().join("state/reborn-local-dev.db").is_file());
}

#[test]
fn adoption_rejects_non_skill_content_under_a_legacy_tenants_tree() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    let unknown = legacy.join("tenants/tenant-a/users/user-a/private.txt");
    fs::create_dir_all(unknown.parent().expect("unknown parent")).expect("tenant tree");
    fs::write(&unknown, b"must not be reinterpreted").expect("unknown legacy file");

    let error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect_err("only the released tenant/user skill grammar is adoptable");

    assert!(error.to_string().contains("tenants"), "{error:#}");
    assert!(unknown.is_file(), "rejected source remains untouched");
    assert!(
        !temp
            .path()
            .join("runtime/layout-adoption/journal.toml")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn adoption_rejects_an_insecure_legacy_master_key_before_journal_mutation() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let key = legacy.join(".reborn-local-dev-secrets-master-key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("insecure key mode");

    let error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect_err("a group-readable key must never be copied");

    assert!(error.to_string().contains("master key"));
    assert!(key.is_file(), "source remains untouched");
    assert!(
        !temp
            .path()
            .join("runtime/layout-adoption/journal.toml")
            .exists(),
        "key security is checked before a journal is written"
    );
}

#[cfg(unix)]
#[test]
fn master_key_copy_reestablishes_and_verifies_owner_only_mode() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let key = legacy.join(".reborn-local-dev-secrets-master-key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("secure key mode");
    let source_owner = fs::metadata(&key).expect("source metadata").uid();

    adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect("adoption succeeds with an owner-only source key");

    let destination = temp
        .path()
        .join("state/.reborn-local-dev-secrets-master-key");
    let metadata = fs::metadata(&destination).expect("destination metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), source_owner);
}

#[test]
fn embedded_adoption_verifies_existing_encrypted_secrets_before_manifest_commit() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);

    crate::runtime::block_on_cli({
        let legacy = legacy.clone();
        async move {
            let store = ironclaw_composition::open_standalone_secret_store(&legacy)
                .await
                .map_err(|error| anyhow::anyhow!(error))?;
            ironclaw_operator::LlmKeyStore::new(
                ironclaw_composition::RuntimeOperatorSecretValueStore::shared(store),
            )
            .put(
                "adoption-verification",
                ironclaw_secrets::SecretMaterial::from("encrypted-before-adoption"),
            )
            .await
            .map_err(|error| anyhow::anyhow!(error))
        }
    })
    .expect("seed encrypted legacy secret");

    fs::write(
        legacy.join(MASTER_KEY_FILE),
        ironclaw_secrets::keychain::generate_master_key_hex(),
    )
    .expect("replace legacy master key");

    let error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect_err("adoption must authenticate copied encrypted records before publishing ready");
    assert!(
        format!("{error:#}").contains("verify canonical embedded store"),
        "{error:#}"
    );
    assert!(
        !temp.path().join(LAYOUT_MANIFEST_FILE).exists(),
        "a failed master-key witness must leave the layout manifest unpublished"
    );
}

#[test]
fn multiple_populated_legacy_roots_fail_closed_without_a_source_choice() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    for root in ["local-dev", "hosted-single-tenant-volume"] {
        let path = temp.path().join(root);
        seed_legacy_embedded_store(&path);
    }

    let error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect_err("multiple sources must not be merged");

    assert!(
        error
            .to_string()
            .contains("multiple populated legacy roots")
    );
    assert!(temp.path().join("local-dev/reborn-local-dev.db").exists());
    assert!(
        temp.path()
            .join("hosted-single-tenant-volume/reborn-local-dev.db")
            .exists()
    );
    assert!(
        !temp
            .path()
            .join("runtime/layout-adoption/journal.toml")
            .exists()
    );
}

#[test]
fn unreleased_sandbox_root_blocks_adoption_without_writes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("hosted-single-tenant-volume-sandboxed");
    seed_legacy_embedded_store(&legacy);

    let error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect_err("unreleased sandbox root must be inspected manually");

    assert!(error.to_string().contains("unreleased sandbox"));
    assert!(legacy.join("reborn-local-dev.db").exists());
    assert!(
        !temp
            .path()
            .join("runtime/layout-adoption/journal.toml")
            .exists()
    );
}

#[test]
fn bare_home_db_and_key_are_adopted_as_an_independent_legacy_source() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    seed_legacy_embedded_store(temp.path());

    adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect("bare-home adoption succeeds");

    assert!(temp.path().join("state/reborn-local-dev.db").exists());
    assert!(
        temp.path()
            .join("runtime/layout-adoption/snapshot/bare-home/reborn-local-dev.db")
            .exists()
    );
    assert!(!temp.path().join("reborn-local-dev.db").exists());
}

#[test]
fn hosted_postgres_adoption_requires_verified_store_before_manifest_commit() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("hosted-single-tenant/system/prompts");
    fs::create_dir_all(&legacy).expect("legacy system content");
    fs::write(legacy.join("operator.md"), b"prompt").expect("system prompt");

    let error = adopt_layout(
        &home,
        external_single_user_requirement(),
        confirmed_options(),
    )
    .expect_err("an unverified external store cannot commit readiness");

    assert!(error.to_string().contains("were not verified"), "{error:#}");
    assert!(!temp.path().join("layout.toml").exists());
    assert!(legacy.join("operator.md").is_file());
    assert!(!temp.path().join("runtime/layout-adoption").exists());

    let mut verifier_invoked = false;
    adopt_layout_with_store_verification(
        &home,
        external_single_user_requirement(),
        confirmed_options(),
        || {
            verifier_invoked = true;
            assert!(!temp.path().join("runtime/layout-adoption").exists());
            assert!(
                legacy.join("operator.md").is_file(),
                "external-store verification must precede filesystem mutation"
            );
            Ok(CanonicalStoreVerification::ExternalPostgresVerified)
        },
    )
    .expect("verified PostgreSQL system-content adoption resumes and succeeds");

    assert!(verifier_invoked);
    assert!(temp.path().join("system/prompts/operator.md").is_file());
    assert!(
        temp.path()
            .join(
                "runtime/layout-adoption/snapshot/hosted-single-tenant/system/prompts/operator.md"
            )
            .is_file(),
        "successful adoption retains its durable legacy snapshot"
    );
    assert!(!temp.path().join("state/reborn-local-dev.db").exists());
}

#[test]
fn every_legacy_source_envelope_is_admitted_before_journal_or_mutation() {
    let cases = [
        ("local-dev", embedded_multi_user_requirement()),
        ("bare-home", embedded_multi_user_requirement()),
        ("hosted-single-tenant", embedded_single_user_requirement()),
        (
            "hosted-single-tenant-volume",
            embedded_single_user_requirement(),
        ),
    ];

    for (source, target) in cases {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = reborn_home(temp.path());
        match source {
            "local-dev" => seed_legacy_embedded_store(&temp.path().join(source)),
            "bare-home" => seed_legacy_embedded_store(temp.path()),
            "hosted-single-tenant" => {
                let system = temp.path().join(source).join("system/prompts");
                fs::create_dir_all(&system).expect("hosted system root");
                fs::write(system.join("operator.md"), b"prompt").expect("system prompt");
            }
            "hosted-single-tenant-volume" => {
                seed_legacy_embedded_store(&temp.path().join(source));
            }
            _ => unreachable!("exhaustive source test case"),
        }

        let error = adopt_layout(&home, target, confirmed_options())
            .expect_err("incompatible fixed source envelope must be rejected");

        assert!(
            error
                .to_string()
                .contains("stored durable layout rejects this profile transition"),
            "{source}: {error:#}"
        );
        assert!(
            !temp
                .path()
                .join("runtime/layout-adoption/journal.toml")
                .exists(),
            "{source}: incompatible target must not create a journal"
        );
        assert!(
            !temp.path().join("state").exists(),
            "{source}: incompatible target must not install canonical state"
        );
    }
}

#[test]
fn legacy_source_envelopes_are_exhaustive_and_allow_only_compatible_targets() {
    assert_eq!(
        LegacySourceKind::LocalDev.requirement(),
        embedded_single_user_requirement()
    );
    assert_eq!(
        LegacySourceKind::BareHome.requirement(),
        embedded_single_user_requirement()
    );
    assert_eq!(
        LegacySourceKind::HostedSingleTenant.requirement(),
        external_single_user_requirement()
    );
    assert_eq!(
        LegacySourceKind::HostedSingleTenantVolume.requirement(),
        embedded_multi_user_requirement()
    );

    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    seed_legacy_embedded_store(&temp.path().join("hosted-single-tenant-volume"));

    adopt_layout(
        &home,
        embedded_multi_user_requirement(),
        confirmed_options(),
    )
    .expect("the volume source retains its multi-user isolated envelope");
    assert!(temp.path().join("layout.toml").is_file());
}

#[test]
fn journal_source_envelope_must_match_its_fixed_legacy_source_kind() {
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
    let mut journal = AdoptionJournal::new(candidate, requirement, None);
    journal.source_requirement = embedded_multi_user_requirement();
    write_journal(&adoption_root.join("journal.toml"), &journal).expect("tampered journal");

    let error = adopt_layout(&home, requirement, confirmed_options())
        .expect_err("source envelope is an immutable source fact");

    assert!(error.to_string().contains("source security requirement"));
    assert!(legacy.join("reborn-local-dev.db").is_file());
    assert!(!temp.path().join("state").exists());
    assert!(!temp.path().join("layout.toml").exists());
}

#[test]
fn unknown_legacy_entries_fail_before_journal_or_snapshot_mutation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    fs::write(legacy.join("operator-notes.txt"), b"do not discard").expect("unknown file");

    let error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect_err("unknown entries must fail closed");

    assert!(error.to_string().contains("unknown entry"));
    assert!(legacy.join("operator-notes.txt").exists());
    assert!(
        !temp
            .path()
            .join("runtime/layout-adoption/journal.toml")
            .exists()
    );
}

#[test]
fn canonical_content_conflict_never_overwrites_or_snapshots_the_source() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    fs::create_dir_all(temp.path().join("state")).expect("canonical state");
    fs::write(temp.path().join("state/sentinel"), b"keep").expect("sentinel");

    let error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect_err("canonical state must not be overwritten");

    assert!(error.to_string().contains("already contains data"));
    assert!(legacy.join("reborn-local-dev.db").exists());
    assert_eq!(
        fs::read(temp.path().join("state/sentinel")).expect("sentinel"),
        b"keep"
    );
    assert!(
        !temp
            .path()
            .join("runtime/layout-adoption/journal.toml")
            .exists()
    );
}

#[test]
fn initial_adoption_rejects_unexplained_populated_workspace_or_runtime_namespaces() {
    for namespace in ["workspaces", "runtime"] {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = reborn_home(temp.path());
        let legacy = temp.path().join("local-dev");
        seed_legacy_embedded_store(&legacy);
        let sentinel = temp.path().join(namespace).join("operator-sentinel");
        fs::create_dir_all(sentinel.parent().expect("sentinel has a namespace parent"))
            .expect("canonical namespace");
        fs::write(&sentinel, b"do not infer ownership").expect("sentinel");

        let error = adopt_layout(
            &home,
            embedded_single_user_requirement(),
            confirmed_options(),
        )
        .expect_err("initial adoption must not merge unexplained canonical namespaces");

        assert!(
            error.to_string().contains("unexplained"),
            "{namespace}: {error:#}"
        );
        assert!(legacy.join("reborn-local-dev.db").is_file());
        assert_eq!(
            fs::read(&sentinel).expect("sentinel retained"),
            b"do not infer ownership"
        );
        assert!(
            !temp
                .path()
                .join("runtime/layout-adoption/journal.toml")
                .exists(),
            "{namespace}: initial rejection must precede journal creation"
        );
    }
}

#[test]
fn ready_manifest_rejects_an_incompatible_security_envelope_without_writes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    ensure_ready_layout(&home, embedded_single_user_requirement()).expect("fresh layout");
    let layout_before = fs::read(temp.path().join("layout.toml")).expect("layout manifest");

    let error = ensure_ready_layout(&home, embedded_multi_user_requirement())
        .expect_err("single-user to multi-user transition requires ownership migration");

    assert!(error.to_string().contains("tenancy transition"));
    assert_eq!(
        fs::read(temp.path().join("layout.toml")).expect("layout manifest"),
        layout_before
    );
}

#[test]
fn unsupported_manifest_and_journal_versions_fail_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    fs::write(
            temp.path().join("layout.toml"),
            "schema_version = 2\nstate_layout_version = 1\ndurable_state = \"embedded-libsql\"\n\n[security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n",
        )
        .expect("unsupported manifest");

    let manifest_error = ensure_ready_layout(&home, embedded_single_user_requirement())
        .expect_err("unsupported manifest must not be accepted");
    assert!(manifest_error.to_string().contains("unsupported"));

    fs::remove_file(temp.path().join("layout.toml")).expect("remove manifest");
    fs::create_dir_all(temp.path().join("runtime/layout-adoption")).expect("adoption root");
    fs::write(
            temp.path().join("runtime/layout-adoption/journal.toml"),
            "schema_version = 5\noperation_id = \"00000000-0000-4000-8000-000000000001\"\nsource = \"local-dev\"\nphase = \"prepare\"\n\n[source_requirement]\ndurable_state = \"embedded-libsql\"\n\n[source_requirement.security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n\n[target_requirement]\ndurable_state = \"embedded-libsql\"\n\n[target_requirement.security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n\n[inventory]\ndb_files = []\nhas_master_key = false\nhas_system_content = false\nhas_legacy_skills = false\n",
        )
        .expect("unsupported journal");

    let journal_error = adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect_err("unsupported journal must not be resumed");
    assert!(journal_error.to_string().contains("unsupported"));
}

#[test]
fn completed_adoption_is_idempotent_and_retains_snapshot_and_journal() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);

    adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect("first adoption");
    let snapshot = temp
        .path()
        .join("runtime/layout-adoption/snapshot/local-dev");
    let journal = temp.path().join("runtime/layout-adoption/journal.toml");
    let manifest = temp.path().join(LAYOUT_MANIFEST_FILE);
    assert!(snapshot.is_dir());
    assert!(journal.is_file());
    let manifest_before = fs::read(&manifest).expect("read committed manifest");
    let journal_before = fs::read(&journal).expect("read committed journal");

    reset_canonical_store_verification_count();
    adopt_layout(
        &home,
        embedded_single_user_requirement(),
        confirmed_options(),
    )
    .expect("completed adoption is a no-op");
    assert!(snapshot.is_dir());
    assert!(journal.is_file());
    assert_eq!(
        fs::read(&manifest).expect("reread committed manifest"),
        manifest_before,
        "an equivalent restart must not rewrite the layout receipt"
    );
    assert_eq!(
        fs::read(&journal).expect("reread committed journal"),
        journal_before,
        "an equivalent restart must not restart or advance adoption"
    );
    assert_eq!(
        canonical_store_verification_count(),
        0,
        "a ready canonical layout must bypass adoption store verification"
    );
}
