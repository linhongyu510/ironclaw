#[cfg(test)]
use super::test_support::*;
use super::*;
use super::{filesystem::*, locks::*, model::*};

/// Run or resume the one bounded offline adoption state machine after validating
/// its operator confirmations and optional tenant/user workspace import.
#[cfg(test)]
pub(crate) fn adopt_layout(
    home: &RebornHome,
    requirement: LayoutRequirement,
    options: AdoptOptions,
) -> anyhow::Result<()> {
    adopt_layout_with_store_verification(home, requirement, options, || {
        Ok(CanonicalStoreVerification::EmbeddedLibSql)
    })
}

/// Run or resume the one bounded offline adoption state machine and verify the
/// canonical store before the manifest is published.
pub(crate) fn adopt_layout_with_store_verification<VerifyStore>(
    home: &RebornHome,
    requirement: LayoutRequirement,
    options: AdoptOptions,
    mut verify_store: VerifyStore,
) -> anyhow::Result<()>
where
    VerifyStore: FnMut() -> anyhow::Result<CanonicalStoreVerification>,
{
    validate_adopt_options(&options)?;
    run_adoption_with_store_verification(
        home,
        requirement,
        options.workspace_import.as_ref(),
        &mut verify_store,
    )
}

/// Run or resume automatic startup adoption without inferring an external
/// workspace owner. Ambiguous and unsupported sources still fail closed in
/// the shared state machine.
pub(crate) fn automatically_adopt_layout_with_store_verification<VerifyStore>(
    home: &RebornHome,
    requirement: LayoutRequirement,
    permit: AutomaticAdoptionPermit,
    mut verify_store: VerifyStore,
) -> anyhow::Result<()>
where
    VerifyStore: FnMut() -> anyhow::Result<CanonicalStoreVerification>,
{
    if permit.home != home.path() || permit.requirement != requirement {
        bail!("automatic adoption permit does not match this home and layout requirement");
    }
    // The permit keeps the cutover lock alive through this call. Revalidate
    // immediately before the journaled filesystem transition begins.
    preflight_automatic_adoption(home, requirement)?;
    run_adoption_with_store_verification(home, requirement, None, &mut verify_store)
}

pub(super) fn run_adoption_with_store_verification<VerifyStore>(
    home: &RebornHome,
    requirement: LayoutRequirement,
    workspace_import: Option<&WorkspaceImportOptions>,
    verify_store: &mut VerifyStore,
) -> anyhow::Result<()>
where
    VerifyStore: FnMut() -> anyhow::Result<CanonicalStoreVerification>,
{
    let home_path = home.path();
    let paths = RebornStoragePaths::from_home(home);
    let manifest_path = home_path.join(LAYOUT_MANIFEST_FILE);
    if manifest_path.exists() {
        if workspace_import.is_some() {
            bail!(
                "canonical layout is already ready; refusing to silently ignore a workspace import request"
            );
        }
        let manifest = read_manifest(&manifest_path)?;
        admit_manifest(&manifest, requirement)?;
        return Ok(());
    }

    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    let journal_path = adoption_root.join(JOURNAL_FILE);
    validate_adoption_ancestors(home_path, &paths, &adoption_root)?;

    let (mut journal, _lock) = if journal_path.exists() {
        validate_journal_owned_runtime(&paths, &adoption_root)?;
        let lock = acquire_existing_adoption_lock(&adoption_root)?;
        (read_journal(&journal_path)?, lock)
    } else {
        let candidates = inspect_legacy_candidates(home_path)?;
        if candidates.len() != 1 {
            if candidates.is_empty() {
                bail!(
                    "no supported populated legacy source found under {}; normal boot initializes a genuinely fresh home",
                    home_path.display()
                );
            }
            bail!(
                "multiple populated legacy roots detected; no source was selected or modified: {}",
                candidate_paths(&candidates)
            );
        }
        let candidate = &candidates[0];
        admit_manifest(
            &LayoutManifest::new(candidate.kind.requirement()),
            requirement,
        )?;
        ensure_initial_adoption_namespaces_empty(&paths)?;
        let workspace = prepare_workspace_import(workspace_import, &paths)?;
        create_adoption_root(home_path, &paths, &adoption_root)?;
        let lock = acquire_adoption_lock(&adoption_root)?;
        if journal_path.exists() {
            (read_journal(&journal_path)?, lock)
        } else {
            let journal = AdoptionJournal::new(candidate, requirement, workspace);
            write_journal(&journal_path, &journal)?;
            (journal, lock)
        }
    };

    journal.validate_source_requirement()?;
    admit_manifest(
        &LayoutManifest::new(journal.source_requirement),
        requirement,
    )?;

    if journal.target_requirement != requirement {
        bail!(
            "adoption journal security requirement does not match this restart; inspect the preserved snapshot and resume with the original compatible profile"
        );
    }

    resume_adoption(
        home_path,
        &paths,
        &adoption_root,
        &journal_path,
        &mut journal,
        verify_store,
    )?;
    Ok(())
}

pub(crate) fn validate_adopt_options(options: &AdoptOptions) -> anyhow::Result<()> {
    require_operator_confirmations(options)
}

pub(super) fn require_operator_confirmations(options: &AdoptOptions) -> anyhow::Result<()> {
    if !options.confirm_processes_stopped {
        bail!(
            "refusing storage adoption without --confirm-processes-stopped; an advisory lock cannot prove old IronClaw binaries are quiescent"
        );
    }
    if !options.confirm_backup_snapshot {
        bail!("refusing storage adoption without --confirm-backup-snapshot");
    }
    Ok(())
}

pub(super) fn resume_adoption<VerifyStore>(
    home: &Path,
    paths: &RebornStoragePaths,
    adoption_root: &Path,
    journal_path: &Path,
    journal: &mut AdoptionJournal,
    verify_store: &mut VerifyStore,
) -> anyhow::Result<()>
where
    VerifyStore: FnMut() -> anyhow::Result<CanonicalStoreVerification>,
{
    let candidate = journal.candidate(home);
    let expected_memory_provider_app_id =
        ironclaw_config::legacy_memory_provider_app_id(&candidate.source_root);
    let memory_provider_app_id = match &journal.memory_provider_app_id {
        Some(app_id) if app_id == &expected_memory_provider_app_id => app_id.clone(),
        Some(_) => bail!(
            "adoption journal memory-provider namespace does not match its legacy source; refusing to resume"
        ),
        None => expected_memory_provider_app_id,
    };
    let snapshot = candidate.snapshot_root(adoption_root);
    let workspace = journal.validated_workspace()?;

    if journal.phase == AdoptionPhase::Prepare {
        reconcile_prepare_shape(&candidate, &snapshot)?;
        journal.phase = AdoptionPhase::SnapshotOwned;
        write_journal(journal_path, journal)?;
    }

    require_snapshot_shape(&candidate, &snapshot)?;

    if journal.phase == AdoptionPhase::SnapshotOwned {
        discard_proven_partial_staging(adoption_root, &journal.operation_id)?;
        stage_snapshot(
            &candidate,
            &snapshot,
            adoption_root,
            workspace.as_ref(),
            &journal.operation_id,
        )?;
        journal.phase = AdoptionPhase::Staged;
        write_journal(journal_path, journal)?;
    }

    if journal.phase == AdoptionPhase::Staged {
        reconcile_staged_install(
            paths,
            &candidate,
            &snapshot,
            adoption_root,
            workspace.as_ref(),
            &journal.operation_id,
        )?;
        journal.phase = AdoptionPhase::CanonicalInstalled;
        write_journal(journal_path, journal)?;
    }

    if journal.phase == AdoptionPhase::CanonicalInstalled {
        verify_canonical_inventory(paths, &candidate, &snapshot)?;
        verify_canonical_workspace(paths, workspace.as_ref())?;
        cleanup_completed_staging(adoption_root, &journal.operation_id)?;
        journal.phase = AdoptionPhase::MigrationPending;
        write_journal(journal_path, journal)?;
    }

    let store_verified_on_this_run = if journal.phase == AdoptionPhase::MigrationPending {
        verify_post_migration_canonical_shape(paths, &candidate, &snapshot, false)?;
        let store_verification = verify_store()?;
        verify_canonical_store(
            paths,
            candidate.kind.requirement().durable_state,
            store_verification,
        )?;
        verify_post_migration_canonical_shape(paths, &candidate, &snapshot, true)?;
        verify_canonical_workspace(paths, workspace.as_ref())?;
        journal.phase = AdoptionPhase::StoreVerified;
        write_journal(journal_path, journal)?;
        true
    } else {
        false
    };

    // StoreVerified is durable progress, not a proof that the canonical tree
    // still exists. Never compare post-migration libSQL bytes to the immutable
    // snapshot; validate the post-migration shape and reopen the real store.
    verify_post_migration_canonical_shape(paths, &candidate, &snapshot, true)?;
    if !store_verified_on_this_run {
        let store_verification = verify_store()?;
        verify_canonical_store(
            paths,
            candidate.kind.requirement().durable_state,
            store_verification,
        )?;
    }
    verify_post_migration_canonical_shape(paths, &candidate, &snapshot, true)?;
    verify_canonical_workspace(paths, workspace.as_ref())?;
    initialize_disposable_namespaces(home, paths)?;

    let manifest = LayoutManifest::new(journal.target_requirement)
        .with_memory_provider_app_id(memory_provider_app_id);
    write_manifest_last(home, &manifest)?;
    Ok(())
}

pub(super) fn reconcile_staged_install(
    paths: &RebornStoragePaths,
    candidate: &LegacyCandidate,
    snapshot: &Path,
    adoption_root: &Path,
    workspace: Option<&ValidatedWorkspaceImportDecision>,
    operation_id: &str,
) -> anyhow::Result<()> {
    let staging = adoption_root.join(STAGING_DIR);
    match fs::symlink_metadata(&staging) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            verify_completed_staged_install(paths, candidate, snapshot, workspace)?;
            return Ok(());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect staging root {}", staging.display()));
        }
        Ok(_) => {}
    }
    require_proven_staging(&staging, operation_id)?;
    reconcile_staged_state(
        candidate,
        snapshot,
        &staging.join("state"),
        paths.state_root(),
    )?;
    reconcile_staged_system(
        candidate,
        snapshot,
        &staging.join("system"),
        paths.system_root(),
    )?;
    reconcile_staged_workspace(paths, workspace, &staging.join("workspace-leaf"))?;
    let home = paths.workspace_root().parent().ok_or_else(|| {
        anyhow!(
            "canonical workspaces namespace has no installation parent: {}",
            paths.workspace_root().display()
        )
    })?;
    create_or_validate_direct_child(home, paths.workspace_root())?;
    Ok(())
}

pub(super) fn cleanup_completed_staging(
    adoption_root: &Path,
    operation_id: &str,
) -> anyhow::Result<()> {
    let staging = adoption_root.join(STAGING_DIR);
    match fs::symlink_metadata(&staging) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect completed staging root {}", staging.display()));
        }
        Ok(_) => {}
    }

    let marker = staging.join(STAGING_OWNER_FILE);
    match fs::symlink_metadata(&marker) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            if !directory_is_empty(&staging)? {
                bail!(
                    "completed staging tree at {} has content but no ownership marker; refusing to clean it",
                    staging.display()
                );
            }
            fs::remove_dir(&staging).with_context(|| {
                format!("remove empty post-phase staging root {}", staging.display())
            })?;
            return sync_directory(adoption_root);
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspect completed staging ownership marker {}",
                    marker.display()
                )
            });
        }
        Ok(_) => {}
    }

    require_proven_staging(&staging, operation_id)?;
    remove_staging_owner_marker(&staging, operation_id)?;
    #[cfg(test)]
    fail_at_test_adoption_fault(
        TestAdoptionFaultPoint::MarkerRemovedBeforeStagingDirectoryRemoval,
    )?;
    fs::remove_dir(&staging)
        .with_context(|| format!("remove completed staging root {}", staging.display()))?;
    sync_directory(adoption_root)
}

pub(super) fn discard_proven_partial_staging(
    adoption_root: &Path,
    operation_id: &str,
) -> anyhow::Result<()> {
    let staging = adoption_root.join(STAGING_DIR);
    match fs::symlink_metadata(&staging) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect staging root {}", staging.display()));
        }
        Ok(_) => {}
    }
    let marker = staging.join(STAGING_OWNER_FILE);
    match fs::symlink_metadata(&marker) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            if !directory_is_empty(&staging)? {
                bail!(
                    "staging tree at {} has mutable content but no ownership marker; refusing to discard it",
                    staging.display()
                );
            }
            fs::remove_dir(&staging).with_context(|| {
                format!(
                    "discard empty pre-marker staging root {}",
                    staging.display()
                )
            })?;
            return sync_directory(adoption_root);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect staging ownership marker {}", marker.display()));
        }
        Ok(_) => {}
    }
    require_proven_staging(&staging, operation_id)?;
    validate_ordinary_tree(&staging)?;
    fs::remove_dir_all(&staging).with_context(|| {
        format!(
            "discard journal-proven partial staging tree {}",
            staging.display()
        )
    })?;
    sync_directory(adoption_root)
}

pub(super) fn verify_completed_staged_install(
    paths: &RebornStoragePaths,
    candidate: &LegacyCandidate,
    snapshot: &Path,
    workspace: Option<&ValidatedWorkspaceImportDecision>,
) -> anyhow::Result<()> {
    verify_canonical_inventory(paths, candidate, snapshot)?;
    verify_canonical_workspace(paths, workspace)?;
    require_ordinary_directory(paths.workspace_root())?;
    Ok(())
}

pub(super) fn verify_canonical_workspace(
    paths: &RebornStoragePaths,
    workspace: Option<&ValidatedWorkspaceImportDecision>,
) -> anyhow::Result<()> {
    let Some(workspace) = workspace else {
        return Ok(());
    };
    require_matching_tree(
        &workspace.source,
        &workspace_leaf_path(paths, workspace),
        "canonical tenant/user workspace",
    )
}

pub(super) fn require_proven_staging(staging: &Path, operation_id: &str) -> anyhow::Result<()> {
    require_ordinary_directory(staging)?;
    let marker = staging.join(STAGING_OWNER_FILE);
    let contents = read_utf8_file_no_follow(&marker)?;
    if contents != operation_id {
        bail!(
            "staging ownership marker at {} does not match the adoption journal; refusing to discard or install it",
            marker.display()
        );
    }
    Ok(())
}

pub(super) fn remove_staging_owner_marker(
    staging: &Path,
    operation_id: &str,
) -> anyhow::Result<()> {
    require_proven_staging(staging, operation_id)?;
    let marker = staging.join(STAGING_OWNER_FILE);
    fs::remove_file(&marker)
        .with_context(|| format!("remove staging ownership marker {}", marker.display()))?;
    sync_directory(staging)
}

pub(super) fn reconcile_staged_state(
    candidate: &LegacyCandidate,
    snapshot: &Path,
    staged: &Path,
    canonical: &Path,
) -> anyhow::Result<()> {
    match (staged.exists(), canonical.exists()) {
        (true, false) => {
            verify_state_inventory(staged, candidate, snapshot, "staged state")?;
            fs::rename(staged, canonical)
                .with_context(|| format!("install staged state at {}", canonical.display()))?;
            sync_directory(
                canonical
                    .parent()
                    .ok_or_else(|| anyhow!("canonical state root has no parent"))?,
            )?;
            #[cfg(test)]
            {
                fail_at_test_adoption_fault(TestAdoptionFaultPoint::StateRename)?;
            }
            Ok(())
        }
        (false, true) => verify_state_inventory(canonical, candidate, snapshot, "canonical state"),
        (true, true) => bail!(
            "staged and canonical state both exist; refusing to choose or overwrite either tree"
        ),
        (false, false) => bail!(
            "staged recovery is missing both staged and canonical state; refusing to reconstruct an ambiguous install"
        ),
    }
}

pub(super) fn reconcile_staged_system(
    candidate: &LegacyCandidate,
    snapshot: &Path,
    staged: &Path,
    canonical: &Path,
) -> anyhow::Result<()> {
    match (staged.exists(), canonical.exists()) {
        (true, false) => {
            verify_system_inventory(staged, candidate, snapshot, "staged system")?;
            fs::rename(staged, canonical)
                .with_context(|| format!("install staged system at {}", canonical.display()))?;
            sync_directory(
                canonical
                    .parent()
                    .ok_or_else(|| anyhow!("canonical system root has no parent"))?,
            )
        }
        (false, true) => {
            verify_system_inventory(canonical, candidate, snapshot, "canonical system")
        }
        (true, true) => bail!(
            "staged and canonical system content both exist; refusing to choose or overwrite either tree"
        ),
        (false, false) => bail!(
            "staged recovery is missing both staged and canonical system content; refusing to reconstruct an ambiguous install"
        ),
    }
}

pub(super) fn reconcile_staged_workspace(
    paths: &RebornStoragePaths,
    workspace: Option<&ValidatedWorkspaceImportDecision>,
    staged_leaf: &Path,
) -> anyhow::Result<()> {
    let Some(workspace) = workspace else {
        return Ok(());
    };
    let destination = workspace_leaf_path(paths, workspace);
    match (staged_leaf.exists(), destination.exists()) {
        (true, false) => {
            validate_ordinary_tree(staged_leaf)?;
            install_workspace_leaf(paths, workspace, staged_leaf)
        }
        (false, true) => validate_ordinary_tree(&destination),
        (true, true) => bail!(
            "staged and canonical workspace leaves both exist; refusing to choose or overwrite either leaf"
        ),
        (false, false) => {
            bail!("staged recovery is missing both staged and canonical workspace leaves")
        }
    }
}

pub(super) fn reconcile_prepare_shape(
    candidate: &LegacyCandidate,
    snapshot: &Path,
) -> anyhow::Result<()> {
    if candidate.kind == LegacySourceKind::BareHome {
        if !snapshot.exists() {
            return snapshot_source(candidate, snapshot);
        }
        if bare_source_entries_absent(candidate)? {
            return Ok(());
        }
        bail!(
            "adoption journal phase `prepare` does not match the exact bare-home source/snapshot shape; refusing to guess which files are authoritative"
        );
    }
    match (!path_is_absent(&candidate.source_root)?, snapshot.exists()) {
        (true, false) => snapshot_source(candidate, snapshot),
        (false, true) => Ok(()),
        _ => bail!(
            "adoption journal phase `prepare` does not match the exact source/snapshot shape for {}; refusing to guess which files are authoritative",
            candidate.kind.label()
        ),
    }
}

pub(super) fn snapshot_source(candidate: &LegacyCandidate, snapshot: &Path) -> anyhow::Result<()> {
    let snapshot_parent = snapshot
        .parent()
        .ok_or_else(|| anyhow!("snapshot has no parent: {}", snapshot.display()))?;
    create_or_validate_direct_child(
        snapshot_parent.parent().ok_or_else(|| {
            anyhow!(
                "snapshot parent has no parent: {}",
                snapshot_parent.display()
            )
        })?,
        snapshot_parent,
    )?;

    if candidate.kind.profile_directory().is_some() {
        fs::rename(&candidate.source_root, snapshot).with_context(|| {
            format!(
                "snapshot legacy root {} -> {}",
                candidate.source_root.display(),
                snapshot.display()
            )
        })?;
        sync_directory(snapshot_parent)?;
        sync_directory(
            candidate
                .source_root
                .parent()
                .ok_or_else(|| anyhow!("legacy root has no parent"))?,
        )?;
        return Ok(());
    }

    fs::create_dir(snapshot)
        .with_context(|| format!("create bare-home snapshot {}", snapshot.display()))?;
    for entry in &candidate.db_files {
        fs::rename(candidate.source_root.join(entry), snapshot.join(entry))
            .with_context(|| format!("snapshot bare-home legacy entry {entry}"))?;
    }
    if candidate.has_master_key {
        fs::rename(
            candidate.source_root.join(MASTER_KEY_FILE),
            snapshot.join(MASTER_KEY_FILE),
        )
        .context("snapshot bare-home cached secrets master key")?;
    }
    sync_directory(snapshot)?;
    sync_directory(snapshot_parent)?;
    sync_directory(&candidate.source_root)?;
    Ok(())
}

pub(super) fn require_snapshot_shape(
    candidate: &LegacyCandidate,
    snapshot: &Path,
) -> anyhow::Result<()> {
    require_ordinary_directory(snapshot).with_context(|| {
        format!(
            "adoption snapshot is missing or unsafe at {}; only the offline adoption command may recover it",
            snapshot.display()
        )
    })?;
    let snapshot_handle = open_directory_no_follow(snapshot)?;
    if candidate.kind != LegacySourceKind::BareHome && !path_is_absent(&candidate.source_root)? {
        bail!(
            "legacy source {} still exists after snapshot ownership; refusing to copy from an ambiguous source/snapshot pair",
            candidate.source_root.display()
        );
    }
    if candidate.kind == LegacySourceKind::BareHome && !bare_source_entries_absent(candidate)? {
        bail!(
            "bare-home legacy DB/key entries remain after snapshot ownership; refusing to copy from an ambiguous source/snapshot pair"
        );
    }
    validate_snapshot_inventory(candidate, snapshot)?;
    ensure_directory_path_matches_handle(snapshot, &snapshot_handle)
}

pub(super) fn bare_source_entries_absent(candidate: &LegacyCandidate) -> anyhow::Result<bool> {
    recorded_bare_source_entries_absent(candidate)
}

pub(super) fn validate_snapshot_inventory(
    candidate: &LegacyCandidate,
    snapshot: &Path,
) -> anyhow::Result<()> {
    for file in &candidate.db_files {
        require_ordinary_file(&snapshot.join(file))?;
    }
    if candidate.has_master_key {
        require_ordinary_file(&snapshot.join(MASTER_KEY_FILE))?;
        validate_master_key_source(&snapshot.join(MASTER_KEY_FILE))?;
    }
    if candidate.has_system_content {
        validate_system_tree(&snapshot.join("system"))?;
    }
    Ok(())
}

pub(super) fn stage_snapshot(
    candidate: &LegacyCandidate,
    snapshot: &Path,
    adoption_root: &Path,
    workspace: Option<&ValidatedWorkspaceImportDecision>,
    operation_id: &str,
) -> anyhow::Result<()> {
    let staging = adoption_root.join(STAGING_DIR);
    if staging.exists() {
        bail!(
            "journal-owned staging tree already exists at {}; recovery must remove only recorded incomplete artifacts before restaging",
            staging.display()
        );
    }
    fs::create_dir(&staging).with_context(|| format!("create staging {}", staging.display()))?;
    write_atomic_synced(&staging.join(STAGING_OWNER_FILE), operation_id, false)?;
    let staging_state = staging.join("state");
    let staging_system = staging.join("system");
    fs::create_dir(&staging_state)
        .with_context(|| format!("create {}", staging_state.display()))?;
    fs::create_dir(&staging_system)
        .with_context(|| format!("create {}", staging_system.display()))?;
    #[cfg(test)]
    fail_at_test_adoption_fault(TestAdoptionFaultPoint::StagingChildrenCreated)?;

    for (index, file) in candidate.db_files.iter().enumerate() {
        copy_ordinary_file(&snapshot.join(file), &staging_state.join(file))?;
        let is_first_file = index == 0;
        #[cfg(test)]
        if is_first_file {
            fail_at_test_adoption_fault(TestAdoptionFaultPoint::FirstStateCopy)?;
        }
        #[cfg(not(test))]
        let _ = is_first_file;
    }
    if candidate.has_master_key {
        copy_master_key(
            &snapshot.join(MASTER_KEY_FILE),
            &staging_state.join(MASTER_KEY_FILE),
        )?;
    }
    if candidate.has_system_content {
        copy_system_tree(&snapshot.join("system"), &staging_system)?;
    }
    if let Some(workspace) = workspace {
        copy_ordinary_tree(&workspace.source, &staging.join("workspace-leaf"))?;
    }
    sync_directory(&staging_state)?;
    sync_directory(&staging_system)?;
    sync_directory(&staging)?;
    Ok(())
}

#[cfg(test)]
pub(super) fn install_staged(
    paths: &RebornStoragePaths,
    adoption_root: &Path,
    workspace: Option<&ValidatedWorkspaceImportDecision>,
) -> anyhow::Result<()> {
    let staging = adoption_root.join(STAGING_DIR);
    let staging_state = staging.join("state");
    let staging_system = staging.join("system");
    ensure_canonical_install_targets_empty(paths)?;
    fs::rename(&staging_state, paths.state_root())
        .with_context(|| format!("install staged state at {}", paths.state_root().display()))?;
    sync_directory(
        paths
            .state_root()
            .parent()
            .ok_or_else(|| anyhow!("canonical state root has no parent"))?,
    )?;
    fs::rename(&staging_system, paths.system_root())
        .with_context(|| format!("install staged system at {}", paths.system_root().display()))?;
    sync_directory(
        paths
            .system_root()
            .parent()
            .ok_or_else(|| anyhow!("canonical system root has no parent"))?,
    )?;
    if let Some(workspace) = workspace {
        install_workspace_leaf(paths, workspace, &staging.join("workspace-leaf"))?;
    }
    fs::remove_file(staging.join(STAGING_OWNER_FILE)).with_context(|| {
        format!(
            "remove staging ownership marker under {}",
            staging.display()
        )
    })?;
    fs::remove_dir(&staging)
        .with_context(|| format!("remove empty staging root {}", staging.display()))?;
    sync_directory(adoption_root)?;
    Ok(())
}

pub(super) fn verify_canonical_store(
    paths: &RebornStoragePaths,
    durable_state: DurableStateKind,
    verification: CanonicalStoreVerification,
) -> anyhow::Result<()> {
    #[cfg(test)]
    record_canonical_store_verification();
    match (durable_state, verification) {
        (DurableStateKind::EmbeddedLibSql, CanonicalStoreVerification::EmbeddedLibSql) => {
            let state_root = paths.state_root().to_path_buf();
            crate::runtime::block_on_cli(async move {
                ironclaw_composition::verify_standalone_secret_store_for_adoption(&state_root).await
            })
            .context(
                "verify canonical embedded store and secret resolver before committing adoption",
            )
        }
        (
            DurableStateKind::ExternalPostgres,
            CanonicalStoreVerification::ExternalPostgresVerified,
        ) => Ok(()),
        (DurableStateKind::ExternalPostgres, CanonicalStoreVerification::EmbeddedLibSql) => {
            bail!(
                "canonical external PostgreSQL store and secret resolver were not verified; refusing to commit StoreVerified or layout.toml"
            )
        }
        (
            DurableStateKind::EmbeddedLibSql,
            CanonicalStoreVerification::ExternalPostgresVerified,
        ) => bail!("external-store verification cannot admit an embedded libSQL layout"),
    }
}

pub(super) fn verify_canonical_inventory(
    paths: &RebornStoragePaths,
    candidate: &LegacyCandidate,
    snapshot: &Path,
) -> anyhow::Result<()> {
    verify_inventory_roots(
        paths.state_root(),
        paths.system_root(),
        candidate,
        snapshot,
        "canonical",
    )
}

pub(super) fn verify_post_migration_canonical_shape(
    paths: &RebornStoragePaths,
    candidate: &LegacyCandidate,
    snapshot: &Path,
    require_embedded_database: bool,
) -> anyhow::Result<()> {
    require_ordinary_directory(paths.state_root())?;
    if candidate.is_embedded() && require_embedded_database {
        require_ordinary_file(&paths.state_root().join(DB_FILE))?;
    }
    if candidate.has_master_key {
        validate_master_key_source(&paths.state_root().join(MASTER_KEY_FILE))?;
    }
    for entry in fs::read_dir(paths.state_root())
        .with_context(|| format!("read canonical state {}", paths.state_root().display()))?
    {
        let entry =
            entry.with_context(|| format!("read entry under {}", paths.state_root().display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let expected_master_key = name == MASTER_KEY_FILE && candidate.has_master_key;
        if !expected_master_key && !LIBSQL_DB_UNIT.contains(&name.as_ref()) {
            bail!(
                "canonical state contains unexpected post-migration entry `{name}` at {}",
                paths.state_root().display()
            );
        }
        require_ordinary_file(&entry.path())?;
    }
    if candidate.has_system_content {
        require_matching_tree(
            &snapshot.join("system"),
            paths.system_root(),
            "canonical system content",
        )?;
    } else {
        require_exact_file_inventory(paths.system_root(), &[], "canonical system")?;
    }
    Ok(())
}

pub(super) fn verify_inventory_roots(
    state_root: &Path,
    system_root: &Path,
    candidate: &LegacyCandidate,
    snapshot: &Path,
    label: &str,
) -> anyhow::Result<()> {
    verify_state_inventory(state_root, candidate, snapshot, &format!("{label} state"))?;
    verify_system_inventory(system_root, candidate, snapshot, &format!("{label} system"))
}

pub(super) fn verify_state_inventory(
    state_root: &Path,
    candidate: &LegacyCandidate,
    snapshot: &Path,
    label: &str,
) -> anyhow::Result<()> {
    let mut expected_state_files = candidate.db_files.clone();
    if candidate.has_master_key {
        expected_state_files.push(MASTER_KEY_FILE.to_string());
    }
    expected_state_files.sort();
    require_exact_file_inventory(state_root, &expected_state_files, label)?;
    for file in &candidate.db_files {
        require_matching_file(
            &snapshot.join(file),
            &state_root.join(file),
            &format!("{label} database"),
        )?;
    }
    if candidate.has_master_key {
        let source_key = snapshot.join(MASTER_KEY_FILE);
        validate_master_key_source(&source_key)?;
        validate_master_key_source(&state_root.join(MASTER_KEY_FILE))?;
        require_matching_file(
            &source_key,
            &state_root.join(MASTER_KEY_FILE),
            &format!("{label} master key"),
        )?;
    }
    Ok(())
}

pub(super) fn verify_system_inventory(
    system_root: &Path,
    candidate: &LegacyCandidate,
    snapshot: &Path,
    label: &str,
) -> anyhow::Result<()> {
    if candidate.has_system_content {
        require_matching_tree(&snapshot.join("system"), system_root, label)?;
    } else {
        require_exact_file_inventory(system_root, &[], label)?;
    }
    Ok(())
}

pub(super) fn require_exact_file_inventory(
    directory: &Path,
    expected: &[String],
    label: &str,
) -> anyhow::Result<()> {
    require_ordinary_directory(directory)?;
    let directory_handle = open_directory_no_follow(directory)?;
    let mut actual = Vec::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("read {label} directory {}", directory.display()))?
    {
        let entry = entry.with_context(|| format!("read entry under {}", directory.display()))?;
        let path = entry.path();
        require_ordinary_file(&path)?;
        actual.push(entry.file_name().to_string_lossy().into_owned());
    }
    actual.sort();
    if actual != expected {
        bail!(
            "{label} inventory at {} does not exactly match the recorded adoption snapshot",
            directory.display()
        );
    }
    ensure_directory_path_matches_handle(directory, &directory_handle)
}

pub(super) fn require_matching_tree(
    source: &Path,
    destination: &Path,
    label: &str,
) -> anyhow::Result<()> {
    require_ordinary_directory(source)?;
    require_ordinary_directory(destination)?;
    let source_handle = open_directory_no_follow(source)?;
    let destination_handle = open_directory_no_follow(destination)?;
    let mut source_entries = fs::read_dir(source)
        .with_context(|| format!("read {label} source {}", source.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("enumerate {label} source {}", source.display()))?;
    let mut destination_entries = fs::read_dir(destination)
        .with_context(|| format!("read {label} destination {}", destination.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("enumerate {label} destination {}", destination.display()))?;
    source_entries.sort_by_key(|entry| entry.file_name());
    destination_entries.sort_by_key(|entry| entry.file_name());
    let source_names = source_entries
        .iter()
        .map(|entry| entry.file_name())
        .collect::<Vec<_>>();
    let destination_names = destination_entries
        .iter()
        .map(|entry| entry.file_name())
        .collect::<Vec<_>>();
    if source_names != destination_names {
        bail!(
            "{label} inventory at {} does not exactly match snapshot {}",
            destination.display(),
            source.display()
        );
    }
    for source_entry in source_entries {
        let source_path = source_entry.path();
        let destination_path = destination.join(source_entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .with_context(|| format!("inspect {label} source entry {}", source_path.display()))?;
        if metadata.is_dir() {
            require_matching_tree(&source_path, &destination_path, label)?;
        } else {
            require_matching_file(&source_path, &destination_path, label)?;
        }
    }
    ensure_directory_path_matches_handle(source, &source_handle)?;
    ensure_directory_path_matches_handle(destination, &destination_handle)
}

pub(super) fn require_matching_file(
    source: &Path,
    destination: &Path,
    label: &str,
) -> anyhow::Result<()> {
    let source_digest = digest_ordinary_file(source)?;
    let destination_digest = digest_ordinary_file(destination)?;
    if source_digest != destination_digest {
        bail!(
            "{label} at {} does not match adoption snapshot {}",
            destination.display(),
            source.display()
        );
    }
    Ok(())
}

pub(super) fn digest_ordinary_file(path: &Path) -> anyhow::Result<String> {
    require_ordinary_file(path)?;
    let mut file = open_file_no_follow(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read file while hashing {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn initialize_fresh_layout(
    home: &Path,
    paths: &RebornStoragePaths,
    requirement: LayoutRequirement,
) -> anyhow::Result<()> {
    fs::create_dir_all(home).with_context(|| format!("create Reborn home {}", home.display()))?;
    for path in [
        paths.state_root(),
        paths.system_root(),
        paths.workspace_root(),
        paths.runtime_root(),
        paths.logs_root(),
        paths.cache_root(),
        paths.temp_root(),
    ] {
        create_or_validate_direct_child(home, path)?;
        sync_directory(path)?;
    }
    let manifest = LayoutManifest::new(requirement).with_memory_provider_app_id(
        ironclaw_config::canonical_memory_provider_app_id(paths.installation_root()),
    );
    write_manifest_last(home, &manifest)
}
