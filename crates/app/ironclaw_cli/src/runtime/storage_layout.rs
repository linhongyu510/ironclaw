//! Bounded, offline adoption for the profile-stable Reborn durable layout.
//!
//! This is deliberately a single state machine for this one filesystem
//! transition. It does not discover arbitrary roots, infer workspace owners,
//! or serve as a generic migration framework.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
#[cfg(unix)]
use fs2::FileExt as _;
use ironclaw_composition::LegacySkillSnapshotSource;
use ironclaw_config::{
    DeploymentSecurityEnvelope, DurableStateKind, LayoutManifest, LayoutRequirement,
    ProfileTransitionAdmission, RebornHome, RebornStoragePaths, TenancyModel, WorkspaceAccessFloor,
};
use ironclaw_host_api::ids::{TenantId, TenantUserWorkspaceKey, UserId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const LAYOUT_MANIFEST_FILE: &str = "layout.toml";
const ADOPTION_DIR: &str = "layout-adoption";
const JOURNAL_FILE: &str = "journal.toml";
const SNAPSHOT_DIR: &str = "snapshot";
const STAGING_DIR: &str = "staging";
const STAGING_OWNER_FILE: &str = ".adoption-owner";
const ADOPTION_LOCK_FILE: &str = "adoption.lock";
const JOURNAL_SCHEMA_VERSION: u32 = 4;
const DB_FILE: &str = "reborn-local-dev.db";
const MASTER_KEY_FILE: &str = ".reborn-local-dev-secrets-master-key";
const LIBSQL_DB_UNIT: &[&str] = &[
    DB_FILE,
    "reborn-local-dev.db-wal",
    "reborn-local-dev.db-shm",
    "reborn-local-dev.db-journal",
];
const SYSTEM_CONTENT_DIRS: &[&str] = &["extensions", "prompts", "skills"];
const OFFLINE_ADOPT_COMMAND: &str =
    "ironclaw storage adopt --confirm-processes-stopped --confirm-backup-snapshot";

/// Explicit operator acknowledgements required before source mutation.
#[derive(Debug, Clone)]
pub(crate) struct AdoptOptions {
    pub(crate) confirm_processes_stopped: bool,
    pub(crate) confirm_backup_snapshot: bool,
    pub(crate) workspace_import: Option<WorkspaceImportOptions>,
}

/// An operator-selected external legacy workspace and its explicit owner.
#[derive(Debug, Clone)]
pub(crate) struct WorkspaceImportOptions {
    pub(crate) source: PathBuf,
    pub(crate) tenant: TenantId,
    pub(crate) user: UserId,
    pub(crate) confirmed: bool,
}

/// Proof supplied by the caller that the target authoritative store was
/// verified through its production opener before adoption can commit Ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanonicalStoreVerification {
    EmbeddedLibSql,
    ExternalPostgresVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AdoptionPhase {
    Prepare,
    SnapshotOwned,
    Staged,
    CanonicalInstalled,
    MigrationPending,
    StoreVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum LegacySourceKind {
    LocalDev,
    HostedSingleTenant,
    HostedSingleTenantVolume,
    BareHome,
}

impl LegacySourceKind {
    const fn label(self) -> &'static str {
        match self {
            Self::LocalDev => "local-dev",
            Self::HostedSingleTenant => "hosted-single-tenant",
            Self::HostedSingleTenantVolume => "hosted-single-tenant-volume",
            Self::BareHome => "bare-home",
        }
    }

    const fn profile_directory(self) -> Option<&'static str> {
        match self {
            Self::LocalDev => Some("local-dev"),
            Self::HostedSingleTenant => Some("hosted-single-tenant"),
            Self::HostedSingleTenantVolume => Some("hosted-single-tenant-volume"),
            Self::BareHome => None,
        }
    }

    const fn skill_snapshot_source(self) -> LegacySkillSnapshotSource {
        match self {
            Self::LocalDev => LegacySkillSnapshotSource::LocalDev,
            Self::HostedSingleTenant => LegacySkillSnapshotSource::HostedSingleTenant,
            Self::HostedSingleTenantVolume => LegacySkillSnapshotSource::HostedSingleTenantVolume,
            Self::BareHome => LegacySkillSnapshotSource::BareHome,
        }
    }

    /// The historical source envelope is fixed and never inferred from the
    /// requested target profile.
    const fn requirement(self) -> LayoutRequirement {
        match self {
            Self::LocalDev | Self::BareHome => LayoutRequirement {
                durable_state: DurableStateKind::EmbeddedLibSql,
                security: DeploymentSecurityEnvelope {
                    tenancy: TenancyModel::SingleUser,
                    workspace_access_floor: WorkspaceAccessFloor::SingleTrustedOperator,
                },
            },
            Self::HostedSingleTenant => LayoutRequirement {
                durable_state: DurableStateKind::ExternalPostgres,
                security: DeploymentSecurityEnvelope {
                    tenancy: TenancyModel::SingleUser,
                    workspace_access_floor: WorkspaceAccessFloor::SingleTrustedOperator,
                },
            },
            Self::HostedSingleTenantVolume => LayoutRequirement {
                durable_state: DurableStateKind::EmbeddedLibSql,
                security: DeploymentSecurityEnvelope {
                    tenancy: TenancyModel::MultiUser,
                    workspace_access_floor: WorkspaceAccessFloor::PerCallerIsolated,
                },
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyCandidate {
    kind: LegacySourceKind,
    source_root: PathBuf,
    db_files: Vec<String>,
    has_master_key: bool,
    has_system_content: bool,
    has_legacy_skills: bool,
}

impl LegacyCandidate {
    fn is_embedded(&self) -> bool {
        self.kind.requirement().durable_state == DurableStateKind::EmbeddedLibSql
    }

    fn snapshot_root(&self, adoption_root: &Path) -> PathBuf {
        adoption_root.join(SNAPSHOT_DIR).join(self.kind.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptionInventory {
    db_files: Vec<String>,
    has_master_key: bool,
    has_system_content: bool,
    has_legacy_skills: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptionJournal {
    schema_version: u32,
    operation_id: String,
    source: LegacySourceKind,
    phase: AdoptionPhase,
    source_requirement: LayoutRequirement,
    target_requirement: LayoutRequirement,
    inventory: AdoptionInventory,
    workspace: Option<WorkspaceImportDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceImportDecision {
    source: PathBuf,
    tenant: String,
    user: String,
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedWorkspaceImportDecision {
    source: PathBuf,
    tenant: TenantId,
    user: UserId,
    digest: String,
}

impl WorkspaceImportDecision {
    fn validate(&self) -> anyhow::Result<ValidatedWorkspaceImportDecision> {
        if !self.source.is_absolute() {
            bail!(
                "workspace journal source must be absolute; refusing to resolve a persisted relative path"
            );
        }
        require_ordinary_directory(&self.source)
            .context("workspace journal source must be an ordinary non-symlink directory")?;
        validate_ordinary_tree(&self.source).context(
            "workspace journal source tree must contain only ordinary non-symlink entries",
        )?;
        let tenant = TenantId::new(self.tenant.clone())
            .map_err(|error| anyhow!("invalid workspace journal tenant identity: {error}"))?;
        let user = UserId::new(self.user.clone())
            .map_err(|error| anyhow!("invalid workspace journal user identity: {error}"))?;
        let digest = TenantUserWorkspaceKey::from_tenant_user(&tenant, &user)
            .digest_segment()
            .to_string();
        if !is_single_path_segment(&self.digest) {
            bail!(
                "workspace journal digest must be one normal path segment; refusing to derive a workspace destination from {}",
                self.digest
            );
        }
        if self.digest != digest {
            bail!(
                "workspace journal digest does not match its tenant/user identities; refusing to derive a workspace destination"
            );
        }
        Ok(ValidatedWorkspaceImportDecision {
            source: self.source.clone(),
            tenant,
            user,
            digest,
        })
    }
}

impl AdoptionJournal {
    fn new(
        candidate: &LegacyCandidate,
        target_requirement: LayoutRequirement,
        workspace: Option<WorkspaceImportDecision>,
    ) -> Self {
        Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            operation_id: Uuid::new_v4().to_string(),
            source: candidate.kind,
            phase: AdoptionPhase::Prepare,
            source_requirement: candidate.kind.requirement(),
            target_requirement,
            inventory: AdoptionInventory {
                db_files: candidate.db_files.clone(),
                has_master_key: candidate.has_master_key,
                has_system_content: candidate.has_system_content,
                has_legacy_skills: candidate.has_legacy_skills,
            },
            workspace,
        }
    }

    fn candidate(&self, home: &Path) -> LegacyCandidate {
        let source_root = self
            .source
            .profile_directory()
            .map_or_else(|| home.to_path_buf(), |directory| home.join(directory));
        LegacyCandidate {
            kind: self.source,
            source_root,
            db_files: self.inventory.db_files.clone(),
            has_master_key: self.inventory.has_master_key,
            has_system_content: self.inventory.has_system_content,
            has_legacy_skills: self.inventory.has_legacy_skills,
        }
    }

    fn validate_source_requirement(&self) -> anyhow::Result<()> {
        Uuid::parse_str(&self.operation_id)
            .map_err(|error| anyhow!("adoption journal operation_id must be a UUID: {error}"))?;
        if self.source_requirement != self.source.requirement() {
            bail!(
                "adoption journal source security requirement does not match its fixed legacy source kind; refusing to resume"
            );
        }
        Ok(())
    }

    fn validated_workspace(&self) -> anyhow::Result<Option<ValidatedWorkspaceImportDecision>> {
        self.workspace
            .as_ref()
            .map(WorkspaceImportDecision::validate)
            .transpose()
    }
}

/// Validate a ready layout, initialize a genuinely fresh home, or fail closed.
///
/// This never performs adoption work. In particular it never creates an
/// adoption journal, snapshots a source, or copies legacy state.
pub(crate) fn ensure_ready_layout(
    home: &RebornHome,
    requirement: LayoutRequirement,
) -> anyhow::Result<RebornStoragePaths> {
    let home_path = home.path();
    let paths = RebornStoragePaths::from_home(home);
    let manifest_path = home_path.join(LAYOUT_MANIFEST_FILE);
    let adoption_journal = paths.runtime_root().join(ADOPTION_DIR).join(JOURNAL_FILE);
    if manifest_path.exists() {
        let manifest = read_manifest(&manifest_path)?;
        if adoption_journal.exists() {
            let journal = read_journal(&adoption_journal)?;
            if journal.phase != AdoptionPhase::StoreVerified
                || journal.target_requirement != manifest.requirement()
            {
                bail!(
                    "ready layout manifest and adoption journal disagree at {}; refusing to open durable state",
                    adoption_journal.display()
                );
            }
        }
        admit_manifest(&manifest, requirement)?;
        return Ok(paths);
    }

    if adoption_journal.exists() {
        bail!(
            "durable layout adoption is incomplete; stop IronClaw and resume offline with `{OFFLINE_ADOPT_COMMAND}`"
        );
    }

    let candidates = inspect_legacy_candidates(home_path)?;
    if candidates.is_empty() && canonical_layout_is_empty(&paths)? {
        initialize_fresh_layout(home_path, &paths, requirement)?;
        return Ok(paths);
    }

    if candidates.len() == 1 {
        bail!(
            "legacy durable state detected at {}; normal boot will not copy it. Stop every old IronClaw process, take an operator backup/snapshot, then run `{OFFLINE_ADOPT_COMMAND}`",
            candidates[0].source_root.display()
        );
    }
    if candidates.len() > 1 {
        bail!(
            "multiple populated legacy roots detected; no source was selected or modified: {}",
            candidate_paths(&candidates)
        );
    }

    bail!(
        "canonical durable layout is incomplete or unrecognized at {}; refusing to open stores without a valid layout.toml. Inspect it and use `{OFFLINE_ADOPT_COMMAND}` only for one supported legacy source",
        home_path.display()
    );
}

/// Validate a ready canonical layout without creating any directories,
/// snapshots, journals, or manifests. This is the migration-dry-run admission
/// path: it may report an unsafe deployment, but it must not change it.
pub(crate) fn inspect_ready_layout(
    home: &RebornHome,
    requirement: LayoutRequirement,
) -> anyhow::Result<RebornStoragePaths> {
    let paths = RebornStoragePaths::from_home(home);
    let manifest_path = home.path().join(LAYOUT_MANIFEST_FILE);
    let journal_path = paths.runtime_root().join(ADOPTION_DIR).join(JOURNAL_FILE);
    if !manifest_path.exists() {
        bail!(
            "canonical durable layout is not ready at {}; migration dry-run will not initialize it",
            home.path().display()
        );
    }
    let manifest = read_manifest(&manifest_path)?;
    if journal_path.exists() {
        let journal = read_journal(&journal_path)?;
        if journal.phase != AdoptionPhase::StoreVerified
            || journal.target_requirement != manifest.requirement()
        {
            bail!(
                "ready layout manifest and adoption journal disagree at {}; refusing to open durable state",
                journal_path.display()
            );
        }
    }
    admit_manifest(&manifest, requirement)?;
    Ok(paths)
}

/// Return the fixed legacy snapshot source after normal layout admission has
/// verified a completed journal. Composition receives this enum, never a
/// caller-selected host path, and derives the snapshot location itself.
pub(crate) fn ready_legacy_skill_snapshot_source(
    home: &RebornHome,
) -> anyhow::Result<Option<LegacySkillSnapshotSource>> {
    let paths = RebornStoragePaths::from_home(home);
    let journal_path = paths.runtime_root().join(ADOPTION_DIR).join(JOURNAL_FILE);
    if !journal_path.exists() {
        return Ok(None);
    }
    let journal = read_journal(&journal_path)?;
    if journal.phase != AdoptionPhase::StoreVerified {
        bail!(
            "durable layout adoption is incomplete at {}; refusing to select a legacy skill snapshot",
            journal_path.display()
        );
    }
    Ok(journal
        .inventory
        .has_legacy_skills
        .then(|| journal.source.skill_snapshot_source()))
}

/// Run or resume the one bounded offline adoption state machine.
#[cfg(test)]
pub(crate) fn adopt_layout(
    home: &RebornHome,
    requirement: LayoutRequirement,
    options: AdoptOptions,
) -> anyhow::Result<()> {
    adopt_layout_with_store_verification(
        home,
        requirement,
        options,
        CanonicalStoreVerification::EmbeddedLibSql,
    )
}

pub(crate) fn adopt_layout_with_store_verification(
    home: &RebornHome,
    requirement: LayoutRequirement,
    options: AdoptOptions,
    store_verification: CanonicalStoreVerification,
) -> anyhow::Result<()> {
    validate_adopt_options(&options)?;
    let home_path = home.path();
    let paths = RebornStoragePaths::from_home(home);
    let manifest_path = home_path.join(LAYOUT_MANIFEST_FILE);
    if manifest_path.exists() {
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
        let workspace = prepare_workspace_import(options.workspace_import.as_ref(), &paths)?;
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
        store_verification,
    )?;
    Ok(())
}

pub(crate) fn validate_adopt_options(options: &AdoptOptions) -> anyhow::Result<()> {
    require_operator_confirmations(options)
}

fn require_operator_confirmations(options: &AdoptOptions) -> anyhow::Result<()> {
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

fn resume_adoption(
    home: &Path,
    paths: &RebornStoragePaths,
    adoption_root: &Path,
    journal_path: &Path,
    journal: &mut AdoptionJournal,
    store_verification: CanonicalStoreVerification,
) -> anyhow::Result<()> {
    let candidate = journal.candidate(home);
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
        cleanup_completed_staging(adoption_root, &journal.operation_id)?;
        journal.phase = AdoptionPhase::MigrationPending;
        write_journal(journal_path, journal)?;
    }

    if journal.phase == AdoptionPhase::MigrationPending {
        verify_post_migration_canonical_shape(paths, &candidate, &snapshot, false)?;
        verify_canonical_store(
            paths,
            candidate.kind.requirement().durable_state,
            store_verification,
        )?;
        verify_post_migration_canonical_shape(paths, &candidate, &snapshot, true)?;
        journal.phase = AdoptionPhase::StoreVerified;
        write_journal(journal_path, journal)?;
    }

    // StoreVerified is durable progress, not a proof that the canonical tree
    // still exists. Never compare post-migration libSQL bytes to the immutable
    // snapshot; validate the post-migration shape and reopen the real store.
    verify_post_migration_canonical_shape(paths, &candidate, &snapshot, true)?;
    verify_canonical_store(
        paths,
        candidate.kind.requirement().durable_state,
        store_verification,
    )?;
    verify_post_migration_canonical_shape(paths, &candidate, &snapshot, true)?;

    let manifest = LayoutManifest::new(journal.target_requirement);
    write_manifest_last(home, &manifest)?;
    Ok(())
}

fn reconcile_staged_install(
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

fn cleanup_completed_staging(adoption_root: &Path, operation_id: &str) -> anyhow::Result<()> {
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

fn discard_proven_partial_staging(adoption_root: &Path, operation_id: &str) -> anyhow::Result<()> {
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

fn verify_completed_staged_install(
    paths: &RebornStoragePaths,
    candidate: &LegacyCandidate,
    snapshot: &Path,
    workspace: Option<&ValidatedWorkspaceImportDecision>,
) -> anyhow::Result<()> {
    verify_canonical_inventory(paths, candidate, snapshot)?;
    if let Some(workspace) = workspace {
        validate_ordinary_tree(&workspace_leaf_path(paths, workspace))?;
    }
    require_ordinary_directory(paths.workspace_root())?;
    Ok(())
}

fn require_proven_staging(staging: &Path, operation_id: &str) -> anyhow::Result<()> {
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

fn remove_staging_owner_marker(staging: &Path, operation_id: &str) -> anyhow::Result<()> {
    require_proven_staging(staging, operation_id)?;
    let marker = staging.join(STAGING_OWNER_FILE);
    fs::remove_file(&marker)
        .with_context(|| format!("remove staging ownership marker {}", marker.display()))?;
    sync_directory(staging)
}

fn reconcile_staged_state(
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

fn reconcile_staged_system(
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

fn reconcile_staged_workspace(
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

fn reconcile_prepare_shape(candidate: &LegacyCandidate, snapshot: &Path) -> anyhow::Result<()> {
    if candidate.kind == LegacySourceKind::BareHome {
        return match snapshot.exists() {
            false => snapshot_source(candidate, snapshot),
            true if bare_source_entries_absent(candidate) => Ok(()),
            true => bail!(
                "adoption journal phase `prepare` does not match the exact bare-home source/snapshot shape; refusing to guess which files are authoritative"
            ),
        };
    }
    match (candidate.source_root.exists(), snapshot.exists()) {
        (true, false) => snapshot_source(candidate, snapshot),
        (false, true) => Ok(()),
        _ => bail!(
            "adoption journal phase `prepare` does not match the exact source/snapshot shape for {}; refusing to guess which files are authoritative",
            candidate.kind.label()
        ),
    }
}

fn snapshot_source(candidate: &LegacyCandidate, snapshot: &Path) -> anyhow::Result<()> {
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

fn require_snapshot_shape(candidate: &LegacyCandidate, snapshot: &Path) -> anyhow::Result<()> {
    require_ordinary_directory(snapshot).with_context(|| {
        format!(
            "adoption snapshot is missing or unsafe at {}; only the offline adoption command may recover it",
            snapshot.display()
        )
    })?;
    let snapshot_handle = open_directory_no_follow(snapshot)?;
    if candidate.kind != LegacySourceKind::BareHome && candidate.source_root.exists() {
        bail!(
            "legacy source {} still exists after snapshot ownership; refusing to copy from an ambiguous source/snapshot pair",
            candidate.source_root.display()
        );
    }
    if candidate.kind == LegacySourceKind::BareHome && !bare_source_entries_absent(candidate) {
        bail!(
            "bare-home legacy DB/key entries remain after snapshot ownership; refusing to copy from an ambiguous source/snapshot pair"
        );
    }
    validate_snapshot_inventory(candidate, snapshot)?;
    ensure_directory_path_matches_handle(snapshot, &snapshot_handle)
}

fn bare_source_entries_absent(candidate: &LegacyCandidate) -> bool {
    candidate
        .db_files
        .iter()
        .all(|file| !candidate.source_root.join(file).exists())
        && (!candidate.has_master_key || !candidate.source_root.join(MASTER_KEY_FILE).exists())
}

fn validate_snapshot_inventory(candidate: &LegacyCandidate, snapshot: &Path) -> anyhow::Result<()> {
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

fn stage_snapshot(
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
fn install_staged(
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

fn verify_canonical_store(
    paths: &RebornStoragePaths,
    durable_state: DurableStateKind,
    verification: CanonicalStoreVerification,
) -> anyhow::Result<()> {
    match (durable_state, verification) {
        (DurableStateKind::EmbeddedLibSql, CanonicalStoreVerification::EmbeddedLibSql) => {
            let state_root = paths.state_root().to_path_buf();
            crate::runtime::block_on_cli(async move {
                ironclaw_composition::open_standalone_secret_store(&state_root)
                    .await
                    .map(|_| ())
            })
            .context("open canonical embedded store and construct the canonical secret resolver")
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

fn verify_canonical_inventory(
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

fn verify_post_migration_canonical_shape(
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
        if name != MASTER_KEY_FILE && !LIBSQL_DB_UNIT.contains(&name.as_ref()) {
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

fn verify_inventory_roots(
    state_root: &Path,
    system_root: &Path,
    candidate: &LegacyCandidate,
    snapshot: &Path,
    label: &str,
) -> anyhow::Result<()> {
    verify_state_inventory(state_root, candidate, snapshot, &format!("{label} state"))?;
    verify_system_inventory(system_root, candidate, snapshot, &format!("{label} system"))
}

fn verify_state_inventory(
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

fn verify_system_inventory(
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

fn require_exact_file_inventory(
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

fn require_matching_tree(source: &Path, destination: &Path, label: &str) -> anyhow::Result<()> {
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

fn require_matching_file(source: &Path, destination: &Path, label: &str) -> anyhow::Result<()> {
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

fn digest_ordinary_file(path: &Path) -> anyhow::Result<String> {
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

fn initialize_fresh_layout(
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
    ] {
        create_or_validate_direct_child(home, path)?;
        sync_directory(path)?;
    }
    write_manifest_last(home, &LayoutManifest::new(requirement))
}

fn write_manifest_last(home: &Path, manifest: &LayoutManifest) -> anyhow::Result<()> {
    let manifest_path = home.join(LAYOUT_MANIFEST_FILE);
    if manifest_path.exists() {
        let existing = read_manifest(&manifest_path)?;
        if existing == *manifest {
            return Ok(());
        }
        bail!(
            "refusing to replace existing layout manifest at {}",
            manifest_path.display()
        );
    }
    let contents = toml::to_string(manifest).context("serialize durable layout manifest")?;
    write_atomic_synced(&manifest_path, &contents, false)
}

fn read_manifest(path: &Path) -> anyhow::Result<LayoutManifest> {
    let contents = read_utf8_file_no_follow(path)?;
    toml::from_str(&contents)
        .map_err(|error| anyhow!("parse durable layout manifest {}: {error}", path.display()))
}

fn admit_manifest(manifest: &LayoutManifest, requirement: LayoutRequirement) -> anyhow::Result<()> {
    match manifest.admit(requirement) {
        ProfileTransitionAdmission::Allowed => Ok(()),
        ProfileTransitionAdmission::Rejected { reason } => {
            bail!("stored durable layout rejects this profile transition: {reason}")
        }
    }
}

fn read_journal(path: &Path) -> anyhow::Result<AdoptionJournal> {
    let contents = read_utf8_file_no_follow(path)?;
    let journal: AdoptionJournal = toml::from_str(&contents)
        .map_err(|error| anyhow!("parse adoption journal {}: {error}", path.display()))?;
    if journal.schema_version != JOURNAL_SCHEMA_VERSION {
        bail!(
            "unsupported layout adoption journal schema_version {}; expected {}",
            journal.schema_version,
            JOURNAL_SCHEMA_VERSION
        );
    }
    journal.validate_source_requirement()?;
    let _ = journal.validated_workspace()?;
    Ok(journal)
}

fn write_journal(path: &Path, journal: &AdoptionJournal) -> anyhow::Result<()> {
    let contents = toml::to_string(journal).context("serialize adoption journal")?;
    write_atomic_synced(path, &contents, true)
}

fn write_atomic_synced(path: &Path, contents: &str, replace: bool) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;
    require_ordinary_directory(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary file beside {}", path.display()))?;
    temp.write_all(contents.as_bytes())
        .with_context(|| format!("write temporary file for {}", path.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("sync temporary file for {}", path.display()))?;
    if replace {
        temp.persist(path).map_err(|error| {
            anyhow!(
                "atomically replace {} with {}: {}",
                path.display(),
                error.file.path().display(),
                error.error
            )
        })?;
    } else {
        temp.persist_noclobber(path).map_err(|error| {
            anyhow!(
                "atomically create {} from {}: {}",
                path.display(),
                error.file.path().display(),
                error.error
            )
        })?;
    }
    sync_directory(parent)
}

fn inspect_legacy_candidates(home: &Path) -> anyhow::Result<Vec<LegacyCandidate>> {
    let sandbox_root = home.join("hosted-single-tenant-volume-sandboxed");
    if unreleased_sandbox_is_populated(&sandbox_root)? {
        bail!(
            "unreleased sandbox legacy root is populated at {}; inspect or archive it explicitly before adoption. IronClaw will not auto-adopt sandbox state or workspaces",
            sandbox_root.display()
        );
    }

    let mut candidates = Vec::new();
    for kind in [
        LegacySourceKind::LocalDev,
        LegacySourceKind::HostedSingleTenant,
        LegacySourceKind::HostedSingleTenantVolume,
    ] {
        let candidate = inspect_profile_root(home, kind)?;
        if let Some(candidate) = candidate {
            candidates.push(candidate);
        }
    }
    if let Some(candidate) = inspect_bare_home(home)? {
        candidates.push(candidate);
    }
    Ok(candidates)
}

fn inspect_profile_root(
    home: &Path,
    kind: LegacySourceKind,
) -> anyhow::Result<Option<LegacyCandidate>> {
    let directory = kind
        .profile_directory()
        .ok_or_else(|| anyhow!("bare home is not a profile root"))?;
    let root = home.join(directory);
    if !root.exists() {
        return Ok(None);
    }
    require_ordinary_directory(&root)?;
    let mut db_files = Vec::new();
    let mut has_master_key = false;
    let mut has_system_content = false;
    let mut has_legacy_skills = false;
    for entry in
        fs::read_dir(&root).with_context(|| format!("read legacy root {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("read entry under {}", root.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let path = entry.path();
        if LIBSQL_DB_UNIT.contains(&name.as_ref()) {
            require_ordinary_file(&path)?;
            db_files.push(name.into_owned());
        } else if name == MASTER_KEY_FILE {
            require_ordinary_file(&path)?;
            validate_master_key_source(&path)?;
            has_master_key = true;
        } else if name == "system" {
            require_ordinary_directory(&path)?;
            has_system_content = system_tree_has_content(&path)?;
            validate_system_tree(&path)?;
        } else if name == "skills" {
            require_ordinary_directory(&path)?;
            validate_ordinary_tree(&path)?;
            has_legacy_skills |= directory_has_content(&path)?;
        } else if name == "tenants" {
            require_ordinary_directory(&path)?;
            has_legacy_skills |= validate_legacy_tenant_skill_tree(&path)?;
        } else if path.is_dir() && directory_is_empty(&path)? {
            // Empty directory entries are not state and cannot be inferred as
            // workspaces or ownership. Leave them in the preserved snapshot.
        } else {
            bail!(
                "unknown entry `{name}` in populated legacy root {}; adoption will not discard or reinterpret it",
                root.display()
            );
        }
    }

    db_files.sort();
    if db_files.iter().any(|file| file != DB_FILE) && !db_files.iter().any(|file| file == DB_FILE) {
        bail!(
            "legacy root {} has libSQL sidecars without {DB_FILE}",
            root.display()
        );
    }
    let populated =
        !db_files.is_empty() || has_master_key || has_system_content || has_legacy_skills;
    if !populated {
        return Ok(None);
    }
    if kind == LegacySourceKind::HostedSingleTenant {
        if !db_files.is_empty() || has_master_key {
            bail!(
                "{} is a PostgreSQL/system-content legacy source but contains embedded DB/key files; inspect it manually",
                root.display()
            );
        }
    } else if !db_files.is_empty() && !has_master_key {
        bail!(
            "legacy embedded state at {} lacks its cached secrets master key; refusing adoption that could make encrypted secrets unreadable",
            root.display()
        );
    }

    Ok(Some(LegacyCandidate {
        kind,
        source_root: root,
        db_files,
        has_master_key,
        has_system_content,
        has_legacy_skills,
    }))
}

fn inspect_bare_home(home: &Path) -> anyhow::Result<Option<LegacyCandidate>> {
    let mut db_files = Vec::new();
    for file in LIBSQL_DB_UNIT {
        let path = home.join(file);
        if path.exists() {
            require_ordinary_file(&path)?;
            db_files.push((*file).to_string());
        }
    }
    let key_path = home.join(MASTER_KEY_FILE);
    let has_master_key = key_path.exists();
    if has_master_key {
        require_ordinary_file(&key_path)?;
        validate_master_key_source(&key_path)?;
    }
    if db_files.is_empty() && !has_master_key {
        return Ok(None);
    }
    if db_files.iter().any(|file| file != DB_FILE) && !db_files.iter().any(|file| file == DB_FILE) {
        bail!(
            "bare Reborn home {} has libSQL sidecars without {DB_FILE}",
            home.display()
        );
    }
    if !db_files.is_empty() && !has_master_key {
        bail!(
            "bare Reborn home {} has embedded state without its cached secrets master key; refusing adoption",
            home.display()
        );
    }
    Ok(Some(LegacyCandidate {
        kind: LegacySourceKind::BareHome,
        source_root: home.to_path_buf(),
        db_files,
        has_master_key,
        has_system_content: false,
        has_legacy_skills: false,
    }))
}

fn unreleased_sandbox_is_populated(path: &Path) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    require_ordinary_directory(path)?;
    directory_has_content(path)
}

fn canonical_layout_is_empty(paths: &RebornStoragePaths) -> anyhow::Result<bool> {
    for path in [
        paths.state_root(),
        paths.system_root(),
        paths.workspace_root(),
        paths.runtime_root(),
    ] {
        if path.exists() && !directory_is_empty(path)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn ensure_canonical_install_targets_empty(paths: &RebornStoragePaths) -> anyhow::Result<()> {
    for path in [paths.state_root(), paths.system_root()] {
        if path.exists() && !directory_is_empty(path)? {
            bail!(
                "canonical destination {} already contains data; adoption never overwrites or merges canonical state",
                path.display()
            );
        }
        if path.exists() {
            fs::remove_dir(path).with_context(|| {
                format!("remove empty canonical placeholder {}", path.display())
            })?;
        }
    }
    Ok(())
}

fn ensure_initial_adoption_namespaces_empty(paths: &RebornStoragePaths) -> anyhow::Result<()> {
    ensure_canonical_install_targets_empty(paths)?;
    for path in [paths.workspace_root(), paths.runtime_root()] {
        if path.exists() && !directory_is_empty(path)? {
            bail!(
                "canonical namespace {} contains unexplained data; initial adoption only permits an empty workspace/runtime namespace and never infers ownership or runtime provenance",
                path.display()
            );
        }
    }
    Ok(())
}

fn validate_adoption_ancestors(
    home: &Path,
    paths: &RebornStoragePaths,
    adoption_root: &Path,
) -> anyhow::Result<()> {
    require_ordinary_directory(home)?;
    if paths.runtime_root().exists() {
        require_ordinary_directory(paths.runtime_root())?;
    }
    if adoption_root.exists() {
        require_ordinary_directory(adoption_root)?;
    }
    Ok(())
}

fn create_adoption_root(
    home: &Path,
    paths: &RebornStoragePaths,
    adoption_root: &Path,
) -> anyhow::Result<()> {
    create_or_validate_direct_child(home, paths.runtime_root())?;
    create_or_validate_direct_child(paths.runtime_root(), adoption_root)
}

fn validate_journal_owned_runtime(
    paths: &RebornStoragePaths,
    adoption_root: &Path,
) -> anyhow::Result<()> {
    require_ordinary_directory(paths.runtime_root())?;
    let runtime_entries = fs::read_dir(paths.runtime_root())
        .with_context(|| format!("read runtime namespace {}", paths.runtime_root().display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "enumerate runtime namespace {}",
                paths.runtime_root().display()
            )
        })?;
    if runtime_entries.len() != 1 || runtime_entries[0].file_name() != ADOPTION_DIR {
        bail!(
            "runtime namespace {} contains unexplained data; recovery permits only the journal-owned layout-adoption directory",
            paths.runtime_root().display()
        );
    }
    require_ordinary_directory(adoption_root)?;
    for entry in fs::read_dir(adoption_root)
        .with_context(|| format!("read adoption root {}", adoption_root.display()))?
    {
        let entry =
            entry.with_context(|| format!("read entry under {}", adoption_root.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let path = entry.path();
        match name.as_ref() {
            JOURNAL_FILE | ADOPTION_LOCK_FILE => require_ordinary_file(&path)?,
            SNAPSHOT_DIR | STAGING_DIR => require_ordinary_directory(&path)?,
            _ => bail!(
                "adoption root {} contains unexplained recovery artifact `{name}`",
                adoption_root.display()
            ),
        }
    }
    Ok(())
}

fn create_or_validate_direct_child(parent: &Path, child: &Path) -> anyhow::Result<()> {
    if child.parent() != Some(parent) {
        bail!(
            "refusing to create non-direct child {} beneath {}",
            child.display(),
            parent.display()
        );
    }
    require_ordinary_directory(parent)?;
    if child.exists() {
        return require_ordinary_directory(child);
    }
    fs::create_dir(child)
        .with_context(|| format!("create adoption directory {}", child.display()))?;
    sync_directory(parent)
}

fn prepare_workspace_import(
    options: Option<&WorkspaceImportOptions>,
    paths: &RebornStoragePaths,
) -> anyhow::Result<Option<WorkspaceImportDecision>> {
    let Some(options) = options else {
        return Ok(None);
    };
    if !options.source.is_absolute() {
        bail!(
            "--workspace-source must be an absolute path; IronClaw never infers an ambient working directory as a workspace"
        );
    }
    require_ordinary_directory(&options.source)?;
    validate_ordinary_tree(&options.source)?;
    let decision = WorkspaceImportDecision {
        source: options.source.clone(),
        tenant: options.tenant.as_str().to_string(),
        user: options.user.as_str().to_string(),
        digest: TenantUserWorkspaceKey::from_tenant_user(&options.tenant, &options.user)
            .digest_segment()
            .to_string(),
    };
    let destination = workspace_leaf_path(paths, &decision.validate()?);
    if destination.exists() {
        bail!(
            "workspace import destination {} already exists; refusing to merge or overwrite a tenant/user workspace leaf",
            destination.display()
        );
    }
    if !options.confirmed {
        bail!(
            "workspace import preview: {} -> {} for tenant `{}` user `{}`; rerun with --confirm-workspace-import to copy without deleting the source",
            decision.source.display(),
            destination.display(),
            decision.tenant,
            decision.user
        );
    }
    Ok(Some(decision))
}

fn is_single_path_segment(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn workspace_leaf_path(
    paths: &RebornStoragePaths,
    workspace: &ValidatedWorkspaceImportDecision,
) -> PathBuf {
    paths.workspace_root().join("users").join(&workspace.digest)
}

fn install_workspace_leaf(
    paths: &RebornStoragePaths,
    workspace: &ValidatedWorkspaceImportDecision,
    staged_leaf: &Path,
) -> anyhow::Result<()> {
    let workspace_root = paths.workspace_root();
    create_or_validate_directory(workspace_root)?;
    let users_root = workspace_root.join("users");
    create_or_validate_directory(&users_root)?;
    let destination = workspace_leaf_path(paths, workspace);
    if destination.exists() {
        bail!(
            "workspace import destination {} already exists; refusing to merge or overwrite a tenant/user workspace leaf",
            destination.display()
        );
    }
    fs::rename(staged_leaf, &destination).with_context(|| {
        format!(
            "install tenant/user workspace leaf {} -> {}",
            staged_leaf.display(),
            destination.display()
        )
    })?;
    sync_directory(&users_root)
}

fn create_or_validate_directory(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        return require_ordinary_directory(path);
    }
    fs::create_dir(path)
        .with_context(|| format!("create canonical directory {}", path.display()))?;
    sync_directory(
        path.parent()
            .ok_or_else(|| anyhow!("canonical directory has no parent: {}", path.display()))?,
    )
}

fn candidate_paths(candidates: &[LegacyCandidate]) -> String {
    candidates
        .iter()
        .map(|candidate| candidate.source_root.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn validate_system_tree(root: &Path) -> anyhow::Result<()> {
    require_ordinary_directory(root)?;
    for entry in
        fs::read_dir(root).with_context(|| format!("read system content {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("read system entry under {}", root.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !SYSTEM_CONTENT_DIRS.contains(&name.as_ref()) {
            bail!(
                "unknown system entry `{name}` under {}; adoption will not reinterpret it",
                root.display()
            );
        }
        validate_ordinary_tree(&entry.path())?;
    }
    Ok(())
}

/// Validate the one released host-disk user-skill grammar without accepting
/// arbitrary tenant content as a migration source.
fn validate_legacy_tenant_skill_tree(tenants_root: &Path) -> anyhow::Result<bool> {
    let mut has_content = false;
    for tenant in fs::read_dir(tenants_root)
        .with_context(|| format!("read legacy tenants tree {}", tenants_root.display()))?
    {
        let tenant = tenant
            .with_context(|| format!("read tenant entry under {}", tenants_root.display()))?;
        let tenant_path = tenant.path();
        require_ordinary_directory(&tenant_path)?;
        let tenant_name = tenant.file_name().to_string_lossy().into_owned();
        TenantId::new(tenant_name.clone())
            .map_err(|error| anyhow!("invalid legacy skill tenant `{tenant_name}`: {error}"))?;
        let users_root = tenant_path.join("users");
        for entry in fs::read_dir(&tenant_path)
            .with_context(|| format!("read legacy tenant {}", tenant_path.display()))?
        {
            let entry = entry.with_context(|| {
                format!("read entry under legacy tenant {}", tenant_path.display())
            })?;
            if entry.file_name() != "users" {
                bail!(
                    "unknown entry `{}` under legacy tenant {}; only users/<user>/skills is adoptable",
                    entry.file_name().to_string_lossy(),
                    tenant_path.display()
                );
            }
            require_ordinary_directory(&entry.path())?;
        }
        if !users_root.exists() {
            continue;
        }
        for user in fs::read_dir(&users_root)
            .with_context(|| format!("read legacy users tree {}", users_root.display()))?
        {
            let user =
                user.with_context(|| format!("read user entry under {}", users_root.display()))?;
            let user_path = user.path();
            require_ordinary_directory(&user_path)?;
            let user_name = user.file_name().to_string_lossy().into_owned();
            UserId::new(user_name.clone())
                .map_err(|error| anyhow!("invalid legacy skill user `{user_name}`: {error}"))?;
            let skills_root = user_path.join("skills");
            for entry in fs::read_dir(&user_path)
                .with_context(|| format!("read legacy user {}", user_path.display()))?
            {
                let entry = entry.with_context(|| {
                    format!("read entry under legacy user {}", user_path.display())
                })?;
                if entry.file_name() != "skills" {
                    bail!(
                        "unknown entry `{}` under legacy user {}; only the skills tree is adoptable",
                        entry.file_name().to_string_lossy(),
                        user_path.display()
                    );
                }
                require_ordinary_directory(&entry.path())?;
            }
            if skills_root.exists() {
                validate_ordinary_tree(&skills_root)?;
                has_content |= directory_has_content(&skills_root)?;
            }
        }
    }
    Ok(has_content)
}

fn system_tree_has_content(root: &Path) -> anyhow::Result<bool> {
    for entry in
        fs::read_dir(root).with_context(|| format!("read system content {}", root.display()))?
    {
        let entry = entry.with_context(|| format!("read system entry under {}", root.display()))?;
        if directory_has_content(&entry.path())? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn copy_system_tree(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let source_handle = open_directory_no_follow(source)?;
    for entry in
        fs::read_dir(source).with_context(|| format!("read system source {}", source.display()))?
    {
        let entry = entry
            .with_context(|| format!("read system source entry under {}", source.display()))?;
        let destination = destination.join(entry.file_name());
        copy_ordinary_tree(&entry.path(), &destination)?;
    }
    ensure_directory_path_matches_handle(source, &source_handle)?;
    Ok(())
}

fn copy_ordinary_tree(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("inspect source {}", source.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing symbolic link in adoption source: {}",
            source.display()
        );
    }
    if metadata.is_file() {
        return copy_ordinary_file(source, destination);
    }
    if !metadata.is_dir() {
        bail!("refusing non-ordinary source entry: {}", source.display());
    }
    let source_handle = open_directory_no_follow(source)?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| anyhow!("destination has no parent: {}", destination.display()))?;
    require_ordinary_directory(destination_parent)?;
    fs::create_dir(destination)
        .with_context(|| format!("create destination directory {}", destination.display()))?;
    for entry in fs::read_dir(source)
        .with_context(|| format!("read source directory {}", source.display()))?
    {
        let entry =
            entry.with_context(|| format!("read source entry under {}", source.display()))?;
        copy_ordinary_tree(&entry.path(), &destination.join(entry.file_name()))?;
    }
    ensure_directory_path_matches_handle(source, &source_handle)?;
    sync_directory(destination)
}

fn copy_ordinary_file(source: &Path, destination: &Path) -> anyhow::Result<()> {
    require_ordinary_file(source)?;
    let mut input = open_file_no_follow(source)?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| anyhow!("destination has no parent: {}", destination.display()))?;
    require_ordinary_directory(destination_parent)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| format!("create destination file {}", destination.display()))?;
    std::io::copy(&mut input, &mut output)
        .with_context(|| format!("copy {} -> {}", source.display(), destination.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync copied file {}", destination.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(source)
            .with_context(|| format!("read source mode {}", source.display()))?
            .permissions()
            .mode();
        fs::set_permissions(destination, fs::Permissions::from_mode(mode))
            .with_context(|| format!("preserve mode on {}", destination.display()))?;
    }
    Ok(())
}

/// Copy the cached secrets master key under the owner-only policy. The output
/// is created with mode 0600 before any bytes are written and that policy is
/// re-established and verified after the synced copy. On Unix the mode is the
/// POSIX ACL mask, so it denies group and other access for the entire copy.
fn copy_master_key(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let mut input = validate_master_key_source(source)?;
    let destination_parent = destination.parent().ok_or_else(|| {
        anyhow!(
            "master key destination has no parent: {}",
            destination.display()
        )
    })?;
    require_ordinary_directory(destination_parent)?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = options
        .open(destination)
        .with_context(|| format!("create owner-only master key {}", destination.display()))?;
    std::io::copy(&mut input, &mut output).with_context(|| {
        format!(
            "copy master key {} -> {}",
            source.display(),
            destination.display()
        )
    })?;
    output
        .sync_all()
        .with_context(|| format!("sync copied master key {}", destination.display()))?;
    establish_and_verify_master_key_policy(destination)
}

fn validate_master_key_source(path: &Path) -> anyhow::Result<File> {
    require_ordinary_file(path)?;
    let file = open_file_no_follow(path)?;
    verify_master_key_policy(&file, path, "source")?;
    Ok(file)
}

fn establish_and_verify_master_key_policy(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "re-establish owner-only master key mode at {}",
                path.display()
            )
        })?;
    }
    let file = open_file_no_follow(path)?;
    verify_master_key_policy(&file, path, "destination")
}

fn verify_master_key_policy(file: &File, path: &Path, location: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let mode = file
            .metadata()
            .with_context(|| format!("read {location} master key metadata at {}", path.display()))?
            .mode()
            & 0o777;
        if mode != 0o600 {
            bail!(
                "{location} master key at {} must have owner-only mode 0600; found {mode:03o}",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path, location);
    }
    Ok(())
}

fn open_file_no_follow(path: &Path) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).with_context(|| {
        format!(
            "open ordinary source file without following links {}",
            path.display()
        )
    })
}

fn open_directory_no_follow(path: &Path) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    options.open(path).with_context(|| {
        format!(
            "open ordinary directory without following links {}",
            path.display()
        )
    })
}

fn ensure_directory_path_matches_handle(path: &Path, handle: &File) -> anyhow::Result<()> {
    let reopened = open_directory_no_follow(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let original = handle
            .metadata()
            .with_context(|| format!("read opened directory metadata {}", path.display()))?;
        let current = reopened
            .metadata()
            .with_context(|| format!("read reopened directory metadata {}", path.display()))?;
        if original.dev() != current.dev() || original.ino() != current.ino() {
            bail!(
                "directory {} changed while adoption was traversing it; refusing to continue with a raced path",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (handle, reopened);
    }
    Ok(())
}

fn read_utf8_file_no_follow(path: &Path) -> anyhow::Result<String> {
    require_ordinary_file(path)?;
    let mut file = open_file_no_follow(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("read UTF-8 text file {}", path.display()))?;
    Ok(contents)
}

fn validate_ordinary_tree(path: &Path) -> anyhow::Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing symbolic link in adoption source: {}",
            path.display()
        );
    }
    if metadata.is_file() {
        return Ok(());
    }
    if !metadata.is_dir() {
        bail!("refusing non-ordinary source entry: {}", path.display());
    }
    let directory_handle = open_directory_no_follow(path)?;
    for entry in
        fs::read_dir(path).with_context(|| format!("read source directory {}", path.display()))?
    {
        let entry = entry.with_context(|| format!("read source entry under {}", path.display()))?;
        validate_ordinary_tree(&entry.path())?;
    }
    ensure_directory_path_matches_handle(path, &directory_handle)
}

fn require_ordinary_file(path: &Path) -> anyhow::Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "expected an ordinary non-symlink file at {}",
            path.display()
        );
    }
    Ok(())
}

fn require_ordinary_directory(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "expected an ordinary non-symlink directory at {}",
            path.display()
        );
    }
    let handle = open_directory_no_follow(path)?;
    if !handle
        .metadata()
        .with_context(|| format!("read opened directory metadata {}", path.display()))?
        .is_dir()
    {
        bail!(
            "expected an ordinary non-symlink directory at {}",
            path.display()
        );
    }
    Ok(())
}

fn directory_is_empty(path: &Path) -> anyhow::Result<bool> {
    require_ordinary_directory(path)?;
    Ok(fs::read_dir(path)
        .with_context(|| format!("read directory {}", path.display()))?
        .next()
        .is_none())
}

fn directory_has_content(path: &Path) -> anyhow::Result<bool> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "refusing symbolic link in adoption candidate: {}",
            path.display()
        );
    }
    if metadata.is_file() {
        return Ok(true);
    }
    if !metadata.is_dir() {
        bail!(
            "refusing non-ordinary adoption candidate entry: {}",
            path.display()
        );
    }
    for entry in fs::read_dir(path).with_context(|| format!("read directory {}", path.display()))? {
        let entry = entry.with_context(|| format!("read entry under {}", path.display()))?;
        if directory_has_content(&entry.path())? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sync_directory(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        open_directory_no_follow(path)?
            .sync_all()
            .with_context(|| format!("sync directory {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

struct AdoptionLock {
    #[cfg(unix)]
    _file: File,
    #[cfg(not(unix))]
    path: PathBuf,
}

#[cfg(not(unix))]
impl Drop for AdoptionLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn acquire_adoption_lock(adoption_root: &Path) -> anyhow::Result<AdoptionLock> {
    let path = adoption_root.join(ADOPTION_LOCK_FILE);
    require_ordinary_directory(adoption_root)?;
    #[cfg(unix)]
    let mut file = open_adoption_lock_file(&path)?;
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| {
            format!(
                "another storage adoption may already be running; advisory lock {} exists",
                path.display()
            )
        })?;
    #[cfg(unix)]
    file.try_lock_exclusive().with_context(|| {
        format!(
            "another storage adoption is holding advisory lock {}; wait for it to finish before retrying",
            path.display()
        )
    })?;
    file.set_len(0)
        .with_context(|| format!("clear advisory lock {}", path.display()))?;
    writeln!(file, "pid={}", std::process::id())
        .with_context(|| format!("write advisory lock {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync advisory lock {}", path.display()))?;
    sync_directory(adoption_root)?;
    Ok(AdoptionLock {
        #[cfg(unix)]
        _file: file,
        #[cfg(not(unix))]
        path,
    })
}

#[cfg(unix)]
fn open_adoption_lock_file(path: &Path) -> anyhow::Result<File> {
    if path.exists() {
        require_ordinary_file(path)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).with_context(|| {
        format!(
            "open advisory lock without following links {}",
            path.display()
        )
    })
}

fn acquire_existing_adoption_lock(adoption_root: &Path) -> anyhow::Result<AdoptionLock> {
    if !adoption_root.is_dir() {
        bail!(
            "adoption journal parent is not an ordinary directory at {}; refusing recovery",
            adoption_root.display()
        );
    }
    acquire_adoption_lock(adoption_root)
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestAdoptionFaultPoint {
    StagingChildrenCreated,
    FirstStateCopy,
    StateRename,
    MarkerRemovedBeforeStagingDirectoryRemoval,
}

#[cfg(test)]
thread_local! {
    static TEST_ADOPTION_FAULT: std::cell::Cell<Option<TestAdoptionFaultPoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
struct TestAdoptionFaultGuard;

#[cfg(test)]
impl TestAdoptionFaultGuard {
    fn arm(point: TestAdoptionFaultPoint) -> Self {
        TEST_ADOPTION_FAULT.with(|fault| fault.set(Some(point)));
        Self
    }
}

#[cfg(test)]
impl Drop for TestAdoptionFaultGuard {
    fn drop(&mut self) {
        TEST_ADOPTION_FAULT.with(|fault| fault.set(None));
    }
}

#[cfg(test)]
fn fail_at_test_adoption_fault(point: TestAdoptionFaultPoint) -> anyhow::Result<()> {
    let should_fail = TEST_ADOPTION_FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            true
        } else {
            false
        }
    });
    if should_fail {
        bail!("injected ENOSPC-style adoption fault at {point:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::process::Command;
    #[cfg(unix)]
    use std::thread;
    #[cfg(unix)]
    use std::time::{Duration, Instant};

    use ironclaw_config::{
        DeploymentSecurityEnvelope, DurableStateKind, LayoutRequirement, RebornHome, TenancyModel,
        WorkspaceAccessFloor,
    };

    use super::{
        ADOPTION_DIR, AdoptOptions, AdoptionJournal, AdoptionPhase, CanonicalStoreVerification,
        LegacySourceKind, RebornStoragePaths, STAGING_OWNER_FILE, TestAdoptionFaultGuard,
        TestAdoptionFaultPoint, WorkspaceImportDecision, WorkspaceImportOptions,
        acquire_adoption_lock, adopt_layout, adopt_layout_with_store_verification,
        ensure_ready_layout, inspect_legacy_candidates, inspect_ready_layout, install_staged,
        ready_legacy_skill_snapshot_source, snapshot_source, stage_snapshot,
        verify_canonical_store, write_journal,
    };
    use ironclaw_composition::LegacySkillSnapshotSource;
    use ironclaw_host_api::ids::{TenantId, TenantUserWorkspaceKey, UserId};

    fn embedded_single_user_requirement() -> LayoutRequirement {
        LayoutRequirement {
            durable_state: DurableStateKind::EmbeddedLibSql,
            security: DeploymentSecurityEnvelope {
                tenancy: TenancyModel::SingleUser,
                workspace_access_floor: WorkspaceAccessFloor::SingleTrustedOperator,
            },
        }
    }

    fn external_single_user_requirement() -> LayoutRequirement {
        LayoutRequirement {
            durable_state: DurableStateKind::ExternalPostgres,
            security: DeploymentSecurityEnvelope {
                tenancy: TenancyModel::SingleUser,
                workspace_access_floor: WorkspaceAccessFloor::SingleTrustedOperator,
            },
        }
    }

    fn embedded_multi_user_requirement() -> LayoutRequirement {
        LayoutRequirement {
            durable_state: DurableStateKind::EmbeddedLibSql,
            security: DeploymentSecurityEnvelope {
                tenancy: TenancyModel::MultiUser,
                workspace_access_floor: WorkspaceAccessFloor::PerCallerIsolated,
            },
        }
    }

    fn confirmed_options() -> AdoptOptions {
        AdoptOptions {
            confirm_processes_stopped: true,
            confirm_backup_snapshot: true,
            workspace_import: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn advisory_lock_holder_subprocess() {
        let Ok(adoption_root) = std::env::var("IRONCLAW_TEST_ADOPTION_LOCK_ROOT") else {
            return;
        };
        let ready =
            std::env::var("IRONCLAW_TEST_ADOPTION_LOCK_READY").expect("lock holder ready path");
        let release =
            std::env::var("IRONCLAW_TEST_ADOPTION_LOCK_RELEASE").expect("lock holder release path");
        let _lock = acquire_adoption_lock(std::path::Path::new(&adoption_root))
            .expect("subprocess holds adoption lock");
        fs::write(ready, b"ready").expect("signal held lock");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !std::path::Path::new(&release).is_file() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            std::path::Path::new(&release).is_file(),
            "parent did not release lock holder within the bounded test interval"
        );
    }

    #[cfg(unix)]
    #[test]
    fn advisory_lock_recovers_after_a_crashed_process_without_reusing_a_stale_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let adoption_root = temp.path().join("layout-adoption");
        fs::create_dir(&adoption_root).expect("adoption root");
        let ready = temp.path().join("lock-ready");
        let release = temp.path().join("lock-release");
        let test_binary = std::env::current_exe().expect("test binary");
        let mut child = Command::new(test_binary)
            .args([
                "--exact",
                "runtime::storage_layout::tests::advisory_lock_holder_subprocess",
                "--nocapture",
            ])
            .env("IRONCLAW_TEST_ADOPTION_LOCK_ROOT", &adoption_root)
            .env("IRONCLAW_TEST_ADOPTION_LOCK_READY", &ready)
            .env("IRONCLAW_TEST_ADOPTION_LOCK_RELEASE", &release)
            .spawn()
            .expect("spawn lock holder");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.is_file(), "lock holder reached its critical section");
        let contention = match acquire_adoption_lock(&adoption_root) {
            Ok(_) => panic!("live lock holder prevents concurrent adoption"),
            Err(error) => error,
        };
        assert!(
            !format!("{contention:#}").is_empty(),
            "contention exposes a diagnostic error"
        );
        fs::write(&release, b"release").expect("release lock holder");
        let status = child.wait().expect("wait for released lock holder");
        assert!(
            status.success(),
            "lock holder exits cleanly after its descriptor is released"
        );

        let _lock = acquire_adoption_lock(&adoption_root)
            .expect("OS advisory lock is released when the holder process exits");
    }

    fn workspace_import(source: std::path::PathBuf, confirmed: bool) -> WorkspaceImportOptions {
        WorkspaceImportOptions {
            source,
            tenant: TenantId::new("tenant-a").expect("tenant id"),
            user: UserId::new("user-a").expect("user id"),
            confirmed,
        }
    }

    fn reborn_home(path: &std::path::Path) -> RebornHome {
        RebornHome::resolve_from_env_parts(Some(path.as_os_str().to_os_string()), None, None)
            .expect("test Reborn home")
    }

    fn seed_legacy_embedded_store(root: &std::path::Path) {
        fs::create_dir_all(root).expect("legacy root");
        let key = ironclaw_secrets::keychain::generate_master_key_hex();
        fs::write(
            root.join(ironclaw_composition::STANDALONE_SECRETS_MASTER_KEY_PATH),
            key,
        )
        .expect("legacy key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                root.join(ironclaw_composition::STANDALONE_SECRETS_MASTER_KEY_PATH),
                fs::Permissions::from_mode(0o600),
            )
            .expect("owner-only legacy key");
        }
        crate::runtime::block_on_cli({
            let root = root.to_path_buf();
            async move {
                ironclaw_composition::open_standalone_secret_store(&root)
                    .await
                    .map(|_| ())
            }
        })
        .expect("seed legacy libSQL store");
    }

    #[test]
    fn fresh_home_initializes_canonical_namespaces_and_commits_manifest_last() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = reborn_home(temp.path());

        ensure_ready_layout(&home, embedded_single_user_requirement())
            .expect("fresh home initializes");

        assert!(temp.path().join("layout.toml").is_file());
        assert!(temp.path().join("state").is_dir());
        assert!(temp.path().join("system").is_dir());
        assert!(temp.path().join("workspaces").is_dir());
        assert!(temp.path().join("runtime").is_dir());
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
    }

    #[test]
    fn normal_boot_refuses_legacy_root_without_mutating_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = reborn_home(temp.path());
        let legacy = temp.path().join("local-dev");
        seed_legacy_embedded_store(&legacy);

        let error = ensure_ready_layout(&home, embedded_single_user_requirement())
            .expect_err("normal boot must require offline adoption");

        assert!(error.to_string().contains("ironclaw storage adopt"));
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
        fs::create_dir_all(legacy.join("system/extensions")).expect("legacy system root");
        fs::write(legacy.join("system/extensions/example.toml"), b"extension").expect("extension");

        adopt_layout(
            &home,
            embedded_single_user_requirement(),
            confirmed_options(),
        )
        .expect("offline adoption succeeds");

        assert!(temp.path().join("layout.toml").is_file());
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

        adopt_layout_with_store_verification(
            &home,
            external_single_user_requirement(),
            confirmed_options(),
            CanonicalStoreVerification::ExternalPostgresVerified,
        )
        .expect("verified PostgreSQL system-content adoption resumes and succeeds");

        assert!(temp.path().join("system/prompts/operator.md").is_file());
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
        assert!(snapshot.is_dir());
        assert!(journal.is_file());

        adopt_layout(
            &home,
            embedded_single_user_requirement(),
            confirmed_options(),
        )
        .expect("completed adoption is a no-op");
        assert!(snapshot.is_dir());
        assert!(journal.is_file());
    }

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
    fn tampered_workspace_journal_identity_is_rejected_before_snapshot_or_install() {
        for journal_digest in ["not-the-canonical-digest", "../escape"] {
            let temp = tempfile::tempdir().expect("tempdir");
            let home = reborn_home(temp.path());
            let requirement = embedded_single_user_requirement();
            let legacy = temp.path().join("local-dev");
            seed_legacy_embedded_store(&legacy);
            let workspace_source = temp.path().join("workspace-source");
            fs::create_dir_all(&workspace_source).expect("workspace source");
            fs::write(workspace_source.join("keep.txt"), b"workspace data")
                .expect("workspace file");
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

        adopt_layout(&home, requirement, confirmed_options())
            .expect("recovery completes the remaining system rename");
        assert!(temp.path().join("layout.toml").is_file());
    }

    #[test]
    fn offline_adopt_resumes_every_persisted_phase_and_commits_manifest_last() {
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
            adopt_layout(&home, requirement, confirmed_options())
                .expect("resume exact persisted phase");
            assert!(temp.path().join("layout.toml").is_file());
            assert!(temp.path().join("state/reborn-local-dev.db").is_file());
        }
    }
}
