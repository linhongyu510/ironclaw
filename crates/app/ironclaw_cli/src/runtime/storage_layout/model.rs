use super::*;
use super::{adoption::*, filesystem::*, locks::*};

pub(super) const LAYOUT_MANIFEST_FILE: &str = "layout.toml";
pub(super) const ADOPTION_DIR: &str = "layout-adoption";
pub(super) const JOURNAL_FILE: &str = "journal.toml";
pub(super) const SNAPSHOT_DIR: &str = "snapshot";
pub(super) const STAGING_DIR: &str = "staging";
pub(super) const STAGING_OWNER_FILE: &str = ".adoption-owner";
pub(super) const ADOPTION_LOCK_FILE: &str = "adoption.lock";
pub(super) const CUTOVER_LOCK_FILE: &str = ".reborn-storage-cutover.lock";
pub(super) const JOURNAL_SCHEMA_VERSION: u32 = 4;
pub(super) const DB_FILE: &str = "reborn-local-dev.db";
pub(super) const MASTER_KEY_FILE: &str = ".reborn-local-dev-secrets-master-key";
pub(super) const LIBSQL_DB_UNIT: &[&str] = &[
    DB_FILE,
    "reborn-local-dev.db-wal",
    "reborn-local-dev.db-shm",
    "reborn-local-dev.db-journal",
];
pub(super) const SYSTEM_CONTENT_DIRS: &[&str] = &["extensions", "prompts", "skills"];
pub(super) const OFFLINE_ADOPT_COMMAND: &str =
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
pub(super) enum AdoptionPhase {
    Prepare,
    SnapshotOwned,
    Staged,
    CanonicalInstalled,
    MigrationPending,
    StoreVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum LegacySourceKind {
    LocalDev,
    HostedSingleTenant,
    HostedSingleTenantVolume,
    BareHome,
}

impl LegacySourceKind {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::LocalDev => "local-dev",
            Self::HostedSingleTenant => "hosted-single-tenant",
            Self::HostedSingleTenantVolume => "hosted-single-tenant-volume",
            Self::BareHome => "bare-home",
        }
    }

    pub(super) const fn profile_directory(self) -> Option<&'static str> {
        match self {
            Self::LocalDev => Some("local-dev"),
            Self::HostedSingleTenant => Some("hosted-single-tenant"),
            Self::HostedSingleTenantVolume => Some("hosted-single-tenant-volume"),
            Self::BareHome => None,
        }
    }

    pub(super) const fn skill_snapshot_source(self) -> LegacySkillSnapshotSource {
        match self {
            Self::LocalDev => LegacySkillSnapshotSource::LocalDev,
            Self::HostedSingleTenant => LegacySkillSnapshotSource::HostedSingleTenant,
            Self::HostedSingleTenantVolume => LegacySkillSnapshotSource::HostedSingleTenantVolume,
            Self::BareHome => LegacySkillSnapshotSource::BareHome,
        }
    }

    /// The historical source envelope is fixed and never inferred from the
    /// requested target profile.
    pub(super) const fn requirement(self) -> LayoutRequirement {
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
pub(super) struct LegacyCandidate {
    pub(super) kind: LegacySourceKind,
    pub(super) source_root: PathBuf,
    pub(super) db_files: Vec<String>,
    pub(super) has_master_key: bool,
    pub(super) has_system_content: bool,
    pub(super) has_legacy_skills: bool,
}

impl LegacyCandidate {
    pub(super) fn is_embedded(&self) -> bool {
        self.kind.requirement().durable_state == DurableStateKind::EmbeddedLibSql
    }

    pub(super) fn snapshot_root(&self, adoption_root: &Path) -> PathBuf {
        adoption_root.join(SNAPSHOT_DIR).join(self.kind.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdoptionInventory {
    pub(super) db_files: Vec<String>,
    pub(super) has_master_key: bool,
    pub(super) has_system_content: bool,
    pub(super) has_legacy_skills: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdoptionJournal {
    pub(super) schema_version: u32,
    pub(super) operation_id: String,
    pub(super) source: LegacySourceKind,
    pub(super) phase: AdoptionPhase,
    pub(super) source_requirement: LayoutRequirement,
    pub(super) target_requirement: LayoutRequirement,
    #[serde(default)]
    pub(super) memory_provider_app_id: Option<String>,
    pub(super) inventory: AdoptionInventory,
    pub(super) workspace: Option<WorkspaceImportDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkspaceImportDecision {
    pub(super) source: PathBuf,
    pub(super) tenant: String,
    pub(super) user: String,
    pub(super) digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ValidatedWorkspaceImportDecision {
    pub(super) source: PathBuf,
    pub(super) tenant: TenantId,
    pub(super) user: UserId,
    pub(super) digest: String,
}

impl WorkspaceImportDecision {
    pub(super) fn validate(&self) -> anyhow::Result<ValidatedWorkspaceImportDecision> {
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
    pub(super) fn new(
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
            memory_provider_app_id: Some(ironclaw_config::legacy_memory_provider_app_id(
                &candidate.source_root,
            )),
            inventory: AdoptionInventory {
                db_files: candidate.db_files.clone(),
                has_master_key: candidate.has_master_key,
                has_system_content: candidate.has_system_content,
                has_legacy_skills: candidate.has_legacy_skills,
            },
            workspace,
        }
    }

    pub(super) fn candidate(&self, home: &Path) -> LegacyCandidate {
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

    pub(super) fn validate_source_requirement(&self) -> anyhow::Result<()> {
        Uuid::parse_str(&self.operation_id)
            .map_err(|error| anyhow!("adoption journal operation_id must be a UUID: {error}"))?;
        if self.source_requirement != self.source.requirement() {
            bail!(
                "adoption journal source security requirement does not match its fixed legacy source kind; refusing to resume"
            );
        }
        Ok(())
    }

    pub(super) fn validated_workspace(
        &self,
    ) -> anyhow::Result<Option<ValidatedWorkspaceImportDecision>> {
        self.workspace
            .as_ref()
            .map(WorkspaceImportDecision::validate)
            .transpose()
    }
}

/// Typed startup decision before any legacy adoption work begins.
#[derive(Debug)]
pub(crate) enum StartupLayoutAdmission {
    Ready(RebornStoragePaths),
    AdoptionRequired,
}

/// Ephemeral deployment evidence that old replicas were stopped before this
/// process was allowed to mutate a released storage layout.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StartupAdoptionAuthority(());

impl StartupAdoptionAuthority {
    pub(crate) const ENV: &'static str = "IRONCLAW_REBORN_STORAGE_CUTOVER";
    pub(crate) const LEGACY_LAYOUT_V1: &'static str = "legacy-layout-v1";

    pub(crate) fn from_environment_value(value: Option<&str>) -> anyhow::Result<Self> {
        match value {
            Some(Self::LEGACY_LAYOUT_V1) => Ok(Self(())),
            None => bail!(
                "legacy durable storage requires a deployment cutover before automatic adoption; stop every old replica, then set {}={} for the migration startup, or run `{OFFLINE_ADOPT_COMMAND}`",
                Self::ENV,
                Self::LEGACY_LAYOUT_V1
            ),
            Some(_) => bail!(
                "{} must be exactly `{}` when the deployment has stopped every old replica",
                Self::ENV,
                Self::LEGACY_LAYOUT_V1
            ),
        }
    }
}

/// Holds the new-binary cutover lock from preflight through store verification
/// and the complete journaled adoption operation.
pub(crate) struct AutomaticAdoptionPermit {
    pub(super) home: PathBuf,
    pub(super) requirement: LayoutRequirement,
    _lock: AdoptionLock,
}

pub(crate) fn prepare_automatic_adoption(
    home: &RebornHome,
    requirement: LayoutRequirement,
    _authority: StartupAdoptionAuthority,
) -> anyhow::Result<AutomaticAdoptionPermit> {
    preflight_automatic_adoption(home, requirement)?;
    let lock = acquire_named_lock(home.path(), CUTOVER_LOCK_FILE, "automatic storage cutover")?;
    // Classification happened before the lock. Re-read every source/journal
    // invariant under the lock before a PostgreSQL verifier can run.
    preflight_automatic_adoption(home, requirement)?;
    Ok(AutomaticAdoptionPermit {
        home: home.path().to_path_buf(),
        requirement,
        _lock: lock,
    })
}

pub(super) fn preflight_automatic_adoption(
    home: &RebornHome,
    requirement: LayoutRequirement,
) -> anyhow::Result<()> {
    let home_path = home.path();
    let paths = RebornStoragePaths::from_home(home);
    let manifest_path = home_path.join(LAYOUT_MANIFEST_FILE);
    if manifest_path.exists() {
        bail!("automatic adoption is unnecessary because the canonical layout is already ready");
    }
    let adoption_root = paths.runtime_root().join(ADOPTION_DIR);
    let journal_path = adoption_root.join(JOURNAL_FILE);
    validate_adoption_ancestors(home_path, &paths, &adoption_root)?;
    if journal_path.exists() {
        validate_journal_owned_runtime(&paths, &adoption_root)?;
        let journal = read_journal(&journal_path)?;
        journal.validate_source_requirement()?;
        admit_manifest(
            &LayoutManifest::new(journal.source_requirement),
            requirement,
        )?;
        if journal.target_requirement != requirement {
            bail!("adoption journal security requirement does not match this automatic restart");
        }
        if journal.workspace.is_some() {
            bail!(
                "automatic startup will not resume an external workspace import; keep services stopped and resume with `{OFFLINE_ADOPT_COMMAND}` so tenant/user ownership remains explicit"
            );
        }
        validate_automatic_journal_resume_shape(home_path, &paths, &adoption_root, &journal)?;
        return Ok(());
    }

    let candidates = inspect_legacy_candidates(home_path)?;
    if candidates.len() != 1 {
        if candidates.is_empty() {
            bail!("automatic adoption requires exactly one supported populated legacy source");
        }
        bail!(
            "multiple populated legacy roots detected; no source was selected or modified: {}",
            candidate_paths(&candidates)
        );
    }
    admit_manifest(
        &LayoutManifest::new(candidates[0].kind.requirement()),
        requirement,
    )?;
    validate_initial_adoption_namespaces_empty(&paths)
}

/// Prove that an interrupted journal's recorded phase matches the filesystem
/// before startup is allowed to connect to or migrate an external store.
pub(super) fn validate_automatic_journal_resume_shape(
    home: &Path,
    paths: &RebornStoragePaths,
    adoption_root: &Path,
    journal: &AdoptionJournal,
) -> anyhow::Result<()> {
    let candidate = journal.candidate(home);
    let snapshot = candidate.snapshot_root(adoption_root);
    validate_automatic_workspace_namespace(paths)?;
    match journal.phase {
        AdoptionPhase::Prepare => {
            validate_pre_install_namespaces(paths)?;
            if ordinary_directory_presence(
                &adoption_root.join(STAGING_DIR),
                "prepare-phase staging root",
            )? {
                bail!("prepare-phase adoption journal cannot own a staging tree");
            }
            validate_prepare_recovery_shape(home, &candidate, &snapshot)
        }
        AdoptionPhase::SnapshotOwned => {
            validate_pre_install_namespaces(paths)?;
            require_snapshot_shape(&candidate, &snapshot)?;
            validate_discardable_staging(adoption_root, &journal.operation_id)
        }
        AdoptionPhase::Staged => {
            require_snapshot_shape(&candidate, &snapshot)?;
            validate_staged_recovery_shape(
                paths,
                &candidate,
                &snapshot,
                adoption_root,
                &journal.operation_id,
            )
        }
        AdoptionPhase::CanonicalInstalled => {
            require_snapshot_shape(&candidate, &snapshot)?;
            verify_canonical_inventory(paths, &candidate, &snapshot)?;
            validate_completed_staging(adoption_root, &journal.operation_id)
        }
        AdoptionPhase::MigrationPending => {
            require_snapshot_shape(&candidate, &snapshot)?;
            validate_no_staging_root(adoption_root, "migration-pending")?;
            verify_post_migration_canonical_shape(paths, &candidate, &snapshot, false)
        }
        AdoptionPhase::StoreVerified => {
            require_snapshot_shape(&candidate, &snapshot)?;
            validate_no_staging_root(adoption_root, "store-verified")?;
            verify_post_migration_canonical_shape(paths, &candidate, &snapshot, true)
        }
    }
}

pub(super) fn validate_automatic_workspace_namespace(
    paths: &RebornStoragePaths,
) -> anyhow::Result<()> {
    if ordinary_directory_presence(
        paths.workspace_root(),
        "automatic-adoption workspace namespace",
    )? && !directory_is_empty(paths.workspace_root())?
    {
        bail!(
            "automatic adoption journal has no workspace owner but {} contains data",
            paths.workspace_root().display()
        );
    }
    Ok(())
}

pub(super) fn validate_no_staging_root(adoption_root: &Path, phase: &str) -> anyhow::Result<()> {
    let staging = adoption_root.join(STAGING_DIR);
    if ordinary_directory_presence(&staging, &format!("{phase} staging root"))? {
        bail!("adoption journal phase `{phase}` cannot retain a staging tree");
    }
    Ok(())
}

pub(super) fn validate_pre_install_namespaces(paths: &RebornStoragePaths) -> anyhow::Result<()> {
    for path in [paths.state_root(), paths.system_root()] {
        if ordinary_directory_presence(path, "pre-install canonical destination")? {
            bail!(
                "pre-install adoption journal conflicts with canonical destination {}",
                path.display()
            );
        }
    }
    if ordinary_directory_presence(paths.workspace_root(), "pre-install workspace namespace")?
        && !directory_is_empty(paths.workspace_root())?
    {
        bail!(
            "pre-install adoption journal conflicts with populated workspace namespace {}",
            paths.workspace_root().display()
        );
    }
    Ok(())
}

pub(super) fn validate_prepare_recovery_shape(
    home: &Path,
    candidate: &LegacyCandidate,
    snapshot: &Path,
) -> anyhow::Result<()> {
    if ordinary_directory_presence(snapshot, "prepare-phase adoption snapshot")? {
        let source_is_absent = if candidate.kind == LegacySourceKind::BareHome {
            recorded_bare_source_entries_absent(candidate)?
        } else {
            path_is_absent(&candidate.source_root)?
        };
        if !source_is_absent {
            bail!(
                "adoption journal phase `prepare` has both source and snapshot content for {}",
                candidate.kind.label()
            );
        }
        return require_snapshot_shape(candidate, snapshot);
    }

    let candidates = inspect_legacy_candidates(home)?;
    if candidates.len() == 1 && candidates[0] == *candidate {
        Ok(())
    } else {
        bail!(
            "adoption journal phase `prepare` does not match the exact source/snapshot shape for {}; refusing to verify an external store",
            candidate.kind.label()
        )
    }
}

pub(super) fn recorded_bare_source_entries_absent(
    candidate: &LegacyCandidate,
) -> anyhow::Result<bool> {
    for entry in &candidate.db_files {
        if !path_is_absent(&candidate.source_root.join(entry))? {
            return Ok(false);
        }
    }
    if candidate.has_master_key && !path_is_absent(&candidate.source_root.join(MASTER_KEY_FILE))? {
        return Ok(false);
    }
    Ok(true)
}

pub(super) fn path_is_absent(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error).with_context(|| format!("inspect path {}", path.display())),
        Ok(_) => Ok(false),
    }
}

pub(super) fn ordinary_directory_presence(path: &Path, label: &str) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {label} {}", path.display())),
        Ok(_) => {
            require_ordinary_directory(path)
                .with_context(|| format!("validate {label} {}", path.display()))?;
            Ok(true)
        }
    }
}

pub(super) fn validate_discardable_staging(
    adoption_root: &Path,
    operation_id: &str,
) -> anyhow::Result<()> {
    let staging = adoption_root.join(STAGING_DIR);
    match fs::symlink_metadata(&staging) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("inspect staging root {}", staging.display()))
        }
        Ok(_) => {
            require_ordinary_directory(&staging)?;
            let marker = staging.join(STAGING_OWNER_FILE);
            match fs::symlink_metadata(&marker) {
                Ok(_) => {
                    require_proven_staging(&staging, operation_id)?;
                    validate_ordinary_tree(&staging)
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    if directory_is_empty(&staging)? {
                        Ok(())
                    } else {
                        bail!(
                            "staging tree at {} has mutable content but no ownership marker",
                            staging.display()
                        )
                    }
                }
                Err(error) => Err(error).with_context(|| {
                    format!("inspect staging ownership marker {}", marker.display())
                }),
            }
        }
    }
}

pub(super) fn validate_staged_recovery_shape(
    paths: &RebornStoragePaths,
    candidate: &LegacyCandidate,
    snapshot: &Path,
    adoption_root: &Path,
    operation_id: &str,
) -> anyhow::Result<()> {
    let staging = adoption_root.join(STAGING_DIR);
    if !ordinary_directory_presence(&staging, "staged recovery root")? {
        return verify_completed_staged_install(paths, candidate, snapshot, None);
    }
    require_proven_staging(&staging, operation_id)?;
    validate_staged_or_canonical_state(
        candidate,
        snapshot,
        &staging.join("state"),
        paths.state_root(),
    )?;
    validate_staged_or_canonical_system(
        candidate,
        snapshot,
        &staging.join("system"),
        paths.system_root(),
    )?;
    Ok(())
}

pub(super) fn validate_staged_or_canonical_state(
    candidate: &LegacyCandidate,
    snapshot: &Path,
    staged: &Path,
    canonical: &Path,
) -> anyhow::Result<()> {
    match (
        ordinary_directory_presence(staged, "staged state")?,
        ordinary_directory_presence(canonical, "canonical state")?,
    ) {
        (true, false) => verify_state_inventory(staged, candidate, snapshot, "staged state"),
        (false, true) => verify_state_inventory(canonical, candidate, snapshot, "canonical state"),
        (true, true) => bail!("staged and canonical state both exist"),
        (false, false) => bail!("staged recovery is missing both staged and canonical state"),
    }
}

pub(super) fn validate_staged_or_canonical_system(
    candidate: &LegacyCandidate,
    snapshot: &Path,
    staged: &Path,
    canonical: &Path,
) -> anyhow::Result<()> {
    match (
        ordinary_directory_presence(staged, "staged system")?,
        ordinary_directory_presence(canonical, "canonical system")?,
    ) {
        (true, false) => verify_system_inventory(staged, candidate, snapshot, "staged system"),
        (false, true) => {
            verify_system_inventory(canonical, candidate, snapshot, "canonical system")
        }
        (true, true) => bail!("staged and canonical system content both exist"),
        (false, false) => {
            bail!("staged recovery is missing both staged and canonical system content")
        }
    }
}

pub(super) fn validate_completed_staging(
    adoption_root: &Path,
    operation_id: &str,
) -> anyhow::Result<()> {
    let staging = adoption_root.join(STAGING_DIR);
    match fs::symlink_metadata(&staging) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("inspect completed staging root {}", staging.display())),
        Ok(_) => {
            require_ordinary_directory(&staging)?;
            let marker = staging.join(STAGING_OWNER_FILE);
            match fs::symlink_metadata(&marker) {
                Ok(_) => {
                    require_proven_staging(&staging, operation_id)?;
                    let mut entries = fs::read_dir(&staging).with_context(|| {
                        format!("read completed staging root {}", staging.display())
                    })?;
                    let only = entries.next().transpose()?.map(|entry| entry.file_name());
                    if only.as_deref() != Some(std::ffi::OsStr::new(STAGING_OWNER_FILE))
                        || entries.next().transpose()?.is_some()
                    {
                        bail!("completed staging tree contains unexplained content");
                    }
                    Ok(())
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    if directory_is_empty(&staging)? {
                        Ok(())
                    } else {
                        bail!("completed staging tree has content but no ownership marker")
                    }
                }
                Err(error) => Err(error).with_context(|| {
                    format!(
                        "inspect completed staging ownership marker {}",
                        marker.display()
                    )
                }),
            }
        }
    }
}
