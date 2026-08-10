//! Bounded, offline adoption for the profile-stable Reborn durable layout.
//!
//! This is deliberately a single state machine for this one filesystem
//! transition. It does not discover arbitrary roots, infer workspace owners,
//! or serve as a generic migration framework.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use ironclaw_composition::host_api::{TenantId, UserId};
use ironclaw_config::{
    LayoutManifest, LayoutRequirement, ProfileTransitionAdmission, RebornHome, RebornStoragePaths,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const LAYOUT_MANIFEST_FILE: &str = "layout.toml";
const ADOPTION_DIR: &str = "layout-adoption";
const JOURNAL_FILE: &str = "journal.toml";
const SNAPSHOT_DIR: &str = "snapshot";
const STAGING_DIR: &str = "staging";
const ADOPTION_LOCK_FILE: &str = "adoption.lock";
const JOURNAL_SCHEMA_VERSION: u32 = 1;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AdoptionPhase {
    Prepare,
    SnapshotOwned,
    Staged,
    CanonicalInstalled,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyCandidate {
    kind: LegacySourceKind,
    source_root: PathBuf,
    db_files: Vec<String>,
    has_master_key: bool,
    has_system_content: bool,
}

impl LegacyCandidate {
    fn is_embedded(&self) -> bool {
        !self.db_files.is_empty() || self.has_master_key
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptionJournal {
    schema_version: u32,
    source: LegacySourceKind,
    phase: AdoptionPhase,
    requirement: LayoutRequirement,
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

impl AdoptionJournal {
    fn new(
        candidate: &LegacyCandidate,
        requirement: LayoutRequirement,
        workspace: Option<WorkspaceImportDecision>,
    ) -> Self {
        Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            source: candidate.kind,
            phase: AdoptionPhase::Prepare,
            requirement,
            inventory: AdoptionInventory {
                db_files: candidate.db_files.clone(),
                has_master_key: candidate.has_master_key,
                has_system_content: candidate.has_system_content,
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
        }
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
                || journal.requirement != manifest.requirement()
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

    let candidates = inspect_legacy_candidates(home_path, requirement)?;
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

/// Run or resume the one bounded offline adoption state machine.
pub(crate) fn adopt_layout(
    home: &RebornHome,
    requirement: LayoutRequirement,
    options: AdoptOptions,
) -> anyhow::Result<()> {
    require_operator_confirmations(&options)?;
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

    let (mut journal, _lock) = if journal_path.exists() {
        let lock = acquire_existing_adoption_lock(&adoption_root)?;
        (read_journal(&journal_path)?, lock)
    } else {
        let candidates = inspect_legacy_candidates(home_path, requirement)?;
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
        ensure_canonical_install_targets_empty(&paths)?;
        let workspace = prepare_workspace_import(options.workspace_import.as_ref(), &paths)?;
        fs::create_dir_all(&adoption_root)
            .with_context(|| format!("create adoption root {}", adoption_root.display()))?;
        let lock = acquire_adoption_lock(&adoption_root)?;
        if journal_path.exists() {
            (read_journal(&journal_path)?, lock)
        } else {
            let journal = AdoptionJournal::new(&candidates[0], requirement, workspace);
            write_journal(&journal_path, &journal)?;
            (journal, lock)
        }
    };

    if journal.requirement != requirement {
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
    )?;
    Ok(())
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
) -> anyhow::Result<()> {
    let candidate = journal.candidate(home);
    let snapshot = candidate.snapshot_root(adoption_root);

    if journal.phase == AdoptionPhase::Prepare {
        reconcile_prepare_shape(&candidate, &snapshot)?;
        journal.phase = AdoptionPhase::SnapshotOwned;
        write_journal(journal_path, journal)?;
    }

    require_snapshot_shape(&candidate, &snapshot)?;

    if journal.phase != AdoptionPhase::StoreVerified {
        remove_interrupted_owned_artifacts(paths, adoption_root, journal.phase)?;
        stage_snapshot(
            &candidate,
            &snapshot,
            adoption_root,
            journal.workspace.as_ref(),
        )?;
        journal.phase = AdoptionPhase::Staged;
        write_journal(journal_path, journal)?;

        install_staged(paths, adoption_root, journal.workspace.as_ref())?;
        journal.phase = AdoptionPhase::CanonicalInstalled;
        write_journal(journal_path, journal)?;

        verify_canonical_store(paths, candidate.is_embedded())?;
        journal.phase = AdoptionPhase::StoreVerified;
        write_journal(journal_path, journal)?;
    }

    let manifest = LayoutManifest::new(journal.requirement);
    write_manifest_last(home, &manifest)?;
    Ok(())
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
    fs::create_dir_all(snapshot_parent)
        .with_context(|| format!("create snapshot parent {}", snapshot_parent.display()))?;

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
    if !snapshot.is_dir() {
        bail!(
            "adoption snapshot is missing at {}; only the offline adoption command may recover it",
            snapshot.display()
        );
    }
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
    validate_snapshot_inventory(candidate, snapshot)
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
    workspace: Option<&WorkspaceImportDecision>,
) -> anyhow::Result<()> {
    let staging = adoption_root.join(STAGING_DIR);
    if staging.exists() {
        bail!(
            "journal-owned staging tree already exists at {}; recovery must remove only recorded incomplete artifacts before restaging",
            staging.display()
        );
    }
    fs::create_dir(&staging).with_context(|| format!("create staging {}", staging.display()))?;
    let staging_state = staging.join("state");
    let staging_system = staging.join("system");
    fs::create_dir(&staging_state)
        .with_context(|| format!("create {}", staging_state.display()))?;
    fs::create_dir(&staging_system)
        .with_context(|| format!("create {}", staging_system.display()))?;

    for file in &candidate.db_files {
        copy_ordinary_file(&snapshot.join(file), &staging_state.join(file))?;
    }
    if candidate.has_master_key {
        copy_ordinary_file(
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

fn install_staged(
    paths: &RebornStoragePaths,
    adoption_root: &Path,
    workspace: Option<&WorkspaceImportDecision>,
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
    fs::remove_dir(&staging)
        .with_context(|| format!("remove empty staging root {}", staging.display()))?;
    sync_directory(adoption_root)?;
    Ok(())
}

fn verify_canonical_store(paths: &RebornStoragePaths, embedded_state: bool) -> anyhow::Result<()> {
    if !embedded_state {
        return Ok(());
    }
    let state_root = paths.state_root().to_path_buf();
    crate::runtime::block_on_cli(async move {
        ironclaw_composition::open_standalone_secret_store(&state_root)
            .await
            .map(|_| ())
    })
    .context("open canonical embedded store and construct the canonical secret resolver")
}

fn remove_interrupted_owned_artifacts(
    paths: &RebornStoragePaths,
    adoption_root: &Path,
    phase: AdoptionPhase,
) -> anyhow::Result<()> {
    let staging = adoption_root.join(STAGING_DIR);
    if staging.exists() {
        remove_owned_tree(&staging, adoption_root)?;
    }
    if matches!(
        phase,
        AdoptionPhase::CanonicalInstalled | AdoptionPhase::Staged
    ) {
        for path in [paths.state_root(), paths.system_root()] {
            if path.exists() {
                remove_owned_tree(
                    path,
                    path.parent()
                        .ok_or_else(|| anyhow!("canonical path has no parent"))?,
                )?;
            }
        }
    }
    Ok(())
}

fn remove_owned_tree(path: &Path, expected_parent: &Path) -> anyhow::Result<()> {
    if path.parent() != Some(expected_parent) {
        bail!(
            "refusing to remove non-direct journal-owned path {}",
            path.display()
        );
    }
    fs::remove_dir_all(path)
        .with_context(|| format!("remove interrupted journal-owned tree {}", path.display()))?;
    sync_directory(expected_parent)
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
        fs::create_dir(path)
            .with_context(|| format!("create canonical namespace {}", path.display()))?;
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

fn inspect_legacy_candidates(
    home: &Path,
    requirement: LayoutRequirement,
) -> anyhow::Result<Vec<LegacyCandidate>> {
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
        let candidate = inspect_profile_root(home, kind, requirement)?;
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
    requirement: LayoutRequirement,
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
            has_master_key = true;
        } else if name == "system" {
            require_ordinary_directory(&path)?;
            has_system_content = system_tree_has_content(&path)?;
            validate_system_tree(&path)?;
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
    let populated = !db_files.is_empty() || has_master_key || has_system_content;
    if !populated {
        return Ok(None);
    }
    if kind == LegacySourceKind::HostedSingleTenant {
        if requirement.durable_state != ironclaw_config::DurableStateKind::ExternalPostgres {
            bail!(
                "{} is a PostgreSQL/system-content legacy source and cannot be adopted into embedded libSQL state",
                root.display()
            );
        }
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
        digest: tenant_user_workspace_digest(&options.tenant, &options.user),
    };
    let destination = workspace_leaf_path(paths, &decision);
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

fn tenant_user_workspace_digest(tenant: &TenantId, user: &UserId) -> String {
    let encoded = format!(
        "{}:tenant={}:{};{}:user={}:{};",
        "tenant".len(),
        tenant.as_str().len(),
        tenant.as_str(),
        "user".len(),
        user.as_str().len(),
        user.as_str(),
    );
    hex::encode(Sha256::digest(encoded.as_bytes()))
}

fn workspace_leaf_path(paths: &RebornStoragePaths, workspace: &WorkspaceImportDecision) -> PathBuf {
    paths.workspace_root().join("users").join(&workspace.digest)
}

fn install_workspace_leaf(
    paths: &RebornStoragePaths,
    workspace: &WorkspaceImportDecision,
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
    for entry in
        fs::read_dir(source).with_context(|| format!("read system source {}", source.display()))?
    {
        let entry = entry
            .with_context(|| format!("read system source entry under {}", source.display()))?;
        let destination = destination.join(entry.file_name());
        copy_ordinary_tree(&entry.path(), &destination)?;
    }
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
    fs::create_dir(destination)
        .with_context(|| format!("create destination directory {}", destination.display()))?;
    for entry in fs::read_dir(source)
        .with_context(|| format!("read source directory {}", source.display()))?
    {
        let entry =
            entry.with_context(|| format!("read source entry under {}", source.display()))?;
        copy_ordinary_tree(&entry.path(), &destination.join(entry.file_name()))?;
    }
    sync_directory(destination)
}

fn copy_ordinary_file(source: &Path, destination: &Path) -> anyhow::Result<()> {
    require_ordinary_file(source)?;
    let mut input = open_file_no_follow(source)?;
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
    for entry in
        fs::read_dir(path).with_context(|| format!("read source directory {}", path.display()))?
    {
        let entry = entry.with_context(|| format!("read source entry under {}", path.display()))?;
        validate_ordinary_tree(&entry.path())?;
    }
    Ok(())
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
        File::open(path)
            .with_context(|| format!("open directory for sync {}", path.display()))?
            .sync_all()
            .with_context(|| format!("sync directory {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

struct AdoptionLock {
    path: PathBuf,
}

impl Drop for AdoptionLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn acquire_adoption_lock(adoption_root: &Path) -> anyhow::Result<AdoptionLock> {
    let path = adoption_root.join(ADOPTION_LOCK_FILE);
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
    writeln!(file, "pid={}", std::process::id())
        .with_context(|| format!("write advisory lock {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync advisory lock {}", path.display()))?;
    sync_directory(adoption_root)?;
    Ok(AdoptionLock { path })
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
mod tests {
    use std::fs;

    use ironclaw_config::{
        DeploymentSecurityEnvelope, DurableStateKind, LayoutRequirement, RebornHome, TenancyModel,
        WorkspaceAccessFloor,
    };

    use super::{
        ADOPTION_DIR, AdoptOptions, AdoptionJournal, AdoptionPhase, RebornStoragePaths,
        WorkspaceImportOptions, adopt_layout, ensure_ready_layout, inspect_legacy_candidates,
        install_staged, snapshot_source, stage_snapshot, tenant_user_workspace_digest,
        verify_canonical_store, write_journal,
    };
    use ironclaw_composition::host_api::{TenantId, UserId};

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
    fn hosted_postgres_legacy_root_adopts_only_recognized_system_content() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = reborn_home(temp.path());
        let legacy = temp.path().join("hosted-single-tenant/system/prompts");
        fs::create_dir_all(&legacy).expect("legacy system content");
        fs::write(legacy.join("operator.md"), b"prompt").expect("system prompt");

        adopt_layout(
            &home,
            external_single_user_requirement(),
            confirmed_options(),
        )
        .expect("PostgreSQL system-content adoption succeeds");

        assert!(temp.path().join("system/prompts/operator.md").is_file());
        assert!(!temp.path().join("state/reborn-local-dev.db").exists());
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
            "schema_version = 2\nsource = \"local-dev\"\nphase = \"prepare\"\n\n[requirement]\ndurable_state = \"embedded-libsql\"\n\n[requirement.security]\ntenancy = \"single-user\"\nworkspace_access_floor = \"single-trusted-operator\"\n\n[inventory]\ndb_files = []\nhas_master_key = false\nhas_system_content = false\n",
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

        let expected_digest = tenant_user_workspace_digest(
            &TenantId::new("tenant-a").expect("tenant id"),
            &UserId::new("user-a").expect("user id"),
        );
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
    fn offline_adopt_resumes_every_persisted_phase_and_commits_manifest_last() {
        for phase in [
            AdoptionPhase::Prepare,
            AdoptionPhase::SnapshotOwned,
            AdoptionPhase::Staged,
            AdoptionPhase::CanonicalInstalled,
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
            let candidates =
                inspect_legacy_candidates(temp.path(), requirement).expect("inspect source");
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
                    | AdoptionPhase::StoreVerified
            ) {
                stage_snapshot(candidate, &snapshot, &adoption_root, None).expect("stage snapshot");
                journal.phase = AdoptionPhase::Staged;
            }
            if matches!(
                phase,
                AdoptionPhase::CanonicalInstalled | AdoptionPhase::StoreVerified
            ) {
                install_staged(&paths, &adoption_root, None).expect("install staged content");
                journal.phase = AdoptionPhase::CanonicalInstalled;
            }
            if phase == AdoptionPhase::StoreVerified {
                verify_canonical_store(&paths, true).expect("verify canonical store");
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
