use super::*;
use super::{adoption::*, filesystem::*, model::*};

/// Validate a ready layout, initialize a genuinely fresh home, or classify a
/// single supported legacy source for adoption.
///
/// This never performs adoption work. In particular it never creates an
/// adoption journal, snapshots a source, or copies legacy state.
pub(crate) fn admit_startup_layout(
    home: &RebornHome,
    requirement: LayoutRequirement,
) -> anyhow::Result<StartupLayoutAdmission> {
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
        validate_ready_namespace_roots(&paths)?;
        return Ok(StartupLayoutAdmission::Ready(paths));
    }

    if adoption_journal.exists() {
        return Ok(StartupLayoutAdmission::AdoptionRequired);
    }

    let candidates = inspect_legacy_candidates(home_path)?;
    if candidates.is_empty() && canonical_layout_is_empty(&paths)? {
        initialize_fresh_layout(home_path, &paths, requirement)?;
        return Ok(StartupLayoutAdmission::Ready(paths));
    }

    if candidates.len() == 1 {
        return Ok(StartupLayoutAdmission::AdoptionRequired);
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
    )
}

/// Validate a ready layout, initialize a genuinely fresh home, or retain the
/// manual-command behavior for stateful CLI commands outside runtime startup.
pub(crate) fn ensure_ready_layout(
    home: &RebornHome,
    requirement: LayoutRequirement,
) -> anyhow::Result<RebornStoragePaths> {
    match admit_startup_layout(home, requirement)? {
        StartupLayoutAdmission::Ready(paths) => Ok(paths),
        StartupLayoutAdmission::AdoptionRequired => bail!(
            "legacy durable storage requires adoption; run `{OFFLINE_ADOPT_COMMAND}` or start the Reborn runtime to perform safe automatic adoption"
        ),
    }
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
    validate_ready_namespace_roots(&paths)?;
    Ok(paths)
}

fn validate_ready_namespace_roots(paths: &RebornStoragePaths) -> anyhow::Result<()> {
    for namespace in [
        paths.state_root(),
        paths.system_root(),
        paths.workspace_root(),
        paths.runtime_root(),
        paths.logs_root(),
        paths.cache_root(),
        paths.temp_root(),
    ] {
        require_ordinary_directory(namespace)?;
    }
    Ok(())
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
