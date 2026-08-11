//! CLI-facing durable-storage boot orchestration.
//!
//! This module maps an active deployment profile onto the pure transition
//! machinery in [`super::storage_layout`]. It owns command and startup
//! sequencing; `storage_layout` owns filesystem-state admission and adoption.

use anyhow::Context as _;
use ironclaw_composition::{RebornHostBindings, deployment::DeploymentConfig};
use ironclaw_config::{
    DurableStateKind, LayoutRequirement, RebornBootConfig, RebornProfile, RebornStoragePaths,
};

use crate::context::RebornCliContext;

use super::{block_on_cli, default_owner_id, effective_profile, read_config_file, storage_layout};

pub(super) fn storage_layout_requirement_for_profile(
    profile: RebornProfile,
) -> anyhow::Result<LayoutRequirement> {
    let deployment = DeploymentConfig::for_profile(profile.into(), false);
    deployment.storage_layout_requirement().ok_or_else(|| {
        anyhow::anyhow!(
            "profile {} has no durable filesystem layout to adopt",
            profile
        )
    })
}

pub(super) fn startup_adoption_authority_from_environment()
-> anyhow::Result<storage_layout::StartupAdoptionAuthority> {
    let cutover_value = match std::env::var(storage_layout::StartupAdoptionAuthority::ENV) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!(
            "{} is invalid: the value must be valid UTF-8",
            storage_layout::StartupAdoptionAuthority::ENV
        ),
    };
    storage_layout::StartupAdoptionAuthority::from_environment_value(cutover_value.as_deref())
}

pub(crate) fn ensure_ready_layout_for_profile(
    config: &RebornBootConfig,
    profile: RebornProfile,
) -> anyhow::Result<RebornStoragePaths> {
    let requirement = storage_layout_requirement_for_profile(profile)?;
    if profile == RebornProfile::MigrationDryRun {
        return storage_layout::inspect_ready_layout(config.home(), requirement);
    }
    storage_layout::ensure_ready_layout(config.home(), requirement)
}

pub(super) fn ensure_startup_layout(
    config: &RebornBootConfig,
    profile: RebornProfile,
    config_file: Option<&ironclaw_config::RebornConfigFile>,
) -> anyhow::Result<RebornStoragePaths> {
    let requirement = storage_layout_requirement_for_profile(profile)?;
    if profile == RebornProfile::MigrationDryRun {
        return storage_layout::inspect_ready_layout(config.home(), requirement);
    }
    match storage_layout::admit_startup_layout(config.home(), requirement)? {
        storage_layout::StartupLayoutAdmission::Ready(paths) => Ok(paths),
        storage_layout::StartupLayoutAdmission::AdoptionRequired => {
            let authority = startup_adoption_authority_from_environment()?;
            let permit =
                storage_layout::prepare_automatic_adoption(config.home(), requirement, authority)?;
            let deployment = DeploymentConfig::for_profile(profile.into(), false);
            storage_layout::automatically_adopt_layout_with_store_verification(
                config.home(),
                requirement,
                permit,
                || {
                    canonical_store_verification_for_adoption(
                        config,
                        &deployment,
                        config_file,
                        requirement,
                    )
                },
            )?;
            storage_layout::ensure_ready_layout(config.home(), requirement)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnboardingSecretStoreMode {
    Embedded,
    HostedExternal,
}

/// Admit the active layout before onboarding writes home-local configuration.
/// Only embedded profiles may provision the standalone master key or encrypted
/// secret store; hosted onboarding leaves credentials to its hosted surface.
pub(crate) fn prepare_onboarding_layout(
    config: &RebornBootConfig,
) -> anyhow::Result<OnboardingSecretStoreMode> {
    let config_file = read_config_file(config)?;
    let profile = effective_profile(config, config_file.as_ref())?;
    let requirement = storage_layout_requirement_for_profile(profile)?;
    ensure_ready_layout_for_profile(config, profile)?;
    Ok(match requirement.durable_state {
        DurableStateKind::EmbeddedLibSql => OnboardingSecretStoreMode::Embedded,
        DurableStateKind::ExternalPostgres => OnboardingSecretStoreMode::HostedExternal,
    })
}

/// Admit the active profile's durable layout before a CLI command opens a
/// stateful store outside the runtime assembly path.
#[cfg(test)]
pub(crate) fn ensure_ready_layout_for_active_profile(
    config: &RebornBootConfig,
) -> anyhow::Result<RebornStoragePaths> {
    let config_file = read_config_file(config)?;
    let profile = effective_profile(config, config_file.as_ref())?;
    ensure_ready_layout_for_profile(config, profile)
}

/// Admit a CLI secret write only when it can open the same embedded store as
/// the selected runtime. Hosted PostgreSQL writes must use a PostgreSQL-aware
/// operator surface; silently creating a local libSQL database would report a
/// credential as saved while `serve` reads a different backend.
pub(crate) fn ensure_embedded_secret_store_for_active_profile(
    config: &RebornBootConfig,
) -> anyhow::Result<RebornStoragePaths> {
    let config_file = read_config_file(config)?;
    let profile = effective_profile(config, config_file.as_ref())?;
    let requirement = storage_layout_requirement_for_profile(profile)?;
    if requirement.durable_state != DurableStateKind::EmbeddedLibSql {
        anyhow::bail!(
            "profile {profile} uses external PostgreSQL durable state; this CLI secret command cannot safely write that backend. Configure the credential through the hosted operator/WebUI surface or deployment secret environment"
        );
    }
    ensure_ready_layout_for_profile(config, profile)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StorageAdoptionOutcome {
    Adopted,
    MigrationDryRunValidated,
}

pub(crate) fn adopt_storage_layout(
    context: &RebornCliContext,
    confirm_processes_stopped: bool,
    confirm_backup_snapshot: bool,
    workspace_import: Option<storage_layout::WorkspaceImportOptions>,
) -> anyhow::Result<StorageAdoptionOutcome> {
    let config = context.boot_config();
    let config_file = read_config_file(config)?;
    let profile = effective_profile(config, config_file.as_ref())?;
    let requirement = storage_layout_requirement_for_profile(profile)?;
    if profile == RebornProfile::MigrationDryRun {
        return storage_layout::inspect_ready_layout(config.home(), requirement)
            .map(|_| StorageAdoptionOutcome::MigrationDryRunValidated);
    }
    let options = storage_layout::AdoptOptions {
        confirm_processes_stopped,
        confirm_backup_snapshot,
        workspace_import,
    };
    storage_layout::validate_adopt_options(&options)?;
    let deployment = DeploymentConfig::for_profile(profile.into(), false);
    storage_layout::adopt_layout_with_store_verification(
        config.home(),
        requirement,
        options,
        || {
            canonical_store_verification_for_adoption(
                config,
                &deployment,
                config_file.as_ref(),
                requirement,
            )
        },
    )?;
    // The adoption command does not start a runtime. Validate the manifest
    // through the same normal-boot prerequisite before reporting completion.
    storage_layout::ensure_ready_layout(config.home(), requirement)
        .map(|_| StorageAdoptionOutcome::Adopted)
}

pub(super) fn canonical_store_verification_for_adoption(
    config: &RebornBootConfig,
    deployment: &DeploymentConfig,
    config_file: Option<&ironclaw_config::RebornConfigFile>,
    requirement: LayoutRequirement,
) -> anyhow::Result<storage_layout::CanonicalStoreVerification> {
    match requirement.durable_state {
        DurableStateKind::EmbeddedLibSql => {
            Ok(storage_layout::CanonicalStoreVerification::EmbeddedLibSql)
        }
        DurableStateKind::ExternalPostgres => match deployment.storage_shape() {
            ironclaw_composition::deployment::StorageShape::HostedSingleTenantPool => {
                let paths = RebornStoragePaths::from_home(config.home());
                let bindings = RebornHostBindings::hosted_single_tenant_postgres_from_config_and_env(
                    deployment.profile(),
                    default_owner_id(config_file),
                    paths,
                    config_file,
                )
                .context(
                    "open hosted single-tenant PostgreSQL store and secret resolver for adoption preflight",
                )?;
                block_on_cli(ironclaw_composition::verify_hosted_postgres_store_for_adoption(
                    bindings,
                ))
                .context(
                    "run hosted single-tenant PostgreSQL migrations and encrypted-record verification before adoption",
                )?;
                Ok(storage_layout::CanonicalStoreVerification::ExternalPostgresVerified)
            }
            ironclaw_composition::deployment::StorageShape::OperatorSupplied => anyhow::bail!(
                "external PostgreSQL layout adoption is supported only for hosted single-tenant pool storage; operator-supplied handles cannot be reopened by offline adoption"
            ),
            storage_shape => anyhow::bail!(
                "external PostgreSQL layout adoption is supported only for hosted single-tenant pool storage; got {storage_shape:?}"
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn startup_adoption_authority_rejects_a_non_utf8_cutover_value() {
        use std::os::unix::ffi::OsStringExt as _;

        use super::super::test_env::{EnvGuard, lock_runtime_env};
        use super::{startup_adoption_authority_from_environment, storage_layout};

        let _lock = lock_runtime_env();
        let invalid = std::ffi::OsString::from_vec(vec![0xff, 0xfe]);
        let _cutover = EnvGuard::set_os(storage_layout::StartupAdoptionAuthority::ENV, &invalid);

        let error = startup_adoption_authority_from_environment()
            .expect_err("non-UTF-8 cutover authority must fail loudly");
        assert!(
            error
                .to_string()
                .contains(storage_layout::StartupAdoptionAuthority::ENV),
            "{error:#}"
        );
        assert!(error.to_string().contains("UTF-8"), "{error:#}");
    }
}
