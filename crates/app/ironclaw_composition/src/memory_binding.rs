//! Composition glue for the memory profile binding (issue #3537).
//!
//! Maps the `[memory]` config section + the active deployment profile into a
//! resolved [`MemoryBindingPolicy`], failing closed (a production deployment
//! that binds a required memory profile to `memory.disabled` or an unverified
//! third-party extension without an admin override is a startup error). Also
//! renders the redacted active-override diagnostics for startup/doctor.

use ironclaw_config::MemorySection;
use ironclaw_host_runtime::memory_binding::{
    MemoryAdminOverrideEntry, MemoryBindingInput, MemoryBindingPolicy, MemoryDeploymentProfile,
};

use crate::RebornBuildError;
use crate::root::profile::RebornCompositionProfile;

fn deployment_profile(profile: RebornCompositionProfile) -> MemoryDeploymentProfile {
    match profile {
        // `Disabled` never reaches memory composition; treat it as the safest
        // non-production profile so a stray call cannot relax production rules.
        RebornCompositionProfile::Disabled | RebornCompositionProfile::Standalone => {
            MemoryDeploymentProfile::Standalone
        }
        RebornCompositionProfile::StandaloneUnrestricted => {
            MemoryDeploymentProfile::StandaloneUnrestricted
        }
        // Volume-backed hosted single-tenant shares the same single-tenant trust
        // model as plain hosted-single-tenant, so it gets the same memory
        // deployment classification (and the same binding-certification rules).
        RebornCompositionProfile::HostedSingleTenant
        | RebornCompositionProfile::HostedSingleTenantVolume
        | RebornCompositionProfile::HostedSingleTenantVolumeSandboxed
        | RebornCompositionProfile::HostedSingleTenantVolumeSandboxedRailway => {
            MemoryDeploymentProfile::HostedSingleTenant
        }
        RebornCompositionProfile::Production => MemoryDeploymentProfile::Production,
        RebornCompositionProfile::MigrationDryRun => MemoryDeploymentProfile::MigrationDryRun,
    }
}

/// Resolve the memory binding policy from config + deployment profile,
/// fail-closed. `None` config binds the native provider by default.
pub fn resolve_memory_binding_policy(
    memory: Option<&MemorySection>,
    profile: RebornCompositionProfile,
) -> Result<MemoryBindingPolicy, RebornBuildError> {
    let Some(memory) = memory else {
        return default_binding_policy(profile);
    };

    let mut overrides = Vec::with_capacity(memory.admin_overrides.len());
    for over in &memory.admin_overrides {
        overrides.push(MemoryAdminOverrideEntry {
            extension_id: over.extension_id.clone(),
            deployment_profile: over.deployment_profile.clone(),
        });
    }

    let input = MemoryBindingInput {
        deployment: deployment_profile(profile),
        native_available: true,
        provider: memory.provider.clone(),
        overrides,
    };
    MemoryBindingPolicy::resolve(input).map_err(map_binding_error)
}

/// The provider id an unconfigured deployment binds. Native upstream; Mnesis
/// here. Diagnostics read this rather than restating the default.
pub fn default_memory_provider_id() -> &'static str {
    #[cfg(feature = "memory-mnesis")]
    {
        ironclaw_memory_mnesis::MNESIS_MEMORY_EXTENSION_ID
    }
    #[cfg(not(feature = "memory-mnesis"))]
    {
        ironclaw_host_runtime::memory_native_extension::NATIVE_MEMORY_EXTENSION_ID
    }
}

/// The binding an unconfigured deployment gets. Native upstream; Mnesis here.
#[cfg(feature = "memory-mnesis")]
fn default_binding_policy(
    profile: RebornCompositionProfile,
) -> Result<MemoryBindingPolicy, RebornBuildError> {
    let deployment = deployment_profile(profile);
    MemoryBindingPolicy::resolve(MemoryBindingInput {
        deployment,
        native_available: true,
        provider: Some(ironclaw_memory_mnesis::MNESIS_MEMORY_EXTENSION_ID.to_string()),
        overrides: vec![MemoryAdminOverrideEntry {
            extension_id: ironclaw_memory_mnesis::MNESIS_MEMORY_EXTENSION_ID.to_string(),
            deployment_profile: deployment.as_str().to_string(),
        }],
    })
    .map_err(map_binding_error)
}

#[cfg(not(feature = "memory-mnesis"))]
fn default_binding_policy(
    _profile: RebornCompositionProfile,
) -> Result<MemoryBindingPolicy, RebornBuildError> {
    Ok(MemoryBindingPolicy::native_default())
}

fn map_binding_error(
    error: ironclaw_host_runtime::memory_binding::MemoryBindingError,
) -> RebornBuildError {
    RebornBuildError::InvalidConfig {
        reason: format!("memory binding resolution failed: {error}"),
    }
}

/// Redacted one-line diagnostics for the active third-party binding overrides,
/// for startup logging and the doctor surface.
pub fn memory_binding_diagnostics(policy: &MemoryBindingPolicy) -> Vec<String> {
    policy
        .active_overrides()
        .iter()
        .map(|over| over.redacted_summary())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_config::MemoryAdminOverride;

    fn section(provider: Option<&str>, admin_overrides: Vec<MemoryAdminOverride>) -> MemorySection {
        MemorySection {
            provider: provider.map(|value| value.to_string()),
            admin_overrides,
            ..Default::default()
        }
    }

    /// No `[memory]` stanza binds the default provider. On this branch that is
    /// Mnesis, which the deployment profile reaches through an admin override
    /// rather than a config entry, so the presence of an override is the
    /// first-class binding working, not operator configuration leaking in.
    #[test]
    fn none_config_resolves_to_the_default_provider() {
        let policy = resolve_memory_binding_policy(None, RebornCompositionProfile::Production)
            .expect("the default provider resolves in production");
        match policy.binding() {
            ironclaw_host_runtime::memory_binding::MemoryProviderBinding::ThirdParty {
                extension_id,
                ..
            } => {
                assert_eq!(extension_id.as_str(), default_memory_provider_id());
            }
            ironclaw_host_runtime::memory_binding::MemoryProviderBinding::Native => {
                assert_eq!(
                    default_memory_provider_id(),
                    ironclaw_host_runtime::memory_native_extension::NATIVE_MEMORY_EXTENSION_ID
                );
            }
            binding => panic!("unexpected default binding: {binding:?}"),
        }
    }

    #[test]
    fn production_disabled_binding_fails_startup() {
        let memory = section(Some("memory.disabled"), Vec::new());
        let err =
            resolve_memory_binding_policy(Some(&memory), RebornCompositionProfile::Production)
                .expect_err("production must reject memory.disabled");
        assert!(matches!(err, RebornBuildError::InvalidConfig { .. }));
    }

    #[test]
    fn production_third_party_without_override_fails_startup() {
        let memory = section(Some("acme.honcho"), Vec::new());
        let err =
            resolve_memory_binding_policy(Some(&memory), RebornCompositionProfile::Production)
                .expect_err("production must reject unverified third-party");
        assert!(matches!(err, RebornBuildError::InvalidConfig { .. }));
    }

    #[test]
    fn production_third_party_with_override_resolves_and_reports_redacted() {
        let memory = section(
            Some("acme.honcho"),
            vec![MemoryAdminOverride {
                extension_id: "acme.honcho".to_string(),
                deployment_profile: "production".to_string(),
            }],
        );
        let policy =
            resolve_memory_binding_policy(Some(&memory), RebornCompositionProfile::Production)
                .expect("override permits binding");
        let diagnostics = memory_binding_diagnostics(&policy);
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].contains("memory override"));
        assert!(diagnostics[0].contains("deployment=production"));
    }

    #[test]
    fn invalid_provider_id_fails_startup() {
        let memory = section(Some("not a valid id"), Vec::new());
        let err =
            resolve_memory_binding_policy(Some(&memory), RebornCompositionProfile::Standalone)
                .expect_err("invalid provider id rejected");
        assert!(matches!(err, RebornBuildError::InvalidConfig { .. }));
    }
}
