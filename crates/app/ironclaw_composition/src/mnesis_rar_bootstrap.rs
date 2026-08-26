//! Boot-time credential bind and activation for the Mnesis retrieval package.
//!
//! An `[mcp]` package whose credential is deployment-owned rather than
//! operator-entered, so nothing activates it unless composition binds the
//! token first; the sibling module under `llm_admin/` solves the same problem
//! for the other such package. The token is read from the same variable the
//! memory lanes use, so one deployment setting drives the ambient lanes, the
//! patched endpoint, and this activation.

use std::sync::Arc;

use ironclaw_assistant::{
    ExtensionCredentialSetupService, ExtensionCredentialSubmitRequest, LifecyclePackageKind,
    LifecyclePackageRef, LifecycleProductPayload,
};
use ironclaw_auth::{AuthProductScope, AuthProviderId, AuthSurface, RebornProductAuthServices};
use ironclaw_extension_contracts::state::InstallationState;
use ironclaw_extension_host::extension_activation_credentials::RuntimeExtensionActivationCredentialGate;
use ironclaw_extension_host::extension_lifecycle::RebornLocalExtensionManagementPort;
use ironclaw_extension_manager::webui_extension_credentials::ProductAuthExtensionCredentialSetup;
use ironclaw_host_api::{
    ids::{ExtensionId, InvocationId},
    resource::ResourceScope,
};

use crate::RebornBuildError;

const MNESIS_RAR_EXTENSION_ID: &str = "mnesis-rar";
const MNESIS_RAR_VENDOR_ID: &str = "mnesis";
const MNESIS_RAR_TOKEN_ENV: &str = "MEMORY_MNESIS_KNOWLEDGE_TOKEN";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MnesisRarBootstrapOutcome {
    NotConfigured,
    SkippedNonActivatable,
    ReusedCredential,
    Activated,
}

impl MnesisRarBootstrapOutcome {
    pub(crate) fn log_completion(self) {
        let detail = match self {
            Self::NotConfigured => "not configured; the package stays withheld",
            Self::SkippedNonActivatable => "token present, but not auto-activatable",
            Self::ReusedCredential => "credential already bound; reused",
            Self::Activated => "credential bound and extension activated",
        };
        tracing::debug!(target: "ironclaw_memory_mnesis", "Mnesis retrieval {detail}");
    }
}

fn configured_token() -> Option<String> {
    let raw = std::env::var(MNESIS_RAR_TOKEN_ENV).ok()?;
    Some(raw.trim().to_string()).filter(|token| !token.is_empty())
}

fn invalid_config(reason: String) -> RebornBuildError {
    RebornBuildError::InvalidConfig { reason }
}

pub(crate) async fn bootstrap_mnesis_rar(
    product_auth: &Arc<RebornProductAuthServices>,
    extension_management: &Arc<RebornLocalExtensionManagementPort>,
    owner_scope: ResourceScope,
) -> Result<MnesisRarBootstrapOutcome, RebornBuildError> {
    let Some(token) = configured_token() else {
        return Ok(MnesisRarBootstrapOutcome::NotConfigured);
    };

    let package_ref =
        LifecyclePackageRef::new(LifecyclePackageKind::Extension, MNESIS_RAR_EXTENSION_ID)
            .map_err(|error| {
                invalid_config(format!("Mnesis retrieval package ref is invalid: {error}"))
            })?;
    let resource_scope = ResourceScope {
        invocation_id: InvocationId::new(),
        ..owner_scope.without_thread_and_mission()
    };
    let projection = extension_management
        .project(package_ref.clone(), &owner_scope.user_id)
        .await
        .map_err(|error| {
            invalid_config(format!(
                "Mnesis retrieval extension projection failed: {error}"
            ))
        })?;
    let phase = projection.phase;
    let installed = matches!(
        projection.payload.as_ref(),
        Some(LifecycleProductPayload::ExtensionList { extensions, .. })
            if extensions.first().and_then(|extension| extension.install_scope).is_some()
    );
    if installed
        && !matches!(
            phase,
            InstallationState::Active
                | InstallationState::Installed
                | InstallationState::Configured
        )
    {
        return Ok(MnesisRarBootstrapOutcome::SkippedNonActivatable);
    }

    let scope = AuthProductScope::new(resource_scope.clone(), AuthSurface::Api);
    let provider = AuthProviderId::new(MNESIS_RAR_VENDOR_ID).map_err(|error| {
        invalid_config(format!("Mnesis retrieval provider id is invalid: {error}"))
    })?;
    let requester_extension = ExtensionId::new(MNESIS_RAR_EXTENSION_ID).map_err(|error| {
        invalid_config(format!(
            "Mnesis retrieval requester extension id is invalid: {error}"
        ))
    })?;
    let existing_account = product_auth
        .credential_account_record_source()
        .accounts_for_owner(&scope)
        .await
        .map_err(|error| {
            invalid_config(format!(
                "Mnesis retrieval product-auth lookup failed: {error}"
            ))
        })?
        .into_iter()
        .find(|account| account.provider == provider);

    let already_bound = existing_account.is_some();
    if !already_bound {
        ProductAuthExtensionCredentialSetup::new(Arc::clone(product_auth))
            .submit_manual_token(ExtensionCredentialSubmitRequest {
                scope,
                provider,
                label: "Mnesis retrieval token".to_string(),
                requester_extension,
                existing_account: None,
                secret: token.into(),
            })
            .await
            .map_err(|error| RebornBuildError::InvalidConfig {
                reason: format!("Mnesis retrieval credential submit failed: {error:?}"),
            })?;
    }

    let bootstrap_caller = resource_scope.user_id.clone();
    if !installed {
        extension_management
            .install(package_ref.clone(), &bootstrap_caller)
            .await
            .map_err(|error| {
                invalid_config(format!(
                    "Mnesis retrieval extension install failed: {error}"
                ))
            })?;
    }
    if !installed
        || matches!(
            phase,
            InstallationState::Installed | InstallationState::Configured
        )
    {
        let credential_gate = RuntimeExtensionActivationCredentialGate::new(
            resource_scope.clone(),
            product_auth.runtime_credential_account_selection_service(),
        );
        extension_management
            .activate_with_credential_gate(
                package_ref,
                resource_scope,
                &credential_gate,
                &bootstrap_caller,
            )
            .await
            .map_err(|error| {
                invalid_config(format!(
                    "Mnesis retrieval extension activation failed: {error}"
                ))
            })?;
        return Ok(MnesisRarBootstrapOutcome::Activated);
    }
    Ok(MnesisRarBootstrapOutcome::ReusedCredential)
}
