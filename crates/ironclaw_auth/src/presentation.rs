use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    AuthProductError, AuthProductScope, AuthProviderId, CredentialAccountId,
    CredentialAccountRecordSource, CredentialAccountStatus, CredentialPresentationBindingId,
    CredentialPresentationProfileId, GuestCredentialArtifactId, Timestamp,
};

/// Version of host-reviewed credential-presentation security content.
///
/// Bindings pin this value so changing a profile cannot silently broaden an
/// existing grant. Version zero is invalid and rejected during deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct CredentialPresentationProfileVersion(u32);

impl CredentialPresentationProfileVersion {
    pub fn new(value: u32) -> Result<Self, AuthProductError> {
        if value == 0 {
            return Err(AuthProductError::invalid_request(
                "credential presentation profile version must be non-zero",
            ));
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for CredentialPresentationProfileVersion {
    type Error = AuthProductError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<CredentialPresentationProfileVersion> for u32 {
    fn from(value: CredentialPresentationProfileVersion) -> Self {
        value.0
    }
}

impl fmt::Display for CredentialPresentationProfileVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPresentationBindingStatus {
    Enabled,
    Disabled,
}

/// Durable control-plane link from one product-auth account to reviewed host
/// presentation policy. This record carries no raw credential material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPresentationBinding {
    pub id: CredentialPresentationBindingId,
    pub scope: AuthProductScope,
    pub account_id: CredentialAccountId,
    pub provider: AuthProviderId,
    pub profile_id: CredentialPresentationProfileId,
    pub profile_version: CredentialPresentationProfileVersion,
    pub artifact_id: GuestCredentialArtifactId,
    pub status: CredentialPresentationBindingStatus,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCredentialPresentationBindingRequest {
    pub scope: AuthProductScope,
    pub account_id: CredentialAccountId,
    pub profile_id: CredentialPresentationProfileId,
}

impl CreateCredentialPresentationBindingRequest {
    pub fn new(
        scope: AuthProductScope,
        account_id: CredentialAccountId,
        profile_id: CredentialPresentationProfileId,
    ) -> Self {
        Self {
            scope,
            account_id,
            profile_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReviewedCredentialPresentationProfile {
    id: CredentialPresentationProfileId,
    version: CredentialPresentationProfileVersion,
    provider: AuthProviderId,
}

/// Sealed host-owned catalog of reviewed presentation profiles.
///
/// The empty catalog is the production-safe W12 default. W20 will add explicit
/// first-party constructors for reviewed profile variants; callers cannot add
/// arbitrary destinations or signer logic through this API.
#[derive(Debug, Clone, Default)]
pub struct CredentialPresentationProfileCatalog {
    profiles: BTreeMap<CredentialPresentationProfileId, ReviewedCredentialPresentationProfile>,
}

impl CredentialPresentationProfileCatalog {
    pub fn empty() -> Self {
        Self::default()
    }

    fn get(
        &self,
        id: &CredentialPresentationProfileId,
    ) -> Option<&ReviewedCredentialPresentationProfile> {
        self.profiles.get(id)
    }
}

/// Persistence port beneath the presentation authority.
///
/// Product/UI/capability callers must use
/// [`CredentialPresentationBindingAuthority`] so account ownership, status,
/// provider, and reviewed-profile checks have one chokepoint.
#[async_trait]
pub trait CredentialPresentationBindingRepository: Send + Sync {
    async fn create_presentation_binding(
        &self,
        binding: CredentialPresentationBinding,
    ) -> Result<CredentialPresentationBinding, AuthProductError>;

    async fn presentation_bindings_for_owner(
        &self,
        scope: &AuthProductScope,
    ) -> Result<Vec<CredentialPresentationBinding>, AuthProductError>;

    async fn disable_presentation_bindings_for_account(
        &self,
        scope: &AuthProductScope,
        account_id: CredentialAccountId,
    ) -> Result<(), AuthProductError>;
}

/// Sole admission authority for settings UI and agent-issued binding requests.
pub struct CredentialPresentationBindingAuthority {
    accounts: Arc<dyn CredentialAccountRecordSource>,
    bindings: Arc<dyn CredentialPresentationBindingRepository>,
    profiles: CredentialPresentationProfileCatalog,
}

impl CredentialPresentationBindingAuthority {
    pub fn new(
        accounts: Arc<dyn CredentialAccountRecordSource>,
        bindings: Arc<dyn CredentialPresentationBindingRepository>,
        profiles: CredentialPresentationProfileCatalog,
    ) -> Self {
        Self {
            accounts,
            bindings,
            profiles,
        }
    }

    pub async fn create_binding(
        &self,
        request: CreateCredentialPresentationBindingRequest,
    ) -> Result<CredentialPresentationBinding, AuthProductError> {
        let profile = self.profiles.get(&request.profile_id).ok_or_else(|| {
            AuthProductError::invalid_request("credential presentation profile is not reviewed")
        })?;
        let account = self
            .accounts
            .accounts_for_owner(&request.scope)
            .await?
            .into_iter()
            .find(|account| account.id == request.account_id)
            .ok_or(AuthProductError::CredentialMissing)?;
        if account.status != CredentialAccountStatus::Configured {
            return Err(AuthProductError::CredentialMissing);
        }
        if account.provider != profile.provider {
            return Err(AuthProductError::invalid_request(
                "credential account provider does not match reviewed presentation profile",
            ));
        }

        let now = Utc::now();
        self.bindings
            .create_presentation_binding(CredentialPresentationBinding {
                id: CredentialPresentationBindingId::new(),
                scope: account.scope,
                account_id: account.id,
                provider: profile.provider.clone(),
                profile_id: profile.id.clone(),
                profile_version: profile.version,
                artifact_id: GuestCredentialArtifactId::new(),
                status: CredentialPresentationBindingStatus::Enabled,
                created_at: now,
                updated_at: now,
            })
            .await
    }

    /// Returns only bindings still valid against live account and reviewed
    /// profile state. This is the fail-closed read used by W19b even if a
    /// durable disconnect cascade has not completed yet.
    pub async fn enabled_bindings_for_owner(
        &self,
        scope: &AuthProductScope,
    ) -> Result<Vec<CredentialPresentationBinding>, AuthProductError> {
        let accounts = self.accounts.accounts_for_owner(scope).await?;
        let mut bindings = self.bindings.presentation_bindings_for_owner(scope).await?;
        bindings.retain(|binding| {
            binding.status == CredentialPresentationBindingStatus::Enabled
                && accounts.iter().any(|account| {
                    account.id == binding.account_id
                        && account.status == CredentialAccountStatus::Configured
                        && account.provider == binding.provider
                })
                && self
                    .profiles
                    .get(&binding.profile_id)
                    .is_some_and(|profile| {
                        profile.version == binding.profile_version
                            && profile.provider == binding.provider
                    })
        });
        bindings.sort_by_key(|binding| binding.id);
        Ok(bindings)
    }
}
