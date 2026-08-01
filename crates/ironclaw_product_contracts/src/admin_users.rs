//! The admin user-directory port and its record vocabulary
//! (PROPOSAL §6.1.3).
//!
//! [`AdminUserService`] is a dependency-inversion port: its only production
//! implementation lives in `ironclaw_reborn_composition`, over the identity
//! user-directory and the per-user secret store. It was declared inside
//! `ironclaw_product` so product and WebUI would not have to depend on
//! `ironclaw_reborn_identity` — the right inversion in the wrong crate, since
//! `ironclaw_extension_host` reads the same directory to resolve a channel
//! actor's admin role and had to depend on product to do it.
//!
//! The `Reborn*` HTTP wire DTOs that wrap these records stay with product's
//! frozen surface inventory; only the port, its records, and its error taxonomy
//! are here.
//!
//! Never here: the composition adapter, the fail-closed default, or the
//! authorization/last-admin policy (enforced by the product service).

use std::collections::BTreeMap;

use async_trait::async_trait;
use ironclaw_host_api::ids::{SecretHandle, TenantId, UserId};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Account status. Wire-stable snake_case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminUserStatus {
    Active,
    Suspended,
}

/// Account role. Wire-stable snake_case. `Owner` and `Admin` clear the admin
/// authorization boundary; `Member` does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminUserRole {
    Owner,
    Admin,
    Member,
}

impl AdminUserRole {
    /// Whether this role clears the admin authorization boundary.
    pub fn is_admin(self) -> bool {
        matches!(self, AdminUserRole::Owner | AdminUserRole::Admin)
    }
}

/// One user as seen by the admin surface — doubles as the domain record the
/// port returns and the JSON body the WebUI renders. Never carries an API
/// token: a freshly minted token is exposed exactly once via product's
/// `RebornAdminUserCreatedResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminUserRecord {
    pub user_id: UserId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub status: AdminUserStatus,
    pub role: AdminUserRole,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<UserId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

/// Metadata for one provisioned per-user secret. Never carries the material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminUserSecretMeta {
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Fields for admin-minting a new user.
#[derive(Debug, Clone)]
pub struct AdminCreateUserFields {
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub role: AdminUserRole,
}

/// A newly created user plus its one-time API token. The token is a session
/// bearer minted by the composition adapter; it is returned exactly once and
/// never persisted in plaintext.
pub struct AdminCreatedUser {
    pub record: AdminUserRecord,
    pub api_token: SecretString,
}

/// Failure modes of the admin user port. Deliberately coarse and free of
/// backend detail — the composition adapter maps identity/secret errors into
/// these, and the service maps these into the sanitized `ProductSurfaceError`
/// wire taxonomy. Authorization and last-admin protection are enforced in the
/// service, not here, so they are not modeled as port errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminUserError {
    /// The targeted user id has no record.
    NotFound,
    /// A caller-supplied value is malformed (e.g. an invalid secret handle).
    /// Maps to a 400, not a 500 — it is the client's input at fault, not the
    /// backend.
    InvalidInput,
    /// A transient backend failure; the caller may retry.
    Unavailable,
    /// A backend inconsistency or unexpected failure; not retryable.
    Internal,
}

/// Default page size for `list_users` when the caller omits `limit`.
pub const ADMIN_USER_LIST_DEFAULT_LIMIT: usize = 100;
/// Hard ceiling on the `list_users` page size, so a caller cannot widen the
/// response (and the backing directory scan) by passing a huge `limit`.
pub const ADMIN_USER_LIST_MAX_LIMIT: usize = 200;

/// Admin user-management operations. Implemented by the composition adapter
/// over the identity user-directory + per-user secret store.
///
/// Every method is tenant-scoped from the trusted caller (never a request
/// body). `get_user` must return `Ok(None)` — not `Err(NotFound)` — for a user
/// that does not exist in the tenant, so the service can distinguish "no such
/// user" (404) from "exists but you may not" (403) at the authorization seam.
#[async_trait]
pub trait AdminUserService: Send + Sync {
    /// One bounded page of users in `tenant`, optionally filtered by `status`,
    /// ordered by `user_id` ascending and starting strictly after the `after`
    /// cursor. At most `limit` records are returned; the service derives the
    /// next cursor from the last record when a full page comes back.
    async fn list_users(
        &self,
        tenant: &TenantId,
        status: Option<AdminUserStatus>,
        after: Option<&UserId>,
        limit: usize,
    ) -> Result<Vec<AdminUserRecord>, AdminUserError>;

    async fn get_user(
        &self,
        tenant: &TenantId,
        user_id: &UserId,
    ) -> Result<Option<AdminUserRecord>, AdminUserError>;

    async fn create_user(
        &self,
        tenant: &TenantId,
        actor: &UserId,
        fields: AdminCreateUserFields,
    ) -> Result<AdminCreatedUser, AdminUserError>;

    async fn update_profile(
        &self,
        tenant: &TenantId,
        user_id: &UserId,
        display_name: Option<String>,
        metadata: Option<BTreeMap<String, String>>,
    ) -> Result<AdminUserRecord, AdminUserError>;

    async fn set_status(
        &self,
        tenant: &TenantId,
        user_id: &UserId,
        status: AdminUserStatus,
    ) -> Result<AdminUserRecord, AdminUserError>;

    async fn set_role(
        &self,
        tenant: &TenantId,
        user_id: &UserId,
        role: AdminUserRole,
    ) -> Result<AdminUserRecord, AdminUserError>;

    async fn delete_user(&self, tenant: &TenantId, user_id: &UserId) -> Result<(), AdminUserError>;

    async fn count_active_admins(&self, tenant: &TenantId) -> Result<usize, AdminUserError>;

    async fn list_secrets(
        &self,
        tenant: &TenantId,
        user_id: &UserId,
    ) -> Result<Vec<AdminUserSecretMeta>, AdminUserError>;

    async fn put_secret(
        &self,
        tenant: &TenantId,
        user_id: &UserId,
        handle: SecretHandle,
        material: SecretString,
    ) -> Result<AdminUserSecretMeta, AdminUserError>;

    async fn delete_secret(
        &self,
        tenant: &TenantId,
        user_id: &UserId,
        handle: SecretHandle,
    ) -> Result<bool, AdminUserError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_owner_and_admin_clear_the_admin_boundary() {
        assert!(AdminUserRole::Owner.is_admin());
        assert!(AdminUserRole::Admin.is_admin());
        assert!(!AdminUserRole::Member.is_admin());
    }

    #[test]
    fn role_and_status_wire_forms_stay_snake_case() {
        assert_eq!(
            serde_json::to_value(AdminUserRole::Owner).expect("serialize"),
            serde_json::json!("owner")
        );
        assert_eq!(
            serde_json::to_value(AdminUserStatus::Suspended).expect("serialize"),
            serde_json::json!("suspended")
        );
    }
}
