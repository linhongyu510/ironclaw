//! The admin user-management wire contract + the fail-closed default.
//!
//! The [`AdminUserService`] port and its record vocabulary moved to
//! `ironclaw_product_contracts::admin_users` (PROPOSAL §6.1.3): its only
//! production implementation is a `ironclaw_reborn_composition` adapter over
//! the identity user-directory, and `ironclaw_extension_host` reads the same
//! directory to resolve a channel actor's admin role. What stays here is
//! product's own surface: the `Reborn*` request/response types the WebChat v2
//! admin routes serialize, and the fail-closed default `RebornServices` wires
//! before composition installs the real adapter.

use std::collections::BTreeMap;

use async_trait::async_trait;
use ironclaw_host_api::ids::{SecretHandle, TenantId, UserId};
use ironclaw_product_contracts::admin_users::{
    AdminCreateUserFields, AdminCreatedUser, AdminUserError, AdminUserRecord, AdminUserRole,
    AdminUserSecretMeta, AdminUserService, AdminUserStatus,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Fail-closed default wired into `RebornServices` before composition installs
/// the real adapter. Every operation reports the service unavailable, so a
/// deployment that never wires the admin surface serves 503s rather than
/// panicking or silently succeeding. Mirrors the `Rejecting*` default pattern
/// used for the other optional-but-live services on `RebornServices`.
pub(crate) struct RejectingAdminUserService;

#[async_trait]
impl AdminUserService for RejectingAdminUserService {
    async fn list_users(
        &self,
        _tenant: &TenantId,
        _status: Option<AdminUserStatus>,
        _after: Option<&UserId>,
        _limit: usize,
    ) -> Result<Vec<AdminUserRecord>, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }

    async fn get_user(
        &self,
        _tenant: &TenantId,
        _user_id: &UserId,
    ) -> Result<Option<AdminUserRecord>, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }

    async fn create_user(
        &self,
        _tenant: &TenantId,
        _actor: &UserId,
        _fields: AdminCreateUserFields,
    ) -> Result<AdminCreatedUser, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }

    async fn update_profile(
        &self,
        _tenant: &TenantId,
        _user_id: &UserId,
        _display_name: Option<String>,
        _metadata: Option<BTreeMap<String, String>>,
    ) -> Result<AdminUserRecord, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }

    async fn set_status(
        &self,
        _tenant: &TenantId,
        _user_id: &UserId,
        _status: AdminUserStatus,
    ) -> Result<AdminUserRecord, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }

    async fn set_role(
        &self,
        _tenant: &TenantId,
        _user_id: &UserId,
        _role: AdminUserRole,
    ) -> Result<AdminUserRecord, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }

    async fn delete_user(
        &self,
        _tenant: &TenantId,
        _user_id: &UserId,
    ) -> Result<(), AdminUserError> {
        Err(AdminUserError::Unavailable)
    }

    async fn count_active_admins(&self, _tenant: &TenantId) -> Result<usize, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }

    async fn list_secrets(
        &self,
        _tenant: &TenantId,
        _user_id: &UserId,
    ) -> Result<Vec<AdminUserSecretMeta>, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }

    async fn put_secret(
        &self,
        _tenant: &TenantId,
        _user_id: &UserId,
        _handle: SecretHandle,
        _material: SecretString,
    ) -> Result<AdminUserSecretMeta, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }

    async fn delete_secret(
        &self,
        _tenant: &TenantId,
        _user_id: &UserId,
        _handle: SecretHandle,
    ) -> Result<bool, AdminUserError> {
        Err(AdminUserError::Unavailable)
    }
}

// --- Wire contract (WebChat v2 admin routes) ---------------------------------

/// Query params for `GET /admin/users`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RebornAdminUserListQuery {
    #[serde(default)]
    pub status: Option<AdminUserStatus>,
    /// Page size. Clamped to `[1, ADMIN_USER_LIST_MAX_LIMIT]`; omitted means
    /// `ADMIN_USER_LIST_DEFAULT_LIMIT`.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Opaque forward cursor: the `next_cursor` echoed from a prior response
    /// (a `user_id`). The browser never interprets it.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Request for routes addressing one admin-managed user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornAdminUserRequest {
    pub user_id: UserId,
}

/// Response for `GET /admin/users`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminUserListResponse {
    pub users: Vec<AdminUserRecord>,
    /// Cursor to pass as `?cursor=` for the next page, or `None` when the
    /// caller has reached the end of the tenant's users.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Body for `POST /admin/users`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminCreateUserRequest {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    pub role: AdminUserRole,
}

/// Response for `POST /admin/users` — carries the one-time API token in
/// plaintext. This is the ONLY response that ever exposes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminUserCreatedResponse {
    pub user: AdminUserRecord,
    pub api_token: String,
}

/// Body for `PATCH /admin/users/{id}` — partial profile update.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RebornAdminUpdateUserRequest {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub metadata: Option<BTreeMap<String, String>>,
}

/// ProductSurface mutation input for `PATCH /admin/users/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminUpdateUserProductRequest {
    pub user_id: UserId,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub metadata: Option<BTreeMap<String, String>>,
}

/// Body for `POST /admin/users/{id}/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminSetStatusRequest {
    pub status: AdminUserStatus,
}

/// ProductSurface mutation input for `POST /admin/users/{id}/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminSetStatusProductRequest {
    pub user_id: UserId,
    pub status: AdminUserStatus,
}

/// Body for `POST /admin/users/{id}/role`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminSetRoleRequest {
    pub role: AdminUserRole,
}

/// ProductSurface mutation input for `POST /admin/users/{id}/role`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminSetRoleProductRequest {
    pub user_id: UserId,
    pub role: AdminUserRole,
}

/// Response for the single-user reads/mutations (get, update, status, role).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminUserResponse {
    pub user: AdminUserRecord,
}

/// Response for `DELETE /admin/users/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminUserDeletedResponse {
    pub user_id: UserId,
    pub deleted: bool,
}

/// Response for `GET /admin/users/{id}/secrets`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminUserSecretsListResponse {
    pub secrets: Vec<AdminUserSecretMeta>,
}

/// Body for `PUT /admin/users/{id}/secrets/{handle}` (handle is in the path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminPutSecretRequest {
    pub value: String,
}

/// ProductSurface mutation input for `PUT /admin/users/{id}/secrets/{handle}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminPutSecretProductRequest {
    pub user_id: UserId,
    pub handle: String,
    pub value: String,
}

/// ProductSurface mutation input for `DELETE /admin/users/{id}/secrets/{handle}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminDeleteSecretProductRequest {
    pub user_id: UserId,
    pub handle: String,
}

/// Response for `PUT /admin/users/{id}/secrets/{handle}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminSecretResponse {
    pub secret: AdminUserSecretMeta,
}

/// Response for `DELETE /admin/users/{id}/secrets/{handle}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebornAdminSecretDeletedResponse {
    pub handle: String,
    pub deleted: bool,
}
