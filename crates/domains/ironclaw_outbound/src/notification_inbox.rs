//! Durable, metadata-only user notification inbox contracts.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ironclaw_host_api::{
    ids::{TenantId, ThreadId, UserId},
    turn::TurnRunId,
};
use serde::{Deserialize, Serialize};

use crate::OutboundError;

pub const NOTIFICATION_PAGE_LIMIT_MAX: usize = 100;
/// Maximum number of durable notification records retained for one recipient.
///
/// Publishing a new identity at capacity fails closed. Existing identities
/// remain replayable so idempotent producers can safely retry without making
/// the inbox grow or requiring implicit retention/deletion policy.
pub const NOTIFICATION_INBOX_MAX_RECORDS: usize = 1_000;
pub(crate) const NOTIFICATION_ID_MAX_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct NotificationId(String);

impl NotificationId {
    fn validate(value: &str) -> Result<(), OutboundError> {
        if value.is_empty()
            || value.len() > NOTIFICATION_ID_MAX_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(OutboundError::InvalidRequest {
                reason: "notification id is invalid",
            });
        }
        Ok(())
    }

    pub fn new(value: impl Into<String>) -> Result<Self, OutboundError> {
        let value = value.into();
        Self::validate(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<String> for NotificationId {
    type Error = OutboundError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(value))
    }
}

impl AsRef<str> for NotificationId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationRecipient {
    pub tenant_id: TenantId,
    pub user_id: UserId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    ApprovalRequired,
    AuthenticationRequired,
    RunBlocked,
    RunFailed,
    RunCompleted,
    DeliveryFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationSeverity {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NotificationAction {
    OpenThread { thread_id: ThreadId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationSource {
    pub thread_id: ThreadId,
    pub turn_run_id: Option<TurnRunId>,
    /// Opaque, bounded host-issued reference such as a gate id. It is used
    /// only for deduplication/resolution and is never rendered to the user.
    pub lifecycle_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationRecord {
    pub id: NotificationId,
    pub recipient: NotificationRecipient,
    pub kind: NotificationKind,
    pub severity: NotificationSeverity,
    pub source: NotificationSource,
    pub action: NotificationAction,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub read_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub archived_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishNotificationRequest {
    pub id: NotificationId,
    pub recipient: NotificationRecipient,
    pub kind: NotificationKind,
    pub severity: NotificationSeverity,
    pub source: NotificationSource,
    pub action: NotificationAction,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListNotificationsRequest {
    pub recipient: NotificationRecipient,
    pub limit: usize,
    pub cursor: Option<String>,
    pub include_archived: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationPage {
    pub notifications: Vec<NotificationRecord>,
    pub next_cursor: Option<String>,
    pub unread_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMutationRequest {
    pub recipient: NotificationRecipient,
    pub notification_id: NotificationId,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkAllNotificationsReadRequest {
    pub recipient: NotificationRecipient,
    pub occurred_at: DateTime<Utc>,
}

#[async_trait]
pub trait NotificationInboxStorePort: Send + Sync {
    async fn publish(
        &self,
        request: PublishNotificationRequest,
    ) -> Result<NotificationRecord, OutboundError>;

    async fn list(
        &self,
        request: ListNotificationsRequest,
    ) -> Result<NotificationPage, OutboundError>;

    async fn mark_read(&self, request: NotificationMutationRequest) -> Result<(), OutboundError>;

    async fn mark_all_read(
        &self,
        request: MarkAllNotificationsReadRequest,
    ) -> Result<(), OutboundError>;

    async fn resolve(&self, request: NotificationMutationRequest) -> Result<(), OutboundError>;

    async fn archive(&self, request: NotificationMutationRequest) -> Result<(), OutboundError>;
}

/// Empty default for product surfaces that do not expose an inbox.
///
/// Reads are empty, while every write fails loudly so a production surface
/// cannot acknowledge a notification lifecycle transition without durable
/// storage being wired.
#[derive(Debug, Default)]
pub struct NoopNotificationInboxStore;

#[async_trait]
impl NotificationInboxStorePort for NoopNotificationInboxStore {
    async fn publish(
        &self,
        _request: PublishNotificationRequest,
    ) -> Result<NotificationRecord, OutboundError> {
        Err(OutboundError::Backend)
    }

    async fn list(
        &self,
        _request: ListNotificationsRequest,
    ) -> Result<NotificationPage, OutboundError> {
        Ok(NotificationPage {
            notifications: Vec::new(),
            next_cursor: None,
            unread_count: 0,
        })
    }

    async fn mark_read(&self, _request: NotificationMutationRequest) -> Result<(), OutboundError> {
        Err(OutboundError::Backend)
    }

    async fn mark_all_read(
        &self,
        _request: MarkAllNotificationsReadRequest,
    ) -> Result<(), OutboundError> {
        Err(OutboundError::Backend)
    }

    async fn resolve(&self, _request: NotificationMutationRequest) -> Result<(), OutboundError> {
        Err(OutboundError::Backend)
    }

    async fn archive(&self, _request: NotificationMutationRequest) -> Result<(), OutboundError> {
        Err(OutboundError::Backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_id_uses_the_validated_newtype_contract() {
        let id = NotificationId::try_from("notification-1".to_string()).expect("valid id");
        assert_eq!(id.as_str(), "notification-1");
        assert_eq!(id.as_ref(), "notification-1");
        assert_eq!(id.into_inner(), "notification-1");

        assert!(NotificationId::try_from(String::new()).is_err());
        assert!(serde_json::from_str::<NotificationId>("\"bad\\nid\"").is_err());
    }
}
