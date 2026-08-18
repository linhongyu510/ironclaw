use thiserror::Error;

#[derive(Debug, Error)]
pub enum NotificationInboxError {
    #[error("notification inbox backend unavailable")]
    Backend,
    #[error("notification inbox serialization failed")]
    Serialization,
    #[error("notification inbox request rejected: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("notification inbox access denied")]
    AccessDenied,
    #[error("notification not found")]
    NotificationNotFound,
}
