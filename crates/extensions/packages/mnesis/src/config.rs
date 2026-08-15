use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::url_check::EndpointProfile;

pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_TOTAL_DEADLINE_SECS: u64 = 60;
pub const DEFAULT_MAX_IDLE_CONNECTIONS: usize = 4;
pub const DEFAULT_MAX_RETRIES: u32 = 2;
pub const DEFAULT_RETRY_BACKOFF_MS: u64 = 200;

const MAX_HANDLE_LENGTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct SecretHandle(String);

#[derive(Debug, thiserror::Error)]
#[error("secret handle is invalid: {reason}")]
pub struct SecretHandleError {
    reason: String,
}

impl SecretHandle {
    fn validate(value: &str) -> Result<(), SecretHandleError> {
        if value.is_empty() || value.len() > MAX_HANDLE_LENGTH {
            return Err(SecretHandleError {
                reason: format!("must be 1 to {MAX_HANDLE_LENGTH} characters"),
            });
        }
        if !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '/' | '.')
        }) {
            return Err(SecretHandleError {
                reason: "may contain only ASCII alphanumerics and _-/.".to_string(),
            });
        }
        Ok(())
    }

    pub fn new(raw: impl Into<String>) -> Result<Self, SecretHandleError> {
        let value = raw.into();
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

impl TryFrom<String> for SecretHandle {
    type Error = SecretHandleError;

    fn try_from(value: String) -> Result<Self, SecretHandleError> {
        Self::validate(&value)?;
        Ok(Self(value))
    }
}

impl AsRef<str> for SecretHandle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SecretHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MnesisLimits {
    pub max_response_bytes: usize,
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub total_deadline_secs: u64,
    pub max_idle_connections: usize,
    pub max_retries: u32,
    pub retry_backoff_ms: u64,
}

impl Default for MnesisLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
            total_deadline_secs: DEFAULT_TOTAL_DEADLINE_SECS,
            max_idle_connections: DEFAULT_MAX_IDLE_CONNECTIONS,
            max_retries: DEFAULT_MAX_RETRIES,
            retry_backoff_ms: DEFAULT_RETRY_BACKOFF_MS,
        }
    }
}

impl MnesisLimits {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }

    pub fn total_deadline(&self) -> Duration {
        Duration::from_secs(self.total_deadline_secs)
    }

    pub fn retry_backoff(&self) -> Duration {
        Duration::from_millis(self.retry_backoff_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MnesisConfig {
    pub knowledge_endpoint: String,
    pub memory_endpoint: String,
    pub knowledge_credential: SecretHandle,
    pub memory_credential: SecretHandle,
    #[serde(default)]
    pub host_allowlist: Vec<String>,
    #[serde(default)]
    pub profile: EndpointProfile,
    #[serde(default)]
    pub limits: MnesisLimits,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_handle_rejects_material_shaped_values() {
        SecretHandle::new("services/memory-clients").unwrap();
        SecretHandle::new("mnesis_bearer").unwrap();
        SecretHandle::new("").unwrap_err();
        SecretHandle::new("has space").unwrap_err();
        SecretHandle::new("has\nnewline").unwrap_err();
        SecretHandle::new("a".repeat(MAX_HANDLE_LENGTH + 1)).unwrap_err();
    }

    #[test]
    fn secret_handle_round_trips_through_serde_with_validation() {
        let handle: SecretHandle = serde_json::from_str("\"services/rar-clients\"").unwrap();
        assert_eq!(handle.as_str(), "services/rar-clients");
        serde_json::from_str::<SecretHandle>("\"bad value\"").unwrap_err();
    }

    #[test]
    fn config_debug_carries_no_secret_material() {
        let config = MnesisConfig {
            knowledge_endpoint: "https://mnesis.example.com/rar/mcp".to_string(),
            memory_endpoint: "https://mnesis.example.com/memory/mcp".to_string(),
            knowledge_credential: SecretHandle::new("services/rar-clients").unwrap(),
            memory_credential: SecretHandle::new("services/memory-clients").unwrap(),
            host_allowlist: Vec::new(),
            profile: EndpointProfile::Production,
            limits: MnesisLimits::default(),
        };
        let rendered = format!("{config:?}");
        assert!(rendered.contains("services/rar-clients"));
        assert!(rendered.contains("services/memory-clients"));
        assert!(!rendered.contains("Bearer"));
    }

    #[test]
    fn limits_default_to_bounded_values() {
        let limits = MnesisLimits::default();
        assert_eq!(limits.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
        assert!(limits.connect_timeout() < limits.request_timeout());
        assert!(limits.request_timeout() <= limits.total_deadline());
        assert!(limits.max_retries <= 5);
    }
}
