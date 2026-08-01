//! The deployment-operator control plane's product-side ports (PROPOSAL
//! §6.1.3, §6.9.2).
//!
//! Three ports and their wire vocabulary: operator readiness status, the
//! operator log ring, and OS-service lifecycle control. None of them is
//! implemented by `ironclaw_product` — the log ring and the service lifecycle
//! live in `ironclaw_operator`, the readiness status in
//! `ironclaw_reborn_composition` — which is exactly why declaring them here
//! rather than in `ironclaw_product` un-inverts the ownership: the operator
//! crate compiles against the product boundary instead of against the crate it
//! sits beside.
//!
//! Product keeps what it owns: the fail-closed `Unsupported*` defaults, the
//! `Static*` doubles, the frozen `logs`/`operator_logs` view descriptors, and
//! the operator *command-plane* response envelope that wraps these DTOs. This
//! module holds only shapes.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::surface::{ProductSurfaceCaller, ProductSurfaceError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebornOperatorStatusState {
    Ready,
    Degraded,
    Blocked,
    Unsupported,
    NotConfigured,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebornOperatorStatusSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornOperatorStatusCheck {
    pub id: String,
    pub status: RebornOperatorStatusState,
    pub severity: RebornOperatorStatusSeverity,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornOperatorStatusResponse {
    pub generated_at: DateTime<Utc>,
    pub overall: RebornOperatorStatusState,
    pub checks: Vec<RebornOperatorStatusCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RebornLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornLogQueryRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<RebornLogLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default)]
    pub tail: bool,
    #[serde(default)]
    pub follow: bool,
}

impl RebornLogQueryRequest {
    pub fn set_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn set_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    pub fn set_level(mut self, level: RebornLogLevel) -> Self {
        self.level = Some(level);
        self
    }

    pub fn set_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn set_thread_id(mut self, thread_id: impl Into<String>) -> Self {
        self.thread_id = Some(thread_id.into());
        self
    }

    pub fn set_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }

    pub fn set_turn_id(mut self, turn_id: impl Into<String>) -> Self {
        self.turn_id = Some(turn_id.into());
        self
    }

    pub fn set_tool_call_id(mut self, tool_call_id: impl Into<String>) -> Self {
        self.tool_call_id = Some(tool_call_id.into());
        self
    }

    pub fn set_tool_name(mut self, tool_name: impl Into<String>) -> Self {
        self.tool_name = Some(tool_name.into());
        self
    }

    pub fn set_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    pub fn set_tail(mut self, tail: bool) -> Self {
        self.tail = tail;
        self
    }

    pub fn set_follow(mut self, follow: bool) -> Self {
        self.follow = follow;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornLogEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub level: RebornLogLevel,
    pub target: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornLogQueryResponse {
    pub source: String,
    pub entries: Vec<RebornLogEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub tail_supported: bool,
    pub follow_supported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebornServiceLifecycleAction {
    Install,
    Start,
    Stop,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebornServiceLifecycleState {
    Installed,
    Running,
    Stopped,
    Unsupported,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornServiceLifecycleRequest {
    pub action: RebornServiceLifecycleAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornServiceLifecycleResponse {
    pub action: RebornServiceLifecycleAction,
    pub state: RebornServiceLifecycleState,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Longest operator-log context value that crosses the wire. Values are
/// normalized to this bound by their producer (the log ring), so a caller
/// filtering on a context field never has to reason about an unbounded string.
const OPERATOR_LOGS_CONTEXT_MAX_BYTES: usize = 256;
const OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX: &str = " ... [truncated]";

/// Bound an operator-log context value (thread/run/turn/tool id, tool name,
/// source) to the wire limit, marking the cut so a truncated value is not
/// mistaken for a short one.
///
/// This lives with the DTO rather than with either side because both sides
/// need the same answer: the log ring normalizes on write, and product's
/// operator-logs query bounds the caller's filter the same way. Two copies
/// would let a filter stop matching the entries it was meant to select.
pub fn normalize_operator_log_context_value(value: &str) -> String {
    truncate_utf8_with_suffix(value, OPERATOR_LOGS_CONTEXT_MAX_BYTES)
}

fn truncate_utf8_with_suffix(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    if max_bytes <= OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX.len() {
        return OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX[..max_bytes].to_string();
    }

    let mut end = max_bytes - OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX.len();
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }

    let mut truncated = String::with_capacity(max_bytes);
    truncated.push_str(&value[..end]);
    truncated.push_str(OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX);
    truncated
}

/// Deployment readiness for the operator surface.
///
/// Implemented by `ironclaw_reborn_composition` (it is the only layer that can
/// see every subsystem a readiness check reports on); product supplies the
/// `Static`/`Unsupported` doubles.
#[async_trait]
pub trait OperatorStatusService: Send + Sync {
    async fn status(
        &self,
        caller: ProductSurfaceCaller,
    ) -> Result<RebornOperatorStatusResponse, ProductSurfaceError>;
}

/// The operator log ring's query side. Implemented by
/// `ironclaw_operator::operator_logs::OperatorLogBuffer`.
#[async_trait]
pub trait OperatorLogsService: Send + Sync {
    async fn query_logs(
        &self,
        caller: ProductSurfaceCaller,
        request: RebornLogQueryRequest,
    ) -> Result<RebornLogQueryResponse, ProductSurfaceError>;
}

/// OS-service (install/start/stop/status) control for the host process.
/// Implemented by `ironclaw_operator::operator_service_lifecycle`.
#[async_trait]
pub trait OperatorServiceLifecycleService: Send + Sync {
    async fn control_service(
        &self,
        caller: ProductSurfaceCaller,
        request: RebornServiceLifecycleRequest,
    ) -> Result<RebornServiceLifecycleResponse, ProductSurfaceError>;
}
