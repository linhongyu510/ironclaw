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

/// Readiness verdict for one operator status check, and for the roll-up over
/// all of them.
///
/// The roll-up (`RebornOperatorStatusResponse::overall`) is computed by
/// precedence, not by worst-severity: any `Blocked` check makes the whole
/// response `Blocked`; otherwise any `Degraded` *or* `NotConfigured` check makes
/// it `Degraded`; otherwise `Ready`. `Unsupported` is deliberately excluded from
/// that fold — see its variant note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebornOperatorStatusState {
    /// The subsystem is wired and validated for its profile.
    Ready,
    /// Usable, but not on a production footing — a dev-only or preview-storage
    /// profile, or a non-blocking readiness diagnostic.
    Degraded,
    /// A blocking readiness diagnostic. Wins the roll-up outright.
    Blocked,
    /// **No probe exists for this subsystem yet** — a statement about this
    /// build's coverage, not about the deployment. Reported today for the
    /// `channels` and `extensions` checks, always at `Info` severity, and
    /// excluded from the `overall` fold so an unwritten probe can never degrade
    /// a healthy host.
    Unsupported,
    /// A required service or worker is not wired, or the runtime profile is
    /// disabled. Distinct from `Degraded` in cause but folded into it in the
    /// roll-up.
    NotConfigured,
}

/// How loudly a status check should be surfaced. Independent of
/// [`RebornOperatorStatusState`]: an `Unsupported` check is `Info`, while a
/// `NotConfigured` one is `Warning`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebornOperatorStatusSeverity {
    Info,
    Warning,
    Critical,
}

/// One named readiness probe — its verdict, how loudly to surface it, a
/// human-readable summary, and the operator action that would clear it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornOperatorStatusCheck {
    /// Stable check identifier (`runtime`, `storage`, `secrets`,
    /// `provider_model`, `webui`, `trigger_poller`, `channels`, `extensions`,
    /// or a readiness diagnostic's own id).
    pub id: String,
    pub status: RebornOperatorStatusState,
    pub severity: RebornOperatorStatusSeverity,
    /// One-line human-readable description of what was observed.
    pub summary: String,
    /// The operator action that would clear this check, when one is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// A full operator readiness snapshot: every check plus the precedence roll-up
/// over them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornOperatorStatusResponse {
    /// When this snapshot was taken. Status is computed per request, never
    /// cached, so this is the observation time.
    pub generated_at: DateTime<Utc>,
    /// Precedence roll-up over `checks` — see [`RebornOperatorStatusState`].
    pub overall: RebornOperatorStatusState,
    pub checks: Vec<RebornOperatorStatusCheck>,
}

/// Severity of an operator log entry, and the filter a log query narrows by.
/// Serialized lowercase to match the `tracing` level vocabulary the ring
/// captures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RebornLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// A query against the operator log ring. Every field is an optional narrowing
/// filter; the default value selects the most recent entries unfiltered.
///
/// Context-valued filters (`thread_id`, `run_id`, `turn_id`, `tool_call_id`,
/// `tool_name`, `source`) must be bounded with
/// [`normalize_operator_log_context_value`] before comparison — the ring
/// normalizes on write, so an un-normalized filter would stop matching the
/// entries it was meant to select.
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

/// One captured operator log line, plus whatever turn-kernel context the
/// `tracing` span carried when it was recorded. Every context field is optional
/// because most log lines are emitted outside a turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornLogEntry {
    /// Ring-assigned identifier, also the cursor value for pagination.
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub level: RebornLogLevel,
    /// The `tracing` target the line was emitted under (module path).
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

/// A page of operator log entries, with the capabilities of the backing ring so
/// a client can decide which controls to offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornLogQueryResponse {
    /// Which log source answered (identifies the ring behind this response).
    pub source: String,
    pub entries: Vec<RebornLogEntry>,
    /// Cursor for the next page; absent when this page is the last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Whether this source honours `RebornLogQueryRequest::tail`.
    pub tail_supported: bool,
    /// Whether this source honours `RebornLogQueryRequest::follow`.
    pub follow_supported: bool,
}

/// The OS-service operation an operator requests. `Status` is read-only; the
/// other three mutate the host's service registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebornServiceLifecycleAction {
    Install,
    Start,
    Stop,
    Status,
}

/// The service state observed after a lifecycle action.
///
/// Product folds these into surface availability, and the split is not the
/// obvious one: `Installed`, `Running`, `Stopped`, **and `Unknown`** all mean
/// the lifecycle surface is *available*; only `Unsupported` and `Failed` mark it
/// unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebornServiceLifecycleState {
    /// The unit or plist was written successfully.
    Installed,
    /// The service manager reports the service active.
    Running,
    /// The service manager reports the service inactive, or a stop succeeded.
    Stopped,
    /// **This OS target has no supported local service manager** — a capability
    /// statement, not a failure. The deployment is expected to be run under an
    /// external process supervisor instead.
    Unsupported,
    /// The operation failed, or the service manager reports the service failed.
    /// Covers an unresolvable home directory or executable path, a command
    /// failure, and a status query that errored or timed out.
    Failed,
    /// The service manager answered, but with a state this build does not map.
    /// Distinct from `Failed`, where the query itself did not succeed — and
    /// treated as *available*, because the surface is working even though the
    /// state string is unrecognized.
    Unknown,
}

/// Request to perform one OS-service lifecycle action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornServiceLifecycleRequest {
    pub action: RebornServiceLifecycleAction,
}

/// Outcome of a lifecycle action: the state observed afterwards, what happened,
/// and the operator action that would clear a bad state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornServiceLifecycleResponse {
    /// Echoes the requested action, so a response is self-describing.
    pub action: RebornServiceLifecycleAction,
    pub state: RebornServiceLifecycleState,
    /// One-line human-readable description of what happened.
    pub message: String,
    /// The operator action that would clear this state, when one is known.
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

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_host_api::ids::{TenantId, UserId};
    use std::sync::Arc;

    fn caller(user: &str) -> ProductSurfaceCaller {
        ProductSurfaceCaller::new(
            TenantId::new("tenant").expect("tenant"),
            UserId::new(user).expect("user"),
            None,
            None,
        )
    }

    /// A logs double that **echoes both arguments back**. A double that
    /// discarded `caller` (or ignored the request filter) would make the tests
    /// below pass against an implementation that leaked every caller's log
    /// ring, which is exactly the shape this port exists to keep per-caller.
    struct EchoingLogs;

    #[async_trait]
    impl OperatorLogsService for EchoingLogs {
        async fn query_logs(
            &self,
            caller: ProductSurfaceCaller,
            request: RebornLogQueryRequest,
        ) -> Result<RebornLogQueryResponse, ProductSurfaceError> {
            Ok(RebornLogQueryResponse {
                source: caller.user_id.as_str().to_string(),
                entries: vec![RebornLogEntry {
                    id: "1".to_string(),
                    timestamp: Utc::now(),
                    level: request.level.unwrap_or(RebornLogLevel::Info),
                    target: request.target.clone().unwrap_or_default(),
                    message: String::new(),
                    thread_id: request.thread_id.clone(),
                    run_id: None,
                    turn_id: None,
                    tool_call_id: None,
                    tool_name: None,
                    source: None,
                }],
                next_cursor: request.cursor.clone(),
                tail_supported: request.tail,
                follow_supported: request.follow,
            })
        }
    }

    /// The port hands the implementation *both* of its arguments, and the shape
    /// admits a different answer for each. This pins the contract's plumbing —
    /// it deliberately does **not** claim the production log ring filters
    /// correctly; that belongs to `ironclaw_operator`'s own suite.
    #[tokio::test]
    async fn logs_port_threads_caller_and_request_and_can_answer_differently() {
        let service: Arc<dyn OperatorLogsService> = Arc::new(EchoingLogs);

        let one = service
            .query_logs(
                caller("alice"),
                RebornLogQueryRequest::default()
                    .set_level(RebornLogLevel::Error)
                    .set_target("alpha")
                    .set_tail(true),
            )
            .await
            .expect("double never fails");
        let two = service
            .query_logs(
                caller("bob"),
                RebornLogQueryRequest::default()
                    .set_level(RebornLogLevel::Debug)
                    .set_target("beta")
                    .set_tail(false),
            )
            .await
            .expect("double never fails");

        // Both directions: the caller discriminates, and so does the request.
        assert_eq!(one.source, "alice");
        assert_eq!(two.source, "bob");
        assert_ne!(one.source, two.source);
        assert_eq!(one.entries[0].level, RebornLogLevel::Error);
        assert_eq!(two.entries[0].level, RebornLogLevel::Debug);
        assert_eq!(one.entries[0].target, "alpha");
        assert_eq!(two.entries[0].target, "beta");
        assert!(one.tail_supported);
        assert!(!two.tail_supported);
    }

    /// A `RebornLogQueryRequest` built through the setters round-trips its
    /// filters. The setters are the only way a caller narrows a query, and a
    /// setter that dropped its value would silently widen every log read.
    #[test]
    fn log_query_setters_each_land_on_their_own_field() {
        let request = RebornLogQueryRequest::default()
            .set_limit(7)
            .set_cursor("cursor")
            .set_level(RebornLogLevel::Warn)
            .set_target("target")
            .set_thread_id("thread")
            .set_run_id("run")
            .set_turn_id("turn")
            .set_tool_call_id("tool-call")
            .set_tool_name("tool")
            .set_source("source")
            .set_tail(true)
            .set_follow(true);

        assert_eq!(request.limit, Some(7));
        assert_eq!(request.cursor.as_deref(), Some("cursor"));
        assert_eq!(request.level, Some(RebornLogLevel::Warn));
        assert_eq!(request.target.as_deref(), Some("target"));
        assert_eq!(request.thread_id.as_deref(), Some("thread"));
        assert_eq!(request.run_id.as_deref(), Some("run"));
        assert_eq!(request.turn_id.as_deref(), Some("turn"));
        assert_eq!(request.tool_call_id.as_deref(), Some("tool-call"));
        assert_eq!(request.tool_name.as_deref(), Some("tool"));
        assert_eq!(request.source.as_deref(), Some("source"));
        assert!(request.tail);
        assert!(request.follow);
    }

    /// The bound is enforced *and* marked. An over-long value must come back
    /// within the limit and must be distinguishable from a value that merely
    /// happened to be short, or a filter would silently stop matching the
    /// entries it was written to select.
    #[test]
    fn log_context_normalization_bounds_and_marks_the_cut() {
        let short = "thread-42";
        assert_eq!(normalize_operator_log_context_value(short), short);

        let long = "x".repeat(OPERATOR_LOGS_CONTEXT_MAX_BYTES * 2);
        let bounded = normalize_operator_log_context_value(&long);
        assert!(bounded.len() <= OPERATOR_LOGS_CONTEXT_MAX_BYTES);
        assert!(bounded.ends_with(OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX));
        assert_ne!(bounded, long);

        // A multi-byte value is cut on a character boundary, not mid-codepoint
        // (the cut is byte-counted, so this is the failure mode to pin).
        //
        // Both widths, deliberately — but note what neither of them proves.
        // The cut offset is 256 - 16 = 240, and 2, 3, and 4 all divide 240, so
        // **any** homogeneous repeat lands exactly on a boundary and the
        // back-up loop never executes. A test built only from `glyph.repeat(n)`
        // looks like it covers the multi-byte case and does not; the shifted
        // input below is what actually drives the loop.
        for glyph in ["é", "€"] {
            let multibyte = glyph.repeat(OPERATOR_LOGS_CONTEXT_MAX_BYTES);
            let bounded = normalize_operator_log_context_value(&multibyte);
            assert!(bounded.len() <= OPERATOR_LOGS_CONTEXT_MAX_BYTES);
            assert!(bounded.ends_with(OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX));
            // The prefix is whole characters: re-parsing is what proves the cut
            // did not land inside a codepoint. (`String` cannot hold invalid
            // UTF-8, so slicing mid-codepoint would have panicked above — this
            // asserts the *content*, that no replacement char crept in.)
            let kept = bounded
                .strip_suffix(OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX)
                .expect("the cut is marked");
            assert!(!kept.is_empty());
            assert!(kept.chars().all(|ch| ch.to_string() == glyph));
        }

        // Force the back-up: one ASCII byte then 3-byte characters puts the
        // boundaries at 1, 4, 7 … (≡ 1 mod 3). The cut offset 240 ≡ 0, so the
        // loop must walk back to 238 before it can slice. Without this input
        // the loop body is never executed by any test in this file.
        let shifted = format!("x{}", "€".repeat(OPERATOR_LOGS_CONTEXT_MAX_BYTES));
        let bounded = normalize_operator_log_context_value(&shifted);
        assert!(bounded.len() <= OPERATOR_LOGS_CONTEXT_MAX_BYTES);
        assert!(bounded.ends_with(OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX));
        let kept = bounded
            .strip_suffix(OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX)
            .expect("the cut is marked");
        // Backed up strictly below the naive offset — the proof the loop ran.
        assert!(
            kept.len()
                < OPERATOR_LOGS_CONTEXT_MAX_BYTES - OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX.len()
        );
        assert!(kept.starts_with('x'));
        assert!(kept.chars().skip(1).all(|ch| ch == '€'));
    }

    /// The degenerate bound: a limit shorter than the truncation marker itself.
    ///
    /// Unreachable through `normalize_operator_log_context_value`, whose bound
    /// is a 256-byte constant — so it is reached here directly, through the
    /// private helper. It is a fail-safe, not dead code: it is what stops the
    /// `max_bytes - SUFFIX.len()` subtraction below it from underflowing if the
    /// constant is ever lowered, and an untested fail-safe is how an arithmetic
    /// panic reaches a log-query path.
    #[test]
    fn log_context_bound_shorter_than_the_marker_does_not_underflow() {
        let marker = OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX.len();

        for max_bytes in [0, 1, marker - 1, marker] {
            let bounded = truncate_utf8_with_suffix(&"x".repeat(marker * 4), max_bytes);
            assert_eq!(bounded.len(), max_bytes);
            assert_eq!(bounded, OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX[..max_bytes]);
        }

        // One byte above the marker takes the normal path and still fits.
        let bounded = truncate_utf8_with_suffix(&"x".repeat(marker * 4), marker + 1);
        assert!(bounded.len() <= marker + 1);
        assert!(bounded.ends_with(OPERATOR_LOG_CONTEXT_TRUNCATED_SUFFIX));
    }

    struct EchoingLifecycle;

    #[async_trait]
    impl OperatorServiceLifecycleService for EchoingLifecycle {
        async fn control_service(
            &self,
            caller: ProductSurfaceCaller,
            request: RebornServiceLifecycleRequest,
        ) -> Result<RebornServiceLifecycleResponse, ProductSurfaceError> {
            Ok(RebornServiceLifecycleResponse {
                action: request.action,
                state: RebornServiceLifecycleState::Running,
                message: caller.user_id.as_str().to_string(),
                remediation: None,
            })
        }
    }

    /// The lifecycle port carries the requested *action* through to the
    /// response, so a caller can tell which request an answer belongs to, and
    /// the caller reaches the implementation. Both are properties of the
    /// contract, not of any backend.
    #[tokio::test]
    async fn lifecycle_port_threads_caller_and_echoes_the_requested_action() {
        let service: Arc<dyn OperatorServiceLifecycleService> = Arc::new(EchoingLifecycle);

        let started = service
            .control_service(
                caller("alice"),
                RebornServiceLifecycleRequest {
                    action: RebornServiceLifecycleAction::Start,
                },
            )
            .await
            .expect("double never fails");
        let stopped = service
            .control_service(
                caller("bob"),
                RebornServiceLifecycleRequest {
                    action: RebornServiceLifecycleAction::Stop,
                },
            )
            .await
            .expect("double never fails");

        assert_eq!(started.action, RebornServiceLifecycleAction::Start);
        assert_eq!(stopped.action, RebornServiceLifecycleAction::Stop);
        assert_ne!(started.action, stopped.action);
        assert_eq!(started.message, "alice");
        assert_eq!(stopped.message, "bob");
    }

    struct EchoingStatus;

    #[async_trait]
    impl OperatorStatusService for EchoingStatus {
        async fn status(
            &self,
            caller: ProductSurfaceCaller,
        ) -> Result<RebornOperatorStatusResponse, ProductSurfaceError> {
            Ok(RebornOperatorStatusResponse {
                generated_at: Utc::now(),
                overall: if caller.operator_config {
                    RebornOperatorStatusState::Ready
                } else {
                    RebornOperatorStatusState::Blocked
                },
                checks: vec![RebornOperatorStatusCheck {
                    id: caller.user_id.as_str().to_string(),
                    status: RebornOperatorStatusState::Degraded,
                    severity: RebornOperatorStatusSeverity::Warning,
                    summary: String::new(),
                    remediation: None,
                }],
            })
        }
    }

    /// Status is caller-scoped: the port passes the caller through, and the
    /// shape admits a different overall state per caller. Both directions are
    /// asserted so a double that hard-coded one answer could not satisfy it.
    #[tokio::test]
    async fn status_port_threads_the_caller_and_can_answer_differently_per_caller() {
        let service: Arc<dyn OperatorStatusService> = Arc::new(EchoingStatus);

        let privileged = service
            .status(caller("alice").with_operator_config(true))
            .await
            .expect("double never fails");
        let plain = service
            .status(caller("bob"))
            .await
            .expect("double never fails");

        assert_eq!(privileged.overall, RebornOperatorStatusState::Ready);
        assert_eq!(plain.overall, RebornOperatorStatusState::Blocked);
        assert_ne!(privileged.overall, plain.overall);
        assert_eq!(privileged.checks[0].id, "alice");
        assert_eq!(plain.checks[0].id, "bob");
    }

    /// Every port here is held as `Arc<dyn _>` by its consumer, so each must
    /// stay object-safe. A default method taking `Self: Sized`, or a generic
    /// method added later, would break every wiring site at once; this fails
    /// in the crate that owns the trait instead.
    #[test]
    fn operator_ports_stay_object_safe() {
        fn assert_object_safe(
            _logs: &dyn OperatorLogsService,
            _lifecycle: &dyn OperatorServiceLifecycleService,
            _status: &dyn OperatorStatusService,
        ) {
        }
        assert_object_safe(&EchoingLogs, &EchoingLifecycle, &EchoingStatus);
    }

    /// The wire forms are snake_case and stable — the WebUI reads these strings
    /// directly, so a rename is a breaking wire change, not a refactor.
    #[test]
    fn operator_dtos_keep_their_snake_case_wire_forms() {
        assert_eq!(
            serde_json::to_string(&RebornOperatorStatusState::NotConfigured).expect("serializes"),
            "\"not_configured\""
        );
        assert_eq!(
            serde_json::to_string(&RebornOperatorStatusSeverity::Critical).expect("serializes"),
            "\"critical\""
        );
        assert_eq!(
            serde_json::to_string(&RebornServiceLifecycleAction::Install).expect("serializes"),
            "\"install\""
        );
        assert_eq!(
            serde_json::to_string(&RebornServiceLifecycleState::Unsupported).expect("serializes"),
            "\"unsupported\""
        );
        // Log levels are lowercase, not snake_case — a different `rename_all`
        // on a neighbouring enum, and the one most likely to be "tidied".
        assert_eq!(
            serde_json::to_string(&RebornLogLevel::Warn).expect("serializes"),
            "\"warn\""
        );
    }
}
