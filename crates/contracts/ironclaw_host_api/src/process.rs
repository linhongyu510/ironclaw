//! Placement-neutral process-execution vocabulary and the sandbox transport
//! port.
//!
//! The kernel decides *which* process port receives a command; a lane provides
//! the transport that runs it. Declaring both halves here is what lets a
//! `runtimes`-layer lane implement what the kernel consumes without an upward
//! dependency: `ironclaw_sandbox` (runtimes) implements
//! [`SandboxCommandTransport`], `ironclaw_host_runtime` (kernel) wraps it in
//! `UserSandboxProcessPort`. PROPOSAL §6.6.4 records that this home is
//! load-bearing, not cosmetic.
//!
//! `ironclaw_host_runtime` still owns the *behavior* — process spawning, output
//! capture, alias rewriting, and the local-host port. Only the shapes that
//! cross the kernel↔lane seam live here.

use std::{
    collections::HashMap,
    fmt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use thiserror::Error;

use crate::{mount::MountView, resource::ResourceScope};
/// Cooperative cancellation shared across the kernel-to-sandbox transport seam.
#[derive(Clone)]
pub struct CommandCancellationToken {
    inner: Arc<CommandCancellationState>,
}

struct CommandCancellationState {
    cancelled: AtomicBool,
    notify: tokio::sync::Notify,
}

impl Default for CommandCancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandCancellationToken {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CommandCancellationState {
                cancelled: AtomicBool::new(false),
                notify: tokio::sync::Notify::new(),
            }),
        }
    }

    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::SeqCst) {
            self.inner.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        loop {
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
            if self.is_cancelled() {
                return;
            }
        }
    }
}

impl fmt::Debug for CommandCancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandCancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl PartialEq for CommandCancellationToken {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for CommandCancellationToken {}

/// Metadata for command output persisted behind a saved-output reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedCommandOutput {
    pub path: PathBuf,
    pub sanitization: SavedCommandOutputSanitization,
    pub stream_was_capped: bool,
    pub max_saved_stream_size: usize,
    pub expires_at_unix_secs: u64,
}

/// Whether persisted command output required redaction or blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedCommandOutputSanitization {
    Clean,
    Redacted,
    Blocked,
}

/// Placement-neutral command request handed to the selected process port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandExecutionRequest {
    pub scope: ResourceScope,
    pub mounts: Option<MountView>,
    pub command: String,
    /// Arguments passed directly to `command`. No shell parsing is permitted.
    pub args: Vec<String>,
    pub workdir: Option<String>,
    pub timeout_secs: Option<u64>,
    pub extra_env: HashMap<String, String>,
    pub cancellation: CommandCancellationToken,
}

impl CommandExecutionRequest {
    pub fn argv(&self) -> Vec<&str> {
        std::iter::once(self.command.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect()
    }
}

/// Process-port command result normalized for capability handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandExecutionOutput {
    pub output: String,
    pub saved_output: Option<SavedCommandOutput>,
    pub exit_code: i64,
    pub sandboxed: bool,
    pub duration: Duration,
}

/// One invocation-scoped credential binding handed only to the sandbox
/// transport. The command receives `placeholder`; only the proxy-side
/// transport may expose `secret`.
#[derive(Clone)]
pub struct SandboxCommandCredential {
    pub placeholder_env: String,
    pub placeholder: String,
    pub approved_host: String,
    pub header_name: String,
    pub header_prefix: Option<String>,
    secret: zeroize::Zeroizing<String>,
}

impl SandboxCommandCredential {
    pub fn new(
        placeholder_env: String,
        placeholder: String,
        approved_host: String,
        header_name: String,
        header_prefix: Option<String>,
        secret: String,
    ) -> Self {
        Self {
            placeholder_env,
            placeholder,
            approved_host,
            header_name,
            header_prefix,
            secret: zeroize::Zeroizing::new(secret),
        }
    }

    pub fn expose_secret(&self) -> &str {
        self.secret.as_str()
    }
}

impl std::fmt::Debug for SandboxCommandCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxCommandCredential")
            .field("placeholder_env", &self.placeholder_env)
            .field("approved_host", &self.approved_host)
            .field("header_name", &self.header_name)
            .field("header_prefix", &self.header_prefix)
            .finish_non_exhaustive()
    }
}

/// Stable redacted process-port failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RuntimeProcessError {
    #[error("command timed out after {0:?}")]
    Timeout(Duration),
    #[error("process execution cancelled")]
    Cancelled,
    #[error("process execution failed: {0}")]
    ExecutionFailed(String),
}

/// Transport for user-sandbox command execution.
///
/// This trait intentionally hides Docker/daemon details from host-runtime tool
/// code. A lane implements it with a container runtime or another runner that
/// isolates each authenticated user within the tenant boundary.
///
/// Implementations must enforce [`CommandExecutionRequest::timeout_secs`] and
/// clean up any remote process/container before returning
/// [`RuntimeProcessError::Timeout`].
#[async_trait]
pub trait SandboxCommandTransport: Send + Sync {
    async fn run_command(
        &self,
        request: CommandExecutionRequest,
    ) -> Result<CommandExecutionOutput, RuntimeProcessError>;

    async fn run_credentialed_command(
        &self,
        request: CommandExecutionRequest,
        credentials: Vec<SandboxCommandCredential>,
    ) -> Result<CommandExecutionOutput, RuntimeProcessError> {
        if !credentials.is_empty() {
            return Err(RuntimeProcessError::ExecutionFailed(
                "sandbox transport does not support credential bindings".to_string(),
            ));
        }
        self.run_command(request).await
    }

    /// Release remote resources owned by this transport after command
    /// producers have stopped. Local transports may keep the default no-op;
    /// remote transports override this with idempotent provider cleanup.
    async fn shutdown(&self) -> Result<(), RuntimeProcessError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_request_preserves_argument_boundaries() {
        let request = CommandExecutionRequest {
            scope: ResourceScope::system(),
            mounts: None,
            command: "printf".to_string(),
            args: vec!["%s".to_string(), "one; echo injected".to_string()],
            workdir: None,
            timeout_secs: None,
            extra_env: HashMap::new(),
            cancellation: CommandCancellationToken::new(),
        };

        assert_eq!(
            request.argv(),
            ["printf", "%s", "one; echo injected"],
            "the process boundary must never reinterpret arguments as shell syntax"
        );
    }
    #[tokio::test]
    async fn command_cancellation_wakes_in_flight_waiter() {
        let token = CommandCancellationToken::new();
        let waiter = token.clone();
        let waiting = tokio::spawn(async move {
            waiter.cancelled().await;
        });

        token.cancel();
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("cancellation waiter must wake")
            .expect("cancellation waiter must not panic");
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn command_cancellation_before_wait_returns_immediately() {
        let token = CommandCancellationToken::new();
        token.cancel();

        tokio::time::timeout(Duration::from_secs(1), token.cancelled())
            .await
            .expect("pre-cancelled token must not block");
    }
}
