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

use std::{collections::HashMap, path::PathBuf, time::Duration};

use async_trait::async_trait;
use thiserror::Error;

use crate::{
    capability::RuntimeCredentialRequirement,
    ids::{CapabilityId, SecretHandle},
    mount::MountView,
    resource::ResourceScope,
};

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

/// Placement-neutral shell command request handed to the selected process port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandExecutionRequest {
    pub scope: ResourceScope,
    pub mounts: Option<MountView>,
    pub command: String,
    pub workdir: Option<String>,
    pub timeout_secs: Option<u64>,
    pub extra_env: HashMap<String, String>,
}
/// An authorized runtime credential mapped from its manifest-declared direct
/// executable and placeholder environment variable.
///
/// The requirement is copied from the authorized capability descriptor. The
/// host process adapter consumes its one-shot staged material; callers cannot
/// supply raw credential material through this shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCommandCredentialBinding {
    pub placeholder_env: String,
    pub requirement: RuntimeCredentialRequirement,
}

/// A validated executable plus argument vector. This request is separate from
/// [`CommandExecutionRequest`] so existing shell transports cannot accidentally
/// reinterpret a credentialed command as shell syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectSandboxCommandRequest {
    pub capability_id: CapabilityId,
    pub scope: ResourceScope,
    pub mounts: Option<MountView>,
    pub executable: String,
    pub args: Vec<String>,
    pub workdir: Option<String>,
    pub timeout_secs: Option<u64>,
    pub extra_env: HashMap<String, String>,
    pub credential_bindings: Vec<SandboxCommandCredentialBinding>,
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
/// transport. `credential_key` addresses this value inside the proxy's JSON
/// bundle. The command receives `placeholder`; only the proxy-side transport
/// may expose `secret`.
#[derive(Clone)]
pub struct SandboxCommandCredential {
    pub credential_key: SecretHandle,
    pub placeholder_env: String,
    pub placeholder: String,
    pub approved_host: String,
    pub header_name: String,
    pub header_prefix: Option<String>,
    secret: zeroize::Zeroizing<String>,
}

impl SandboxCommandCredential {
    pub fn new(
        credential_key: SecretHandle,
        placeholder_env: String,
        placeholder: String,
        approved_host: String,
        header_name: String,
        header_prefix: Option<String>,
        secret: String,
    ) -> Self {
        Self {
            credential_key,
            placeholder_env,
            placeholder,
            approved_host: approved_host.to_ascii_lowercase(),
            header_name: header_name.to_ascii_lowercase(),
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
            .field("credential_key", &self.credential_key)
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
    #[error("process execution failed: {0}")]
    ExecutionFailed(String),
}
/// Parse one direct command without invoking a shell.
///
/// Kernel credential enrichment and host-runtime shell dispatch share this
/// parser so authorization and execution apply the same command predicate.
/// The executable must be the exact declared bare basename. Shell operators,
/// expansions, executable paths, and unsupported escapes fail closed.
pub fn single_direct_argv(command: &str, expected_executable: &str) -> Option<Vec<String>> {
    let argv = direct_shell_words(command)?;
    let executable = argv.first()?;
    if executable.contains(['/', '\\']) || executable != expected_executable {
        return None;
    }
    Some(argv)
}

fn direct_shell_words(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = DirectShellQuote::None;
    let mut escaped = false;
    let mut word_started = false;
    for ch in command.chars() {
        if escaped {
            if quote == DirectShellQuote::Double && !matches!(ch, '\\' | '"' | '$') {
                return None;
            }
            current.push(ch);
            escaped = false;
            word_started = true;
            continue;
        }
        match (quote, ch) {
            (DirectShellQuote::Single, '\\') => {
                current.push('\\');
                word_started = true;
            }
            (_, '\\') => {
                escaped = true;
                word_started = true;
            }
            (DirectShellQuote::None, '\'') => {
                quote = DirectShellQuote::Single;
                word_started = true;
            }
            (DirectShellQuote::Single, '\'') => quote = DirectShellQuote::None,
            (DirectShellQuote::None, '"') => {
                quote = DirectShellQuote::Double;
                word_started = true;
            }
            (DirectShellQuote::Double, '"') => quote = DirectShellQuote::None,
            (DirectShellQuote::None | DirectShellQuote::Double, '$' | '`') => return None,
            (DirectShellQuote::None, ';' | '|' | '&' | '<' | '>' | '\n' | '\r') => return None,
            (DirectShellQuote::None, '*' | '?' | '[' | ']' | '{' | '}') => return None,
            (DirectShellQuote::None, '~') if !word_started => return None,
            (DirectShellQuote::None, ch) if ch.is_whitespace() => {
                if word_started {
                    words.push(std::mem::take(&mut current));
                    word_started = false;
                }
            }
            _ => {
                current.push(ch);
                word_started = true;
            }
        }
    }
    if escaped || quote != DirectShellQuote::None {
        return None;
    }
    if word_started {
        words.push(current);
    }
    Some(words)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectShellQuote {
    None,
    Single,
    Double,
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

    async fn run_credentialed_direct_command(
        &self,
        _request: DirectSandboxCommandRequest,
        credentials: Vec<SandboxCommandCredential>,
    ) -> Result<CommandExecutionOutput, RuntimeProcessError> {
        let reason = if credentials.is_empty() {
            "sandbox transport does not support direct-argv execution"
        } else {
            "sandbox transport does not support credential bindings"
        };
        Err(RuntimeProcessError::ExecutionFailed(reason.to_string()))
    }

    fn supports_credentialed_direct_command(&self) -> bool {
        false
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
    fn direct_request_preserves_argument_boundaries() {
        let request = DirectSandboxCommandRequest {
            capability_id: CapabilityId::new("builtin.shell").unwrap(),
            scope: ResourceScope::system(),
            mounts: None,
            executable: "printf".to_string(),
            args: vec!["%s".to_string(), "one; echo injected".to_string()],
            workdir: None,
            timeout_secs: None,
            extra_env: HashMap::new(),
            credential_bindings: Vec::new(),
        };

        assert_eq!(request.executable, "printf");
        assert_eq!(
            request.args,
            ["%s", "one; echo injected"],
            "the credentialed process boundary must never reinterpret arguments as shell syntax"
        );
    }

    #[test]
    fn direct_command_parser_is_shell_aware_and_binds_a_bare_executable() {
        assert_eq!(
            single_direct_argv(r#"gh api --field 'a\b' --raw-field "x\\y\"z\$""#, "gh"),
            Some(vec![
                "gh".to_string(),
                "api".to_string(),
                "--field".to_string(),
                r"a\b".to_string(),
                "--raw-field".to_string(),
                "x\\y\"z$".to_string(),
            ])
        );
        // A quoted head is a valid shell spelling of the same bare basename;
        // authorization and dispatch must both accept it (PR #7810 review:
        // the defect was the two predicates disagreeing on this form).
        assert_eq!(
            single_direct_argv(r#""gh" pr list"#, "gh"),
            Some(vec!["gh".to_string(), "pr".to_string(), "list".to_string(),])
        );
        for command in [
            "/tmp/gh pr list",
            "./gh pr list",
            r#"'C:\tools\gh' pr list"#,
            "GH pr list",
            "gh api x > out",
            r#"gh api "a\q""#,
            "gh api \"$TOKEN\"",
            "gh api user | cat",
        ] {
            assert!(
                single_direct_argv(command, "gh").is_none(),
                "expected direct command rejection: {command}"
            );
        }
    }

    #[test]
    fn sandbox_credential_normalizes_case_insensitive_comparison_fields() {
        let credential = |approved_host: &str, header_name: &str| {
            SandboxCommandCredential::new(
                SecretHandle::new("github_runtime_token").unwrap(),
                "GH_TOKEN".to_string(),
                "icsbx_placeholder".to_string(),
                approved_host.to_string(),
                header_name.to_string(),
                Some("token ".to_string()),
                "secret".to_string(),
            )
        };

        let lowercase = credential("api.github.com", "authorization");
        let mixed_case = credential("API.GitHub.COM", "Authorization");

        assert_eq!(lowercase.approved_host, "api.github.com");
        assert_eq!(lowercase.header_name, "authorization");
        assert_eq!(mixed_case.approved_host, lowercase.approved_host);
        assert_eq!(mixed_case.header_name, lowercase.header_name);
    }
}
