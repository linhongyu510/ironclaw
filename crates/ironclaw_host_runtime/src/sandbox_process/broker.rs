use ironclaw_safety::params_contain_manual_credentials;

use crate::RuntimeProcessError;

use super::reject_nul;

const REBORN_NETWORK_MODE_ENV: &str = "IRONCLAW_REBORN_NETWORK_MODE";
const REBORN_HTTP_PROXY_ENV: &str = "IRONCLAW_REBORN_HTTP_PROXY";
const HTTP_PROXY_ENV_KEYS: &[&str] = &["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"];
/// Reserved names a caller may never inject into the sandboxed container's
/// environment. This list intentionally includes names for broker shapes
/// that no longer have a live implementation
/// (`IRONCLAW_REBORN_HTTP_BROKER_SOCKET`, `IRONCLAW_REBORN_HTTP_BROKER_URL`,
/// `IRONCLAW_REBORN_SECRET_MODE`, `IRONCLAW_REBORN_SECRET_BROKER_URL`,
/// `IRONCLAW_REBORN_SECRET_BROKER_SOCKET`) — the reservation is about
/// refusing caller-controlled injection of names the host itself might one
/// day use for sandbox-internal signaling, not about gating an existing
/// broker. Deleting the broker code that used to set these does not make it
/// safe for a caller to set them instead, so the names stay reserved.
pub(super) const RESERVED_BROKER_ENV_KEYS: &[&str] = &[
    REBORN_NETWORK_MODE_ENV,
    REBORN_HTTP_PROXY_ENV,
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "IRONCLAW_REBORN_HTTP_BROKER_SOCKET",
    "IRONCLAW_REBORN_HTTP_BROKER_URL",
    "IRONCLAW_REBORN_SECRET_MODE",
    "IRONCLAW_REBORN_SECRET_BROKER_URL",
    "IRONCLAW_REBORN_SECRET_BROKER_SOCKET",
];

/// Name of the pinned, `internal: true` Docker network the has-egress
/// sandbox container joins instead of Docker's default bridge (E1,
/// `docs/plans/2026-07-21-persistent-sandbox-container-plan.md` Task 2
/// amendment). Docker's default bridge NATs to the internet, so a container
/// on it can dial out directly and ignore `http_proxy`/`https_proxy` env —
/// that made "proxy-allowlist egress" advisory, not enforced. An `internal:
/// true` network has no default route off-host, so the proxy becomes the
/// only path out. `exec_transport::ensure_egress_network` creates this
/// network idempotently before a container joins it.
///
/// This topology's DinD runtime behavior (does an `internal: true` network's
/// containers really retain reachability to that network's own bridge
/// gateway while losing the internet route?) is NOT validated on this dev
/// machine — no local Docker daemon. Task 3's Docker-real integration test
/// (`tests/integration/reborn_sandbox_egress_proxy.rs`, the E1 bypass
/// assertion) is the CI arbiter for this mechanism.
pub(super) const SANDBOX_EGRESS_NETWORK_NAME: &str = "ironclaw-sandbox-egress";

/// Pinned subnet for [`SANDBOX_EGRESS_NETWORK_NAME`]. Pinning it (rather
/// than letting Docker choose one) makes [`SANDBOX_EGRESS_NETWORK_GATEWAY`]
/// a known constant instead of something that requires a `docker network
/// inspect` round-trip to discover. If this range collides with a DinD
/// host's own address space, that is a config constant to revisit, not a
/// reason to build subnet auto-selection now.
pub(super) const SANDBOX_EGRESS_NETWORK_SUBNET: &str = "10.200.0.0/24";

/// Gateway address of [`SANDBOX_EGRESS_NETWORK_NAME`] — where the sandbox
/// egress proxy (bound `0.0.0.0:0` host-side, see composition's
/// `sandbox_egress_proxy_task.rs`) is reached from inside a container on
/// this network. An `internal: true` network still bridges to the host at
/// its own gateway IP; it just has no NAT/default route beyond the host.
pub(super) const SANDBOX_EGRESS_NETWORK_GATEWAY: &str = "10.200.0.1";

/// Broker affordance exposed to tenant sandbox commands: an HTTP(S) proxy
/// URL injected as `http_proxy`/`https_proxy` (and `IRONCLAW_REBORN_HTTP_PROXY`)
/// env, requiring the container to join the pinned egress network
/// ([`SANDBOX_EGRESS_NETWORK_NAME`]) instead of Docker's default bridge —
/// see `RebornSandboxConfig::container_network_mode`'s doc comment (E1).
///
/// A Unix-socket network-broker shape, a caller-validated arbitrary-proxy-URL
/// constructor, and a wholly separate secret-broker affordance
/// (`RebornSandboxSecretBroker`) used to live alongside this. None had a
/// production caller — only [`Self::from_port`] (via
/// `RebornSandboxConfig::with_network_broker_port`) does — so they were
/// deleted as dead code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebornSandboxNetworkBroker {
    proxy_url: BrokerUrl,
}

impl RebornSandboxNetworkBroker {
    pub fn from_port(port: u16) -> Self {
        // Points at the pinned internal-network gateway (E1), NOT Docker's
        // default-bridge host-gateway address — the container joins
        // `SANDBOX_EGRESS_NETWORK_NAME` (see `container_network_mode`
        // below), which has no route to the internet, only to this gateway.
        let proxy_url = format!("http://{SANDBOX_EGRESS_NETWORK_GATEWAY}:{port}");
        debug_assert!(validate_broker_url("network broker proxy URL", &proxy_url).is_ok());

        Self {
            proxy_url: BrokerUrl::trusted(proxy_url),
        }
    }

    fn push_env(&self, env: &mut Vec<String>) -> Result<(), RuntimeProcessError> {
        push_reserved_env(env, REBORN_NETWORK_MODE_ENV, "brokered")?;
        push_reserved_env(env, REBORN_HTTP_PROXY_ENV, self.proxy_url.as_str())?;
        for key in HTTP_PROXY_ENV_KEYS {
            push_reserved_env(env, key, self.proxy_url.as_str())?;
        }
        Ok(())
    }
}

pub(super) fn push_broker_env(
    network_broker: Option<&RebornSandboxNetworkBroker>,
    env: &mut Vec<String>,
) -> Result<(), RuntimeProcessError> {
    reject_reserved_broker_env_overrides(env)?;
    if let Some(broker) = network_broker {
        broker.push_env(env)?;
    } else {
        push_reserved_env(env, REBORN_NETWORK_MODE_ENV, "disabled")?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BrokerUrl(String);

impl BrokerUrl {
    fn trusted(value: String) -> Self {
        Self(value)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

fn reject_reserved_broker_env_overrides(env: &[String]) -> Result<(), RuntimeProcessError> {
    for entry in env {
        let Some((key, _)) = entry.split_once('=') else {
            continue;
        };
        if RESERVED_BROKER_ENV_KEYS.contains(&key) {
            return Err(RuntimeProcessError::ExecutionFailed(format!(
                "environment variable {key} is reserved for the Reborn sandbox"
            )));
        }
    }
    Ok(())
}

fn push_reserved_env(
    env: &mut Vec<String>,
    key: &str,
    value: &str,
) -> Result<(), RuntimeProcessError> {
    if env
        .iter()
        .any(|entry| entry.starts_with(&format!("{key}=")))
    {
        return Err(RuntimeProcessError::ExecutionFailed(format!(
            "environment variable {key} is reserved for the Reborn sandbox"
        )));
    }
    reject_nul("environment variable name", key)?;
    reject_nul("environment variable value", value)?;
    env.push(format!("{key}={value}"));
    Ok(())
}

fn validate_broker_url(label: &str, value: &str) -> Result<(), RuntimeProcessError> {
    reject_nul(label, value)?;
    let parsed = url::Url::parse(value).map_err(|_| {
        RuntimeProcessError::ExecutionFailed(format!(
            "{label} must be an http(s) URL without credentials, fragments, or control characters"
        ))
    })?;
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(RuntimeProcessError::ExecutionFailed(format!(
            "{label} must be an http(s) URL without credentials, fragments, or control characters"
        )));
    }
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || broker_url_contains_manual_credentials(value)
    {
        return Err(RuntimeProcessError::ExecutionFailed(format!(
            "{label} must be an http(s) URL without credentials, fragments, or control characters"
        )));
    }
    Ok(())
}

fn broker_url_contains_manual_credentials(value: &str) -> bool {
    params_contain_manual_credentials(&serde_json::json!({ "url": value }))
}
