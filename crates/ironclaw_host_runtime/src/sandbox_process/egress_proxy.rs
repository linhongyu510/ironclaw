//! Egress allowlist CONNECT/forward proxy core for the sandboxed shell
//! profile.
//!
//! Enforces [`sandbox_network_policy`](super::network_allowlist::sandbox_network_policy)
//! for real: a sandboxed container's `http_proxy`/`https_proxy` env is
//! pointed at a bound instance of this proxy (see
//! `crates/ironclaw_reborn_composition/src/sandbox/factory.rs`), and every
//! outbound `CONNECT` (HTTPS tunnel) or plain absolute-URI HTTP request the
//! container makes is checked against the policy's `allowed_targets` before
//! any bytes reach the origin.
//!
//! The proxy core remains scheduling-agnostic. This module also owns the one
//! narrowly scoped Docker adapter required for VM-backed local engines: a
//! hardened, secret-free worker-image TCP relay. Composition chooses direct
//! or relay binding, spawns the accept loop, and owns cancellation.
//!
//! Never logs request/response bodies or full URIs (only the host being
//! allowed/denied, at `debug` level) — secret material in query strings or
//! headers must never reach the logs.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions, RemoveContainerOptions,
    StartContainerOptions,
};
use bollard::errors::Error as DockerError;
use bollard::models::HostConfig;
use ironclaw_host_api::{action::NetworkPolicy, ids::InvocationId};
use ironclaw_network::{
    host_matches_host_pattern, network_denies_any_resolved_ip, network_denies_resolved_ip,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

use super::attribution;
use super::ca::{SandboxCertificateAuthority, normalize_host};
use super::credential_firewall::SandboxCredentialConnectionIdentity;
use super::credential_swap::SandboxCredentialRuntime;
use super::tls_intercept::{self, TlsInterceptConfig, VerifiedOriginConnector};

/// Hard ceiling on concurrent client connections the proxy will service at
/// once. The proxy is reachable from *inside* the sandboxed container —
/// treat that container as
/// potentially adversarial (prompt injection or hostile code running there
/// is in-scope for this design) and never let it force unbounded task/socket
/// growth on the host by opening connections faster than they drain.
/// Deliberately generous for legitimate concurrent tool use (parallel
/// `curl`s, package installs, etc.) while still being a real ceiling.
const MAX_CONCURRENT_CONNECTIONS: usize = 128;

const PROXY_V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const PROXY_V2_FIXED_HEADER_BYTES: usize = 16;
const PROXY_V2_IPV4_ADDRESS_BYTES: usize = 12;
const PROXY_V2_IPV6_ADDRESS_BYTES: usize = 36;
const PROXY_V2_MAX_ADDRESS_BYTES: usize = PROXY_V2_IPV6_ADDRESS_BYTES;
const PROXY_V2_READ_TIMEOUT: Duration = Duration::from_secs(2);

const VM_RELAY_CONTAINER_NAME: &str = "ironclaw-sandbox-egress-relay";
const VM_RELAY_LABEL_KEY: &str = "ironclaw.sandbox-egress-relay";
const VM_RELAY_LABEL_VALUE: &str = "true";
const VM_RELAY_OWNER_LABEL_KEY: &str = "ironclaw.sandbox-egress-relay.owner";
const VM_RELAY_TARGET_HOST: &str = "host.docker.internal";
const VM_RELAY_MEMORY_BYTES: i64 = 64 * 1024 * 1024;
const VM_RELAY_PIDS_LIMIT: i64 = 64;

/// Hard ceiling on a single request-line/header line's byte length. Real
/// HTTP headers are a few hundred bytes at most; this only exists to stop an
/// adversarial or buggy client inside the sandbox from making
/// [`read_request_head`] buffer an unbounded line.
pub(super) const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;

/// Hard ceiling on the sum of header bytes (request line plus every header
/// line) for one request — bounds total allocation even across many lines
/// that each individually stay under [`MAX_HEADER_LINE_BYTES`].
pub(super) const MAX_TOTAL_HEADER_BYTES: usize = 32 * 1024;

/// Hard ceiling on header line COUNT — bounds allocation (one `String` per
/// line, in [`RequestHead::header_lines`]) from many small lines that would
/// each individually pass both byte caps above.
pub(super) const MAX_HEADER_LINES: usize = 200;

/// Resolver seam for the dial-time private-IP guard (E2 hardening 1): the
/// production impl below does real DNS; tests inject a fixed-address
/// resolver so a resolved IP (e.g. a simulated cloud-metadata address) can
/// be asserted against without live DNS or a privileged low-port bind.
#[async_trait]
trait HostResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

/// Real DNS via `tokio::net::lookup_host` — the production resolver.
struct DnsResolver;

#[async_trait]
impl HostResolver for DnsResolver {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
}

/// Every distinct branch that can deny an egress request, in both
/// `handle_connect` and `handle_plain_http`. Before this type existed every
/// branch wrote the client-facing body `"host not in allowlist"`
/// unconditionally (see [`write_denied_response`]'s old shape), so a request
/// denied by, say, the private-IP guard told the client it had failed the
/// hostname allowlist instead — found running the proxy against real
/// containers for the first time: Docker's default bridge subnets are
/// RFC1918, so an allowlisted origin on a default bridge tripped
/// [`DenyReason::PrivateAddress`] while [`audit_rule`](Self::audit_rule) and
/// the response body both still said "not in allowlist", sending debugging
/// in exactly the wrong direction.
///
/// Each variant names the *category* of check that failed, both in the
/// `debug!` audit line (`audit_rule`) and the client-facing `403`/`502` body
/// (`client_message`) — never a resolved IP or a full URL (which could carry
/// `user:pass@host` userinfo). Distinguishing the cause does not require
/// disclosing the value that tripped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DenyReason {
    /// Hostname allowlist miss (`host_allowed` returned `false`).
    NotInAllowlist,
    /// `CONNECT host` with no `:port` suffix at all.
    MalformedConnectTarget,
    /// `CONNECT host:port` where `port != 443` (E2 hardening 2).
    ConnectPortNotPermitted,
    /// Plain-HTTP absolute-URI target with a port other than 80.
    PlainHttpPortNotPermitted,
    /// A plain-HTTP request-target that doesn't parse as an absolute URI at
    /// all — nothing to allowlist-check against.
    MalformedRequestTarget,
    /// A credential placeholder appeared in plaintext request metadata. The
    /// static credential lane is HTTPS-only; never disclose even inert
    /// placeholder bytes to a plaintext origin.
    PlainHttpCredentialPlaceholder,
    /// The resolved dial address is private, loopback, link-local, CGNAT, or
    /// otherwise reserved (E2 hardening 1 / SSRF guard). Collapses every
    /// matched range to one reason — see [`denied_ip_reason`]'s doc for why.
    PrivateAddress,
    /// DNS resolution for an otherwise-allowed host returned zero addresses.
    NoAddressesResolved,
}

impl DenyReason {
    /// Audit-log token threaded through this module's `tracing::debug!`
    /// `rule` field.
    fn audit_rule(self) -> &'static str {
        match self {
            Self::NotInAllowlist => "not_in_allowlist",
            Self::MalformedConnectTarget => "malformed_connect_target",
            Self::ConnectPortNotPermitted => "connect_port_not_443",
            Self::PlainHttpPortNotPermitted => "plain_http_port_not_80",
            Self::MalformedRequestTarget => "malformed_request_target",
            Self::PlainHttpCredentialPlaceholder => "credential_placeholder_requires_https",
            Self::PrivateAddress => "private_or_reserved_ip",
            Self::NoAddressesResolved => "no_addresses_resolved",
        }
    }

    /// Client-facing message written into the `403`/`502` body. Names only
    /// the category — never a resolved IP or full URL.
    fn client_message(self) -> &'static str {
        match self {
            Self::NotInAllowlist => "host not in allowlist",
            Self::MalformedConnectTarget => "malformed CONNECT target: missing port",
            Self::ConnectPortNotPermitted => "port not permitted: CONNECT is restricted to 443",
            Self::PlainHttpPortNotPermitted => "port not permitted: plain HTTP is restricted to 80",
            Self::MalformedRequestTarget => "malformed request target",
            Self::PlainHttpCredentialPlaceholder => {
                "credential placeholders require mediated HTTPS"
            }
            Self::PrivateAddress => "resolved address is private",
            Self::NoAddressesResolved => "host did not resolve to any address",
        }
    }
}

/// Returns [`DenyReason::PrivateAddress`] if `ip` is private, loopback,
/// link-local, or otherwise reserved, per `ironclaw_network`'s canonical
/// range check — delegated to via [`network_denies_resolved_ip`] rather than
/// re-implemented here. This proxy previously hand-rolled its own range
/// list and it had already drifted behind that canonical check, missing
/// `0.0.0.0/8`, IPv6 link-local `fe80::/10`, and the `fc00::/7` half of the
/// RFC 4193 unique-local range. The canonical check also unwraps
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to their v4 form itself,
/// and additionally denies broadcast/multicast/documentation addresses — a
/// strictly larger deny set, which is fine for an egress guard. The reason
/// collapses every matched range to one variant rather than re-deriving a
/// granular one per range: the canonical check only returns `bool`, and a
/// second, independently-maintained granular reason table would recreate
/// exactly the kind of drift-prone duplication this delegation removes.
fn denied_ip_reason(ip: IpAddr) -> Option<DenyReason> {
    network_denies_resolved_ip(ip).then_some(DenyReason::PrivateAddress)
}

/// Resolves `host:port` and applies the dial-time private-IP guard when
/// `deny_private_ips` is set. Returns the first resolved candidate address as
/// the `Ok` half; a guard rejection is the `Err` half, carrying the
/// [`DenyReason`] for the audit log and the client response.
/// `deny_private_ips` is only ever turned off by test fixtures standing a
/// loopback echo server in for a real origin (see the byte-plumbing test
/// below) — production callers always pass `true`.
///
/// The guard applies [`network_denies_any_resolved_ip`] to the WHOLE resolved
/// set — matching `ironclaw_network::resolver::resolve_public_ips`'s
/// any-private-denies-all selection policy exactly — rather than picking the
/// first individually-passing candidate. This proxy previously did the
/// latter, which let a resolution mixing a public and a private/loopback
/// address (split-horizon DNS abuse, a compromised or rebinding-prone
/// resolver) through by silently skipping the private candidate and dialing
/// the public one; that diverged from the stricter `ironclaw_network`-mediated
/// HTTP egress path, which denies the whole request in that case. See
/// `resolve_dial_addr_denies_a_mixed_public_and_private_resolution`.
async fn resolve_dial_addr(
    resolver: &dyn HostResolver,
    host: &str,
    port: u16,
    deny_private_ips: bool,
) -> std::io::Result<Result<SocketAddr, DenyReason>> {
    let addrs = resolver.resolve(host, port).await?;
    let Some(first) = addrs.first().copied() else {
        return Ok(Err(DenyReason::NoAddressesResolved));
    };
    if !deny_private_ips {
        return Ok(Ok(first));
    }
    if network_denies_any_resolved_ip(addrs.iter().map(SocketAddr::ip)) {
        let reason = addrs
            .iter()
            .find_map(|addr| denied_ip_reason(addr.ip()))
            .unwrap_or(DenyReason::PrivateAddress);
        return Ok(Err(reason));
    }
    Ok(Ok(first))
}

/// Errors [`EgressAllowlistProxy::bind`] can return. Deliberately minimal —
/// per-connection failures never propagate up through `serve`, they are
/// logged at `debug` and the connection is dropped.
#[derive(Debug, thiserror::Error)]
pub enum EgressProxyError {
    #[error("failed to bind egress proxy listener: {reason}")]
    BindFailed { reason: String },
    #[error("failed to set up TLS interception for the egress proxy: {reason}")]
    TlsInterceptSetupFailed { reason: String },
    #[error("failed to start the VM-backed sandbox egress relay: {reason}")]
    RelayStartFailed { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerSourceMode {
    /// Trust only the kernel-reported TCP peer. This is the native Linux
    /// bridge-gateway topology and never consumes client-authored metadata.
    Direct,
    /// Consume one bounded PROXY v2 address preface from a loopback peer.
    /// This mode exists only on the dedicated host-loopback listener used by
    /// the VM relay; it is never enabled on the direct bridge listener.
    TrustedProxyV2FromLoopback,
}

struct VmEgressRelay {
    docker: Docker,
    container_id: String,
    owner_token: String,
}

impl VmEgressRelay {
    async fn start(port: u16) -> Result<Self, EgressProxyError> {
        let docker = super::connect_docker_with_retry().await.map_err(|error| {
            EgressProxyError::RelayStartFailed {
                reason: format!("Docker is unavailable: {error}"),
            }
        })?;
        ensure_vm_relay_name_available(&docker).await?;
        let owner_token = uuid::Uuid::new_v4().to_string();

        let image = std::env::var("IRONCLAW_REBORN_SANDBOX_IMAGE")
            .or_else(|_| std::env::var("IRONCLAW_SANDBOX_IMAGE"))
            .unwrap_or_else(|_| super::DEFAULT_IMAGE.to_string());
        let labels = HashMap::from([
            (
                VM_RELAY_LABEL_KEY.to_string(),
                VM_RELAY_LABEL_VALUE.to_string(),
            ),
            (VM_RELAY_OWNER_LABEL_KEY.to_string(), owner_token.clone()),
        ]);
        let port = port.to_string();
        let host_config = HostConfig {
            auto_remove: Some(false),
            network_mode: Some("host".to_string()),
            cap_drop: Some(vec!["ALL".to_string()]),
            security_opt: Some(vec!["no-new-privileges:true".to_string()]),
            readonly_rootfs: Some(true),
            pids_limit: Some(VM_RELAY_PIDS_LIMIT),
            memory: Some(VM_RELAY_MEMORY_BYTES),
            memory_swap: Some(VM_RELAY_MEMORY_BYTES),
            ..Default::default()
        };
        let config = Config {
            image: Some(image),
            entrypoint: Some(vec![
                "python3".to_string(),
                "/usr/local/bin/sandbox-egress-relay".to_string(),
            ]),
            cmd: Some(vec![
                "--listen-host".to_string(),
                super::broker::SANDBOX_EGRESS_NETWORK_GATEWAY.to_string(),
                "--listen-port".to_string(),
                port.clone(),
                "--target-host".to_string(),
                VM_RELAY_TARGET_HOST.to_string(),
                "--target-port".to_string(),
                port,
            ]),
            env: Some(vec!["PYTHONDONTWRITEBYTECODE=1".to_string()]),
            labels: Some(labels),
            host_config: Some(host_config),
            user: Some("1000:1000".to_string()),
            attach_stdout: Some(false),
            attach_stderr: Some(false),
            ..Default::default()
        };

        let created = docker
            .create_container(
                Some(CreateContainerOptions {
                    name: VM_RELAY_CONTAINER_NAME.to_string(),
                    platform: None,
                }),
                config,
            )
            .await
            .map_err(|error| EgressProxyError::RelayStartFailed {
                reason: format!("relay container creation failed: {error}"),
            })?;

        if let Err(error) = docker
            .start_container(&created.id, None::<StartContainerOptions<String>>)
            .await
        {
            let _ = remove_owned_vm_relay_container(&docker, &created.id, &owner_token).await;
            return Err(EgressProxyError::RelayStartFailed {
                reason: format!("relay container start failed: {error}"),
            });
        }

        // The relay exits immediately if it cannot bind the VM bridge
        // gateway. Give that failure a bounded window to surface before
        // declaring the topology ready.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let inspected = docker
            .inspect_container(&created.id, None::<InspectContainerOptions>)
            .await;
        let running = inspected
            .as_ref()
            .ok()
            .and_then(|container| container.state.as_ref())
            .and_then(|state| state.running)
            .unwrap_or(false);
        if !running {
            let reason = inspected.err().map_or_else(
                || "relay process exited during startup".to_string(),
                |error| format!("relay readiness inspection failed: {error}"),
            );
            let _ = remove_owned_vm_relay_container(&docker, &created.id, &owner_token).await;
            return Err(EgressProxyError::RelayStartFailed { reason });
        }

        Ok(Self {
            docker,
            container_id: created.id,
            owner_token,
        })
    }

    async fn shutdown(self) -> Result<(), EgressProxyError> {
        remove_owned_vm_relay_container(&self.docker, &self.container_id, &self.owner_token).await
    }
}

async fn remove_owned_vm_relay_container(
    docker: &Docker,
    container: &str,
    owner_token: &str,
) -> Result<(), EgressProxyError> {
    let existing = match docker
        .inspect_container(container, None::<InspectContainerOptions>)
        .await
    {
        Ok(existing) => existing,
        Err(DockerError::DockerResponseServerError {
            status_code: 404, ..
        }) => return Ok(()),
        Err(error) => {
            return Err(EgressProxyError::RelayStartFailed {
                reason: format!("relay ownership inspection failed: {error}"),
            });
        }
    };
    let owner_matches = existing
        .config
        .and_then(|config| config.labels)
        .and_then(|labels| labels.get(VM_RELAY_OWNER_LABEL_KEY).cloned())
        .as_deref()
        == Some(owner_token);
    if !owner_matches {
        return Err(EgressProxyError::RelayStartFailed {
            reason: "relay ownership changed before cleanup".to_string(),
        });
    }
    docker
        .remove_container(
            container,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await
        .or_else(ignore_missing_container)
        .map_err(|error| EgressProxyError::RelayStartFailed {
            reason: format!("relay container cleanup failed: {error}"),
        })
}

fn ignore_missing_container(error: DockerError) -> Result<(), DockerError> {
    match error {
        DockerError::DockerResponseServerError {
            status_code: 404, ..
        } => Ok(()),
        error => Err(error),
    }
}

async fn ensure_vm_relay_name_available(docker: &Docker) -> Result<(), EgressProxyError> {
    let existing = match docker
        .inspect_container(VM_RELAY_CONTAINER_NAME, None::<InspectContainerOptions>)
        .await
    {
        Ok(existing) => existing,
        Err(DockerError::DockerResponseServerError {
            status_code: 404, ..
        }) => return Ok(()),
        Err(error) => {
            return Err(EgressProxyError::RelayStartFailed {
                reason: format!("stale relay inspection failed: {error}"),
            });
        }
    };
    let labels = existing
        .config
        .and_then(|config| config.labels)
        .unwrap_or_default();
    let owned = labels.get(VM_RELAY_LABEL_KEY).map(String::as_str) == Some(VM_RELAY_LABEL_VALUE);
    if !owned {
        return Err(EgressProxyError::RelayStartFailed {
            reason: format!(
                "container name {VM_RELAY_CONTAINER_NAME:?} is occupied without the IronClaw relay label"
            ),
        });
    }
    let Some(owner_token) = labels.get(VM_RELAY_OWNER_LABEL_KEY) else {
        return Err(EgressProxyError::RelayStartFailed {
            reason: format!(
                "container name {VM_RELAY_CONTAINER_NAME:?} is occupied without an instance owner label"
            ),
        });
    };
    let running = existing
        .state
        .as_ref()
        .and_then(|state| state.running)
        .unwrap_or(false);
    if running {
        return Err(EgressProxyError::RelayStartFailed {
            reason: "another IronClaw sandbox egress relay is already active".to_string(),
        });
    }
    remove_owned_vm_relay_container(docker, VM_RELAY_CONTAINER_NAME, owner_token).await
}

/// The forward/CONNECT proxy, not yet bound to a socket.
pub struct EgressAllowlistProxy {
    policy: NetworkPolicy,
    resolver: Arc<dyn HostResolver>,
    /// Always `true` in production (`new`); only a test fixture in this
    /// module's `#[cfg(test)]` submodule constructs this struct directly
    /// with it set `false`, to stand a loopback echo server in for a real
    /// origin without tripping the SSRF guard. See
    /// `connect_to_allowed_host_tunnels_bytes`.
    deny_private_ips: bool,
    /// Always [`MAX_CONCURRENT_CONNECTIONS`] in production (`new`); tests
    /// override it to a small value so the connection-cap test doesn't need
    /// to actually open 128+ sockets.
    max_connections: usize,
    /// W6 phase 1/2's TLS-termination + credential-swap seam (see
    /// `tls_intercept`'s module doc). `None` reproduces the plain-tunnel
    /// posture every CONNECT had before W6; the one production door to
    /// `Some` is [`bind_sandbox_egress_proxy_with_tls_intercept`], which
    /// this crate's sole production caller
    /// (`ironclaw_reborn_composition::sandbox_egress_proxy_task`) uses
    /// instead of [`EgressAllowlistProxy::new`] directly — so the
    /// production proxy always terminates TLS and evaluates the credential
    /// firewall for its `bound_hosts`. `new` itself still leaves this
    /// `None`: ~10 tests in this module exercise the plain
    /// allowlist/tunnel mechanics and have no reason to carry TLS-intercept
    /// setup, and D1 (an unbound host always stays an opaque tunnel even
    /// with intercept configured) is proven independently of whether this
    /// field is populated at all.
    tls_intercept: Option<Arc<TlsInterceptConfig>>,
    /// The connection-attribution resolver (`attribution` module) this proxy
    /// consults to name the `{tenant, user}` behind a peer address before
    /// handing it to the credential firewall — see [`with_attribution_resolver`]
    /// (Self::with_attribution_resolver). `None` reproduces the
    /// pre-attribution posture (every intercepted connection's identity is
    /// `None`, so the credential firewall's `authorize` fails closed with
    /// `AttributionFailed` for any request that actually carries a
    /// placeholder): the one production door to `Some` is
    /// [`bind_sandbox_egress_proxy_with_tls_intercept`], mirroring
    /// `tls_intercept` immediately above. Held as `Arc<dyn
    /// attribution::ResolveAttribution>` rather than the concrete
    /// `Arc<ConnectionAttributionResolver>` composition wires, so this
    /// module's own tests can inject a fake `NetworkContainerLookup`-backed
    /// resolver without a Docker daemon — see `attribution::ResolveAttribution`'s
    /// doc for why this seam exists.
    attribution: Option<Arc<dyn attribution::ResolveAttribution>>,
}

impl EgressAllowlistProxy {
    pub fn new(policy: NetworkPolicy) -> Self {
        Self {
            policy,
            resolver: Arc::new(DnsResolver),
            deny_private_ips: true,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: None,
            attribution: None,
        }
    }

    /// Enables TLS interception (and, when the config carries one, W6
    /// phase 2's credential swap) on this proxy instance. `pub(crate)`,
    /// not `pub`: the only caller is
    /// [`bind_sandbox_egress_proxy_with_tls_intercept`] below, in the same
    /// crate — composition never constructs a [`TlsInterceptConfig`]
    /// itself, it calls that factory.
    pub(crate) fn with_tls_intercept(mut self, tls_intercept: Arc<TlsInterceptConfig>) -> Self {
        self.tls_intercept = Some(tls_intercept);
        self
    }

    /// Wires the connection-attribution resolver this proxy consults on
    /// every intercepted (bound-host) CONNECT. `pub(crate)`: the only
    /// caller is [`bind_sandbox_egress_proxy_with_tls_intercept`] below,
    /// which is handed the SAME `Arc<ConnectionAttributionResolver>`
    /// composition already shares with the exec transport and the reaper
    /// (`ironclaw_reborn_composition::user_sandbox_process_binding`)
    /// — never a second, independently constructed resolver.
    pub(crate) fn with_attribution_resolver(
        mut self,
        attribution: Arc<dyn attribution::ResolveAttribution>,
    ) -> Self {
        self.attribution = Some(attribution);
        self
    }

    /// Binds `bind_addr` (e.g. `"127.0.0.1:0"` for tests, `"0.0.0.0:0"` in
    /// production — see composition's spawn task for why) and returns the
    /// bound proxy plus its resolved local address, so the caller can read
    /// back the OS-chosen port before wiring it into
    /// `RebornSandboxConfig::with_network_broker_port`.
    pub async fn bind(
        self,
        bind_addr: &str,
    ) -> Result<BoundEgressAllowlistProxy, EgressProxyError> {
        self.bind_with_peer_source(bind_addr, PeerSourceMode::Direct)
            .await
    }

    async fn bind_with_peer_source(
        self,
        bind_addr: &str,
        peer_source_mode: PeerSourceMode,
    ) -> Result<BoundEgressAllowlistProxy, EgressProxyError> {
        let listener =
            TcpListener::bind(bind_addr)
                .await
                .map_err(|error| EgressProxyError::BindFailed {
                    reason: format!("{bind_addr}: {error}"),
                })?;
        Ok(BoundEgressAllowlistProxy {
            listener,
            policy: Arc::new(self.policy),
            resolver: self.resolver,
            deny_private_ips: self.deny_private_ips,
            max_connections: self.max_connections,
            tls_intercept: self.tls_intercept,
            attribution: self.attribution,
            peer_source_mode,
        })
    }
}

/// The TLS-interception bound-host set for the production sandbox egress
/// proxy: every EXACT-match hostname in `policy.allowed_targets`,
/// canonicalized through [`normalize_host`]. Wildcard entries (`*.suffix`)
/// are deliberately excluded — see "Why exact-match only" below.
///
/// # Why exact-match only, not the full allowlist (design decision)
///
/// Binding a host here means [`TlsInterceptConfig`] terminates TLS for it
/// with a leaf minted from OUR OWN in-process CA
/// ([`SandboxCertificateAuthority`]) instead of letting the real origin's
/// certificate through. That is now safe for the sandboxed container to
/// trust: [`bind_sandbox_egress_proxy_with_tls_intercept`] builds a
/// container trust bundle from the same CA
/// (`SandboxCertificateAuthority::build_container_trust_bundle_pem`) and
/// `exec_transport::user_container_launch_config` bind-mounts it read-only
/// plus points `SSL_CERT_FILE` and friends at it — W5's CA
/// trust-distribution work, previously the blocker this function's doc
/// named, now landed.
///
/// `bound_hosts` itself, however, is a plain `HashSet<String>` doing
/// EXACT string matching (see [`TlsInterceptConfig::is_bound`]/[`bind`]
/// (Self::bind)) — it has no wildcard-matching capability, unlike
/// [`host_allowed`] below (which delegates to
/// [`ironclaw_network::host_matches_host_pattern`] and does support
/// `*.suffix` patterns for the ALLOWLIST decision). A `*.suffix` allowlist
/// pattern — today only ever operator-configured via
/// `SANDBOX_EXTRA_ALLOWED_DOMAINS_ENV`; [`DEFAULT_SANDBOX_ALLOWED_DOMAINS`]
/// itself has no wildcard entries — cannot be expanded into a finite set of
/// concrete hostnames to bind, so it is left out of `bound_hosts` entirely.
/// A wildcard-matched host therefore still passes the allowlist and still
/// gets proxied, but takes the opaque `copy_bidirectional` tunnel path (D1)
/// exactly as every host did before this wiring — never denied, never
/// silently downgraded, just not intercepted. This is the safe, partial
/// choice: it never breaks egress for a host the operator explicitly
/// allowlisted, and it keeps this crate from having to invent a second,
/// independently-maintained wildcard matcher for the intercept path (this
/// crate composes [`ironclaw_network::host_matches_host_pattern`] rather
/// than hand-rolling wildcard matching — see [`host_allowed`]'s doc).
/// Extending interception to wildcard entries (matching a live SNI/CONNECT
/// host against the pattern set at handshake time rather than pre-expanding
/// into `bound_hosts`) is the natural next step if operator-configured
/// wildcard domains ever need interception too.
fn interception_bound_hosts(policy: &NetworkPolicy) -> HashSet<String> {
    policy
        .allowed_targets
        .iter()
        .filter(|target| !target.host_pattern.starts_with("*."))
        .filter_map(|target| normalize_host(&target.host_pattern))
        .collect()
}

/// Production factory: binds an [`EgressAllowlistProxy`] to `bind_addr` with
/// real TLS interception and W6 phase 2's credential swap wired in — the
/// sole door into this crate's `ca`, `tls_intercept`, and `credential_swap`
/// internals for a caller that must not (and, since those types stay
/// `pub(crate)`, cannot) reach into them directly. This crate's
/// module-owned-initialization convention (`CLAUDE.md`): composition calls
/// this instead of assembling a `TlsInterceptConfig` itself, so it is
/// structurally impossible for the one production caller
/// (`ironclaw_reborn_composition::sandbox_egress_proxy_task::spawn_sandbox_egress_proxy`)
/// to bind a proxy without an intercept config.
///
/// `credential_runtime` is constructed once by composition and shared with
/// `HostRuntimeServices`. The proxy, obligation lifecycle, and host HTTP
/// egress adapter therefore use the exact same placeholder/firewall/injection
/// bundle; this factory never constructs a disconnected credential store.
/// Production Basic/Bearer grants are staged by the obligation lifecycle and
/// resolved here from attributed placeholder-bearing requests. Secret
/// material remains host-side and the resulting origin request is dispatched
/// through the attached [`crate::RuntimeHttpEgress`] service. Unknown,
/// expired, cross-user, or otherwise unauthorized placeholders still fail
/// closed before any credential can be presented to an origin.
///
/// `attribution` is the SAME `ConnectionAttributionResolver` instance
/// composition already shares with the exec transport and the reaper
/// (`ironclaw_reborn_composition::user_sandbox_process_binding`)
/// — `None` only in the rare shape where a caller genuinely has no
/// attribution resolver to wire (today: none in production; every real
/// caller has Docker connectivity by the time it reaches this factory,
/// since the same connectivity already backs the user sandbox transport).
/// A `None` here means every intercepted connection's identity resolves to
/// `None`, which the credential firewall fails closed on
/// (`AttributionFailed`) the moment a request actually carries a
/// placeholder — never a forward-without-attribution.
pub async fn bind_sandbox_egress_proxy_with_tls_intercept(
    bind_addr: &str,
    policy: NetworkPolicy,
    attribution: Option<Arc<attribution::ConnectionAttributionResolver>>,
    credential_runtime: SandboxCredentialRuntime,
) -> Result<SandboxEgressProxyBinding, EgressProxyError> {
    bind_sandbox_egress_proxy(
        bind_addr,
        policy,
        attribution,
        credential_runtime,
        PeerSourceMode::Direct,
    )
    .await
}

async fn bind_sandbox_egress_proxy(
    bind_addr: &str,
    policy: NetworkPolicy,
    attribution: Option<Arc<attribution::ConnectionAttributionResolver>>,
    credential_runtime: SandboxCredentialRuntime,
    peer_source_mode: PeerSourceMode,
) -> Result<SandboxEgressProxyBinding, EgressProxyError> {
    let bound_hosts = interception_bound_hosts(&policy);
    let ca = SandboxCertificateAuthority::generate().map_err(|error| {
        EgressProxyError::TlsInterceptSetupFailed {
            reason: error.to_string(),
        }
    })?;
    // Captured from `ca` BEFORE it moves into `TlsInterceptConfig::new`
    // below. Fail-closed: a broken/empty host system trust store here fails
    // this whole call (see `build_container_trust_bundle_pem`'s doc),
    // exactly like the sibling `VerifiedOriginConnector::from_system_roots`
    // failure a few lines down — neither ships a proxy whose containers
    // could never trust anything, or silently interception-less.
    let ca_bundle_pem = ca.build_container_trust_bundle_pem().map_err(|error| {
        EgressProxyError::TlsInterceptSetupFailed {
            reason: error.to_string(),
        }
    })?;
    let origin_connector = VerifiedOriginConnector::from_system_roots().map_err(|error| {
        EgressProxyError::TlsInterceptSetupFailed {
            reason: error.to_string(),
        }
    })?;
    let credential_swap = credential_runtime.credential_swap();
    let tls_intercept_config = Arc::new(
        TlsInterceptConfig::new(ca, bound_hosts, origin_connector)
            .with_credential_swap(credential_swap),
    );
    let mut builder = EgressAllowlistProxy::new(policy).with_tls_intercept(tls_intercept_config);
    if let Some(attribution) = attribution {
        builder = builder.with_attribution_resolver(attribution);
    }
    let proxy = builder
        .bind_with_peer_source(bind_addr, peer_source_mode)
        .await?;
    Ok(SandboxEgressProxyBinding {
        proxy,
        ca_bundle_pem,
        vm_relay: None,
    })
}

/// Return value of [`bind_sandbox_egress_proxy_with_tls_intercept`]: the
/// bound, ready-to-`serve` proxy plus the PEM container trust bundle its
/// [`SandboxCertificateAuthority`] instance backs
/// (`SandboxCertificateAuthority::build_container_trust_bundle_pem` — system
/// roots plus this CA's own public root certificate, no private key
/// material). Composition
/// (`ironclaw_reborn_composition::user_sandbox_process_binding`)
/// threads `ca_bundle_pem` into
/// [`super::RebornSandboxConfig::with_ca_bundle_pem`] so every sandbox
/// container this proxy instance serves trusts the exact CA that mints its
/// intercepted connections' leaf certificates — this is a plain data carrier,
/// not a second proxy handle, so there is exactly one bound proxy per call.
pub struct SandboxEgressProxyBinding {
    pub proxy: BoundEgressAllowlistProxy,
    pub ca_bundle_pem: String,
    vm_relay: Option<VmEgressRelay>,
}

impl SandboxEgressProxyBinding {
    /// Bind the host proxy to loopback and place the secret-free worker-image
    /// relay in the Docker VM's host network. The listener accepts PROXY v2
    /// source metadata only in this topology; the native factory above stays
    /// in direct mode and cannot be tricked into consuming it.
    pub async fn bind_vm_backed_relay(
        bind_addr: &str,
        policy: NetworkPolicy,
        attribution: Option<Arc<attribution::ConnectionAttributionResolver>>,
        credential_runtime: SandboxCredentialRuntime,
    ) -> Result<Self, EgressProxyError> {
        let mut binding = bind_sandbox_egress_proxy(
            bind_addr,
            policy,
            attribution,
            credential_runtime,
            PeerSourceMode::TrustedProxyV2FromLoopback,
        )
        .await?;
        let relay = VmEgressRelay::start(binding.proxy.local_addr().port()).await?;
        binding.vm_relay = Some(relay);
        Ok(binding)
    }

    /// Serve the existing allowlist/TLS/credential pipeline and clean up the
    /// optional transport-only VM relay when the accept loop stops.
    pub async fn serve(self, shutdown: watch::Receiver<bool>) {
        let Self {
            proxy,
            ca_bundle_pem: _,
            vm_relay,
        } = self;
        proxy.serve(shutdown).await;
        if let Some(relay) = vm_relay
            && let Err(error) = relay.shutdown().await
        {
            tracing::debug!(?error, "sandbox egress relay cleanup failed");
        }
    }

    /// Opaque per-boot ownership token used only for deterministic forced
    /// cleanup. It is a Docker label value, never relay process input.
    pub fn vm_relay_owner_token(&self) -> Option<&str> {
        self.vm_relay
            .as_ref()
            .map(|relay| relay.owner_token.as_str())
    }

    /// Idempotent forced-shutdown cleanup for this exact relay instance.
    pub async fn cleanup_vm_backed_relay(owner_token: &str) -> Result<(), EgressProxyError> {
        let docker = super::connect_docker_with_retry().await.map_err(|error| {
            EgressProxyError::RelayStartFailed {
                reason: format!("Docker is unavailable during relay cleanup: {error}"),
            }
        })?;
        remove_owned_vm_relay_container(&docker, VM_RELAY_CONTAINER_NAME, owner_token).await
    }
}

/// A proxy bound to a real local address, ready to `serve`.
pub struct BoundEgressAllowlistProxy {
    listener: TcpListener,
    policy: Arc<NetworkPolicy>,
    resolver: Arc<dyn HostResolver>,
    deny_private_ips: bool,
    max_connections: usize,
    tls_intercept: Option<Arc<TlsInterceptConfig>>,
    attribution: Option<Arc<dyn attribution::ResolveAttribution>>,
    peer_source_mode: PeerSourceMode,
}

impl BoundEgressAllowlistProxy {
    pub fn local_addr(&self) -> SocketAddr {
        // A bound listener always has a resolvable local address; the only
        // failure mode (an already-closed socket) cannot happen for a
        // listener we just created ourselves.
        self.listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    /// Accept loop; spawns one task per connection, capped at
    /// [`Self::max_connections`] concurrently in flight — a connection
    /// accepted beyond the cap is closed immediately rather than queued or
    /// given an unbounded task (see [`MAX_CONCURRENT_CONNECTIONS`]). Returns
    /// once `shutdown` signals `true` — in-flight connections are left to
    /// finish on their own, no new ones are accepted after that point.
    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) {
        let connection_slots = Arc::new(Semaphore::new(self.max_connections));
        let peer_source_mode = self.peer_source_mode;
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    match changed {
                        Ok(()) if *shutdown.borrow() => break,
                        Ok(()) => continue,
                        Err(_) => break,
                    }
                }
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((mut stream, kernel_peer_addr)) => {
                            let Ok(permit) = Arc::clone(&connection_slots).try_acquire_owned()
                            else {
                                tracing::debug!(
                                    limit = self.max_connections,
                                    "egress proxy: connection rejected, concurrent connection cap reached"
                                );
                                // `stream` drops here, closing it immediately
                                // instead of queueing behind the held slots.
                                continue;
                            };
                            let policy = Arc::clone(&self.policy);
                            let resolver = Arc::clone(&self.resolver);
                            let deny_private_ips = self.deny_private_ips;
                            let tls_intercept = self.tls_intercept.clone();
                            let attribution = self.attribution.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let peer_addr = match resolve_peer_addr(
                                    &mut stream,
                                    kernel_peer_addr,
                                    peer_source_mode,
                                )
                                .await
                                {
                                    Ok(peer_addr) => peer_addr,
                                    Err(error) => {
                                        tracing::debug!(
                                            ?error,
                                            "egress proxy rejected source metadata"
                                        );
                                        return;
                                    }
                                };
                                if let Err(error) = handle_connection(
                                    stream,
                                    peer_addr,
                                    policy,
                                    resolver,
                                    deny_private_ips,
                                    tls_intercept,
                                    attribution,
                                )
                                .await
                                {
                                    tracing::debug!(?error, "egress proxy connection ended with an error");
                                }
                            });
                        }
                        Err(error) => {
                            tracing::debug!(?error, "egress proxy accept failed");
                        }
                    }
                }
            }
        }
    }
}

async fn resolve_peer_addr(
    stream: &mut TcpStream,
    kernel_peer_addr: SocketAddr,
    mode: PeerSourceMode,
) -> std::io::Result<SocketAddr> {
    match mode {
        PeerSourceMode::Direct => Ok(kernel_peer_addr),
        PeerSourceMode::TrustedProxyV2FromLoopback => {
            if !kernel_peer_addr.ip().is_loopback() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "egress proxy: relay metadata arrived from a non-loopback peer",
                ));
            }
            tokio::time::timeout(PROXY_V2_READ_TIMEOUT, read_proxy_v2_source(stream))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "egress proxy: relay metadata timed out",
                    )
                })?
        }
    }
}

async fn read_proxy_v2_source(stream: &mut TcpStream) -> std::io::Result<SocketAddr> {
    let mut fixed = [0u8; PROXY_V2_FIXED_HEADER_BYTES];
    stream.read_exact(&mut fixed).await?;
    if fixed[..PROXY_V2_SIGNATURE.len()] != PROXY_V2_SIGNATURE {
        return Err(invalid_proxy_v2("invalid signature"));
    }
    if fixed[12] != 0x21 {
        return Err(invalid_proxy_v2("unsupported version or command"));
    }
    let payload_len = usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
    if payload_len > PROXY_V2_MAX_ADDRESS_BYTES {
        return Err(invalid_proxy_v2("address payload exceeds the bound"));
    }
    let expected_len = match fixed[13] {
        0x11 => PROXY_V2_IPV4_ADDRESS_BYTES,
        0x21 => PROXY_V2_IPV6_ADDRESS_BYTES,
        _ => return Err(invalid_proxy_v2("unsupported address family or protocol")),
    };
    if payload_len != expected_len {
        return Err(invalid_proxy_v2("unexpected address payload length"));
    }

    let mut payload = [0u8; PROXY_V2_MAX_ADDRESS_BYTES];
    stream.read_exact(&mut payload[..payload_len]).await?;
    let (source_ip, source_port_offset) = match fixed[13] {
        0x11 => (
            IpAddr::V4(Ipv4Addr::new(
                payload[0], payload[1], payload[2], payload[3],
            )),
            8,
        ),
        0x21 => {
            let mut source = [0u8; 16];
            source.copy_from_slice(&payload[..16]);
            (IpAddr::V6(Ipv6Addr::from(source)), 32)
        }
        _ => return Err(invalid_proxy_v2("unsupported address family or protocol")),
    };
    let source_port =
        u16::from_be_bytes([payload[source_port_offset], payload[source_port_offset + 1]]);
    if source_port == 0 {
        return Err(invalid_proxy_v2("source port must be non-zero"));
    }
    Ok(SocketAddr::new(source_ip, source_port))
}

fn invalid_proxy_v2(reason: &'static str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("egress proxy: malformed relay metadata: {reason}"),
    )
}

#[cfg(any(test, feature = "test-support"))]
impl BoundEgressAllowlistProxy {
    /// Test-support only: assert the production factory wired TLS
    /// interception before the binding moves into its serve task.
    pub fn tls_intercept_is_active(&self) -> bool {
        self.tls_intercept.is_some()
    }

    pub fn uses_sandbox_credential_runtime(&self, runtime: &SandboxCredentialRuntime) -> bool {
        self.tls_intercept
            .as_ref()
            .is_some_and(|config| config.uses_sandbox_credential_runtime(runtime))
    }
}

/// Host-only match: exact hostname, or a `*.suffix` glob — the same shape
/// `sandbox_extra_allowed_domains` already accepts. Ports and scheme in
/// [`ironclaw_host_api::NetworkTargetPattern`] are ignored here (the proxy
/// allowlists by host, consistent with `sandbox_network_policy()`'s
/// `port: None` targets). Canonicalizes `host` through the same
/// [`normalize_host`] every other host-identity decision on this seam uses
/// (see that function's doc); a host that fails to normalize (empty,
/// whitespace-only, all-dots) can never match a real target and is denied
/// outright, never coerced into an empty string that a `*` allow-all
/// pattern would otherwise match. Delegates the per-pattern decision to
/// [`ironclaw_network::host_matches_host_pattern`] — this crate composes
/// `ironclaw_network` rather than hand-rolling a second, independently
/// drifting copy of the wildcard-match rule (`ironclaw_host_runtime/CLAUDE.md`).
fn host_allowed(host: &str, policy: &NetworkPolicy) -> bool {
    let Some(host) = normalize_host(host) else {
        return false;
    };
    policy
        .allowed_targets
        .iter()
        .any(|target| host_matches_host_pattern(&host, &target.host_pattern))
}

/// One HTTP request line plus its headers, as read off the client socket.
struct RequestHead {
    method: String,
    target: String,
    /// Raw header lines exactly as read (each still ending in `\r\n`),
    /// forwarded verbatim on the allow path.
    header_lines: Vec<String>,
}

/// Extracts the host-generated invocation identity from standard HTTP proxy
/// authentication. The sandbox command receives this opaque value as the
/// username in its proxy URL, so ordinary clients place it in
/// `Proxy-Authorization: Basic ...` on CONNECT. It is not a provider secret;
/// it only narrows a live host-side credential window to one invocation.
///
/// Missing, duplicated, malformed, or password-bearing values deliberately
/// collapse to `None`. Uncredentialed traffic can still use the allowlisted
/// proxy, but a placeholder-bearing request then fails closed at the
/// credential firewall.
fn proxy_invocation_identity(head: &RequestHead) -> Option<InvocationId> {
    let mut encoded = None;
    for line in &head.header_lines {
        let Some((name, raw_value)) = line.trim_end_matches(['\r', '\n']).split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        if encoded.is_some() {
            return None;
        }
        let value = raw_value.trim_matches([' ', '\t']);
        let (scheme, value) = value.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("basic") || value.is_empty() {
            return None;
        }
        encoded = Some(value);
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded?)
        .ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let invocation = decoded.strip_suffix(':')?;
    if invocation.contains(':') {
        return None;
    }
    InvocationId::parse(invocation).ok()
}

/// `read_line`-alike that never buffers more than `max_bytes` for a single
/// line before giving up: an adversarial or buggy client that sends bytes
/// without a trailing `\n` cannot make this grow the line unboundedly the
/// way plain `AsyncBufReadExt::read_line` would (it loops internally with no
/// length check of its own). Reads via `fill_buf`/`consume` directly so the
/// cap is enforced between each underlying-socket read rather than after
/// the whole (potentially huge) line has already been assembled. Returns
/// `Ok(String::new())` on a clean EOF before any bytes arrive.
async fn read_capped_line<R>(reader: &mut R, max_bytes: usize) -> std::io::Result<String>
where
    R: AsyncBufReadExt + Unpin,
{
    let mut line = String::new();
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            break; // EOF
        }
        let (chunk, found_newline, consumed) = match buf.iter().position(|&b| b == b'\n') {
            Some(pos) => (&buf[..=pos], true, pos + 1),
            None => (buf, false, buf.len()),
        };
        if line.len() + chunk.len() > max_bytes {
            reader.consume(consumed);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "egress proxy: request header line exceeded the size cap",
            ));
        }
        line.push_str(&String::from_utf8_lossy(chunk));
        reader.consume(consumed);
        if found_newline {
            break;
        }
    }
    Ok(line)
}

/// Reads a request line and its headers (up to the blank-line terminator)
/// from `reader`, enforcing [`MAX_HEADER_LINE_BYTES`], [`MAX_TOTAL_HEADER_BYTES`],
/// and [`MAX_HEADER_LINES`] — the proxy binds on the internal egress network
/// and is reachable from inside the (potentially adversarial) sandboxed
/// container, so it never allocates unboundedly off a client's say-so. A cap
/// violation surfaces as `Err` with [`std::io::ErrorKind::InvalidData`],
/// which [`handle_connection`] turns into a `413` before closing. Returns
/// `Ok(None)` on a clean EOF before any bytes arrive (the client closed
/// without sending a request).
async fn read_request_head<R>(reader: &mut R) -> std::io::Result<Option<RequestHead>>
where
    R: AsyncBufReadExt + Unpin,
{
    let request_line = read_capped_line(reader, MAX_HEADER_LINE_BYTES).await?;
    if request_line.is_empty() {
        return Ok(None);
    }
    let mut parts = request_line.trim_end().splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    let mut header_lines = Vec::new();
    let mut total_bytes = request_line.len();
    loop {
        if header_lines.len() >= MAX_HEADER_LINES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "egress proxy: too many request header lines",
            ));
        }
        let line = read_capped_line(reader, MAX_HEADER_LINE_BYTES).await?;
        if line.is_empty() || line.trim_end_matches(['\r', '\n']).is_empty() {
            break;
        }
        total_bytes += line.len();
        if total_bytes > MAX_TOTAL_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "egress proxy: total request header size exceeded the cap",
            ));
        }
        header_lines.push(line);
    }

    Ok(Some(RequestHead {
        method,
        target,
        header_lines,
    }))
}

/// Writes a `403 Forbidden` response naming `reason`'s category, and `host`
/// (when known) as the denied target. The proxy then closes the connection
/// (dropping `stream` after this call sends the TCP FIN) — no tunnel/forward
/// ever opens for a denied host.
///
/// `host` is `None` only for [`DenyReason::MalformedRequestTarget`], where
/// the request-target didn't parse as an absolute URI at all: it is not
/// echoed back, deliberately — an unparsed target is exactly the shape a
/// `user:pass@host` URL would take before parsing, and the category alone
/// (`"malformed request target"`) is enough for the client to fix its
/// request without the proxy echoing back the raw value it sent.
async fn write_denied_response<W>(
    stream: &mut W,
    host: Option<&str>,
    reason: DenyReason,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let body = match host {
        Some(host) => format!("egress denied: {}: {host}", reason.client_message()),
        None => format!("egress denied: {}", reason.client_message()),
    };
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    policy: Arc<NetworkPolicy>,
    resolver: Arc<dyn HostResolver>,
    deny_private_ips: bool,
    tls_intercept: Option<Arc<TlsInterceptConfig>>,
    attribution: Option<Arc<dyn attribution::ResolveAttribution>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let head = match read_request_head(&mut reader).await {
        Ok(Some(head)) => head,
        Ok(None) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            // Oversized/too-numerous request headers — reply with a clean
            // status instead of silently dropping, then close (the egress
            // proxy treats the sandboxed container as untrusted).
            let body = "egress proxy: request header too large";
            let response = format!(
                "HTTP/1.1 413 Payload Too Large\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = reader.write_all(response.as_bytes()).await;
            let _ = reader.flush().await;
            return Ok(());
        }
        Err(error) => return Err(error),
    };

    if head.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(
            reader,
            &head.target,
            &policy,
            resolver.as_ref(),
            deny_private_ips,
            InterceptionContext {
                tls_intercept: tls_intercept.as_deref(),
                peer_addr,
                attribution: attribution.as_deref(),
                invocation_id: proxy_invocation_identity(&head),
            },
        )
        .await
    } else {
        handle_plain_http(reader, &head, &policy, resolver.as_ref(), deny_private_ips).await
    }
}

/// `CONNECT host:port HTTP/1.1` — tunnels raw bytes to `host:port` once
/// allowed, replying `200 Connection Established` first; replies `403` and
/// closes on deny. Three checks gate the dial, in order: the hostname
/// allowlist (E2 predates this proxy), the CONNECT port pin to `443` (E2
/// hardening 2 — the proxy only tunnels HTTPS), and the resolved-IP private
/// range guard (E2 hardening 1). Each decision gets one `debug!` audit line
/// naming the host, allow/deny, and the matched rule — never payloads.
///
/// **W6 phase 1:** once a target passes those checks, an allowed host is
/// further split into BOUND (terminate TLS via `tls_intercept`, see D1 in
/// that module's doc) or UNBOUND (unchanged opaque `copy_bidirectional`
/// tunnel below). The production sandbox factory always supplies
/// `tls_intercept`: exact allowlist hosts take the bound path while
/// wildcard-only hosts remain opaque tunnels as documented by
/// [`interception_bound_hosts`].
/// W6's per-connection interception inputs, bundled to keep
/// [`handle_connect`] under clippy's argument-count ceiling now that
/// connection attribution added a third input (`peer_addr`) alongside
/// `tls_intercept`: these three only ever matter together — `tls_intercept`
/// gates whether interception happens at all, and `peer_addr`/`attribution`
/// only get consulted once a host is actually bound (see the identity
/// resolution inside [`handle_connect`]).
struct InterceptionContext<'a> {
    tls_intercept: Option<&'a TlsInterceptConfig>,
    peer_addr: SocketAddr,
    attribution: Option<&'a dyn attribution::ResolveAttribution>,
    invocation_id: Option<InvocationId>,
}

async fn handle_connect(
    mut client: BufReader<TcpStream>,
    target: &str,
    policy: &NetworkPolicy,
    resolver: &dyn HostResolver,
    deny_private_ips: bool,
    interception: InterceptionContext<'_>,
) -> std::io::Result<()> {
    let InterceptionContext {
        tls_intercept,
        peer_addr,
        attribution,
        invocation_id,
    } = interception;
    // Single normalization point: DNS hostnames are case-insensitive, and
    // every downstream use of `host` in this function treats it that way
    // (`host_allowed` and `TlsInterceptConfig::is_bound`/`bind` canonicalize
    // through this exact same `normalize_host` on their own side of the
    // comparison too — see that function's doc). Fold it ONCE here so the
    // exact same string flows into the allowlist check, `resolve_dial_addr`,
    // the bound check, and — the one that actually needs this, since its
    // cache is keyed on the literal string — `terminate_and_forward`'s cert
    // mint and the origin `ServerName`. Without this, two CONNECTs for the
    // same effective host that merely differ in case, padding, or a
    // trailing root-zone dot would mint and cache two leaf certificates
    // instead of sharing one — or, worse, pass this allowlist check but miss
    // the bound-hosts lookup.
    //
    // A host that fails to normalize to anything meaningful (empty,
    // whitespace-only, all-dots) is rejected here, before it ever reaches
    // `host_allowed` — `host_allowed` would independently reject it too
    // (see its doc), but rejecting once at the single normalization point is
    // the same "reject, don't silently canonicalize" discipline
    // `normalize_host` itself applies.
    let host_str = target.rsplit_once(':').map_or(target, |(host, _port)| host);
    let port: Option<u16> = target
        .rsplit_once(':')
        .and_then(|(_host, port)| port.parse().ok());

    let Some(host) = normalize_host(host_str) else {
        let reason = DenyReason::NotInAllowlist;
        tracing::debug!(
            host = host_str,
            action = "deny",
            rule = reason.audit_rule(),
            "egress proxy: CONNECT denied"
        );
        write_denied_response(&mut client, Some(host_str), reason).await?;
        return Ok(());
    };
    let host = host.as_str();

    if !host_allowed(host, policy) {
        let reason = DenyReason::NotInAllowlist;
        tracing::debug!(
            host,
            action = "deny",
            rule = reason.audit_rule(),
            "egress proxy: CONNECT denied"
        );
        write_denied_response(&mut client, Some(host), reason).await?;
        return Ok(());
    }

    let Some(port) = port else {
        let reason = DenyReason::MalformedConnectTarget;
        tracing::debug!(
            host,
            action = "deny",
            rule = reason.audit_rule(),
            "egress proxy: CONNECT denied"
        );
        write_denied_response(&mut client, Some(host), reason).await?;
        return Ok(());
    };

    if port != 443 {
        let reason = DenyReason::ConnectPortNotPermitted;
        tracing::debug!(
            host,
            port,
            action = "deny",
            rule = reason.audit_rule(),
            "egress proxy: CONNECT denied"
        );
        write_denied_response(&mut client, Some(host), reason).await?;
        return Ok(());
    }

    let dial_addr = match resolve_dial_addr(resolver, host, port, deny_private_ips).await {
        Ok(Ok(addr)) => addr,
        Ok(Err(reason)) => {
            tracing::debug!(
                host,
                action = "deny",
                rule = reason.audit_rule(),
                "egress proxy: CONNECT denied"
            );
            write_denied_response(&mut client, Some(host), reason).await?;
            return Ok(());
        }
        Err(error) => {
            tracing::debug!(host, ?error, "egress proxy: CONNECT DNS resolution failed");
            let body = "egress proxy: origin unreachable";
            let response = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            client.write_all(response.as_bytes()).await?;
            return client.flush().await;
        }
    };

    // D1 split: BOUND hosts get TLS termination (`tls_intercept`), UNBOUND
    // hosts stay an opaque tunnel — see this function's doc and
    // `tls_intercept`'s module doc. `and_then` means a `tls_intercept: Some`
    // config whose allowlist doesn't name this host (i.e. `bind` returns
    // `None`) takes the unbound path below exactly like `tls_intercept:
    // None` would — D1 has no partial state between "bound" and "unbound,"
    // and the resulting `BoundHost` is D1's proof, scoped to this specific
    // config, that `terminate_and_forward` can rely on instead of a bare
    // `&str` + separate `is_bound` check (see `TlsInterceptConfig::bind`'s
    // doc).
    if let Some((config, bound_host)) =
        tls_intercept.and_then(|config| config.bind(host).map(|bound_host| (config, bound_host)))
    {
        tracing::debug!(
            host,
            action = "allow",
            rule = "allowlist_match_intercepted",
            "egress proxy: CONNECT allowed, terminating TLS for a bound host"
        );
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;
        // Same "eager client" buffering case as the unbound path below —
        // see `tls_intercept::LeadingBytes`'s doc for why these bytes can't
        // just be dropped.
        let leftover = client.buffer().to_vec();
        let raw_client = client.into_inner();
        // Resolve the peer's `{tenant, user}` from the kernel-verified
        // `peer_addr` this connection was accepted on — never from anything
        // container-authored, which could be forged. `attribution` is
        // `None` when this proxy wasn't wired with a resolver (every
        // non-production/no-Docker test path); a wired resolver that can't
        // attribute this peer (unknown IP, more than one container
        // reporting it, malformed labels, a Docker query error) returns
        // `Unattributed`. Either way `owned_identity` ends up `None`, which
        // `SandboxCredentialFirewall::authorize` (via
        // `SandboxCredentialSwap::rewrite_request_head`) turns into
        // `Err(AttributionFailed)` — a CONNECTION-DENIAL, not a forward —
        // the instant a request on this connection actually carries a
        // placeholder. See `attribution`'s module doc for why source IP is
        // sound here and why a duplicate/ambiguous peer address must not
        // guess.
        let owned_identity = match attribution {
            Some(resolver) => match resolver.resolve_peer(peer_addr.ip()).await {
                attribution::ConnectionAttribution::Attributed { tenant_id, user_id } => {
                    Some((tenant_id, user_id))
                }
                attribution::ConnectionAttribution::Unattributed => None,
            },
            None => None,
        };
        let connection = tls_intercept::InterceptedConnection {
            identity: owned_identity.as_ref().and_then(|(tenant_id, user_id)| {
                invocation_id.map(|invocation_id| SandboxCredentialConnectionIdentity {
                    tenant_id,
                    user_id,
                    invocation_id,
                })
            }),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
        };
        if let Err(error) = tls_intercept::terminate_and_forward(
            raw_client, leftover, bound_host, dial_addr, config, connection,
        )
        .await
        {
            // Fail CLOSED: log and close. Never fall back to a plaintext
            // relay — the client already believes it completed a CONNECT
            // to what it thinks is a TLS endpoint, and any bytes it sends
            // next are the start of (or expected to be) a TLS handshake,
            // never something safe to tunnel in the clear.
            tracing::debug!(
                host,
                ?error,
                "egress proxy: TLS interception failed, closing the connection (fail closed)"
            );
        }
        return Ok(());
    }

    let mut origin = match TcpStream::connect(dial_addr).await {
        Ok(origin) => origin,
        Err(error) => {
            tracing::debug!(host, ?error, "egress proxy: CONNECT origin unreachable");
            let body = "egress proxy: origin unreachable";
            let response = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            client.write_all(response.as_bytes()).await?;
            return client.flush().await;
        }
    };

    tracing::debug!(
        host,
        action = "allow",
        rule = "allowlist_match",
        "egress proxy: CONNECT allowed"
    );
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    client.flush().await?;

    // `BufReader::into_inner()` drops whatever is still sitting in its read
    // buffer. A client that doesn't wait for the `200` before sending its
    // TLS ClientHello (pipelining, or bytes that just land in the same TCP
    // segment as the CONNECT request) leaves those bytes buffered here —
    // forward them to the origin before handing off to the raw
    // bidirectional copy, or they're silently lost.
    let leftover = client.buffer().to_vec();
    let mut client = client.into_inner();
    if !leftover.is_empty() {
        origin.write_all(&leftover).await?;
    }
    copy_bidirectional(&mut client, &mut origin).await?;
    Ok(())
}

/// Plain absolute-URI HTTP (`GET http://host/path HTTP/1.1`, etc.) —
/// forwards the request verbatim to the origin and streams the response
/// back once allowed; replies `403` and closes on deny.
async fn handle_plain_http(
    mut client: BufReader<TcpStream>,
    head: &RequestHead,
    policy: &NetworkPolicy,
    resolver: &dyn HostResolver,
    deny_private_ips: bool,
) -> std::io::Result<()> {
    let mut untrusted_head = format!("{} {} HTTP/1.1\r\n", head.method, head.target);
    for header_line in &head.header_lines {
        untrusted_head.push_str(header_line);
    }
    if !super::credential_swap::placeholder_candidates(untrusted_head.as_bytes()).is_empty() {
        let reason = DenyReason::PlainHttpCredentialPlaceholder;
        tracing::debug!(
            action = "deny",
            rule = reason.audit_rule(),
            "egress proxy: plain HTTP denied"
        );
        write_denied_response(&mut client, None, reason).await?;
        return Ok(());
    }

    let parsed = url::Url::parse(&head.target).ok();
    let host_only = parsed.as_ref().and_then(|url| url.host_str());
    let Some(host_only) = host_only else {
        // Not a well-formed absolute-URI proxy request; nothing to
        // allowlist-check against, so deny rather than forward blind. `host`
        // is deliberately `None` here — see `write_denied_response`'s doc for
        // why the raw (unparsed) target is never echoed back.
        let reason = DenyReason::MalformedRequestTarget;
        tracing::debug!(
            action = "deny",
            rule = reason.audit_rule(),
            "egress proxy: plain HTTP denied"
        );
        write_denied_response(&mut client, None, reason).await?;
        return Ok(());
    };
    let host_only = host_only.to_string();
    let port = parsed
        .as_ref()
        .and_then(|url| url.port_or_known_default())
        .unwrap_or(80);

    if !host_allowed(&host_only, policy) {
        let reason = DenyReason::NotInAllowlist;
        tracing::debug!(host = %host_only, action = "deny", rule = reason.audit_rule(), "egress proxy: plain HTTP denied");
        write_denied_response(&mut client, Some(&host_only), reason).await?;
        return Ok(());
    }

    if port != 80 {
        let reason = DenyReason::PlainHttpPortNotPermitted;
        tracing::debug!(
            host = %host_only,
            port,
            action = "deny",
            rule = reason.audit_rule(),
            "egress proxy: plain HTTP denied"
        );
        write_denied_response(&mut client, Some(&host_only), reason).await?;
        return Ok(());
    }

    let dial_addr = match resolve_dial_addr(resolver, &host_only, port, deny_private_ips).await {
        Ok(Ok(addr)) => addr,
        Ok(Err(reason)) => {
            tracing::debug!(host = %host_only, action = "deny", rule = reason.audit_rule(), "egress proxy: plain HTTP denied");
            write_denied_response(&mut client, Some(&host_only), reason).await?;
            return Ok(());
        }
        Err(error) => {
            tracing::debug!(host = %host_only, ?error, "egress proxy: plain HTTP DNS resolution failed");
            let body = "egress proxy: origin unreachable";
            let response = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            client.write_all(response.as_bytes()).await?;
            return client.flush().await;
        }
    };

    let mut origin = match TcpStream::connect(dial_addr).await {
        Ok(origin) => origin,
        Err(error) => {
            tracing::debug!(
                host = %host_only,
                ?error,
                "egress proxy: plain HTTP origin unreachable"
            );
            let body = "egress proxy: origin unreachable";
            let response = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            client.write_all(response.as_bytes()).await?;
            return client.flush().await;
        }
    };

    tracing::debug!(host = %host_only, action = "allow", rule = "allowlist_match", "egress proxy: plain HTTP allowed");
    let request_head = forwarded_plain_http_head(head);
    origin.write_all(request_head.as_bytes()).await?;

    // As in `handle_connect`: a request body sent in the same TCP segment
    // as the headers ends up buffered inside `client` (the `BufReader`),
    // and `into_inner()` would silently drop it. Forward whatever is
    // buffered — the start of the body, in order — before streaming the
    // rest via the raw bidirectional copy.
    let leftover = client.buffer().to_vec();
    let mut client = client.into_inner();
    if !leftover.is_empty() {
        origin.write_all(&leftover).await?;
    }
    copy_bidirectional(&mut client, &mut origin).await?;
    Ok(())
}

fn forwarded_plain_http_head(head: &RequestHead) -> String {
    let mut request_head = format!("{} {} HTTP/1.1\r\n", head.method, head.target);
    for header_line in &head.header_lines {
        if header_line
            .split_once(':')
            .is_some_and(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
        {
            continue;
        }
        request_head.push_str(header_line);
    }
    request_head.push_str("\r\n");
    request_head
}

#[cfg(test)]
mod tests {
    use super::super::registry;
    use super::*;
    use crate::sandbox_process::credential_swap::{
        SandboxCredentialRuntime, SandboxStaticCredentialGrant,
    };
    use ironclaw_host_api::{
        action::{NetworkMethod, NetworkTargetPattern},
        http::{
            RuntimeHttpEgress, RuntimeHttpEgressError, RuntimeHttpEgressRequest,
            RuntimeHttpEgressResponse,
        },
        ids::{CapabilityId, ExtensionId, SecretHandle, TenantId, UserId},
        resource::ResourceScope,
    };
    use ironclaw_secrets::{CredentialPathPolicy, CredentialTargetPolicy, SecretMaterial};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;

    /// Test-only resolver that always resolves to a fixed address,
    /// ignoring whatever host/port the request named. Lets a test point
    /// the proxy's dial step at a real local listener (to prove the
    /// tunnel/forward mechanics) or at a synthetic private IP (to prove
    /// the SSRF guard) without live DNS or a privileged low-port bind.
    struct FixedAddrResolver(SocketAddr);

    #[async_trait]
    impl HostResolver for FixedAddrResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![self.0])
        }
    }

    struct AttributionHostEgress;

    #[async_trait]
    impl RuntimeHttpEgress for AttributionHostEgress {
        async fn execute(
            &self,
            _request: RuntimeHttpEgressRequest,
        ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
            Ok(RuntimeHttpEgressResponse {
                status: 200,
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                body: b"origin saw the request\n".to_vec(),
                saved_body: None,
                request_bytes: 1,
                response_bytes: 23,
                redaction_applied: true,
            })
        }
    }

    /// Test-only resolver that returns a fixed, ordered *multi*-address DNS
    /// answer, ignoring the requested host/port — lets a test simulate a
    /// mixed public+private resolution (split-horizon DNS abuse / rebinding)
    /// without live DNS.
    struct MultiAddrResolver(Vec<SocketAddr>);

    #[async_trait]
    impl HostResolver for MultiAddrResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            Ok(self.0.clone())
        }
    }

    fn policy_allowing(hosts: &[&str]) -> NetworkPolicy {
        NetworkPolicy {
            allowed_targets: hosts
                .iter()
                .map(|host| NetworkTargetPattern {
                    scheme: None,
                    host_pattern: (*host).to_string(),
                    port: None,
                })
                .collect(),
            deny_private_ip_ranges: true,
            max_egress_bytes: None,
        }
    }

    fn connect_head_with_proxy_authorization(value: &str) -> RequestHead {
        RequestHead {
            method: "CONNECT".to_string(),
            target: "api.github.com:443".to_string(),
            header_lines: vec![format!("Proxy-Authorization: {value}\r\n")],
        }
    }

    #[test]
    fn proxy_basic_username_recovers_exact_invocation_identity() {
        let invocation_id = InvocationId::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{invocation_id}:"));
        let head = connect_head_with_proxy_authorization(&format!("Basic {encoded}"));
        assert_eq!(proxy_invocation_identity(&head), Some(invocation_id));
    }

    #[test]
    fn proxy_identity_rejects_missing_password_delimiter_and_duplicates() {
        let invocation_id = InvocationId::new();
        let missing_delimiter =
            base64::engine::general_purpose::STANDARD.encode(invocation_id.to_string());
        assert_eq!(
            proxy_invocation_identity(&connect_head_with_proxy_authorization(&format!(
                "Basic {missing_delimiter}"
            ))),
            None
        );

        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{invocation_id}:"));
        let mut duplicate = connect_head_with_proxy_authorization(&format!("Basic {encoded}"));
        duplicate
            .header_lines
            .push(format!("proxy-authorization: Basic {encoded}\r\n"));
        assert_eq!(proxy_invocation_identity(&duplicate), None);
    }

    fn proxy_v2_ipv4_header(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
        let (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) = (source.ip(), destination.ip())
        else {
            panic!("test helper requires IPv4 addresses");
        };
        let mut header = PROXY_V2_SIGNATURE.to_vec();
        header.extend_from_slice(&[0x21, 0x11]);
        header.extend_from_slice(&(PROXY_V2_IPV4_ADDRESS_BYTES as u16).to_be_bytes());
        header.extend_from_slice(&source_ip.octets());
        header.extend_from_slice(&destination_ip.octets());
        header.extend_from_slice(&source.port().to_be_bytes());
        header.extend_from_slice(&destination.port().to_be_bytes());
        header
    }

    async fn loopback_tcp_pair() -> (TcpStream, TcpStream, SocketAddr) {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(listener_addr).await.unwrap();
        let (server, kernel_peer) = listener.accept().await.unwrap();
        (client, server, kernel_peer)
    }

    #[tokio::test]
    async fn relay_mode_consumes_bounded_proxy_v2_source_metadata() {
        let (mut client, mut server, kernel_peer) = loopback_tcp_pair().await;
        let claimed_source: SocketAddr = "10.200.0.42:43123".parse().unwrap();
        let destination: SocketAddr = "10.200.0.1:18443".parse().unwrap();
        let mut bytes = proxy_v2_ipv4_header(claimed_source, destination);
        bytes.extend_from_slice(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n");
        client.write_all(&bytes).await.unwrap();

        let resolved = resolve_peer_addr(
            &mut server,
            kernel_peer,
            PeerSourceMode::TrustedProxyV2FromLoopback,
        )
        .await
        .unwrap();
        assert_eq!(resolved, claimed_source);

        let mut request = [0u8; 7];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"CONNECT");
    }

    #[tokio::test]
    async fn direct_mode_does_not_consume_spoofed_proxy_metadata() {
        let (mut client, mut server, kernel_peer) = loopback_tcp_pair().await;
        let claimed_source: SocketAddr = "10.200.0.99:41234".parse().unwrap();
        let destination: SocketAddr = "10.200.0.1:18443".parse().unwrap();
        client
            .write_all(&proxy_v2_ipv4_header(claimed_source, destination))
            .await
            .unwrap();

        let resolved = resolve_peer_addr(&mut server, kernel_peer, PeerSourceMode::Direct)
            .await
            .unwrap();
        assert_eq!(resolved, kernel_peer);

        let mut signature = [0u8; PROXY_V2_SIGNATURE.len()];
        server.read_exact(&mut signature).await.unwrap();
        assert_eq!(signature, PROXY_V2_SIGNATURE);
    }

    #[tokio::test]
    async fn relay_mode_rejects_non_loopback_metadata_sources() {
        let (_client, mut server, _kernel_peer) = loopback_tcp_pair().await;
        let untrusted_peer: SocketAddr = "192.0.2.10:40000".parse().unwrap();

        let error = resolve_peer_addr(
            &mut server,
            untrusted_peer,
            PeerSourceMode::TrustedProxyV2FromLoopback,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn relay_mode_rejects_oversized_proxy_v2_metadata() {
        let (mut client, mut server, kernel_peer) = loopback_tcp_pair().await;
        let mut header = PROXY_V2_SIGNATURE.to_vec();
        header.extend_from_slice(&[0x21, 0x11]);
        header.extend_from_slice(&((PROXY_V2_MAX_ADDRESS_BYTES + 1) as u16).to_be_bytes());
        client.write_all(&header).await.unwrap();

        let error = resolve_peer_addr(
            &mut server,
            kernel_peer,
            PeerSourceMode::TrustedProxyV2FromLoopback,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn relay_mode_times_out_an_incomplete_proxy_v2_preface() {
        let (mut client, mut server, kernel_peer) = loopback_tcp_pair().await;
        client.write_all(&PROXY_V2_SIGNATURE).await.unwrap();

        let started = std::time::Instant::now();
        let error = resolve_peer_addr(
            &mut server,
            kernel_peer,
            PeerSourceMode::TrustedProxyV2FromLoopback,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "incomplete relay metadata must fail within the production timeout"
        );
    }

    /// Real Colima/Docker proof for the VM topology. Run explicitly after
    /// building `ironclaw-worker:latest` from `Dockerfile.process-sandbox`.
    #[tokio::test]
    #[ignore = "requires a real Docker/Colima engine and the local worker image"]
    async fn vm_relay_connects_internal_worker_and_preserves_source_ip() {
        let docker = super::super::connect_docker_with_retry()
            .await
            .expect("Docker must be reachable");
        super::super::exec_transport::ensure_default_egress_network(&docker)
            .await
            .expect("sandbox egress network must be ready");

        let listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("host-loopback listener binds");
        let port = listener.local_addr().expect("listener address").port();
        let relay = VmEgressRelay::start(port)
            .await
            .expect("VM relay starts from the worker image");
        let relay_owner = relay.owner_token.clone();

        let second = VmEgressRelay::start(port).await;
        let active_owner_was_preserved = second.is_err();
        if let Ok(unexpected) = second {
            let _ = unexpected.shutdown().await;
        }

        let worker_name = format!("ironclaw-egress-relay-probe-{}", uuid::Uuid::new_v4());
        let gateway = super::super::broker::SANDBOX_EGRESS_NETWORK_GATEWAY;
        let script = r#"import socket, sys, time
address = (sys.argv[1], int(sys.argv[2]))
for attempt in range(30):
    try:
        connection = socket.create_connection(address, timeout=1)
        break
    except OSError:
        if attempt == 29:
            raise
        time.sleep(0.1)
connection.sendall(b'ping')
reply = connection.recv(2)
connection.close()
sys.exit(0 if reply == b'ok' else 1)
"#;
        let accepted = tokio::spawn(async move {
            let (mut stream, kernel_peer) = listener.accept().await?;
            let source = resolve_peer_addr(
                &mut stream,
                kernel_peer,
                PeerSourceMode::TrustedProxyV2FromLoopback,
            )
            .await?;
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await?;
            stream.write_all(b"ok").await?;
            Ok::<_, std::io::Error>((source, payload, kernel_peer))
        });

        let mut worker_id = None;
        let outcome = async {
            let created = docker
                .create_container(
                    Some(CreateContainerOptions {
                        name: worker_name,
                        platform: None,
                    }),
                    Config {
                        image: Some(super::super::DEFAULT_IMAGE.to_string()),
                        entrypoint: Some(vec!["python3".to_string(), "-c".to_string()]),
                        cmd: Some(vec![
                            script.to_string(),
                            gateway.to_string(),
                            port.to_string(),
                        ]),
                        user: Some("1000:1000".to_string()),
                        host_config: Some(HostConfig {
                            network_mode: Some(
                                super::super::broker::SANDBOX_EGRESS_NETWORK_NAME.to_string(),
                            ),
                            readonly_rootfs: Some(true),
                            cap_drop: Some(vec!["ALL".to_string()]),
                            security_opt: Some(vec!["no-new-privileges:true".to_string()]),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
            worker_id = Some(created.id.clone());
            docker
                .start_container(&created.id, None::<StartContainerOptions<String>>)
                .await
                .map_err(|error| error.to_string())?;

            let worker = docker
                .inspect_container(&created.id, None::<InspectContainerOptions>)
                .await
                .map_err(|error| error.to_string())?;
            let worker_ip = worker
                .network_settings
                .and_then(|settings| settings.networks)
                .and_then(|networks| {
                    networks
                        .get(super::super::broker::SANDBOX_EGRESS_NETWORK_NAME)
                        .cloned()
                })
                .and_then(|endpoint| endpoint.ip_address)
                .filter(|address| !address.is_empty())
                .ok_or_else(|| "worker had no internal-network IP".to_string())?;
            let worker_ip: IpAddr = worker_ip
                .parse()
                .map_err(|error| format!("worker IP was invalid: {error}"))?;

            let (source, payload, kernel_peer) =
                tokio::time::timeout(Duration::from_secs(10), accepted)
                    .await
                    .map_err(|_| "host listener timed out".to_string())?
                    .map_err(|error| format!("host listener task failed: {error}"))?
                    .map_err(|error| format!("host listener I/O failed: {error}"))?;

            let relay_inspect = docker
                .inspect_container(VM_RELAY_CONTAINER_NAME, None::<InspectContainerOptions>)
                .await
                .map_err(|error| error.to_string())?;
            let relay_config = relay_inspect
                .config
                .ok_or_else(|| "relay inspect omitted Config".to_string())?;
            let relay_host_config = relay_inspect
                .host_config
                .ok_or_else(|| "relay inspect omitted HostConfig".to_string())?;
            let relay_labels = relay_config.labels.unwrap_or_default();
            let relay_env = relay_config.env.unwrap_or_default();
            let relay_mounts = relay_inspect.mounts.unwrap_or_default();

            Ok::<_, String>((
                source,
                payload,
                kernel_peer,
                worker_ip,
                relay_labels,
                relay_env,
                relay_mounts,
                relay_host_config,
            ))
        }
        .await;

        if let Some(worker_id) = worker_id {
            let _ = docker
                .remove_container(
                    &worker_id,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await;
        }
        relay
            .shutdown()
            .await
            .expect("owned relay cleanup succeeds");

        let (source, payload, kernel_peer, worker_ip, labels, env, mounts, host_config) =
            outcome.expect("real relay topology succeeds");
        assert!(active_owner_was_preserved);
        assert!(kernel_peer.ip().is_loopback());
        assert_eq!(source.ip(), worker_ip);
        assert_eq!(payload, *b"ping");
        assert_eq!(labels.get(VM_RELAY_OWNER_LABEL_KEY), Some(&relay_owner));
        assert!(mounts.is_empty(), "relay must have no mounts: {mounts:?}");
        assert!(env.iter().any(|entry| entry == "PYTHONDONTWRITEBYTECODE=1"));
        assert!(
            env.iter().all(|entry| {
                entry.starts_with("PATH=") || entry == "PYTHONDONTWRITEBYTECODE=1"
            }),
            "relay environment must contain no credential-bearing values: {env:?}"
        );
        assert_eq!(host_config.network_mode.as_deref(), Some("host"));
        assert_eq!(host_config.readonly_rootfs, Some(true));
        assert_eq!(host_config.cap_drop, Some(vec!["ALL".to_string()]));
        assert_eq!(host_config.pids_limit, Some(VM_RELAY_PIDS_LIMIT));
        assert_eq!(host_config.memory, Some(VM_RELAY_MEMORY_BYTES));
        assert!(host_config.binds.unwrap_or_default().is_empty());
    }

    /// `interception_bound_hosts` is the exact-match filter feeding
    /// `TlsInterceptConfig`'s `bound_hosts`: exact hostnames from the
    /// allowlist are bound; `*.suffix` wildcard entries are excluded (see
    /// its doc for why — `bound_hosts` has no wildcard-matching capability).
    /// Pins both halves plus normalization (case/whitespace/trailing dot).
    #[test]
    fn interception_bound_hosts_binds_exact_matches_and_excludes_wildcards() {
        let policy = policy_allowing(&[
            "pypi.org",
            "GITHUB.com",
            "  registry.npmjs.org.  ",
            "*.corp.example.com",
        ]);

        let bound = interception_bound_hosts(&policy);

        assert_eq!(
            bound,
            HashSet::from([
                "pypi.org".to_string(),
                "github.com".to_string(),
                "registry.npmjs.org".to_string(),
            ]),
            "exact-match allowlist entries must be bound (normalized); the wildcard entry must \
             be excluded entirely"
        );
        assert!(
            !bound.contains("*.corp.example.com"),
            "a wildcard pattern must never appear in bound_hosts verbatim — it cannot match \
             anything in an exact-match HashSet"
        );
    }

    #[test]
    fn interception_bound_hosts_is_empty_for_an_empty_allowlist() {
        let policy = policy_allowing(&[]);

        assert!(interception_bound_hosts(&policy).is_empty());
    }

    /// `bind_sandbox_egress_proxy_with_tls_intercept` is the sole production
    /// door to a real `SandboxEgressProxyBinding`: this pins that it always
    /// wires TLS interception AND returns a non-empty container trust
    /// bundle containing no private-key material — the two properties
    /// `RebornSandboxConfig::with_ca_bundle_pem` and
    /// `exec_transport::user_container_launch_config` depend on. No Docker
    /// or real network needed: binding a listener and building the CA/trust
    /// bundle are pure host-local operations.
    #[tokio::test]
    async fn bind_sandbox_egress_proxy_with_tls_intercept_wires_interception_and_a_key_free_bundle()
    {
        let credential_runtime = SandboxCredentialRuntime::new();
        let binding = bind_sandbox_egress_proxy_with_tls_intercept(
            "127.0.0.1:0",
            policy_allowing(&["pypi.org"]),
            None,
            credential_runtime.clone(),
        )
        .await
        .expect("binding an ephemeral port and building the CA/trust bundle should succeed");

        assert!(
            binding.proxy.tls_intercept_is_active(),
            "the production factory must always wire TLS interception"
        );
        assert!(
            binding
                .proxy
                .uses_sandbox_credential_runtime(&credential_runtime),
            "the production proxy must consume the caller-owned credential runtime rather than \
             constructing disconnected stores"
        );
        assert!(
            !binding.ca_bundle_pem.is_empty(),
            "the container trust bundle must not be empty"
        );
        assert!(
            !binding.ca_bundle_pem.contains("PRIVATE KEY"),
            "the container trust bundle handed back to composition must never contain private \
             key material"
        );
        assert!(
            binding
                .ca_bundle_pem
                .contains("-----BEGIN CERTIFICATE-----")
        );
    }

    #[tokio::test]
    async fn bind_returns_a_reachable_local_address() {
        let proxy = EgressAllowlistProxy::new(policy_allowing(&["example.com"]));
        let bound = proxy
            .bind("127.0.0.1:0")
            .await
            .expect("binding an ephemeral port always succeeds");

        assert_ne!(bound.local_addr().port(), 0);
    }

    /// Spins up a local echo server, allowlists its host, drives a raw
    /// `CONNECT` handshake through the proxy, and proves bytes actually
    /// tunnel end to end (not just that the handshake completes). Also
    /// covers the E2 port-pin hardening's allow path (`CONNECT ...:443` on
    /// an allowlisted host proceeds) by naming port 443 in the request line
    /// while a `FixedAddrResolver` transparently redirects the actual dial
    /// to the echo server's real (ephemeral) port — real DNS can't be
    /// pointed at an arbitrary local port, and binding the echo server to
    /// the real port 443 would need root. The echo server is a loopback
    /// stand-in for a real origin, not a policy target, so this test also
    /// disables the private-IP guard (`deny_private_ips: false`) rather
    /// than weakening it in production; the guard itself is proven denying
    /// loopback/private/link-local addresses by
    /// `connect_to_allowlisted_host_resolving_private_ip_is_denied` and the
    /// `denied_ip_reason` unit tests below.
    #[tokio::test]
    async fn connect_to_allowed_host_tunnels_bytes() {
        let echo_listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("echo listener binds");
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = echo_listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = socket.read(&mut buf).await {
                    let _ = socket.write_all(&buf[..n]).await;
                }
            }
        });

        let proxy = EgressAllowlistProxy {
            policy: policy_allowing(&["127.0.0.1"]),
            resolver: Arc::new(FixedAddrResolver(echo_addr)),
            deny_private_ips: false,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: None,
            attribution: None,
        };
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        client
            .write_all(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n")
            .await
            .expect("CONNECT request writes");

        let mut response = [0u8; 128];
        let n = client
            .read(&mut response)
            .await
            .expect("reads the CONNECT response");
        let response = String::from_utf8_lossy(&response[..n]);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected 200 Connection Established, got: {response}"
        );

        client
            .write_all(b"hello through the tunnel")
            .await
            .expect("write tunneled bytes");
        let mut echoed = [0u8; 64];
        let n = client
            .read(&mut echoed)
            .await
            .expect("reads the echoed bytes back through the tunnel");
        assert_eq!(&echoed[..n], b"hello through the tunnel");

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    #[tokio::test]
    async fn connect_to_denied_host_returns_403_and_closes() {
        let echo_listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("echo listener binds");
        let echo_port = echo_listener.local_addr().unwrap().port();
        // Proves the ordering, not just the outcome: the allowlist check must
        // reject the CONNECT before the proxy ever dials the origin. If the
        // deny check ran after (or raced) the dial, this fake origin would
        // see a real TCP connection despite the client getting a 403 — the
        // same "record whether the origin was ever dialed" pattern as
        // `tls_intercept::client_handshake_failure_never_dials_the_origin`.
        let origin_saw_a_connection = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(300), echo_listener.accept()).await
        });

        let proxy = EgressAllowlistProxy::new(policy_allowing(&["github.com"]));
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        client
            .write_all(format!("CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .expect("CONNECT request writes");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("reads the full 403 response then EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "expected 403 Forbidden, got: {response}"
        );
        // Names its real cause (hostname allowlist miss), not a generic
        // catch-all — this is the exact denial category the private-IP
        // guard's own denial (`connect_to_allowlisted_host_resolving_private_
        // ip_is_denied`, below) must NOT be confused with.
        assert!(
            response.contains("host not in allowlist"),
            "expected an allowlist-miss message, got: {response}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;

        let origin_result = origin_saw_a_connection
            .await
            .expect("origin probe task did not panic");
        assert!(
            origin_result.is_err(),
            "the denied host's origin must never be dialed — the allowlist check must run \
             strictly before any connection attempt"
        );
    }

    /// E2 hardening 1 (SSRF/DNS-rebinding guard) — headline test. A host
    /// passes the hostname allowlist but resolves to the cloud-metadata
    /// link-local address (via an injected resolver, so the assertion does
    /// not depend on live DNS); the dial-time private-IP check must deny it
    /// even though the hostname itself was allowed.
    ///
    /// Also pins the defect this task fixed: before the fix, this denial's
    /// body read `"host not in allowlist"` — the SAME text
    /// `connect_to_denied_host_returns_403_and_closes` above asserts for an
    /// actual allowlist miss — even though the host in this test WAS
    /// allowlisted and the real cause was the private-IP guard. Distinct
    /// causes must produce distinguishable messages.
    #[tokio::test]
    async fn connect_to_allowlisted_host_resolving_private_ip_is_denied() {
        let proxy = EgressAllowlistProxy {
            policy: policy_allowing(&["metadata.example"]),
            resolver: Arc::new(FixedAddrResolver(SocketAddr::from((
                [169, 254, 169, 254],
                443,
            )))),
            deny_private_ips: true,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: None,
            attribution: None,
        };
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        client
            .write_all(b"CONNECT metadata.example:443 HTTP/1.1\r\n\r\n")
            .await
            .expect("CONNECT request writes");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("reads the full 403 response then EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "expected 403 Forbidden for a private-IP resolution, got: {response}"
        );
        assert!(
            response.contains("resolved address is private"),
            "an allowlisted host denied by the private-IP guard must say so, not \
             claim the host itself isn't allowlisted, got: {response}"
        );
        assert!(
            !response.contains("host not in allowlist"),
            "this host WAS allowlisted — the denial must not misname the cause as an \
             allowlist miss, got: {response}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// Pins the divergence a dedup audit found between this proxy's
    /// dial-time private-IP guard and `ironclaw_network::resolver::
    /// resolve_public_ips`'s canonical selection policy: that function denies
    /// the WHOLE request if ANY resolved address is private (via
    /// `network_denies_any_resolved_ip`), but this proxy previously picked
    /// the first address that individually
    /// passed the guard, silently skipping private candidates ahead of it —
    /// and, worse, would then actually dial that first-passing public
    /// address. A hostname whose DNS answer mixes a public address first and
    /// a private/loopback address second (split-horizon DNS abuse, a
    /// compromised or rebinding-prone resolver) must be denied outright, the
    /// same way it would be through the `ironclaw_network`-mediated HTTP
    /// egress path — an all-private resolution proves nothing about this
    /// selection-over-a-set divergence, only a mixed set does. Exercises
    /// `resolve_dial_addr` directly (not a full CONNECT round trip) so the
    /// assertion never depends on live network reachability of the
    /// (fictitious) public address in the mix.
    #[tokio::test]
    async fn resolve_dial_addr_denies_a_mixed_public_and_private_resolution() {
        let resolver = MultiAddrResolver(vec![
            // Public address first — the bug picked this one as the dial
            // target, silently skipping the private candidate below.
            SocketAddr::from(([93, 184, 216, 34], 443)),
            // Private (RFC1918) address second.
            SocketAddr::from(([10, 0, 0, 5], 443)),
        ]);

        let result = resolve_dial_addr(&resolver, "mixed.example", 443, true)
            .await
            .expect("resolver itself does not error");

        assert_eq!(
            result,
            Err(DenyReason::PrivateAddress),
            "a resolution set containing ANY private address must deny the whole request, \
             matching ironclaw_network::resolver::resolve_public_ips's any-private-denies-all \
             policy — got {result:?}"
        );
    }

    /// E2 hardening 2 (CONNECT port pin) — an allowlisted host is still
    /// denied when the CONNECT target port isn't 443, closing off pivoting
    /// an allowlisted host to an arbitrary port through the tunnel.
    #[tokio::test]
    async fn connect_to_allowed_host_non_443_port_returns_403() {
        let proxy = EgressAllowlistProxy::new(policy_allowing(&["github.com"]));
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        client
            .write_all(b"CONNECT github.com:22 HTTP/1.1\r\n\r\n")
            .await
            .expect("CONNECT request writes");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("reads the full 403 response then EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "expected 403 Forbidden for a non-443 CONNECT port, got: {response}"
        );
        // `github.com` IS allowlisted; the denial must name the port pin as
        // the real cause, not claim the host wasn't allowed.
        assert!(
            response.contains("port not permitted"),
            "expected a port-pin denial message, got: {response}"
        );
        assert!(
            !response.contains("host not in allowlist"),
            "this host WAS allowlisted — the denial must not misname the cause, got: {response}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// `denied_ip_reason` is the pure classification function both dial
    /// paths gate on; exercise every range named in the E2 amendment plus
    /// one public v4/v6 example each, so the range math is pinned
    /// independent of any live connection. Also covers the ranges
    /// `ironclaw_network`'s canonical range check catches that this proxy's
    /// former hand-rolled range list drifted behind: `0.0.0.0/8` and the
    /// `fc00::/8` half of the RFC 4193 unique-local range (the hand-rolled
    /// check only matched `fd00::/8`).
    #[test]
    fn denied_ip_reason_covers_every_e2_range() {
        let denied = [
            ("10.0.0.5", "private (RFC1918 10/8)"),
            ("172.16.0.5", "private (RFC1918 172.16/12)"),
            ("172.31.255.254", "private (RFC1918 172.16/12 upper bound)"),
            ("192.168.1.1", "private (RFC1918 192.168/16)"),
            ("127.0.0.1", "loopback"),
            ("169.254.169.254", "cloud metadata link-local"),
            ("169.254.1.1", "link-local"),
            ("100.64.0.1", "CGNAT lower bound"),
            ("100.100.100.100", "CGNAT mid-range"),
            ("100.127.255.255", "CGNAT upper bound"),
            ("0.0.0.0", "0.0.0.0/8"),
        ];
        for (ip, label) in denied {
            let ip: IpAddr = ip.parse().expect("valid literal");
            assert!(
                denied_ip_reason(ip).is_some(),
                "expected {ip} ({label}) to be denied"
            );
        }

        let denied_v6 = [
            ("::1", "loopback"),
            ("fd00::1", "unique-local lower bound"),
            (
                "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "unique-local upper bound",
            ),
            ("::ffff:169.254.169.254", "IPv4-mapped cloud metadata"),
            ("fe80::1", "unicast link-local lower bound"),
            (
                "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "unicast link-local upper bound",
            ),
            ("fc00::1", "unique-local ULA fc00::/8 half of RFC 4193"),
        ];
        for (ip, label) in denied_v6 {
            let ip: IpAddr = ip.parse().expect("valid literal");
            assert!(
                denied_ip_reason(ip).is_some(),
                "expected {ip} ({label}) to be denied"
            );
        }

        let allowed = ["8.8.8.8", "93.184.216.34", "1.1.1.1"];
        for ip in allowed {
            let ip: IpAddr = ip.parse().expect("valid literal");
            assert_eq!(
                denied_ip_reason(ip),
                None,
                "expected public address {ip} to pass the guard"
            );
        }

        let allowed_v6: IpAddr = "2606:4700:4700::1111".parse().expect("valid literal");
        assert_eq!(
            denied_ip_reason(allowed_v6),
            None,
            "expected public v6 address to pass the guard"
        );
    }

    #[tokio::test]
    async fn plain_http_to_denied_host_returns_403() {
        let proxy = EgressAllowlistProxy::new(policy_allowing(&["github.com"]));
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        client
            .write_all(b"GET http://example.com/index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .expect("plain HTTP request writes");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("reads the full 403 response then EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "expected 403 Forbidden, got: {response}"
        );
        assert!(
            response.contains("host not in allowlist"),
            "expected an allowlist-miss message, got: {response}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// Plain-HTTP mirror of `connect_to_denied_host_returns_403_and_closes`:
    /// the CONNECT and plain-HTTP forward paths are two independently
    /// implemented handlers (`handle_connect` / `handle_plain_http`), each
    /// with its own allowlist-then-dial ordering — a `FixedAddrResolver`
    /// stands a real listener in as the origin the denied host would
    /// resolve to, so a bug that let `handle_plain_http` dial before
    /// checking the allowlist would show up as a real connection here even
    /// though `example.com` itself is never reachable in this environment.
    #[tokio::test]
    async fn plain_http_to_denied_host_never_dials_the_origin() {
        let origin_listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("origin listener binds");
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_saw_a_connection = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(300), origin_listener.accept()).await
        });

        let proxy = EgressAllowlistProxy {
            policy: policy_allowing(&["github.com"]),
            resolver: Arc::new(FixedAddrResolver(origin_addr)),
            deny_private_ips: false,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: None,
            attribution: None,
        };
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        client
            .write_all(b"GET http://example.com/index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .expect("plain HTTP request writes");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("reads the full 403 response then EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "expected 403 Forbidden, got: {response}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;

        let origin_result = origin_saw_a_connection
            .await
            .expect("origin probe task did not panic");
        assert!(
            origin_result.is_err(),
            "the denied host's origin must never be dialed on the plain-HTTP forward path \
             either — the allowlist check must run strictly before any connection attempt"
        );
    }

    #[tokio::test]
    async fn plain_http_placeholder_is_denied_before_origin_dial() {
        let origin_listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("origin listener binds");
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_saw_a_connection = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(300), origin_listener.accept()).await
        });
        let proxy = EgressAllowlistProxy {
            policy: policy_allowing(&["example.com"]),
            resolver: Arc::new(FixedAddrResolver(origin_addr)),
            deny_private_ips: false,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: None,
            attribution: None,
        };
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects");
        client
            .write_all(
                b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer icsbx_0123456789abcdef0123456789abcdef\r\n\r\n",
            )
            .await
            .expect("request writes");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("response reads");
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"));

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
        assert!(
            origin_saw_a_connection
                .await
                .expect("origin probe task did not panic")
                .is_err(),
            "plaintext placeholder must be rejected before origin dial"
        );
    }

    #[test]
    fn plain_http_forwarding_strips_proxy_authorization() {
        let head = RequestHead {
            method: "GET".to_string(),
            target: "http://example.com/".to_string(),
            header_lines: vec![
                "Host: example.com\r\n".to_string(),
                "Proxy-Authorization: Basic opaque-proxy-value\r\n".to_string(),
                "X-Keep: yes\r\n".to_string(),
            ],
        };
        let forwarded = forwarded_plain_http_head(&head);
        assert!(
            !forwarded
                .to_ascii_lowercase()
                .contains("proxy-authorization")
        );
        assert!(forwarded.contains("X-Keep: yes\r\n"));
    }

    /// A CONNECT target with no `:port` suffix at all (e.g. a client that
    /// sends `CONNECT github.com HTTP/1.1` instead of `CONNECT
    /// github.com:443 HTTP/1.1`) must be denied even though the hostname
    /// itself passes the allowlist — `handle_connect` has no port to pin
    /// against and denies rather than assuming one.
    #[tokio::test]
    async fn connect_target_without_a_port_is_denied() {
        let proxy = EgressAllowlistProxy::new(policy_allowing(&["github.com"]));
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        client
            .write_all(b"CONNECT github.com HTTP/1.1\r\n\r\n")
            .await
            .expect("CONNECT request writes");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("reads the full 403 response then EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "expected 403 Forbidden for a portless CONNECT target, got: {response}"
        );
        assert!(
            response.contains("missing port"),
            "expected a malformed-target message distinct from an allowlist miss, got: {response}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// An allowlisted, well-formed CONNECT whose resolved origin refuses the
    /// connection must surface a clean `502 Bad Gateway` to the client
    /// rather than hanging or crashing the connection handler — the origin
    /// is untrusted infrastructure the proxy does not control.
    #[tokio::test]
    async fn connect_to_allowed_host_with_unreachable_origin_returns_502() {
        let proxy = EgressAllowlistProxy {
            policy: policy_allowing(&["unreachable.example"]),
            // Port 1 on loopback: nothing listens there, so the OS refuses
            // the connection immediately instead of timing out.
            resolver: Arc::new(FixedAddrResolver("127.0.0.1:1".parse().unwrap())),
            deny_private_ips: false,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: None,
            attribution: None,
        };
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        client
            .write_all(b"CONNECT unreachable.example:443 HTTP/1.1\r\n\r\n")
            .await
            .expect("CONNECT request writes");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("reads the full response then EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 502"),
            "expected 502 Bad Gateway for an unreachable origin, got: {response}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// `host_allowed` is the pure decision function both `handle_connect`
    /// and `handle_plain_http` gate their dial on. Pin its normalization
    /// directly: DNS hostnames the container sends may differ in case or
    /// carry a trailing root-zone dot from the client's own resolver, and
    /// neither may cause a host that should be denied to slip through, nor
    /// a host that should be allowed to be spuriously rejected.
    #[test]
    fn host_allowed_normalizes_case_and_trailing_dot() {
        let policy = policy_allowing(&["api.github.com", "*.pypi.org"]);

        assert!(
            host_allowed("api.github.com", &policy),
            "exact-case match must be allowed"
        );
        assert!(
            host_allowed("API.GITHUB.COM", &policy),
            "an upper-case host must still match a lower-case allowlist entry"
        );
        assert!(
            host_allowed("Api.GitHub.Com.", &policy),
            "mixed case plus a trailing root-zone dot must still match"
        );
        assert!(
            host_allowed("files.pypi.org", &policy),
            "a `*.suffix` glob must match case-normalized subdomains"
        );
        assert!(
            host_allowed("FILES.PYPI.ORG.", &policy),
            "a `*.suffix` glob must match upper-case, dot-padded subdomains too"
        );
        assert!(
            !host_allowed("api.github.com.evil.example", &policy),
            "a denied host must not slip through by merely containing an allowed suffix"
        );
        assert!(
            !host_allowed("notgithub.com", &policy),
            "an unrelated host must stay denied"
        );
    }

    /// CR-005/CR-006: `host_allowed`'s wildcard arm must match
    /// `ironclaw_network::policy::host_matches_pattern` exactly, not a
    /// looser hand-rolled `ends_with` check. For pattern `*.pypi.org` the
    /// canonical matcher admits exactly one non-empty, dot-free label before
    /// the suffix — never the bare suffix itself, never multiple labels, and
    /// never a bare leading-dot host that happens to `ends_with` the pattern.
    #[test]
    fn host_allowed_matches_exactly_one_wildcard_label() {
        let policy = policy_allowing(&["*.pypi.org"]);

        assert!(
            !host_allowed("pypi.org", &policy),
            "CR-005: the bare suffix itself must not satisfy a `*.` wildcard"
        );
        assert!(
            !host_allowed("a.b.pypi.org", &policy),
            "CR-005: a `*.` wildcard must admit exactly one label, not a multi-label chain"
        );
        assert!(
            !host_allowed(".pypi.org", &policy),
            "CR-006: a bare leading-dot host must not self-match via `ends_with`"
        );
        assert!(
            host_allowed("files.pypi.org", &policy),
            "a single-label subdomain must still be allowed"
        );
    }

    /// Mirrors `connect_to_allowed_host_non_443_port_returns_403`: the
    /// plain-HTTP forward path pins its dial port to 80 the same way the
    /// CONNECT path pins to 443 — an allowlisted host named with a non-80
    /// port in the absolute-URI target must still be denied, closing off
    /// pivoting an allowlisted host to an arbitrary TCP port through the
    /// plain-HTTP forward (before the fix, only the hostname allowlist was
    /// applied here, so `GET http://allowed-host:22/` relayed straight
    /// through to port 22).
    #[tokio::test]
    async fn plain_http_to_allowed_host_non_80_port_returns_403() {
        let proxy = EgressAllowlistProxy::new(policy_allowing(&["github.com"]));
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        client
            .write_all(b"GET http://github.com:22/ HTTP/1.1\r\nHost: github.com:22\r\n\r\n")
            .await
            .expect("plain HTTP request writes");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("reads the full 403 response then EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "expected 403 Forbidden for a non-80 plain-HTTP port, got: {response}"
        );
        // `github.com` IS allowlisted; the denial must name the port pin,
        // not claim the host wasn't allowed.
        assert!(
            response.contains("port not permitted"),
            "expected a port-pin denial message, got: {response}"
        );
        assert!(
            !response.contains("host not in allowlist"),
            "this host WAS allowlisted — the denial must not misname the cause, got: {response}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// A plain-HTTP request-target that doesn't parse as an absolute URI at
    /// all (no scheme, e.g. an origin-form target a client mistakenly sends
    /// to a proxy) has no host to allowlist-check against — `handle_plain_
    /// http` denies it as a malformed target rather than forwarding blind or
    /// misreporting it as an allowlist miss. Also proves the raw
    /// unparseable target is never echoed back into the response body (see
    /// `write_denied_response`'s doc): a request-target that failed to
    /// parse is exactly the shape a `user:pass@host` URL would take before
    /// parsing, so echoing it back would be the same class of leak PR #6746
    /// fixed elsewhere in this crate.
    #[tokio::test]
    async fn plain_http_malformed_target_returns_403_without_echoing_it_back() {
        let proxy = EgressAllowlistProxy::new(policy_allowing(&["github.com"]));
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        let secret_bearing_target = "not-a-url-at-all-user:hunter2@evil.example";
        client
            .write_all(
                format!("GET {secret_bearing_target} HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("plain HTTP request writes");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("reads the full 403 response then EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "expected 403 Forbidden for a malformed request target, got: {response}"
        );
        assert!(
            response.contains("malformed request target"),
            "expected a malformed-target message, got: {response}"
        );
        assert!(
            !response.contains("hunter2"),
            "the raw unparseable target must never be echoed back into the response body, \
             got: {response}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// Regression for `into_inner()` dropping buffered bytes (finding 2,
    /// `handle_plain_http`): the request headers AND the start of the body
    /// are written to the proxy in ONE write, so they land in the same TCP
    /// segment and end up sitting in the `BufReader`'s internal buffer
    /// together after the header-parsing `read_line`s consume just the
    /// header portion. Before the fix, `into_inner()` silently dropped that
    /// buffered body prefix instead of forwarding it to the origin.
    #[tokio::test]
    async fn plain_http_forwards_body_bytes_buffered_alongside_the_headers() {
        let body = b"field=value&more=stuff";
        let request_head = format!(
            "POST http://example.com/submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        // The proxy forwards the head and the buffered leftover as two
        // separate writes; read in a loop up to this total so the
        // assertion doesn't depend on both landing in a single `read()`.
        let expected_len = request_head.len() + body.len();

        let origin_listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("origin listener binds");
        let origin_addr = origin_listener.local_addr().unwrap();
        let (origin_tx, origin_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = origin_listener.accept().await {
                let mut received = Vec::new();
                let mut buf = [0u8; 4096];
                while received.len() < expected_len {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => received.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = origin_tx.send(received);
            }
        });

        let proxy = EgressAllowlistProxy {
            policy: policy_allowing(&["example.com"]),
            resolver: Arc::new(FixedAddrResolver(origin_addr)),
            deny_private_ips: false,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: None,
            attribution: None,
        };
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        let mut payload = request_head.into_bytes();
        payload.extend_from_slice(body);
        // A single write: the proxy's BufReader buffers whatever arrives in
        // this one read past the header terminator, which is exactly the
        // body.
        client
            .write_all(&payload)
            .await
            .expect("single write of headers + body");

        let received = tokio::time::timeout(Duration::from_secs(5), origin_rx)
            .await
            .expect("origin must receive forwarded bytes before the timeout")
            .expect("origin sender not dropped");
        let received = String::from_utf8_lossy(&received);
        assert!(
            received.ends_with(std::str::from_utf8(body).unwrap()),
            "expected the body bytes buffered alongside the headers to reach the origin, got: {received:?}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// Same regression as above but for `handle_connect`: a client that
    /// doesn't wait for the `200 Connection Established` reply before
    /// sending its first tunneled bytes (fast/pipelining clients) can have
    /// those bytes land in the same TCP segment as the CONNECT request and
    /// headers, buffered inside the `BufReader` before `into_inner()` runs.
    #[tokio::test]
    async fn connect_forwards_bytes_buffered_alongside_the_connect_request() {
        let eager_bytes: &[u8] = b"eager-client-hello-bytes";
        let expected_len = eager_bytes.len();

        let origin_listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("origin listener binds");
        let origin_addr = origin_listener.local_addr().unwrap();
        let (origin_tx, origin_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = origin_listener.accept().await {
                let mut received = Vec::new();
                let mut buf = [0u8; 4096];
                while received.len() < expected_len {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => received.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = origin_tx.send(received);
            }
        });

        let proxy = EgressAllowlistProxy {
            policy: policy_allowing(&["127.0.0.1"]),
            resolver: Arc::new(FixedAddrResolver(origin_addr)),
            deny_private_ips: false,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: None,
            attribution: None,
        };
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        let mut payload = b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n".to_vec();
        payload.extend_from_slice(eager_bytes);
        // A single write: the client doesn't wait for the 200 before
        // sending, so these bytes are buffered alongside the CONNECT
        // request/headers in the same read.
        client
            .write_all(&payload)
            .await
            .expect("single write of CONNECT request + eager bytes");

        let received = tokio::time::timeout(Duration::from_secs(5), origin_rx)
            .await
            .expect("origin must receive forwarded bytes before the timeout")
            .expect("origin sender not dropped");
        assert_eq!(
            received, eager_bytes,
            "expected the eager bytes buffered alongside the CONNECT request to reach the origin"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// Finding 4 (header caps): a single header line that exceeds
    /// `MAX_HEADER_LINE_BYTES` must be rejected with a clean `413` and the
    /// connection closed, rather than buffered without bound.
    #[tokio::test]
    async fn oversized_single_header_line_is_rejected_with_413() {
        let proxy = EgressAllowlistProxy::new(policy_allowing(&["example.com"]));
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        let oversized_value = "x".repeat(MAX_HEADER_LINE_BYTES + 1);
        let request =
            format!("GET http://example.com/ HTTP/1.1\r\nX-Big: {oversized_value}\r\n\r\n");
        client
            .write_all(request.as_bytes())
            .await
            .expect("write succeeds");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("reads the full response then EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 413"),
            "expected 413 for an oversized header line, got: {response}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// Finding 4 (header caps): more header lines than `MAX_HEADER_LINES`
    /// must be rejected with a `413`, distinct from the per-line and
    /// total-byte caps (each line here is small, and the running total
    /// stays under `MAX_TOTAL_HEADER_BYTES` until the count cap fires).
    #[tokio::test]
    async fn too_many_header_lines_is_rejected_with_413() {
        let proxy = EgressAllowlistProxy::new(policy_allowing(&["example.com"]));
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        let mut request = String::from("GET http://example.com/ HTTP/1.1\r\n");
        for i in 0..=MAX_HEADER_LINES {
            request.push_str(&format!("X-Header-{i}: v\r\n"));
        }
        request.push_str("\r\n");
        client
            .write_all(request.as_bytes())
            .await
            .expect("write succeeds");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("reads the full response then EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 413"),
            "expected 413 for too many header lines, got: {response}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// Finding 4 (header caps): many individually-small header lines whose
    /// SUM crosses `MAX_TOTAL_HEADER_BYTES` must be rejected too — pins the
    /// total-byte cap specifically, distinct from the per-line and
    /// line-count caps (this request stays under both of those).
    #[tokio::test]
    async fn oversized_total_header_bytes_is_rejected_with_413() {
        let proxy = EgressAllowlistProxy::new(policy_allowing(&["example.com"]));
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        // Stop appending as soon as the running total crosses the cap
        // (rather than sending many multiples of it): the server has to
        // read every line to detect the overrun, so a request that's only
        // marginally over the cap leaves ~nothing unread when it closes the
        // connection after the 413 — sending a payload many times the cap
        // size instead leaves a large unread remainder in the kernel's
        // receive buffer at close time, which triggers a TCP RST (a test
        // harness artifact, not the behavior under test) instead of a
        // clean response + EOF.
        let mut request = String::from("GET http://example.com/ HTTP/1.1\r\n");
        let mut total = request.len();
        let line_value = "x".repeat(500);
        let mut i = 0;
        while total <= MAX_TOTAL_HEADER_BYTES {
            let line = format!("X-Header-{i}: {line_value}\r\n");
            total += line.len();
            request.push_str(&line);
            i += 1;
        }
        assert!(
            i < MAX_HEADER_LINES,
            "test setup must cross the total-byte cap before the line-count cap, got {i} lines"
        );
        client
            .write_all(request.as_bytes())
            .await
            .expect("write succeeds");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("reads the full response then EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 413"),
            "expected 413 for oversized total header bytes, got: {response}"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// Finding 4 (connection cap): a connection accepted beyond
    /// `max_connections` must be closed immediately (no response, no
    /// hanging) rather than queued behind the connections holding the
    /// available slots. Uses a small test-only `max_connections` so the
    /// test doesn't need to open 128+ real sockets to exercise the real
    /// production constant.
    #[tokio::test]
    async fn connection_beyond_the_cap_is_closed_immediately() {
        let max_connections = 2;
        let proxy = EgressAllowlistProxy {
            policy: policy_allowing(&["example.com"]),
            resolver: Arc::new(DnsResolver),
            deny_private_ips: true,
            max_connections,
            tls_intercept: None,
            attribution: None,
        };
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        // Open `max_connections` sockets and never send a request: each
        // connection's task blocks inside `read_request_head` waiting for
        // bytes, holding its permit for the duration of this test.
        let mut held = Vec::new();
        for _ in 0..max_connections {
            held.push(
                TcpStream::connect(proxy_addr)
                    .await
                    .expect("client connects to the proxy"),
            );
        }
        // Give the accept loop a moment to actually spawn+acquire for each
        // of the held connections before probing the cap.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut rejected = TcpStream::connect(proxy_addr)
            .await
            .expect("client connects to the proxy");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), rejected.read_to_end(&mut response))
            .await
            .expect("a connection beyond the cap must close promptly, not hang queued")
            .expect("reading to EOF succeeds");
        assert!(
            response.is_empty(),
            "a connection beyond the cap must be closed without any proxy response, got: {:?}",
            String::from_utf8_lossy(&response)
        );

        drop(held);
        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// W6 phase 1, end to end through the real proxy: a CONNECT to a host
    /// named in the proxy's `TlsInterceptConfig` allowlist gets its TLS
    /// terminated with a leaf certificate chaining to OUR CA (proven by a
    /// real rustls client trusting only that CA's root completing the
    /// handshake), and the decrypted bytes still reach a fake origin and
    /// echo back — the same round-trip proof `tls_intercept`'s own unit
    /// test gives the seam directly, driven here through
    /// `EgressAllowlistProxy::serve`/`handle_connection`/`handle_connect`'s
    /// actual CONNECT dispatch rather than calling `terminate_and_forward`
    /// directly.
    #[tokio::test]
    async fn connect_to_bound_host_through_the_real_proxy_terminates_tls_with_our_ca() {
        use super::super::ca::SandboxCertificateAuthority;
        use super::super::tls_intercept::{
            TlsInterceptConfig, VerifiedOriginConnector, build_server_config,
        };
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let host = "bound.example.com";

        // Fake origin: its own CA, unrelated to the one under test.
        let origin_ca = SandboxCertificateAuthority::generate().unwrap();
        let origin_issued = origin_ca.issue_leaf_for_host(host).unwrap();
        let origin_server_config = build_server_config(&origin_issued.certificate).unwrap();
        let origin_acceptor = TlsAcceptor::from(Arc::new(origin_server_config));
        let origin_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = origin_listener.accept().await
                && let Ok(mut tls) = origin_acceptor.accept(stream).await
            {
                let mut buf = [0u8; 256];
                if let Ok(n) = tls.read(&mut buf).await {
                    let _ = tls.write_all(&buf[..n]).await;
                }
            }
        });

        // The proxy's own CA — this is the one the "container" client must
        // see, not `origin_ca`'s.
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let our_root_pem = ca.root_certificate_pem().to_string();
        let mut origin_trust = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut origin_ca.root_certificate_pem().as_bytes()) {
            origin_trust.add(cert.unwrap()).unwrap();
        }
        let origin_connector = VerifiedOriginConnector::for_test(TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(origin_trust)
                .with_no_client_auth(),
        )));
        let tls_intercept = Arc::new(TlsInterceptConfig::new(
            ca,
            std::collections::HashSet::from([host.to_string()]),
            origin_connector,
        ));

        let proxy = EgressAllowlistProxy {
            policy: policy_allowing(&[host]),
            resolver: Arc::new(FixedAddrResolver(origin_addr)),
            deny_private_ips: false,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: Some(tls_intercept),
            attribution: None,
        };
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut raw_client = TcpStream::connect(proxy_addr).await.unwrap();
        raw_client
            .write_all(format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = [0u8; 128];
        let n = raw_client.read(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 200"));

        let mut our_trust = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut our_root_pem.as_bytes()) {
            our_trust.add(cert.unwrap()).unwrap();
        }
        let client_connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(our_trust)
                .with_no_client_auth(),
        ));
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
        let mut client_tls = tokio::time::timeout(
            Duration::from_secs(5),
            client_connector.connect(server_name, raw_client),
        )
        .await
        .expect("handshake must not hang")
        .expect("client tls handshake must succeed against our proxy's ca-issued leaf");

        client_tls
            .write_all(b"hello through the proxy's intercept")
            .await
            .unwrap();
        let mut echoed = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), client_tls.read(&mut echoed))
            .await
            .expect("read must not hang")
            .expect("reads the echoed bytes back");
        assert_eq!(&echoed[..n], b"hello through the proxy's intercept");

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// D1, driven through the real proxy: a `TlsInterceptConfig` exists
    /// (CA and all), but the CONNECT target isn't in its bound-host set —
    /// the connection must stay a plain, unintercepted tunnel (bytes arrive
    /// at the origin in the clear, exactly like `connect_to_allowed_host_
    /// tunnels_bytes` above), and the CA must never have minted a leaf for
    /// it. This is the case that actually matters for D1: it is not enough
    /// that TLS interception is *possible* — an unbound host must never
    /// trigger it even when the mechanism is fully wired and live.
    #[tokio::test]
    async fn connect_to_unbound_host_stays_opaque_even_with_tls_intercept_configured() {
        use super::super::ca::SandboxCertificateAuthority;
        use super::super::tls_intercept::{TlsInterceptConfig, VerifiedOriginConnector};
        use tokio_rustls::TlsConnector;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let echo_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = echo_listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = socket.read(&mut buf).await {
                    let _ = socket.write_all(&buf[..n]).await;
                }
            }
        });

        let ca = SandboxCertificateAuthority::generate().unwrap();
        // Deliberately never trusted by any client in this test — proves
        // the connector isn't even reachable for an unbound host, not just
        // unused by convention.
        let origin_connector = VerifiedOriginConnector::for_test(TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )));
        let tls_intercept = Arc::new(TlsInterceptConfig::new(
            ca,
            std::collections::HashSet::from(["some-other-bound-host.example.com".to_string()]),
            origin_connector,
        ));

        let proxy = EgressAllowlistProxy {
            policy: policy_allowing(&["127.0.0.1"]),
            resolver: Arc::new(FixedAddrResolver(echo_addr)),
            deny_private_ips: false,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: Some(Arc::clone(&tls_intercept)),
            attribution: None,
        };
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0u8; 128];
        let n = client.read(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 200"));

        client
            .write_all(b"plaintext through the tunnel")
            .await
            .unwrap();
        let mut echoed = [0u8; 64];
        let n = client.read(&mut echoed).await.unwrap();
        assert_eq!(
            &echoed[..n],
            b"plaintext through the tunnel",
            "an unbound host must stay a plain opaque tunnel even when tls_intercept is configured"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;

        // D1's other half: the CA behind this proxy's `TlsInterceptConfig`
        // must never have minted a leaf certificate for the unbound host —
        // checked against the cache count, not just that plaintext flowed.
        assert_eq!(
            tls_intercept.cached_leaf_count(),
            0,
            "an unbound host must never cause a leaf certificate to be minted"
        );
    }

    /// The divergence this PR fixes, driven through the real proxy exactly
    /// like `connect_to_unbound_host_stays_opaque_even_with_tls_intercept_
    /// configured` above: `host_allowed` (`egress_proxy.rs`) strips a
    /// trailing root-zone dot before comparing against the policy, but
    /// `TlsInterceptConfig`'s bound-hosts lookup did not, so `pypi.org.` (a
    /// legal, equivalently-resolving FQDN) passed the allowlist as
    /// `pypi.org` and then silently missed the bound-hosts set that still
    /// held the dot-free form — falling through to an opaque,
    /// un-intercepted tunnel for a host the policy meant to terminate TLS
    /// for and swap credentials on. `interception_bound_hosts` now derives
    /// `bound_hosts` from the real allowlist in production (see its doc),
    /// so this divergence would be live for any exact-match allowlisted
    /// host reached with a trailing root-zone dot. This test connects to a
    /// bound host WITH a trailing dot and asserts a leaf was actually
    /// minted for it — i.e. that interception fired — not merely that the
    /// CONNECT was allowed.
    #[tokio::test]
    async fn connect_with_trailing_dot_still_intercepts_a_bound_host() {
        use super::super::ca::SandboxCertificateAuthority;
        use super::super::tls_intercept::{TlsInterceptConfig, VerifiedOriginConnector};
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let bound_host = "bound.example.com";

        // A real listener that is NOT a TLS server: if the connection stays
        // an opaque plaintext tunnel (the bug), the client's TLS
        // ClientHello bytes just get echoed straight back. If TLS
        // termination correctly fires instead, the proxy's own TLS acceptor
        // answers with a ServerHello/leaf cert (minted just before), which
        // this untrusting client will reject.
        let echo_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = echo_listener.accept().await {
                let mut buf = [0u8; 256];
                if let Ok(n) = socket.read(&mut buf).await {
                    let _ = socket.write_all(&buf[..n]).await;
                }
            }
        });

        let ca = SandboxCertificateAuthority::generate().unwrap();
        let origin_connector = VerifiedOriginConnector::for_test(TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )));
        let tls_intercept = Arc::new(TlsInterceptConfig::new(
            ca,
            std::collections::HashSet::from([bound_host.to_string()]),
            origin_connector,
        ));

        let proxy = EgressAllowlistProxy {
            policy: policy_allowing(&[bound_host]),
            resolver: Arc::new(FixedAddrResolver(echo_addr)),
            deny_private_ips: false,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: Some(Arc::clone(&tls_intercept)),
            attribution: None,
        };
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let mut raw_client = TcpStream::connect(proxy_addr).await.unwrap();
        raw_client
            .write_all(format!("CONNECT {bound_host}.:443 HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = [0u8; 128];
        let n = raw_client.read(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 200"),
            "a trailing dot must not change the allowlist decision itself"
        );

        // Force the connection-handling task forward to (and past) the leaf
        // mint step, regardless of which branch it actually took.
        let untrusting_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(untrusting_client_config));
        let server_name = ServerName::try_from(bound_host.to_string()).unwrap();
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            connector.connect(server_name, raw_client),
        )
        .await;

        assert_eq!(
            tls_intercept.cached_leaf_count(),
            1,
            "a trailing-dot CONNECT to a bound host must still be intercepted (leaf minted), \
             not silently fall through to an opaque tunnel"
        );

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
    }

    /// Host-casing normalization: `is_bound`/`host_allowed` already fold case
    /// (`TlsInterceptConfig::new` lowercases its allowlist; `host_allowed`
    /// lowercases the incoming host), but `handle_connect` used to pass the
    /// CONNECT target's *original* casing straight into
    /// `terminate_and_forward` -> `SandboxCertificateAuthority::
    /// issue_leaf_for_host`, whose cache is keyed on the exact string. Two
    /// CONNECTs for the same effective host that merely differ in case (a
    /// real client behavior — DNS hostnames are case-insensitive) minted and
    /// cached TWO leaves for one host. `handle_connect` must normalize the
    /// host to one canonical case ONCE, before it flows to the allowlist
    /// check, the cert mint, and the origin SNI, so both CONNECTs land on the
    /// same cache entry.
    #[tokio::test]
    async fn different_cased_connects_for_the_same_host_cache_one_leaf_not_two() {
        use super::super::ca::SandboxCertificateAuthority;
        use super::super::tls_intercept::{TlsInterceptConfig, VerifiedOriginConnector};
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let bound_host = "bound.example.com";

        let ca = SandboxCertificateAuthority::generate().unwrap();
        // Trusts nothing: every client-side handshake attempt below fails
        // certificate verification. That failure is exactly the
        // synchronization this test needs — it can only happen after the
        // server side has already minted (and served) a leaf for that
        // CONNECT's host, so awaiting it proves the mint already ran.
        let origin_connector = VerifiedOriginConnector::for_test(TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )));
        let tls_intercept = Arc::new(TlsInterceptConfig::new(
            ca,
            std::collections::HashSet::from([bound_host.to_string()]),
            origin_connector,
        ));

        let proxy = EgressAllowlistProxy {
            policy: policy_allowing(&[bound_host]),
            // Never actually dialed: the client-side handshake below fails
            // before `terminate_and_forward` gets far enough to dial the
            // origin, so this address just needs to parse.
            resolver: Arc::new(FixedAddrResolver("127.0.0.1:1".parse().unwrap())),
            deny_private_ips: false,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: Some(Arc::clone(&tls_intercept)),
            attribution: None,
        };
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        let untrusting_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        for cased_host in ["Bound.Example.Com", "bound.example.com"] {
            let mut raw_client = TcpStream::connect(proxy_addr).await.unwrap();
            raw_client
                .write_all(format!("CONNECT {cased_host}:443 HTTP/1.1\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = [0u8; 128];
            let n = raw_client.read(&mut response).await.unwrap();
            assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 200"));

            let connector = TlsConnector::from(Arc::new(untrusting_client_config.clone()));
            let server_name = ServerName::try_from(cased_host.to_string()).unwrap();
            let handshake = tokio::time::timeout(
                Duration::from_secs(5),
                connector.connect(server_name, raw_client),
            )
            .await
            .expect("handshake attempt must not hang");
            assert!(
                handshake.is_err(),
                "client trusts nothing, so the handshake must fail verification \
                 (proving the server already minted a leaf before this point)"
            );
        }

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;

        assert_eq!(
            tls_intercept.cached_leaf_count(),
            1,
            "two different-cased CONNECTs for the same effective host must share ONE \
             cached leaf, not mint/cache a separate one per casing"
        );
    }

    // --- W8 step 1: connection attribution reaches the credential firewall ---
    //
    // The tests below drive the FULL accept -> resolve -> authorize path
    // (never call the attribution resolver or the firewall directly) so they
    // actually prove the proxy's dispatch is wired, not merely that the
    // resolver/firewall work in isolation — a resolver-only test would pass
    // even if the proxy never called it, which is the exact defect this pins.
    //
    // Both tests connect from the loopback client the proxy bind already
    // uses (`peer_addr.ip()` is always `127.0.0.1` here — binding a second
    // loopback alias address is not available in every sandboxed test
    // environment), so the fake `NetworkContainerLookup` distinguishes
    // "attributed" from "unattributed" by what it reports at that one IP,
    // not by using a different IP per case.

    /// A [`attribution::NetworkContainerLookup`] double that returns a fixed,
    /// pre-programmed container list — lets these tests drive
    /// [`attribution::ConnectionAttributionResolver`] without a Docker
    /// daemon. Mirrors `attribution`'s own private `FakeLookup` test double
    /// (not reusable across modules: it is declared inside that module's
    /// `#[cfg(test)]` block).
    struct FakeNetworkLookup {
        containers: Vec<bollard::models::ContainerSummary>,
    }

    #[async_trait]
    impl attribution::NetworkContainerLookup for FakeNetworkLookup {
        async fn containers_on_network(
            &self,
            _network: &str,
        ) -> Result<Vec<bollard::models::ContainerSummary>, crate::RuntimeProcessError> {
            Ok(self.containers.clone())
        }
    }

    const ATTRIBUTION_TEST_NETWORK: &str = "ironclaw-test-egress-attribution";
    const ATTRIBUTION_TEST_LABEL_PREFIX: &str = "ironclaw";

    fn container_with_ip_and_labels(
        ip: &str,
        tenant: &str,
        user: &str,
    ) -> bollard::models::ContainerSummary {
        use bollard::models::{ContainerSummaryNetworkSettings, EndpointSettings};
        let networks = std::collections::HashMap::from([(
            ATTRIBUTION_TEST_NETWORK.to_string(),
            EndpointSettings {
                ip_address: Some(ip.to_string()),
                ..Default::default()
            },
        )]);
        let labels = std::collections::HashMap::from([
            (
                registry::label_tenant(ATTRIBUTION_TEST_LABEL_PREFIX),
                tenant.to_string(),
            ),
            (
                registry::label_user(ATTRIBUTION_TEST_LABEL_PREFIX),
                user.to_string(),
            ),
        ]);
        bollard::models::ContainerSummary {
            id: Some("fake-container".to_string()),
            labels: Some(labels),
            network_settings: Some(ContainerSummaryNetworkSettings {
                networks: Some(networks),
            }),
            ..Default::default()
        }
    }

    /// Shared harness for the two tests below: a bound host, a fake origin
    /// echo server, and a proxy wired with TLS interception AND W6 phase 2's
    /// credential swap (a registry + firewall + empty injection store — no
    /// grant is ever staged, so both tests only exercise attribution, never
    /// GRANT-DENIAL vs. GRANT). Returns the running proxy plus the minted
    /// placeholder token so the caller can build the request head.
    async fn attribution_test_harness(
        attribution: Option<Arc<dyn attribution::ResolveAttribution>>,
    ) -> (
        SocketAddr,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
        String,
        &'static str,
        InvocationId,
    ) {
        use super::super::ca::SandboxCertificateAuthority;
        use super::super::tls_intercept::{TlsInterceptConfig, VerifiedOriginConnector};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let host = "attribution.bound.example.com";

        let origin_ca = SandboxCertificateAuthority::generate().unwrap();
        let origin_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        drop(origin_listener);

        let ca = SandboxCertificateAuthority::generate().unwrap();
        let mut origin_trust = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut origin_ca.root_certificate_pem().as_bytes()) {
            origin_trust.add(cert.unwrap()).unwrap();
        }
        let origin_connector =
            VerifiedOriginConnector::for_test(tokio_rustls::TlsConnector::from(Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(origin_trust)
                    .with_no_client_auth(),
            )));

        let tenant = TenantId::new("attribution-tenant").unwrap();
        let user = UserId::new("attribution-user").unwrap();
        let provider = ExtensionId::new("attribution-provider").unwrap();
        let capability_id = CapabilityId::new("sandbox.shell").unwrap();
        let secret_handle = SecretHandle::new("attribution-token").unwrap();
        let scope = ResourceScope {
            tenant_id: tenant,
            user_id: user,
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        };
        let credential_runtime = SandboxCredentialRuntime::new();
        let token = credential_runtime
            .placeholder_for(&scope, &provider)
            .expect("placeholder mints");
        credential_runtime
            .secret_injection_store()
            .insert(
                &scope,
                &capability_id,
                &secret_handle,
                SecretMaterial::from("host-side-attribution-secret"),
            )
            .expect("secret material stages");
        credential_runtime.open_static_window(
            &scope,
            &capability_id,
            vec![SandboxStaticCredentialGrant {
                provider_or_extension_id: provider,
                secret_handle,
                allowed_targets: vec![CredentialTargetPolicy {
                    scheme: "https".to_string(),
                    host: host.to_string(),
                    port: None,
                    path: CredentialPathPolicy::Prefix("/".to_string()),
                    methods: vec![NetworkMethod::Get],
                }],
            }],
            Duration::from_secs(60),
        );
        credential_runtime
            .attach_http_egress(Arc::new(AttributionHostEgress))
            .map_err(|_| "host egress was already attached")
            .expect("host egress attaches");
        let credential_swap = credential_runtime.credential_swap();
        let tls_intercept = Arc::new(
            TlsInterceptConfig::new(
                ca,
                std::collections::HashSet::from([host.to_string()]),
                origin_connector,
            )
            .with_credential_swap(credential_swap),
        );

        let mut proxy = EgressAllowlistProxy {
            policy: policy_allowing(&[host]),
            resolver: Arc::new(FixedAddrResolver(origin_addr)),
            deny_private_ips: false,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: Some(tls_intercept),
            attribution: None,
        };
        if let Some(attribution) = attribution {
            proxy = proxy.with_attribution_resolver(attribution);
        }
        let bound = proxy.bind("127.0.0.1:0").await.expect("proxy binds");
        let proxy_addr = bound.local_addr();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let serve_handle = tokio::spawn(bound.serve(shutdown_rx));

        (
            proxy_addr,
            shutdown_tx,
            serve_handle,
            token.as_str().to_string(),
            host,
            scope.invocation_id,
        )
    }

    /// CONNECTs to the bound host through the real proxy, over TLS, and
    /// returns whatever bytes the origin echoed back within a short window —
    /// empty if the connection was closed before (or without) reaching the
    /// origin. `token` is embedded in an `Authorization` header so the
    /// credential swap's `resolvable_candidates` actually finds a
    /// registry-resolvable placeholder and calls `SandboxCredentialFirewall::
    /// authorize` — a request with no placeholder never consults attribution
    /// at all (see `rewrite_request_head`'s doc), so it would prove nothing
    /// here.
    async fn drive_placeholder_request(
        proxy_addr: SocketAddr,
        host: &str,
        token: &str,
        invocation_id: InvocationId,
    ) -> Vec<u8> {
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let mut raw_client = TcpStream::connect(proxy_addr).await.unwrap();
        let proxy_identity =
            base64::engine::general_purpose::STANDARD.encode(format!("{invocation_id}:"));
        raw_client
            .write_all(
                format!(
                    "CONNECT {host}:443 HTTP/1.1\r\nProxy-Authorization: Basic {proxy_identity}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = [0u8; 128];
        let n = raw_client.read(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 200"));

        // Trust nothing real — this test only cares whether bytes flow, not
        // whether the client validates the leaf, so skip cert verification
        // entirely via a permissive `ServerCertVerifier` rather than pulling
        // in the proxy's minted CA root.
        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from(host.to_string()).unwrap();
        let mut client_tls = tokio::time::timeout(
            Duration::from_secs(5),
            connector.connect(server_name, raw_client),
        )
        .await
        .expect("client tls handshake must not hang")
        .expect("client tls handshake succeeds against the proxy's minted leaf");

        let request =
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n\r\n");
        client_tls.write_all(request.as_bytes()).await.unwrap();

        let mut received = Vec::new();
        let _ = tokio::time::timeout(
            Duration::from_millis(500),
            client_tls.read_to_end(&mut received),
        )
        .await;
        received
    }

    /// Permissive `rustls` server-cert verifier for
    /// `drive_placeholder_request` — these tests assert on whether the
    /// request reached the origin, not on leaf-certificate trust (already
    /// covered by the other tests in this module).
    #[derive(Debug)]
    struct NoVerify;

    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// THE FIX'S PROOF, positive case: a connecting peer that a real
    /// `ConnectionAttributionResolver` (backed here by a fake
    /// `NetworkContainerLookup`, no Docker needed) can attribute to a known
    /// `{tenant, user}` reaches `SandboxCredentialFirewall::authorize` with
    /// the matching invocation identity — proven by the granted request
    /// reaching canonical host HTTP egress and returning its sanitized
    /// response. The direct-origin socket remains closed. Before the
    /// accept-loop peer-address wiring, this
    /// proxy could never construct anything but `identity: None`, so this
    /// assertion is exactly the one a pre-fix build fails — see this
    /// function's `PLANTED-RED` sibling assertion in the module's manual
    /// verification, not a separate test (planting is done by hand against
    /// this same test, per the task's proof requirement).
    #[tokio::test]
    async fn attributed_peer_reaches_the_credential_firewall_and_is_forwarded() {
        let fake_lookup = FakeNetworkLookup {
            containers: vec![container_with_ip_and_labels(
                "127.0.0.1",
                "attribution-tenant",
                "attribution-user",
            )],
        };
        let resolver: Arc<dyn attribution::ResolveAttribution> =
            Arc::new(attribution::ConnectionAttributionResolver::with_lookup(
                fake_lookup,
                ATTRIBUTION_TEST_NETWORK,
                ATTRIBUTION_TEST_LABEL_PREFIX,
            ));

        let (proxy_addr, shutdown_tx, serve_handle, token, host, invocation_id) =
            attribution_test_harness(Some(resolver)).await;

        let received = drive_placeholder_request(proxy_addr, host, &token, invocation_id).await;

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;

        assert!(
            received.ends_with(b"origin saw the request\n"),
            "an attributed peer's granted placeholder request must reach host HTTP egress; \
             an empty response means the complete tenant/user/invocation identity never \
             reached the firewall; response={received:?}"
        );
    }

    /// THE FIX'S PROOF, negative case: a connecting peer the resolver cannot
    /// attribute (no container reports this IP on the egress network) must
    /// be a CONNECTION-DENIAL — the connection closes before the origin is
    /// ever dialed, never a forward without credentials and never a guess.
    /// Uses the SAME harness and the SAME placeholder-bearing request as the
    /// positive case above; only the fake lookup's contents differ (empty —
    /// no container anywhere claims this peer's IP).
    #[tokio::test]
    async fn unattributable_peer_is_denied_not_forwarded() {
        let fake_lookup = FakeNetworkLookup { containers: vec![] };
        let resolver: Arc<dyn attribution::ResolveAttribution> =
            Arc::new(attribution::ConnectionAttributionResolver::with_lookup(
                fake_lookup,
                ATTRIBUTION_TEST_NETWORK,
                ATTRIBUTION_TEST_LABEL_PREFIX,
            ));

        let (proxy_addr, shutdown_tx, serve_handle, token, host, invocation_id) =
            attribution_test_harness(Some(resolver)).await;

        let received = drive_placeholder_request(proxy_addr, host, &token, invocation_id).await;

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;

        assert!(
            received.is_empty(),
            "an unattributable peer's placeholder-bearing request must never reach the \
             origin — got {received:?}, which means the connection was forwarded instead \
             of denied"
        );
    }

    /// Same negative outcome as `unattributable_peer_is_denied_not_forwarded`,
    /// but for the OTHER shape of "no resolver wired into the proxy" (an
    /// explicit `None`, e.g. today's non-Docker test/dev proxies) rather
    /// than a resolver that looked and found nothing — pins that both
    /// collapse to the same fail-closed `identity: None` path, never a
    /// silent fallback to "forward anyway."
    #[tokio::test]
    async fn no_attribution_resolver_wired_is_also_denied_not_forwarded() {
        let (proxy_addr, shutdown_tx, serve_handle, token, host, invocation_id) =
            attribution_test_harness(None).await;

        let received = drive_placeholder_request(proxy_addr, host, &token, invocation_id).await;

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;

        assert!(
            received.is_empty(),
            "a proxy with no attribution resolver wired must deny a placeholder-bearing \
             request, not forward it — got {received:?}"
        );
    }
}
