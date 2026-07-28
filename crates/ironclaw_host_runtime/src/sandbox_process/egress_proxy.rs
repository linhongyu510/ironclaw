//! Egress allowlist CONNECT/forward proxy core for the sandboxed shell
//! profile.
//!
//! Enforces [`sandbox_network_policy`](super::network_allowlist::sandbox_network_policy)
//! for real: a sandboxed container's `http_proxy`/`https_proxy` env is
//! pointed at a bound instance of this proxy (see
//! `crates/ironclaw_reborn_composition/src/sandbox_boot.rs`), and every
//! outbound `CONNECT` (HTTPS tunnel) or plain absolute-URI HTTP request the
//! container makes is checked against the policy's `allowed_targets` before
//! any bytes reach the origin.
//!
//! This module is deliberately Docker-agnostic and scheduling-agnostic: it
//! only knows how to bind a `TcpListener` and serve connections against it.
//! Composition (`ironclaw_reborn_composition::sandbox_egress_proxy_task`)
//! connects this core to a real bind address, spawns it, and owns its
//! cancellation — mirroring the `SandboxReaper` core/spawn split.
//!
//! Never logs request/response bodies or full URIs (only the host being
//! allowed/denied, at `debug` level) — secret material in query strings or
//! headers must never reach the logs.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_host_api::NetworkPolicy;
use ironclaw_network::network_denies_resolved_ip;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

use super::tls_intercept::{self, TlsInterceptConfig};

/// Hard ceiling on concurrent client connections the proxy will service at
/// once. The proxy binds `0.0.0.0` on the internal egress network and is
/// reachable from *inside* the sandboxed container — treat that container as
/// potentially adversarial (prompt injection or hostile code running there
/// is in-scope for this design) and never let it force unbounded task/socket
/// growth on the host by opening connections faster than they drain.
/// Deliberately generous for legitimate concurrent tool use (parallel
/// `curl`s, package installs, etc.) while still being a real ceiling.
const MAX_CONCURRENT_CONNECTIONS: usize = 128;

/// Hard ceiling on a single request-line/header line's byte length. Real
/// HTTP headers are a few hundred bytes at most; this only exists to stop an
/// adversarial or buggy client inside the sandbox from making
/// [`read_request_head`] buffer an unbounded line.
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;

/// Hard ceiling on the sum of header bytes (request line plus every header
/// line) for one request — bounds total allocation even across many lines
/// that each individually stay under [`MAX_HEADER_LINE_BYTES`].
const MAX_TOTAL_HEADER_BYTES: usize = 32 * 1024;

/// Hard ceiling on header line COUNT — bounds allocation (one `String` per
/// line, in [`RequestHead::header_lines`]) from many small lines that would
/// each individually pass both byte caps above.
const MAX_HEADER_LINES: usize = 200;

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

/// Returns a fixed audit label if `ip` is private, loopback, link-local, or
/// otherwise reserved, per `ironclaw_network`'s canonical range check —
/// delegated to via [`network_denies_resolved_ip`] rather than
/// re-implemented here. This proxy previously hand-rolled its own range
/// list and it had already drifted behind that canonical check, missing
/// `0.0.0.0/8`, IPv6 link-local `fe80::/10`, and the `fc00::/7` half of the
/// RFC 4193 unique-local range. The canonical check also unwraps
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to their v4 form itself,
/// and additionally denies broadcast/multicast/documentation addresses — a
/// strictly larger deny set, which is fine for an egress guard. The label
/// collapses every reason to one generic string rather than re-deriving a
/// granular one: the canonical check only returns `bool`, and a second,
/// independently-maintained granular reason table would recreate exactly
/// the kind of drift-prone duplication this delegation removes.
fn denied_ip_reason(ip: IpAddr) -> Option<&'static str> {
    network_denies_resolved_ip(ip).then_some("private_or_reserved_ip")
}

/// Resolves `host:port` and applies the dial-time private-IP guard when
/// `deny_private_ips` is set. Returns the first candidate address that
/// passes the guard (or the first candidate at all, when the guard is
/// disabled) as the `Ok` half; a guard rejection is the `Err` half, carrying
/// the matched rule for the audit log. `deny_private_ips` is only ever
/// turned off by test fixtures standing a loopback echo server in for a
/// real origin (see the byte-plumbing test below) — production callers
/// always pass `true`.
async fn resolve_dial_addr(
    resolver: &dyn HostResolver,
    host: &str,
    port: u16,
    deny_private_ips: bool,
) -> std::io::Result<Result<SocketAddr, &'static str>> {
    let addrs = resolver.resolve(host, port).await?;
    if !deny_private_ips {
        return Ok(addrs.into_iter().next().ok_or("no addresses resolved"));
    }
    match addrs
        .iter()
        .find(|addr| denied_ip_reason(addr.ip()).is_none())
    {
        Some(addr) => Ok(Ok(*addr)),
        None => {
            let reason = addrs
                .first()
                .and_then(|addr| denied_ip_reason(addr.ip()))
                .unwrap_or("no addresses resolved");
            Ok(Err(reason))
        }
    }
}

/// Errors [`EgressAllowlistProxy::bind`] can return. Deliberately minimal —
/// per-connection failures never propagate up through `serve`, they are
/// logged at `debug` and the connection is dropped.
#[derive(Debug, thiserror::Error)]
pub enum EgressProxyError {
    #[error("failed to bind egress proxy listener: {reason}")]
    BindFailed { reason: String },
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
    /// W6 phase 1's TLS-termination seam (see `tls_intercept`'s module
    /// doc). Always `None` in production (`new`) — nothing in this crate
    /// constructs a [`TlsInterceptConfig`] yet, so every CONNECT stays an
    /// opaque tunnel until a production caller wires one in. Only this
    /// module's own tests set it, via the struct-literal construction
    /// pattern the other test-only fields above already use.
    tls_intercept: Option<Arc<TlsInterceptConfig>>,
}

impl EgressAllowlistProxy {
    pub fn new(policy: NetworkPolicy) -> Self {
        Self {
            policy,
            resolver: Arc::new(DnsResolver),
            deny_private_ips: true,
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            tls_intercept: None,
        }
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
        })
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
                        Ok((stream, _peer_addr)) => {
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
                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(error) = handle_connection(
                                    stream,
                                    policy,
                                    resolver,
                                    deny_private_ips,
                                    tls_intercept,
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

/// Host-only match: exact hostname, or a `*.suffix` glob — the same shape
/// `sandbox_extra_allowed_domains` already accepts. Ports and scheme in
/// [`ironclaw_host_api::NetworkTargetPattern`] are ignored here (the proxy
/// allowlists by host, consistent with `sandbox_network_policy()`'s
/// `port: None` targets).
fn host_allowed(host: &str, policy: &NetworkPolicy) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    policy.allowed_targets.iter().any(|target| {
        let pattern = target.host_pattern.to_ascii_lowercase();
        if pattern == "*" {
            return true;
        }
        match pattern.strip_prefix("*.") {
            Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
            None => host == pattern,
        }
    })
}

/// One HTTP request line plus its headers, as read off the client socket.
struct RequestHead {
    method: String,
    target: String,
    /// Raw header lines exactly as read (each still ending in `\r\n`),
    /// forwarded verbatim on the allow path.
    header_lines: Vec<String>,
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

/// Writes a `403 Forbidden` response naming `host` as the denied target.
/// The proxy then closes the connection (dropping `stream` after this call
/// sends the TCP FIN) — no tunnel/forward ever opens for a denied host.
async fn write_denied_response<W>(stream: &mut W, host: &str) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let body = format!("egress denied: host not in allowlist: {host}");
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

async fn handle_connection(
    stream: TcpStream,
    policy: Arc<NetworkPolicy>,
    resolver: Arc<dyn HostResolver>,
    deny_private_ips: bool,
    tls_intercept: Option<Arc<TlsInterceptConfig>>,
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
            tls_intercept.as_deref(),
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
/// tunnel below). `tls_intercept` is `None` in every production path today
/// (see [`EgressAllowlistProxy::new`]), so this split is a no-op in
/// production until something wires a [`TlsInterceptConfig`] in — every host
/// takes the unbound branch, exactly as before this phase.
async fn handle_connect(
    mut client: BufReader<TcpStream>,
    target: &str,
    policy: &NetworkPolicy,
    resolver: &dyn HostResolver,
    deny_private_ips: bool,
    tls_intercept: Option<&TlsInterceptConfig>,
) -> std::io::Result<()> {
    // Single normalization point: DNS hostnames are case-insensitive, and
    // every downstream use of `host` in this function treats it that way
    // (`host_allowed` and `TlsInterceptConfig::is_bound` already lowercase
    // their own side of the comparison). Fold it ONCE here so the exact same
    // string flows into the allowlist check, `resolve_dial_addr`, the bound
    // check, and — the one that actually needs this, since its cache is
    // keyed on the literal string — `terminate_and_forward`'s cert mint and
    // the origin `ServerName`. Without this, two different-cased CONNECTs for
    // the same effective host would mint and cache two leaf certificates
    // instead of sharing one.
    let host = target
        .rsplit_once(':')
        .map_or(target, |(host, _port)| host)
        .to_ascii_lowercase();
    let host = host.as_str();
    let port: Option<u16> = target
        .rsplit_once(':')
        .and_then(|(_host, port)| port.parse().ok());

    if !host_allowed(host, policy) {
        tracing::debug!(
            host,
            action = "deny",
            rule = "not_in_allowlist",
            "egress proxy: CONNECT denied"
        );
        write_denied_response(&mut client, host).await?;
        return Ok(());
    }

    let Some(port) = port else {
        tracing::debug!(
            host,
            action = "deny",
            rule = "malformed_connect_target",
            "egress proxy: CONNECT denied"
        );
        write_denied_response(&mut client, host).await?;
        return Ok(());
    };

    if port != 443 {
        tracing::debug!(
            host,
            port,
            action = "deny",
            rule = "connect_port_not_443",
            "egress proxy: CONNECT denied"
        );
        write_denied_response(&mut client, host).await?;
        return Ok(());
    }

    let dial_addr = match resolve_dial_addr(resolver, host, port, deny_private_ips).await {
        Ok(Ok(addr)) => addr,
        Ok(Err(rule)) => {
            tracing::debug!(host, action = "deny", rule, "egress proxy: CONNECT denied");
            write_denied_response(&mut client, host).await?;
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
    // `tls_intercept`'s module doc. `filter` means a `tls_intercept: Some`
    // config whose allowlist doesn't name this host takes the unbound path
    // below exactly like `tls_intercept: None` would — D1 has no partial
    // state between "bound" and "unbound."
    if let Some(config) = tls_intercept.filter(|config| config.is_bound(host)) {
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
        if let Err(error) =
            tls_intercept::terminate_and_forward(raw_client, leftover, host, dial_addr, config)
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
    let parsed = url::Url::parse(&head.target).ok();
    let host_only = parsed.as_ref().and_then(|url| url.host_str());
    let Some(host_only) = host_only else {
        // Not a well-formed absolute-URI proxy request; nothing to
        // allowlist-check against, so deny rather than forward blind.
        write_denied_response(&mut client, &head.target).await?;
        return Ok(());
    };
    let host_only = host_only.to_string();
    let port = parsed
        .as_ref()
        .and_then(|url| url.port_or_known_default())
        .unwrap_or(80);

    if !host_allowed(&host_only, policy) {
        tracing::debug!(host = %host_only, action = "deny", rule = "not_in_allowlist", "egress proxy: plain HTTP denied");
        write_denied_response(&mut client, &host_only).await?;
        return Ok(());
    }

    if port != 80 {
        tracing::debug!(
            host = %host_only,
            port,
            action = "deny",
            rule = "plain_http_port_not_80",
            "egress proxy: plain HTTP denied"
        );
        write_denied_response(&mut client, &host_only).await?;
        return Ok(());
    }

    let dial_addr = match resolve_dial_addr(resolver, &host_only, port, deny_private_ips).await {
        Ok(Ok(addr)) => addr,
        Ok(Err(rule)) => {
            tracing::debug!(host = %host_only, action = "deny", rule, "egress proxy: plain HTTP denied");
            write_denied_response(&mut client, &host_only).await?;
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
    let mut request_head = format!("{} {} HTTP/1.1\r\n", head.method, head.target);
    for header_line in &head.header_lines {
        request_head.push_str(header_line);
    }
    request_head.push_str("\r\n");
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

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_host_api::NetworkTargetPattern;
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

        let _ = shutdown_tx.send(true);
        let _ = serve_handle.await;
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
        use super::super::tls_intercept::{TlsInterceptConfig, build_server_config};
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
        let origin_connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(origin_trust)
                .with_no_client_auth(),
        ));
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
        use super::super::tls_intercept::TlsInterceptConfig;
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
        let origin_connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        ));
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
        use super::super::tls_intercept::TlsInterceptConfig;
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
        let origin_connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        ));
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
}
