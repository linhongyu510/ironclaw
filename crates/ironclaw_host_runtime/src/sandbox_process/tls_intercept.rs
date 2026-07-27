//! TLS termination seam for the sandbox egress proxy — W6 phase 1 (design
//! doc `docs/plans/2026-07-26-sandbox-credential-firewall-design.md` §4,
//! §3.4, §3.5).
//!
//! Carved out of `egress_proxy.rs` from day one per the design doc's own
//! guidance: that file already mixes DNS resolution, private-IP denial, and
//! plain-HTTP handling, and cert-minting + MITM termination is over the
//! thermo file-size/complexity ceiling for growing it further in place.
//!
//! **D1 (hard invariant):** an unbound host MUST stay an opaque
//! `copy_bidirectional` tunnel with NO leaf cert ever issued for it. This
//! module never mints or looks up a leaf certificate except from
//! [`terminate_and_forward`], and `egress_proxy::handle_connect` only calls
//! that function once it has already confirmed the host is bound (see
//! [`TlsInterceptConfig::is_bound`]) — an unbound host never reaches this
//! module at all.
//!
//! **Binding decision — phase 1 is a flat allowlist, not a binding model.**
//! [`TlsInterceptConfig`] carries a plain `HashSet<String>` of hosts this
//! proxy instance terminates TLS for. W12 (design doc §4) owns the real
//! binding model (provider-scoped child records, UI, validation); this phase
//! deliberately does not anticipate it — the design doc calls out per-command
//! or per-binding predicates as its own, separately-justified follow-up, not
//! something to build speculatively here.
//!
//! **Phase 1 scope: forward the decrypted stream unchanged.** Preserved
//! exactly when [`TlsInterceptConfig`]'s `credential_swap` is `None`.
//!
//! **Phase 2 scope: the credential swap.** When a
//! [`super::credential_swap::SandboxCredentialSwap`] is configured, the first
//! decrypted request head is read (bounded by [`MAX_REQUEST_HEAD_BYTES`]),
//! any `icsbx_` placeholder in it is resolved/authorized/substituted, and the
//! rewritten head is what reaches the origin. The response direction is
//! untouched. Ordering is load-bearing: the swap runs **before** the origin is
//! dialed, so a CONNECTION-DENIAL means no origin socket is ever opened. See
//! `credential_swap`'s module doc for the two-refusal contract and the
//! keep-alive limitation.
//!
//! **Fail closed.** Any failure — leaf mint, server handshake with the
//! client, origin dial, or origin handshake — closes the connection. There
//! is deliberately no code path from a [`TlsInterceptError`] back to a
//! plaintext `copy_bidirectional` fallback; `egress_proxy::handle_connect`
//! must not add one.
//!
//! **Not wired to a production caller yet.** [`TlsInterceptConfig`] has no
//! production constructor — nothing in this crate builds a
//! [`super::ca::SandboxCertificateAuthority`] or a real "trust the sandbox
//! egress network" `TlsConnector` today. `egress_proxy`'s proxy types carry
//! an `Option<Arc<TlsInterceptConfig>>` that production always leaves `None`
//! (see `EgressAllowlistProxy::new`), matching the same unwired-`Option<Arc<
//! ..>>` shape `attribution`'s resolver field already uses in this crate.

use std::{
    collections::HashSet,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Once},
    task::{Context, Poll},
};

use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::{
    ca::{LeafCertificate, SandboxCertificateAuthority},
    credential_firewall::SandboxCredentialFirewallError,
    credential_swap::{SandboxCredentialSwap, scrub_for_model_visibility},
};

/// Cap on the decrypted request head this seam will buffer before deciding a
/// credential swap. Bounded because the bytes come from the container: without
/// a cap, a client that opens a request and never sends `\r\n\r\n` would grow
/// a host-side buffer without limit. Exceeding it is fail-closed (the
/// connection is refused), never "give up and forward it raw".
const MAX_REQUEST_HEAD_BYTES: usize = 64 * 1024;

const REQUEST_HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Installs rustls's default (`ring`) process-level crypto provider exactly
/// once. rustls 0.23 requires one to be installed before any `ServerConfig`/
/// `ClientConfig` builder call; a second install attempt from a concurrent
/// caller (e.g. parallel tests) would return `Err` for the loser, which is
/// harmless — the provider is already installed by then — so this only
/// needs to run the *first* call exactly once, not guard every call.
static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

fn ensure_crypto_provider_installed() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Errors from the TLS-termination seam. Every variant is a **fail-closed**
/// signal to the caller: `egress_proxy::handle_connect` treats any `Err`
/// here as "close the connection," never "fall back to a plaintext tunnel."
#[derive(Debug, thiserror::Error)]
pub(crate) enum TlsInterceptError {
    #[error("sandbox tls intercept: failed to mint leaf certificate for {host}: {reason}")]
    LeafMintFailed { host: String, reason: String },
    #[error("sandbox tls intercept: failed to build server tls config: {0}")]
    ServerConfigFailed(String),
    #[error("sandbox tls intercept: client tls handshake failed: {0}")]
    ClientHandshakeFailed(String),
    #[error("sandbox tls intercept: failed to dial origin {dial_addr}: {reason}")]
    OriginDialFailed {
        dial_addr: SocketAddr,
        reason: String,
    },
    #[error("sandbox tls intercept: origin tls handshake failed: {0}")]
    OriginHandshakeFailed(String),
    #[error("sandbox tls intercept: invalid sni host {host:?}: {reason}")]
    InvalidSniHost { host: String, reason: String },
    #[error("sandbox tls intercept: relaying decrypted bytes failed: {0}")]
    RelayFailed(String),
    /// CONNECTION-DENIAL from the credential firewall (attribution failed, or
    /// the lookup deadline passed). Kept as its own variant carrying the
    /// firewall's own error so the caller can still tell the two refusals
    /// apart in audit; it is deliberately **not** merged with the
    /// GRANT-DENIAL path, which never surfaces as an error at all (D5: strip
    /// and forward bare).
    #[error("sandbox tls intercept: {0}")]
    CredentialFirewallDenied(#[from] SandboxCredentialFirewallError),
    /// The container sent more than [`MAX_REQUEST_HEAD_BYTES`] without
    /// terminating the request head. Carries only the limit — never the bytes.
    #[error("sandbox tls intercept: request head exceeded {limit_bytes} bytes without terminating")]
    RequestHeadTooLarge { limit_bytes: usize },
    /// The stream ended (or was not HTTP) before a request head could be
    /// framed. Carries no detail: the only material available to describe it
    /// is the container's own bytes.
    #[error("sandbox tls intercept: decrypted stream did not contain a complete request head")]
    MalformedRequestHead,
}

/// Shared, per-proxy-instance TLS-interception configuration:
/// [`super::ca::SandboxCertificateAuthority`] to mint leaf certs from, the
/// flat set of hosts to terminate (see the module doc's "binding decision"),
/// and a pre-built [`TlsConnector`] for re-originating a TLS connection to
/// the real upstream once decrypted. The `TlsConnector`'s trust roots are a
/// caller decision (production would use system roots; this phase leaves
/// that to whoever eventually wires a production caller) — this type only
/// carries whatever connector it is given.
///
/// # WARNING: `origin_connector`'s trust store is a production security
/// boundary, not a test convenience
///
/// Every `TlsInterceptConfig` constructed anywhere in this crate today comes
/// from a test, and every one of those tests hands it a `TlsConnector` built
/// from a real (test) root store. **There is no production constructor yet.**
/// When one is wired (composition, phase 2+), the `origin_connector` it
/// builds MUST be backed by a real trusted root store — the pattern
/// `ironclaw_reborn_event_store` already uses in this workspace via
/// `rustls-native-certs` — and MUST NEVER be:
///
/// - built with `rustls::ClientConfig::dangerous()` or any verifier that
///   skips or weakens certificate verification,
/// - given a custom `ServerCertVerifier` that always accepts,
/// - built with an empty `RootCertStore` (equivalent to trusting nothing on
///   paper, but see below — the actual production risk is the opposite
///   mistake: trusting *everything*).
///
/// This module re-originates a TLS connection to the real upstream on behalf
/// of the sandboxed container, using the same host/port the container
/// thought it was dialing. If `origin_connector` ever fails to verify the
/// origin's certificate against a real root store, this seam stops being a
/// credential firewall and becomes a working, silent MITM against our own
/// users' egress traffic to every "bound" host — the exact opposite of what
/// W6 exists to build. Every test in this file supplies its own real or
/// deliberately-empty root store, so **no existing test would catch a
/// permissive production connector** being wired in; this is a wiring-time
/// requirement the composition PR that adds a production constructor must be
/// reviewed against, not something this phase's test suite enforces.
///
/// **Phase 2 raises the stakes.** Phase 1 forwarded the container's own bytes;
/// phase 2 substitutes the user's **real secret** into the request before it
/// leaves. A connector that does not verify the origin therefore no longer
/// leaks only the container's traffic — it hands the real credential to
/// whatever answers at the dialed address. Treat any production
/// `origin_connector` construction as a blocking review item.
pub(crate) struct TlsInterceptConfig {
    ca: SandboxCertificateAuthority,
    bound_hosts: HashSet<String>,
    /// See the struct-level `# WARNING` above: this MUST be built from a
    /// real trusted root store in production (e.g. `rustls-native-certs`),
    /// and MUST NEVER use `dangerous()`, a verifier that skips verification,
    /// or an empty root store. Getting this wrong turns the whole TLS
    /// interception seam into a silent MITM against our own users.
    origin_connector: TlsConnector,
    /// W6 phase 2. `None` reproduces phase 1 exactly: the decrypted stream is
    /// relayed byte-for-byte with no parsing and no credential handling.
    /// `Some` enables the placeholder → real-secret substitution described in
    /// [`super::credential_swap`]. Production leaves this `None` today; it is
    /// populated by future profile-gated wiring.
    credential_swap: Option<SandboxCredentialSwap>,
}

impl TlsInterceptConfig {
    #[allow(dead_code)] // constructed by this module's tests; a production caller is future wiring
    pub(crate) fn new(
        ca: SandboxCertificateAuthority,
        bound_hosts: HashSet<String>,
        origin_connector: TlsConnector,
    ) -> Self {
        Self {
            ca,
            bound_hosts: bound_hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
            origin_connector,
            credential_swap: None,
        }
    }

    /// Enables W6 phase 2's credential substitution on this config.
    #[allow(dead_code)] // used by this module's tests; production wiring is future
    pub(crate) fn with_credential_swap(mut self, swap: SandboxCredentialSwap) -> Self {
        self.credential_swap = Some(swap);
        self
    }

    /// D1's predicate: is `host` one this proxy instance terminates TLS for?
    /// Case-insensitive to match `egress_proxy::host_allowed`'s own
    /// normalization. Everything not in this set stays an opaque tunnel —
    /// see the module doc's D1 section.
    pub(crate) fn is_bound(&self, host: &str) -> bool {
        self.bound_hosts.contains(&host.to_ascii_lowercase())
    }

    /// Test/introspection seam: how many hosts this config's CA currently
    /// holds a cached leaf certificate for — D1's assertion surface for "an
    /// unbound host must never have a leaf minted for it," independent of
    /// whether traffic merely *looked* like it flowed correctly.
    #[cfg(test)]
    pub(crate) fn cached_leaf_count(&self) -> usize {
        self.ca.cached_entry_count()
    }
}

/// Terminates TLS from `client` using a leaf certificate minted for `host`,
/// dials `dial_addr` and re-originates TLS to the real upstream (SNI =
/// `host`), then relays the decrypted bytes unmodified (phase 1: no parsing,
/// no injection — see the module doc). `leftover` is whatever bytes the
/// egress proxy's `BufReader` had already buffered past the CONNECT
/// request/`200` reply (the same "eager client" case `egress_proxy`'s own
/// tunnel path already has to handle) — fed to the TLS acceptor before any
/// further bytes are read off the socket, via [`LeadingBytes`].
///
/// Every failure path returns `Err` and touches neither `client` nor an
/// origin socket again — no code path here ever falls through to a
/// plaintext relay. `egress_proxy::handle_connect` must preserve that: log
/// and close, never retry unencrypted.
pub(crate) async fn terminate_and_forward(
    client: TcpStream,
    leftover: Vec<u8>,
    host: &str,
    dial_addr: SocketAddr,
    config: &TlsInterceptConfig,
    connection: InterceptedConnection<'_>,
) -> Result<(), TlsInterceptError> {
    let issued =
        config
            .ca
            .issue_leaf_for_host(host)
            .map_err(|error| TlsInterceptError::LeafMintFailed {
                // `host` is container-controlled (it comes from the CONNECT
                // line), and this error's `Display` can reach a log line or,
                // once the sandbox lane is wired, `DispatchError::Script`'s
                // `model_visible_cause`. Scrub before it can.
                host: scrub_for_model_visibility(host),
                reason: error.to_string(),
            })?;
    tracing::debug!(
        host = %issued.certificate.host,
        cache_hit = issued.cache_hit,
        "sandbox tls intercept: leaf certificate ready"
    );

    let server_config = build_server_config(&issued.certificate)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let client_with_leftover = LeadingBytes::new(leftover, client);
    let mut client_tls = acceptor
        .accept(client_with_leftover)
        .await
        .map_err(|error| TlsInterceptError::ClientHandshakeFailed(error.to_string()))?;

    // W6 phase 2: read and rewrite the first request head BEFORE the origin is
    // dialed. Ordering is load-bearing — a CONNECTION-DENIAL from the
    // credential firewall must mean the origin socket is never opened at all,
    // not "opened and then abandoned."
    let rewritten_head = match &config.credential_swap {
        None => None,
        Some(swap) => {
            let Some((head, trailing)) = read_request_head(&mut client_tls).await? else {
                // The client closed without sending anything. Nothing to
                // forward, and no reason to dial the origin.
                return Ok(());
            };
            Some((
                swap.rewrite_request_head(&head, host, connection.identity, connection.deadline)?,
                trailing,
            ))
        }
    };

    // Only reachable once the client trusts our leaf and completed its
    // handshake — a client-side failure above never gets this far, so an
    // unbound/failed interception never opens an origin socket either.
    let origin_stream = TcpStream::connect(dial_addr).await.map_err(|error| {
        TlsInterceptError::OriginDialFailed {
            dial_addr,
            reason: error.to_string(),
        }
    })?;
    let server_name = ServerName::try_from(host.to_string()).map_err(|error| {
        TlsInterceptError::InvalidSniHost {
            // Container-controlled, same reasoning as `LeafMintFailed` above.
            host: scrub_for_model_visibility(host),
            reason: error.to_string(),
        }
    })?;
    let mut origin_tls = config
        .origin_connector
        .connect(server_name, origin_stream)
        .await
        .map_err(|error| TlsInterceptError::OriginHandshakeFailed(error.to_string()))?;

    let (Some(swap), Some((rewritten_head, trailing))) = (&config.credential_swap, rewritten_head)
    else {
        copy_bidirectional(&mut client_tls, &mut origin_tls)
            .await
            .map_err(|error| TlsInterceptError::RelayFailed(error.to_string()))?;
        return Ok(());
    };

    let (mut client_read, mut client_write) = tokio::io::split(client_tls);
    let (mut origin_read, mut origin_write) = tokio::io::split(origin_tls);
    origin_write
        .write_all(rewritten_head.bytes())
        .await
        .map_err(|error| TlsInterceptError::RelayFailed(error.to_string()))?;
    // Drop the rewritten head as soon as it is on the wire: it holds the real
    // secret, and `SecretSlice`'s `Drop` zeroizes it.
    drop(rewritten_head);

    // `trailing` seeds the scrubbing relay so a request pipelined behind the
    // first one is scrubbed, never swapped — see `read_request_head`'s doc.
    let upstream = swap.relay_scrubbing_placeholders(trailing, &mut client_read, &mut origin_write);
    let downstream = async {
        tokio::io::copy(&mut origin_read, &mut client_write).await?;
        client_write.shutdown().await
    };
    tokio::try_join!(upstream, downstream)
        .map_err(|error| TlsInterceptError::RelayFailed(error.to_string()))?;
    Ok(())
}

/// Per-connection inputs the credential swap needs and the per-proxy
/// [`TlsInterceptConfig`] cannot carry: who the proxy attributed this
/// connection to (`None` = attribution failed), and the deadline bounding the
/// firewall lookup.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InterceptedConnection<'a> {
    pub(crate) identity: Option<(
        &'a ironclaw_host_api::TenantId,
        &'a ironclaw_host_api::UserId,
    )>,
    pub(crate) deadline: std::time::Instant,
}

/// Reads one HTTP request head off the decrypted client stream, framed at the
/// FIRST `\r\n\r\n` and bounded by [`MAX_REQUEST_HEAD_BYTES`]. Returns the
/// head and any bytes that arrived behind it in the same read.
///
/// Framing at the first terminator is a security boundary, not tidiness: two
/// requests can arrive in one TCP segment, and a head that ran past the
/// terminator would let a pipelined second request's placeholder be evaluated
/// against the FIRST request's method and path — a credential-scope bypass
/// (`a_pipelined_second_request_cannot_borrow_the_first_requests_authorization`
/// pins it). The trailing bytes are handed to the scrubbing relay instead, so
/// a placeholder in them is stripped, never swapped.
///
/// `Ok(None)` means the client closed without sending a byte. Anything else
/// that fails to frame — EOF mid-head, a non-HTTP protocol, or exceeding the
/// cap — is an `Err`, i.e. fail closed: a bound host is an HTTPS API by
/// construction, and forwarding unframed bytes would mean forwarding a
/// placeholder this seam never got to inspect.
async fn read_request_head(
    client: &mut (impl AsyncRead + Unpin),
) -> Result<Option<(Vec<u8>, Vec<u8>)>, TlsInterceptError> {
    let mut buffered = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = client
            .read(&mut chunk)
            .await
            .map_err(|error| TlsInterceptError::RelayFailed(error.to_string()))?;
        if read == 0 {
            if buffered.is_empty() {
                return Ok(None);
            }
            return Err(TlsInterceptError::MalformedRequestHead);
        }
        buffered.extend_from_slice(&chunk[..read]);
        if let Some(start) = buffered
            .windows(REQUEST_HEAD_TERMINATOR.len())
            .position(|window| window == REQUEST_HEAD_TERMINATOR)
        {
            let rest = buffered.split_off(start + REQUEST_HEAD_TERMINATOR.len());
            return Ok(Some((buffered, rest)));
        }
        if buffered.len() > MAX_REQUEST_HEAD_BYTES {
            return Err(TlsInterceptError::RequestHeadTooLarge {
                limit_bytes: MAX_REQUEST_HEAD_BYTES,
            });
        }
    }
}

/// Builds a single-host rustls server config serving exactly the leaf
/// certificate minted for one host — no SNI-keyed multi-cert resolver is
/// needed because a CONNECT tunnel already pins the intended host before
/// this is called (see [`terminate_and_forward`]); the client's SNI, if
/// present, is not consulted.
pub(crate) fn build_server_config(
    leaf: &LeafCertificate,
) -> Result<rustls::ServerConfig, TlsInterceptError> {
    ensure_crypto_provider_installed();
    let chain = rustls_pemfile::certs(&mut leaf.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            TlsInterceptError::ServerConfigFailed(format!("parsing leaf cert pem: {error}"))
        })?;
    let key = rustls_pemfile::private_key(&mut leaf.key_pem.as_bytes())
        .map_err(|error| {
            TlsInterceptError::ServerConfigFailed(format!("parsing leaf key pem: {error}"))
        })?
        .ok_or_else(|| {
            TlsInterceptError::ServerConfigFailed("leaf key pem contained no key".to_string())
        })?;

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|error| TlsInterceptError::ServerConfigFailed(error.to_string()))
}

/// Wraps an `AsyncRead + AsyncWrite` stream with bytes that must be replayed
/// to the first reader before any further bytes are read off the underlying
/// stream. Mirrors the same "bytes buffered alongside the CONNECT request"
/// case `egress_proxy::handle_connect`'s plaintext tunnel path already
/// handles (see that module's `connect_forwards_bytes_buffered_alongside_
/// the_connect_request` test) — a client that doesn't wait for the proxy's
/// `200 Connection Established` before starting its TLS handshake can have
/// the start of its `ClientHello` land in the same TCP segment as the
/// CONNECT request, which ends up sitting in the proxy's `BufReader` rather
/// than the socket. Writes always delegate straight to the inner stream —
/// only reads need the replay.
struct LeadingBytes<S> {
    leftover: Vec<u8>,
    leftover_pos: usize,
    inner: S,
}

impl<S> LeadingBytes<S> {
    fn new(leftover: Vec<u8>, inner: S) -> Self {
        Self {
            leftover,
            leftover_pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for LeadingBytes<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.leftover_pos < this.leftover.len() {
            let remaining = &this.leftover[this.leftover_pos..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            this.leftover_pos += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for LeadingBytes<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
