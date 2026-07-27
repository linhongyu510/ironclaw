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
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use x509_parser::prelude::*;

    /// Builds a `TlsConnector` that trusts exactly one extra root — the
    /// test seam standing in for "production would use system roots"
    /// (see the module doc). Used to make a fake local origin TLS server
    /// trusted by the connector under test without depending on any real
    /// certificate authority.
    fn connector_trusting_only(root_pem: &str) -> TlsConnector {
        ensure_crypto_provider_installed();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut root_pem.as_bytes()) {
            roots
                .add(cert.expect("valid root cert pem"))
                .expect("root cert adds");
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(client_config))
    }

    /// A `TlsConnector` with an empty trust store — every origin handshake
    /// through it fails certificate verification. Used to force the
    /// fail-closed path deterministically without relying on network
    /// conditions.
    fn connector_trusting_nothing() -> TlsConnector {
        ensure_crypto_provider_installed();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        TlsConnector::from(Arc::new(client_config))
    }

    /// Spins up a local TLS "origin" server on loopback, using its own
    /// self-signed CA (separate from the CA under test) so tests can
    /// distinguish "chains to our CA" from "chains to the origin's own
    /// cert." Echoes back whatever it receives once, then closes — enough
    /// to prove decrypted bytes actually reach the origin and come back.
    async fn spawn_fake_tls_origin(host: &str) -> (SocketAddr, String) {
        let origin_ca = SandboxCertificateAuthority::generate().expect("origin ca generates");
        let issued = origin_ca
            .issue_leaf_for_host(host)
            .expect("origin leaf issues");
        let server_config =
            build_server_config(&issued.certificate).expect("origin server config builds");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("origin listener binds");
        let addr = listener.local_addr().expect("origin listener has an addr");

        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(mut tls) = acceptor.accept(stream).await
            {
                let mut buf = [0u8; 256];
                if let Ok(n) = tls.read(&mut buf).await {
                    let _ = tls.write_all(&buf[..n]).await;
                    let _ = tls.shutdown().await;
                }
            }
        });

        (addr, origin_ca.root_certificate_pem().to_string())
    }

    fn parse<'a>(pem: &'a str) -> X509Certificate<'a> {
        let (_, parsed) = parse_x509_pem(pem.as_bytes()).expect("valid pem");
        let cert = Box::leak(Box::new(parsed));
        cert.parse_x509().expect("valid x.509 der")
    }

    /// D1: an unbound host must never even reach `terminate_and_forward` —
    /// `TlsInterceptConfig::is_bound` is the gate `egress_proxy::
    /// handle_connect` checks before calling it. Pinning this at the
    /// config-predicate level (rather than only end-to-end through the
    /// proxy) keeps the assertion tied directly to the CA's own cache
    /// counter, independent of `egress_proxy`'s plumbing.
    #[test]
    fn unbound_host_is_not_bound_and_mints_no_leaf() {
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let bound_hosts = HashSet::from(["bound.example.com".to_string()]);
        let config = TlsInterceptConfig::new(ca, bound_hosts, connector_trusting_nothing());

        assert!(!config.is_bound("unbound.example.com"));
        assert!(config.is_bound("bound.example.com"));
        // No leaf was ever minted for either host by constructing/querying
        // the config alone — the cache is still empty.
        assert_eq!(config.ca.cached_entry_count(), 0);
    }

    /// A BOUND host is genuinely intercepted end to end: a real rustls
    /// client dialing through `terminate_and_forward` completes its TLS
    /// handshake against a certificate chaining to OUR CA (not the fake
    /// origin's own CA), and the decrypted bytes it sends still reach the
    /// origin and echo back — proving both the MITM cert swap and the
    /// relay work, not just the handshake.
    #[tokio::test]
    async fn bound_host_is_intercepted_with_our_ca_and_relays_bytes() {
        let host = "bound.example.com";
        let (origin_addr, origin_root_pem) = spawn_fake_tls_origin(host).await;

        let ca = SandboxCertificateAuthority::generate().unwrap();
        let our_root_pem = ca.root_certificate_pem().to_string();
        let bound_hosts = HashSet::from([host.to_string()]);
        let config =
            TlsInterceptConfig::new(ca, bound_hosts, connector_trusting_only(&origin_root_pem));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            terminate_and_forward(
                stream,
                Vec::new(),
                host,
                origin_addr,
                &config,
                unattributed_connection(),
            )
            .await
        });

        // The "container" side: a real rustls client, trusting only OUR
        // CA's root — if the proxy served the origin's own cert (or any
        // cert not signed by our CA), this handshake fails.
        let mut our_roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut our_root_pem.as_bytes()) {
            our_roots.add(cert.unwrap()).unwrap();
        }
        ensure_crypto_provider_installed();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(our_roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let raw_client = TcpStream::connect(proxy_addr).await.unwrap();
        let server_name = ServerName::try_from(host.to_string()).unwrap();
        let mut client_tls = tokio::time::timeout(
            Duration::from_secs(5),
            connector.connect(server_name, raw_client),
        )
        .await
        .expect("handshake must not hang")
        .expect("client tls handshake must succeed against a cert chaining to OUR ca");

        client_tls
            .write_all(b"hello through the intercept")
            .await
            .unwrap();
        let mut echoed = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), client_tls.read(&mut echoed))
            .await
            .expect("read must not hang")
            .expect("reads the echoed bytes back");
        assert_eq!(&echoed[..n], b"hello through the intercept");
        // Send a clean TLS close on both directions so `copy_bidirectional`
        // inside `terminate_and_forward` sees EOF and returns, instead of
        // waiting forever for a client that never closes.
        client_tls.shutdown().await.unwrap();

        tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server task must finish")
            .expect("server task did not panic")
            .expect("terminate_and_forward must succeed");
    }

    /// Cert issued for host A must never be served for host B — pins the
    /// property `terminate_and_forward` relies on `SandboxCertificateAuthority`
    /// for, at the level `build_server_config` actually consumes it: the
    /// SAN on the config's certificate is exactly the requested host.
    #[test]
    fn leaf_used_to_build_a_server_config_is_scoped_to_its_own_host() {
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let issued_a = ca.issue_leaf_for_host("a.example.com").unwrap();
        let issued_b = ca.issue_leaf_for_host("b.example.com").unwrap();

        assert_ne!(issued_a.certificate.cert_pem, issued_b.certificate.cert_pem);
        let leaf_a = parse(&issued_a.certificate.cert_pem);
        let dns_sans: Vec<String> = leaf_a
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(dns) => Some((*dns).to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(dns_sans, vec!["a.example.com".to_string()]);
        assert_ne!(dns_sans, vec!["b.example.com".to_string()]);
    }

    /// Fail-closed: when the client can't complete a valid TLS handshake
    /// with the proxy (garbage instead of a `ClientHello`), the origin is
    /// never dialed at all — there is no plaintext fallback that would let
    /// bytes reach the origin unencrypted. Asserted directly (the origin
    /// listener never sees a connection within the timeout), not just
    /// inferred from `terminate_and_forward`'s `Err` return.
    #[tokio::test]
    async fn client_handshake_failure_never_dials_the_origin() {
        let host = "bound.example.com";
        let ca = SandboxCertificateAuthority::generate().unwrap();

        // A listener standing in for the origin: if `terminate_and_forward`
        // ever fell back to a plaintext relay after the client handshake
        // failed, this would be the first thing it dialed.
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_saw_a_connection = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(300), origin_listener.accept()).await
        });

        let config = TlsInterceptConfig::new(
            ca,
            HashSet::from([host.to_string()]),
            connector_trusting_nothing(),
        );

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            terminate_and_forward(
                stream,
                Vec::new(),
                host,
                origin_addr,
                &config,
                unattributed_connection(),
            )
            .await
        });

        let mut raw_client = TcpStream::connect(proxy_addr).await.unwrap();
        // Not a TLS ClientHello — the server-side handshake must reject this.
        raw_client
            .write_all(b"this is not a tls client hello at all")
            .await
            .unwrap();
        drop(raw_client);

        let result = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server task must finish")
            .expect("server task did not panic");
        assert!(
            matches!(result, Err(TlsInterceptError::ClientHandshakeFailed(_))),
            "expected a client handshake failure, got: {result:?}"
        );

        let origin_result = origin_saw_a_connection
            .await
            .expect("origin probe task did not panic");
        assert!(
            origin_result.is_err(),
            "origin must never be dialed after a failed client handshake (fail-closed, no \
             plaintext fallback)"
        );
    }

    // ---------------------------------------------------------------
    // W6 phase 2 — the credential swap
    // ---------------------------------------------------------------

    use crate::obligations::RuntimeSecretInjectionStore;
    use ironclaw_host_api::{
        CapabilityId, ExtensionId, InvocationId, NetworkMethod, ResourceScope, SecretHandle,
        TenantId, UserId,
    };
    use ironclaw_secrets::{
        CredentialPathPolicy, CredentialPlaceholderRegistry, CredentialTargetPolicy, SecretMaterial,
    };
    use std::sync::Mutex;

    use super::super::credential_firewall::{
        SandboxCredentialFirewall, StagedCredentialObligation, StagedCredentialObligationSource,
    };
    use super::super::credential_swap::SandboxCredentialSwap;

    const REAL_SECRET: &str = "ghp-REAL-SECRET-MATERIAL-nsQ82hd7";
    const BOUND_HOST: &str = "bound.example.com";

    fn unattributed_connection() -> InterceptedConnection<'static> {
        InterceptedConnection {
            identity: None,
            deadline: Instant::now() + Duration::from_secs(3600),
        }
    }

    fn tenant() -> TenantId {
        TenantId::new("tenant-a").unwrap()
    }

    fn user() -> UserId {
        UserId::new("user-a").unwrap()
    }

    fn provider() -> ExtensionId {
        ExtensionId::new("github").unwrap()
    }

    fn scope() -> ResourceScope {
        ResourceScope {
            tenant_id: tenant(),
            user_id: user(),
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        }
    }

    fn get_policy(path: &str) -> CredentialTargetPolicy {
        CredentialTargetPolicy {
            scheme: "https".to_string(),
            host: BOUND_HOST.to_string(),
            port: None,
            path: CredentialPathPolicy::Prefix(path.to_string()),
            methods: vec![NetworkMethod::Get],
        }
    }

    /// Builds the full phase-2 wiring a swap needs: a registry holding a
    /// stable placeholder for `(tenant-a, user-a, github)`, an injection
    /// store holding [`REAL_SECRET`] under a known
    /// `(scope, capability, handle)`, and a firewall with (optionally) a
    /// matching obligation staged. Returns the swap, the placeholder token,
    /// and the lease keeping the obligation staged (dropping it revokes).
    fn swap_fixture(
        stage_grant: bool,
        policy: CredentialTargetPolicy,
    ) -> (
        SandboxCredentialSwap,
        String,
        Option<super::super::credential_firewall::StagedObligationLease>,
    ) {
        let registry = Arc::new(CredentialPlaceholderRegistry::new());
        let placeholder = registry
            .get_or_create(&tenant(), &user(), &provider())
            .expect("placeholder mints");
        let firewall = Arc::new(SandboxCredentialFirewall::new());
        let injections = RuntimeSecretInjectionStore::new();
        let handle = SecretHandle::new("github-token").unwrap();
        let capability = CapabilityId::new("sandbox.shell").unwrap();
        // One scope value, used for BOTH the staged material and the
        // obligation that points at it: `ResourceScope` carries a fresh
        // `InvocationId`, so building it twice would key the injection store
        // under a scope the obligation never names.
        let staged_scope = scope();
        injections
            .insert(
                &staged_scope,
                &capability,
                &handle,
                SecretMaterial::from(REAL_SECRET.to_string()),
            )
            .expect("staged material inserts");
        let lease = stage_grant.then(|| {
            firewall.stage(
                &tenant(),
                &user(),
                StagedCredentialObligation::new(
                    StagedCredentialObligationSource {
                        scope: staged_scope,
                        capability_id: capability,
                        provider_or_extension_id: provider(),
                        secret_handle: handle,
                    },
                    vec![policy],
                    Duration::from_secs(600),
                ),
            )
        });
        let token = placeholder.as_str().to_string();
        (
            SandboxCredentialSwap::new(registry, firewall, injections),
            token,
            lease,
        )
    }

    /// A TLS "origin" that records every byte it is sent and answers each
    /// request with a fixed HTTP response, so a test can assert on exactly
    /// what crossed the boundary in each direction.
    async fn spawn_recording_tls_origin(
        host: &str,
        responses: usize,
    ) -> (SocketAddr, String, Arc<Mutex<Vec<u8>>>) {
        let origin_ca = SandboxCertificateAuthority::generate().expect("origin ca generates");
        let issued = origin_ca
            .issue_leaf_for_host(host)
            .expect("origin leaf issues");
        let server_config =
            build_server_config(&issued.certificate).expect("origin server config builds");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("origin listener binds");
        let addr = listener.local_addr().expect("origin listener has an addr");
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);

        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(mut tls) = acceptor.accept(stream).await
            {
                let mut buf = [0u8; 4096];
                let mut answered = 0usize;
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if let Ok(mut guard) = sink.lock() {
                        guard.extend_from_slice(&buf[..n]);
                    }
                    if answered < responses {
                        answered += 1;
                        let _ = tls
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .await;
                    }
                }
                let _ = tls.shutdown().await;
            }
        });

        (addr, origin_ca.root_certificate_pem().to_string(), received)
    }

    /// Drives one intercepted connection end to end and returns
    /// `(terminate_and_forward result, bytes the container observed)`.
    async fn drive_intercepted_connection(
        config: TlsInterceptConfig,
        our_root_pem: String,
        origin_addr: SocketAddr,
        identity: bool,
        deadline: Instant,
        requests: Vec<Vec<u8>>,
    ) -> (Result<(), TlsInterceptError>, Vec<u8>) {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let tenant_id = tenant();
            let user_id = user();
            terminate_and_forward(
                stream,
                Vec::new(),
                BOUND_HOST,
                origin_addr,
                &config,
                InterceptedConnection {
                    identity: identity.then_some((&tenant_id, &user_id)),
                    deadline,
                },
            )
            .await
        });

        let mut our_roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut our_root_pem.as_bytes()) {
            our_roots.add(cert.unwrap()).unwrap();
        }
        ensure_crypto_provider_installed();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(our_roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let raw_client = TcpStream::connect(proxy_addr).await.unwrap();
        let server_name = ServerName::try_from(BOUND_HOST.to_string()).unwrap();
        let container_visible = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&container_visible);
        let client_task = tokio::spawn(async move {
            let mut client_tls = connector
                .connect(server_name, raw_client)
                .await
                .expect("client tls handshake");
            for request in requests {
                if client_tls.write_all(&request).await.is_err() {
                    break;
                }
                let mut buf = [0u8; 4096];
                match client_tls.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut guard) = sink.lock() {
                            guard.extend_from_slice(&buf[..n]);
                        }
                    }
                }
            }
            let _ = client_tls.shutdown().await;
        });

        let result = tokio::time::timeout(Duration::from_secs(10), server_task)
            .await
            .expect("server task must finish")
            .expect("server task did not panic");
        let _ = tokio::time::timeout(Duration::from_secs(5), client_task).await;
        let observed = container_visible.lock().unwrap().clone();
        (result, observed)
    }

    fn request_with(token: &str) -> Vec<u8> {
        format!(
            "GET /repos/x HTTP/1.1\r\nHost: {BOUND_HOST}\r\nAuthorization: token {token}\r\n\r\n"
        )
        .into_bytes()
    }

    /// **THE core invariant** (design doc §6 row 8): the real secret is what
    /// the ORIGIN sees and is never anything the CONTAINER can observe.
    ///
    /// Discriminating in three separate directions, so it cannot pass by
    /// accident:
    /// - a no-op implementation fails, because the origin would receive the
    ///   placeholder and never the secret;
    /// - a swap applied in the wrong direction (rewriting the response
    ///   instead of the request) fails on *both* the origin assertion and
    ///   the container assertion;
    /// - a secret that leaks into the error path fails, because the
    ///   `Result`'s rendered error is checked for the secret too.
    #[tokio::test]
    async fn real_secret_never_appears_in_container() {
        let (origin_addr, origin_root_pem, origin_received) =
            spawn_recording_tls_origin(BOUND_HOST, 1).await;
        let (swap, token, _lease) = swap_fixture(true, get_policy("/repos"));
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let our_root_pem = ca.root_certificate_pem().to_string();
        let config = TlsInterceptConfig::new(
            ca,
            HashSet::from([BOUND_HOST.to_string()]),
            connector_trusting_only(&origin_root_pem),
        )
        .with_credential_swap(swap);

        let (result, container_visible) = drive_intercepted_connection(
            config,
            our_root_pem,
            origin_addr,
            true,
            Instant::now() + Duration::from_secs(3600),
            vec![request_with(&token)],
        )
        .await;

        let origin_bytes = origin_received.lock().unwrap().clone();
        let origin_text = String::from_utf8_lossy(&origin_bytes).to_string();
        assert!(
            origin_text.contains(REAL_SECRET),
            "the origin must receive the REAL secret — got: {origin_text:?}"
        );
        assert!(
            !origin_text.contains(&token),
            "the placeholder must never leave the boundary — got: {origin_text:?}"
        );

        let container_text = String::from_utf8_lossy(&container_visible).to_string();
        assert!(
            !container_text.contains(REAL_SECRET),
            "the container must never observe the real secret — got: {container_text:?}"
        );
        let rendered_error = match &result {
            Ok(()) => String::new(),
            Err(error) => format!("{error} / {error:?}"),
        };
        assert!(
            !rendered_error.contains(REAL_SECRET),
            "the real secret must never reach an error surfaced to the container: \
             {rendered_error}"
        );
    }

    /// D5 GRANT-DENIAL: nothing staged, so the placeholder is stripped and
    /// the request is still forwarded — the origin's own 401 is the better
    /// error than refusing a request that may not have needed a credential.
    #[tokio::test]
    async fn grant_denial_strips_the_placeholder_and_forwards_the_request_bare() {
        let (origin_addr, origin_root_pem, origin_received) =
            spawn_recording_tls_origin(BOUND_HOST, 1).await;
        let (swap, token, _lease) = swap_fixture(false, get_policy("/repos"));
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let our_root_pem = ca.root_certificate_pem().to_string();
        let config = TlsInterceptConfig::new(
            ca,
            HashSet::from([BOUND_HOST.to_string()]),
            connector_trusting_only(&origin_root_pem),
        )
        .with_credential_swap(swap);

        let (result, _) = drive_intercepted_connection(
            config,
            our_root_pem,
            origin_addr,
            true,
            Instant::now() + Duration::from_secs(3600),
            vec![request_with(&token)],
        )
        .await;
        assert!(
            result.is_ok(),
            "a grant denial must NOT tear down the connection: {result:?}"
        );

        let origin_text = String::from_utf8_lossy(&origin_received.lock().unwrap()).to_string();
        assert!(
            origin_text.starts_with("GET /repos/x HTTP/1.1"),
            "the request must still be forwarded, bare — got: {origin_text:?}"
        );
        assert!(
            !origin_text.contains(&token),
            "the placeholder must be stripped, not forwarded — got: {origin_text:?}"
        );
        assert!(
            !origin_text.contains(REAL_SECRET),
            "no secret may be attached without a grant — got: {origin_text:?}"
        );
    }

    /// CONNECTION-DENIAL (attribution failed) is categorically different
    /// from a grant denial: nothing is forwarded, and the origin is never
    /// even dialed. Asserted against the origin socket directly, not just
    /// from the returned error.
    #[tokio::test]
    async fn connection_denial_refuses_outright_and_never_dials_the_origin() {
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_probe = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(500), origin_listener.accept()).await
        });

        let (swap, token, _lease) = swap_fixture(true, get_policy("/repos"));
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let our_root_pem = ca.root_certificate_pem().to_string();
        let config = TlsInterceptConfig::new(
            ca,
            HashSet::from([BOUND_HOST.to_string()]),
            connector_trusting_nothing(),
        )
        .with_credential_swap(swap);

        let (result, _) = drive_intercepted_connection(
            config,
            our_root_pem,
            origin_addr,
            false, // attribution failed
            Instant::now() + Duration::from_secs(3600),
            vec![request_with(&token)],
        )
        .await;

        assert!(
            matches!(
                result,
                Err(TlsInterceptError::CredentialFirewallDenied(
                    SandboxCredentialFirewallError::AttributionFailed
                ))
            ),
            "expected a connection denial for an unattributed peer, got: {result:?}"
        );
        assert!(
            origin_probe.await.unwrap().is_err(),
            "a connection denial must never dial the origin"
        );
    }

    /// The other CONNECTION-DENIAL: the lookup deadline has already passed
    /// by the time the request arrives. Same fail-closed shape, different
    /// variant — the two must stay distinguishable.
    #[tokio::test]
    async fn expired_deadline_denies_the_connection_mid_flight() {
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_probe = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(500), origin_listener.accept()).await
        });

        let (swap, token, _lease) = swap_fixture(true, get_policy("/repos"));
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let our_root_pem = ca.root_certificate_pem().to_string();
        let config = TlsInterceptConfig::new(
            ca,
            HashSet::from([BOUND_HOST.to_string()]),
            connector_trusting_nothing(),
        )
        .with_credential_swap(swap);

        let (result, _) = drive_intercepted_connection(
            config,
            our_root_pem,
            origin_addr,
            true,
            Instant::now() - Duration::from_secs(1), // already expired
            vec![request_with(&token)],
        )
        .await;

        assert!(
            matches!(
                result,
                Err(TlsInterceptError::CredentialFirewallDenied(
                    SandboxCredentialFirewallError::LookupTimedOut
                ))
            ),
            "expected a deadline-expiry connection denial, got: {result:?}"
        );
        assert!(
            origin_probe.await.unwrap().is_err(),
            "an expired deadline must never dial the origin"
        );
    }

    /// D1 still holds with the swap configured: an unbound host is not
    /// bound, and configuring credential substitution mints no leaf for it.
    #[test]
    fn unbound_host_stays_opaque_with_the_credential_swap_configured() {
        let (swap, _token, _lease) = swap_fixture(true, get_policy("/repos"));
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let config = TlsInterceptConfig::new(
            ca,
            HashSet::from([BOUND_HOST.to_string()]),
            connector_trusting_nothing(),
        )
        .with_credential_swap(swap);

        assert!(!config.is_bound("unbound.example.com"));
        assert_eq!(
            config.cached_leaf_count(),
            0,
            "configuring the credential swap must not mint a leaf for anything"
        );
    }

    /// A token that is not a valid placeholder — 40 suffix characters
    /// instead of exactly 32, and a truncated one — is left completely
    /// untouched, and the origin sees it verbatim. Pins that untrusted
    /// container input cannot drive the registry/firewall path at all.
    #[tokio::test]
    async fn malformed_or_oversized_token_is_not_a_placeholder() {
        let (origin_addr, origin_root_pem, origin_received) =
            spawn_recording_tls_origin(BOUND_HOST, 1).await;
        let (swap, _token, _lease) = swap_fixture(true, get_policy("/repos"));
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let our_root_pem = ca.root_certificate_pem().to_string();
        let config = TlsInterceptConfig::new(
            ca,
            HashSet::from([BOUND_HOST.to_string()]),
            connector_trusting_only(&origin_root_pem),
        )
        .with_credential_swap(swap);

        let oversized = format!("icsbx_{}", "a".repeat(40));
        let truncated = "icsbx_short";
        let request = format!(
            "GET /repos/x HTTP/1.1\r\nHost: {BOUND_HOST}\r\nAuthorization: token {oversized}\r\n\
             X-Other: {truncated}\r\n\r\n"
        )
        .into_bytes();

        let (result, _) = drive_intercepted_connection(
            config,
            our_root_pem,
            origin_addr,
            true,
            Instant::now() + Duration::from_secs(3600),
            vec![request],
        )
        .await;
        assert!(result.is_ok(), "unexpected failure: {result:?}");

        let origin_text = String::from_utf8_lossy(&origin_received.lock().unwrap()).to_string();
        assert!(
            origin_text.contains(&oversized) && origin_text.contains(truncated),
            "a non-placeholder must be forwarded verbatim — got: {origin_text:?}"
        );
        assert!(
            !origin_text.contains(REAL_SECRET),
            "a malformed token must never resolve to a secret — got: {origin_text:?}"
        );
    }

    /// Keep-alive: the swap only parses the FIRST request head, so a
    /// placeholder on a later request on the same connection is *stripped*
    /// rather than forwarded. Pins the invariant "the placeholder never
    /// leaves the boundary" across the whole connection, not just its first
    /// request.
    #[tokio::test]
    async fn placeholder_on_a_later_keep_alive_request_never_leaves_the_boundary() {
        let (origin_addr, origin_root_pem, origin_received) =
            spawn_recording_tls_origin(BOUND_HOST, 2).await;
        let (swap, token, _lease) = swap_fixture(true, get_policy("/repos"));
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let our_root_pem = ca.root_certificate_pem().to_string();
        let config = TlsInterceptConfig::new(
            ca,
            HashSet::from([BOUND_HOST.to_string()]),
            connector_trusting_only(&origin_root_pem),
        )
        .with_credential_swap(swap);

        let (result, _) = drive_intercepted_connection(
            config,
            our_root_pem,
            origin_addr,
            true,
            Instant::now() + Duration::from_secs(3600),
            vec![request_with(&token), request_with(&token)],
        )
        .await;
        assert!(result.is_ok(), "unexpected failure: {result:?}");

        let origin_text = String::from_utf8_lossy(&origin_received.lock().unwrap()).to_string();
        assert!(
            !origin_text.contains(&token),
            "no placeholder may cross the boundary on any request — got: {origin_text:?}"
        );
        assert_eq!(
            origin_text.matches(REAL_SECRET).count(),
            1,
            "only the first request's placeholder is swapped; the second is stripped — got: \
             {origin_text:?}"
        );
    }

    /// Request smuggling: two requests arriving in the SAME segment must not
    /// let the second one borrow the first one's authorization. The head is
    /// framed at the first `\r\n\r\n`, so the placeholder sitting in the
    /// pipelined `DELETE /admin/keys` is evaluated against nothing — it is
    /// stripped, not swapped against the covered `GET /repos/x` that precedes
    /// it. Without the framing this test fails by handing the real secret to
    /// a method and path the grant never covered.
    #[tokio::test]
    async fn a_pipelined_second_request_cannot_borrow_the_first_requests_authorization() {
        let (origin_addr, origin_root_pem, origin_received) =
            spawn_recording_tls_origin(BOUND_HOST, 2).await;
        let (swap, token, _lease) = swap_fixture(true, get_policy("/repos"));
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let our_root_pem = ca.root_certificate_pem().to_string();
        let config = TlsInterceptConfig::new(
            ca,
            HashSet::from([BOUND_HOST.to_string()]),
            connector_trusting_only(&origin_root_pem),
        )
        .with_credential_swap(swap);

        // One write, two requests. The FIRST carries no placeholder and is
        // covered by the grant; the SECOND carries the placeholder and is
        // not covered (wrong method AND wrong path).
        let smuggled = format!(
            "GET /repos/x HTTP/1.1\r\nHost: {BOUND_HOST}\r\n\r\n\
             DELETE /admin/keys HTTP/1.1\r\nHost: {BOUND_HOST}\r\n\
             Authorization: token {token}\r\n\r\n"
        )
        .into_bytes();

        let (result, _) = drive_intercepted_connection(
            config,
            our_root_pem,
            origin_addr,
            true,
            Instant::now() + Duration::from_secs(3600),
            vec![smuggled],
        )
        .await;
        assert!(result.is_ok(), "unexpected failure: {result:?}");

        let origin_text = String::from_utf8_lossy(&origin_received.lock().unwrap()).to_string();
        assert!(
            !origin_text.contains(REAL_SECRET),
            "a pipelined request must not inherit the first request's grant — got: \
             {origin_text:?}"
        );
        assert!(
            !origin_text.contains(&token),
            "the placeholder must still never cross the boundary — got: {origin_text:?}"
        );
        assert!(
            origin_text.contains("DELETE /admin/keys"),
            "the pipelined request itself is still forwarded (bare) — got: {origin_text:?}"
        );
    }
}
