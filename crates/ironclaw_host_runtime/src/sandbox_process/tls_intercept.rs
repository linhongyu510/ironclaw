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
//! **Phase 1 scope: forward the decrypted stream unchanged.** No credential
//! injection, no body parsing — that is phase 2, gated on a `RuntimeKind::
//! Sandbox` variant that does not exist yet (design doc, W6 gating note).
//! Proving the interception mechanism works (real MITM, real fail-closed
//! behavior) stands on its own before any injection logic lands on top.
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
    time::Duration,
};

use rustls::pki_types::ServerName;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::ca::{LeafCertificate, SandboxCertificateAuthority};

/// Installs rustls's default (`ring`) process-level crypto provider exactly
/// once. rustls 0.23 requires one to be installed before any `ServerConfig`/
/// `ClientConfig` builder call; a second install attempt from a concurrent
/// caller (e.g. parallel tests) would return `Err` for the loser, which is
/// harmless — the provider is already installed by then — so this only
/// needs to run the *first* call exactly once, not guard every call.
#[allow(dead_code)] // consumed by W6; not wired yet
static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

#[allow(dead_code)] // consumed by W6; not wired yet
fn ensure_crypto_provider_installed() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Errors from the TLS-termination seam. Every variant is a **fail-closed**
/// signal to the caller: `egress_proxy::handle_connect` treats any `Err`
/// here as "close the connection," never "fall back to a plaintext tunnel."
#[allow(dead_code)] // consumed by W6; not wired yet
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
    #[error("sandbox tls intercept: failed to load system trust roots: {0}")]
    TrustRootsUnavailable(String),
}

/// A [`TlsConnector`] whose trust store is guaranteed to be the real
/// platform root-of-trust — never empty, never `dangerous()`, never a
/// custom verifier that skips or weakens certificate verification.
///
/// This wraps the invariant the struct-level `# WARNING` on
/// [`TlsInterceptConfig`] used to only document: `origin_connector` is what
/// the proxy uses to verify the origin it re-originates TLS to, on behalf
/// of a sandboxed container that is deliberately never given the real
/// secret. If that connector's trust store is ever empty or permissive, the
/// interception seam stops being a credential firewall and becomes a
/// working, silent MITM against our own users' egress traffic to every
/// bound host.
///
/// [`from_system_roots`](Self::from_system_roots) is the **only** door in a
/// production build — there is no way to build one from a caller-supplied
/// `TlsConnector`, `RootCertStore`, or verifier outside `#[cfg(test)]`. This
/// makes the mistake this type exists to prevent (an empty or permissive
/// connector reaching `TlsInterceptConfig::new`) a compile error for any
/// non-test caller, not merely a documented review requirement.
#[allow(dead_code)] // consumed by W6; not wired to a production caller yet
pub(crate) struct VerifiedOriginConnector(TlsConnector);

impl VerifiedOriginConnector {
    /// Builds the connector from the platform's real trust anchors via
    /// `rustls-native-certs` (the same crate and pattern
    /// `ironclaw_reborn_event_store::make_rustls_connector` already uses in
    /// this workspace for remote Postgres TLS). An empty or unreadable
    /// system trust store is a returned `Err`, never a silent `Ok` with
    /// zero roots — that empty-store case is exactly the bug this type
    /// exists to make unrepresentable, so it must fail closed rather than
    /// hand back a connector that verifies against nothing.
    #[allow(dead_code)] // consumed by W6; not wired to a production caller yet
    pub(crate) fn from_system_roots() -> Result<Self, TlsInterceptError> {
        ensure_crypto_provider_installed();
        let mut root_store = rustls::RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for error in &native.errors {
            // `debug!`, not `warn!`/`info!`: this is an internal diagnostic on
            // a per-process background path, not intentionally user-facing
            // status, and a messy system trust store can emit one line per
            // unparseable root — `warn!`/`info!` here would corrupt the
            // REPL/TUI (see the crate logging-level rule). The empty-store
            // case still fails loudly via `TrustRootsUnavailable`.
            tracing::debug!("sandbox tls intercept: error loading system root certs: {error}");
        }
        for cert in native.certs {
            if let Err(error) = root_store.add(cert) {
                tracing::debug!(
                    "sandbox tls intercept: skipping invalid system root cert: {error}"
                );
            }
        }
        Self::from_root_store(root_store)
    }

    /// The fail-closed core `from_system_roots` delegates to: an empty root
    /// store — whether a genuinely bare system trust store or, in tests, a
    /// synthetic one — must never produce a connector that verifies against
    /// nothing. Split out so this branch is deterministically unit-testable
    /// without needing to fake `rustls_native_certs::load_native_certs`'s
    /// OS-level behavior.
    #[allow(dead_code)] // consumed by W6; not wired to a production caller yet
    fn from_root_store(root_store: rustls::RootCertStore) -> Result<Self, TlsInterceptError> {
        if root_store.is_empty() {
            return Err(TlsInterceptError::TrustRootsUnavailable(
                "system trust store yielded zero usable root certificates".to_string(),
            ));
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(Self(TlsConnector::from(Arc::new(client_config))))
    }

    /// Test-only escape hatch: wrap an arbitrary connector (e.g. one
    /// trusting only a fake origin's root, or trusting nothing at all, to
    /// force the fail-closed path deterministically). `#[cfg(test)]` means
    /// this constructor does not exist in a production build — a
    /// production caller reaching for a permissive connector gets a
    /// compile error, not a review comment.
    #[cfg(test)]
    pub(crate) fn for_test(connector: TlsConnector) -> Self {
        Self(connector)
    }

    /// Named accessor for the wrapped connector, matching the crate's other
    /// newtypes (e.g. `IdempotencyKey::as_str`) instead of letting callers
    /// reach past the type via `.0` — the one call site
    /// ([`terminate_and_forward`]) goes through this, not the tuple field.
    fn connector(&self) -> &TlsConnector {
        &self.0
    }
}

/// Shared, per-proxy-instance TLS-interception configuration:
/// [`super::ca::SandboxCertificateAuthority`] to mint leaf certs from, the
/// flat set of hosts to terminate (see the module doc's "binding decision"),
/// and a [`VerifiedOriginConnector`] for re-originating a TLS connection to
/// the real upstream once decrypted.
///
/// # WARNING: `origin_connector`'s trust store is a production security
/// boundary, not a test convenience
///
/// This is now **type-enforced**, not just documented: [`new`](Self::new)
/// takes a [`VerifiedOriginConnector`], whose only production constructor
/// ([`VerifiedOriginConnector::from_system_roots`]) builds from the
/// platform's real trust anchors and fails closed on an empty or unreadable
/// store. The test-only escape hatch
/// ([`VerifiedOriginConnector::for_test`]) is `#[cfg(test)]`, so it does not
/// exist in a production build — there is no bare `TlsConnector` overload
/// for a production caller to reach for `dangerous()`,
/// `with_custom_certificate_verifier`, or an empty `RootCertStore` with.
///
/// The invariant this protects has not changed: this module re-originates a
/// TLS connection to the real upstream on behalf of the sandboxed
/// container, using the same host/port the container thought it was
/// dialing. If `origin_connector` ever fails to verify the origin's
/// certificate against a real root store, this seam stops being a
/// credential firewall and becomes a working, silent MITM against our own
/// users' egress traffic to every "bound" host — the exact opposite of what
/// W6 exists to build. `crates/ironclaw_architecture` also bans the escape
/// hatches (`dangerous(`, `with_custom_certificate_verifier`,
/// `RootCertStore::empty()`) from non-test code under
/// `sandbox_process/`, so a caller can no longer route around this type and
/// hand-roll a permissive connector either.
#[allow(dead_code)] // consumed by W6; not wired yet
pub(crate) struct TlsInterceptConfig {
    ca: SandboxCertificateAuthority,
    bound_hosts: HashSet<String>,
    origin_connector: VerifiedOriginConnector,
}

impl TlsInterceptConfig {
    #[allow(dead_code)] // constructed by this module's tests; a production caller is future wiring
    pub(crate) fn new(
        ca: SandboxCertificateAuthority,
        bound_hosts: HashSet<String>,
        origin_connector: VerifiedOriginConnector,
    ) -> Self {
        Self {
            ca,
            bound_hosts: bound_hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
            origin_connector,
        }
    }

    /// D1's predicate: is `host` one this proxy instance terminates TLS for?
    /// Case-insensitive to match `egress_proxy::host_allowed`'s own
    /// normalization. Everything not in this set stays an opaque tunnel —
    /// see the module doc's D1 section.
    #[allow(dead_code)] // consumed by W6; not wired yet
    pub(crate) fn is_bound(&self, host: &str) -> bool {
        self.bound_hosts.contains(&host.to_ascii_lowercase())
    }

    /// Test/introspection seam: how many hosts this config's CA currently
    /// holds a cached leaf certificate for — D1's assertion surface for "an
    /// unbound host must never have a leaf minted for it," independent of
    /// whether traffic merely *looked* like it flowed correctly.
    #[cfg(test)]
    #[allow(dead_code)] // consumed by W6; not wired yet
    pub(crate) fn cached_leaf_count(&self) -> usize {
        self.ca.cached_entry_count()
    }
}

/// Bound applied to every handshake/dial leg of [`terminate_and_forward`]:
/// the client TLS accept, the origin TCP dial, and the origin TLS connect.
/// The client side of this seam is untrusted worker/container traffic — a
/// peer that opens the socket and then sends nothing (or half a
/// `ClientHello` and stalls) must not be able to pin this task and its
/// sockets open indefinitely. Deliberately does **not** bound
/// `copy_bidirectional`'s steady-state relay: an idle-timeout/byte-ceiling
/// policy for a live, decrypted proxy connection is a product decision (what
/// counts as "idle," whether a byte cap is even correct for a general HTTPS
/// relay that legitimately serves large downloads) that belongs with
/// whichever PR gives this seam a production caller and a concurrency/fan-out
/// policy to sit inside, not invented ad hoc here.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

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
#[allow(dead_code)] // consumed by W6; not wired yet
pub(crate) async fn terminate_and_forward(
    client: TcpStream,
    leftover: Vec<u8>,
    host: &str,
    dial_addr: SocketAddr,
    config: &TlsInterceptConfig,
) -> Result<(), TlsInterceptError> {
    terminate_and_forward_with_timeout(client, leftover, host, dial_addr, config, HANDSHAKE_TIMEOUT)
        .await
}

/// The timeout-parameterized core `terminate_and_forward` delegates to with
/// [`HANDSHAKE_TIMEOUT`] — split out so tests can drive the timeout branch
/// deterministically with a short real duration instead of either sleeping
/// [`HANDSHAKE_TIMEOUT`] wall-clock seconds or fighting tokio's paused/
/// advanceable virtual clock against a task that also does real loopback
/// socket I/O.
#[allow(dead_code)] // consumed by W6; not wired yet
async fn terminate_and_forward_with_timeout(
    client: TcpStream,
    leftover: Vec<u8>,
    host: &str,
    dial_addr: SocketAddr,
    config: &TlsInterceptConfig,
    handshake_timeout: Duration,
) -> Result<(), TlsInterceptError> {
    let issued =
        config
            .ca
            .issue_leaf_for_host(host)
            .map_err(|error| TlsInterceptError::LeafMintFailed {
                host: host.to_string(),
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
    let mut client_tls =
        tokio::time::timeout(handshake_timeout, acceptor.accept(client_with_leftover))
            .await
            .map_err(|_| {
                TlsInterceptError::ClientHandshakeFailed(format!(
                    "client handshake timed out after {handshake_timeout:?}"
                ))
            })?
            .map_err(|error| TlsInterceptError::ClientHandshakeFailed(error.to_string()))?;

    // Only reachable once the client trusts our leaf and completed its
    // handshake — a client-side failure above never gets this far, so an
    // unbound/failed interception never opens an origin socket either.
    //
    // Validate the SNI host BEFORE dialing the origin. `ca.rs::
    // validate_dns_host` is a charset/length plausibility filter, not full
    // RFC 1035 label-syntax enforcement (its own doc comment says so) — it
    // accepts hosts (e.g. a hyphen-prefixed label) that `ServerName::
    // try_from` rejects as an invalid DNS name. Dialing first would open a
    // real outbound TCP connection to an attacker-influenced host that is
    // about to be rejected anyway; validating first means an invalid host
    // never causes any origin-directed network activity at all.
    let server_name = ServerName::try_from(host.to_string()).map_err(|error| {
        TlsInterceptError::InvalidSniHost {
            host: host.to_string(),
            reason: error.to_string(),
        }
    })?;
    let origin_stream = tokio::time::timeout(handshake_timeout, TcpStream::connect(dial_addr))
        .await
        .map_err(|_| TlsInterceptError::OriginDialFailed {
            dial_addr,
            reason: format!("dial timed out after {handshake_timeout:?}"),
        })?
        .map_err(|error| TlsInterceptError::OriginDialFailed {
            dial_addr,
            reason: error.to_string(),
        })?;
    let mut origin_tls = tokio::time::timeout(
        handshake_timeout,
        config
            .origin_connector
            .connector()
            .connect(server_name, origin_stream),
    )
    .await
    .map_err(|_| {
        TlsInterceptError::OriginHandshakeFailed(format!(
            "origin handshake timed out after {handshake_timeout:?}"
        ))
    })?
    .map_err(|error| TlsInterceptError::OriginHandshakeFailed(error.to_string()))?;

    copy_bidirectional(&mut client_tls, &mut origin_tls)
        .await
        .map_err(|error| TlsInterceptError::RelayFailed(error.to_string()))?;
    Ok(())
}

/// Builds a single-host rustls server config serving exactly the leaf
/// certificate minted for one host — no SNI-keyed multi-cert resolver is
/// needed because a CONNECT tunnel already pins the intended host before
/// this is called (see [`terminate_and_forward`]); the client's SNI, if
/// present, is not consulted.
#[allow(dead_code)] // consumed by W6; not wired yet
pub(crate) fn build_server_config(
    leaf: &LeafCertificate,
) -> Result<rustls::ServerConfig, TlsInterceptError> {
    ensure_crypto_provider_installed();
    let chain = CertificateDer::pem_slice_iter(leaf.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            TlsInterceptError::ServerConfigFailed(format!("parsing leaf cert pem: {error}"))
        })?;
    // `PrivateKeyDer::from_pem_slice` (unlike `rustls_pemfile::private_key`'s
    // `Result<Option<_>>`) already returns `Err(pem::Error::NoItemsFound)`
    // when the PEM contains no key — no separate `None` case to handle, and
    // still fails closed exactly the same as the explicit `ok_or_else` this
    // replaces.
    let key = PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes()).map_err(|error| {
        TlsInterceptError::ServerConfigFailed(format!("parsing leaf key pem: {error}"))
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
#[allow(dead_code)] // consumed by W6; not wired yet
struct LeadingBytes<S> {
    leftover: Vec<u8>,
    leftover_pos: usize,
    inner: S,
}

impl<S> LeadingBytes<S> {
    #[allow(dead_code)] // consumed by W6; not wired yet
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
