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
    let server_name = ServerName::try_from(host.to_string()).map_err(|error| {
        TlsInterceptError::InvalidSniHost {
            host: host.to_string(),
            reason: error.to_string(),
        }
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
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use x509_parser::prelude::*;

    /// Builds a [`VerifiedOriginConnector`] (via the `#[cfg(test)]`-only
    /// [`VerifiedOriginConnector::for_test`] escape hatch) that trusts
    /// exactly one extra root — the test seam standing in for "production
    /// would use system roots" (see the module doc). Used to make a fake
    /// local origin TLS server trusted by the connector under test without
    /// depending on any real certificate authority.
    fn connector_trusting_only(root_pem: &str) -> VerifiedOriginConnector {
        ensure_crypto_provider_installed();
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(root_pem.as_bytes()) {
            roots
                .add(cert.expect("valid root cert pem"))
                .expect("root cert adds");
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        VerifiedOriginConnector::for_test(TlsConnector::from(Arc::new(client_config)))
    }

    /// A [`VerifiedOriginConnector`] with an empty trust store — every
    /// origin handshake through it fails certificate verification. Used to
    /// force the fail-closed path deterministically without relying on
    /// network conditions.
    fn connector_trusting_nothing() -> VerifiedOriginConnector {
        ensure_crypto_provider_installed();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        VerifiedOriginConnector::for_test(TlsConnector::from(Arc::new(client_config)))
    }

    /// Spins up a local TLS "origin" server on loopback, using its own
    /// self-signed CA (separate from the CA under test) so tests can
    /// distinguish "chains to our CA" from "chains to the origin's own
    /// cert." Echoes back whatever it receives once, then closes — enough
    /// to prove decrypted bytes actually reach the origin and come back.
    ///
    /// The returned `AtomicBool` flips to `true` iff the origin's TLS
    /// handshake completed *and* it read at least one byte of plaintext —
    /// the assertion surface tests use to prove that a failure elsewhere in
    /// `terminate_and_forward` (e.g. the origin handshake itself failing)
    /// never lets any decrypted application data reach the origin.
    async fn spawn_fake_tls_origin(host: &str) -> (SocketAddr, String, Arc<AtomicBool>) {
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
        let received_plaintext = Arc::new(AtomicBool::new(false));
        let received_plaintext_writer = Arc::clone(&received_plaintext);

        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(mut tls) = acceptor.accept(stream).await
            {
                let mut buf = [0u8; 256];
                if let Ok(n) = tls.read(&mut buf).await
                    && n > 0
                {
                    received_plaintext_writer.store(true, Ordering::SeqCst);
                    let _ = tls.write_all(&buf[..n]).await;
                    let _ = tls.shutdown().await;
                }
            }
        });

        (
            addr,
            origin_ca.root_certificate_pem().to_string(),
            received_plaintext,
        )
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

    /// `is_bound`'s doc comment claims case-insensitive matching "to match
    /// `egress_proxy::host_allowed`'s own normalization" — this pins that
    /// the *implementation* actually delivers it, not just the comment.
    /// `TlsInterceptConfig::new` lowercases every host it's constructed
    /// with, and `is_bound` lowercases its query argument, so a
    /// lowercase-configured allowlist must still match a mixed-case query —
    /// exactly what a real CONNECT host (whose casing a client controls)
    /// can look like on the wire. A case-sensitive allowlist here would be
    /// a security bug: it would let a client dodge interception (or, if
    /// the allowlist federated a broader policy, dodge a security control)
    /// just by changing the request's casing.
    #[test]
    fn is_bound_matches_a_mixed_case_query_against_a_lowercase_allowlist() {
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let bound_hosts = HashSet::from(["bound.example.com".to_string()]);
        let config = TlsInterceptConfig::new(ca, bound_hosts, connector_trusting_nothing());

        assert!(config.is_bound("BOUND.EXAMPLE.COM"));
        assert!(config.is_bound("Bound.Example.Com"));
        assert_eq!(config.ca.cached_entry_count(), 0);
    }

    /// An empty allowlist must reject every host, including one that would
    /// otherwise look plausible — the degenerate case of D1's "unbound
    /// stays an opaque tunnel" invariant with no bound hosts configured at
    /// all (e.g. before W12's binding model has bound anything yet).
    #[test]
    fn is_bound_is_false_for_any_host_when_bound_hosts_is_empty() {
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let config = TlsInterceptConfig::new(ca, HashSet::new(), connector_trusting_nothing());

        assert!(!config.is_bound("bound.example.com"));
        assert!(!config.is_bound(""));
    }

    /// A BOUND host is genuinely intercepted end to end: a real rustls
    /// client dialing through `terminate_and_forward` completes its TLS
    /// handshake against a certificate chaining to OUR CA (not the fake
    /// origin's own CA), and the decrypted bytes it sends still reach the
    /// origin and echo back — proving both the MITM cert swap and the
    /// relay work, not just the handshake.
    ///
    /// Also exercises `LeadingBytes` replay (`leftover` non-empty), the
    /// "eager client" case the module doc describes: the server task reads
    /// a small prefix directly off the accepted socket — standing in for
    /// bytes `egress_proxy`'s own `BufReader` would have already buffered
    /// past the CONNECT request — and hands it to `terminate_and_forward`
    /// as `leftover` instead of leaving it on the socket for the acceptor
    /// to read itself. If the replay were broken, the acceptor would be
    /// missing the first bytes of the `ClientHello` and the handshake below
    /// would fail instead of completing.
    #[tokio::test]
    async fn bound_host_is_intercepted_with_our_ca_and_relays_bytes() {
        let host = "bound.example.com";
        let (origin_addr, origin_root_pem, _origin_received_plaintext) =
            spawn_fake_tls_origin(host).await;

        let ca = SandboxCertificateAuthority::generate().unwrap();
        let our_root_pem = ca.root_certificate_pem().to_string();
        let bound_hosts = HashSet::from([host.to_string()]);
        let config =
            TlsInterceptConfig::new(ca, bound_hosts, connector_trusting_only(&origin_root_pem));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await.unwrap();
            // Peel a small prefix of the client's `ClientHello` off the raw
            // socket ourselves, exactly as `egress_proxy`'s `BufReader`
            // would if it had already buffered these bytes while parsing
            // the CONNECT request. The rest of the `ClientHello` is still
            // sitting on the socket for the acceptor to read normally.
            let mut leftover = [0u8; 4];
            stream
                .read_exact(&mut leftover)
                .await
                .expect("reads the buffered ClientHello prefix");
            terminate_and_forward(stream, leftover.to_vec(), host, origin_addr, &config).await
        });

        // The "container" side: a real rustls client, trusting only OUR
        // CA's root — if the proxy served the origin's own cert (or any
        // cert not signed by our CA), this handshake fails.
        let mut our_roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(our_root_pem.as_bytes()) {
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
            terminate_and_forward(stream, Vec::new(), host, origin_addr, &config).await
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

    /// Fail-closed on the *other* handshake leg: the client's handshake with
    /// the proxy succeeds fine (the proxy serves a leaf the client trusts),
    /// but re-originating TLS to the origin fails because `origin_connector`
    /// (deliberately `connector_trusting_nothing()` here) does not trust the
    /// fake origin's self-signed cert. `terminate_and_forward` must return
    /// `OriginHandshakeFailed` and — the invariant this test exists to pin —
    /// the origin must never receive a single byte of decrypted application
    /// data: a TLS handshake failure happens strictly before any application
    /// data would be exchanged, so there is no window where a partial relay
    /// could leak plaintext.
    #[tokio::test]
    async fn origin_handshake_failure_never_leaks_plaintext_to_the_origin() {
        let host = "bound.example.com";
        let (origin_addr, _origin_root_pem_untrusted_on_purpose, origin_received_plaintext) =
            spawn_fake_tls_origin(host).await;

        let ca = SandboxCertificateAuthority::generate().unwrap();
        let our_root_pem = ca.root_certificate_pem().to_string();
        let bound_hosts = HashSet::from([host.to_string()]);
        // `connector_trusting_nothing()` is the deterministic fail-closed
        // lever: the origin's cert chains to a throwaway CA no root store
        // trusts, so the origin handshake below must fail certificate
        // verification.
        let config = TlsInterceptConfig::new(ca, bound_hosts, connector_trusting_nothing());

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            terminate_and_forward(stream, Vec::new(), host, origin_addr, &config).await
        });

        // The "container" side trusts OUR ca, so its own handshake with the
        // proxy succeeds regardless of what happens next between the proxy
        // and the origin — this test's assertions are on
        // `terminate_and_forward`'s return value and the origin's receipt,
        // not on the client's own view of its handshake.
        let mut our_roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(our_root_pem.as_bytes()) {
            our_roots.add(cert.unwrap()).unwrap();
        }
        ensure_crypto_provider_installed();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(our_roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let raw_client = TcpStream::connect(proxy_addr).await.unwrap();
        let server_name = ServerName::try_from(host.to_string()).unwrap();
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            connector.connect(server_name, raw_client),
        )
        .await;

        let result = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server task must finish")
            .expect("server task did not panic");
        assert!(
            matches!(result, Err(TlsInterceptError::OriginHandshakeFailed(_))),
            "expected an origin handshake failure, got: {result:?}"
        );
        assert!(
            !origin_received_plaintext.load(Ordering::SeqCst),
            "origin must never receive decrypted application data when the origin handshake \
             itself fails — that would mean a partial relay leaked plaintext despite the \
             fail-closed contract"
        );
    }

    /// The untrusted-client DoS this seam must not be vulnerable to: a peer
    /// that opens the socket and then never sends a `ClientHello` (or stalls
    /// mid-handshake) must not be able to pin this task and its client
    /// socket open forever. Drives `terminate_and_forward_with_timeout`
    /// directly with a short real duration (rather than
    /// `HANDSHAKE_TIMEOUT`'s production value) so the test proves the
    /// timeout wiring itself without sleeping tens of seconds of real wall
    /// clock.
    #[tokio::test]
    async fn client_handshake_times_out_instead_of_hanging_forever() {
        let host = "bound.example.com";
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let config = TlsInterceptConfig::new(
            ca,
            HashSet::from([host.to_string()]),
            connector_trusting_nothing(),
        );

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        // Never dialed: the client handshake times out well before
        // `terminate_and_forward` would reach the origin-dial step.
        let unreachable_origin_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            terminate_and_forward_with_timeout(
                stream,
                Vec::new(),
                host,
                unreachable_origin_addr,
                &config,
                Duration::from_millis(200),
            )
            .await
        });

        // Connects but never sends a byte.
        let _raw_client = TcpStream::connect(proxy_addr).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server task must finish (the timeout must fire, not hang forever)")
            .expect("server task did not panic");
        match result {
            Err(TlsInterceptError::ClientHandshakeFailed(reason)) => {
                assert!(
                    reason.contains("timed out"),
                    "expected a timeout reason, got: {reason}"
                );
            }
            other => panic!("expected a client-handshake timeout, got: {other:?}"),
        }
    }

    /// **This is the test that must not be faked.** Every other test in this
    /// file builds its own `VerifiedOriginConnector::for_test` connector —
    /// correct for those tests, but it proves nothing about
    /// `VerifiedOriginConnector::from_system_roots` itself, which is the
    /// only production door and the one a wiring bug could actually reach.
    /// This test drives `from_system_roots` directly: it builds a connector
    /// from the platform's real trust anchors, points it at a loopback
    /// origin serving a certificate from a throwaway self-signed CA that no
    /// real trust store has ever heard of (the same `spawn_fake_tls_origin`
    /// helper other tests use, minus handing the connector its root PEM),
    /// and asserts the handshake fails. If `from_system_roots` ever silently
    /// trusted everything (an empty root store that verifies nothing, or a
    /// `dangerous()` verifier), this is the test that would start passing
    /// against a real MITM instead of catching it.
    #[tokio::test]
    async fn from_system_roots_rejects_an_untrusted_origin_certificate() {
        let host = "untrusted-origin.example.com";
        let (origin_addr, _origin_root_pem_unused_on_purpose, _origin_received_plaintext) =
            spawn_fake_tls_origin(host).await;

        let connector = VerifiedOriginConnector::from_system_roots()
            .expect("system trust store must load on the test host");

        let origin_stream = TcpStream::connect(origin_addr)
            .await
            .expect("tcp connect to the fake origin must succeed");
        let server_name = ServerName::try_from(host.to_string()).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            connector.connector().connect(server_name, origin_stream),
        )
        .await
        .expect("handshake must not hang");

        let error = result.expect_err(
            "from_system_roots() must reject a certificate from a CA no real trust store \
             recognizes — an Ok here means the production connector verifies against \
             nothing, which is exactly the MITM this type exists to prevent",
        );
        // Not just "any I/O error": pin that this is specifically a
        // certificate-verification rejection (`rustls::Error`, the type
        // `tokio-rustls` wraps as the `io::Error`'s source), so this test
        // can't be satisfied by an unrelated TCP/protocol failure that
        // happens to also return `Err`.
        let source = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<rustls::Error>());
        assert!(
            matches!(source, Some(rustls::Error::InvalidCertificate(_))),
            "expected a certificate-verification rejection (rustls::Error::InvalidCertificate), \
             got: {error:?}"
        );
    }

    /// `build_server_config` must fail closed — `ServerConfigFailed`, never
    /// a panic or a silently-accepted config — when the cert PEM it's
    /// handed doesn't parse. Covers both "not PEM at all" (garbage bytes)
    /// and "syntactically PEM-shaped but empty" (no cert blocks), since
    /// `CertificateDer::pem_slice_iter` can fail on either. Nothing at the
    /// call site (`terminate_and_forward_with_timeout`) touches the origin
    /// before this returns, so a malformed leaf can never reach the dial
    /// step either.
    #[test]
    fn build_server_config_fails_closed_on_garbage_cert_pem() {
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let mut leaf = ca
            .issue_leaf_for_host("bound.example.com")
            .unwrap()
            .certificate;
        leaf.cert_pem = "this is not pem at all".to_string();

        let result = build_server_config(&leaf);
        assert!(
            matches!(result, Err(TlsInterceptError::ServerConfigFailed(_))),
            "expected Err(ServerConfigFailed) for garbage cert pem, got: {result:?}"
        );
    }

    #[test]
    fn build_server_config_fails_closed_on_empty_cert_pem() {
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let mut leaf = ca
            .issue_leaf_for_host("bound.example.com")
            .unwrap()
            .certificate;
        leaf.cert_pem = String::new();

        let result = build_server_config(&leaf);
        assert!(
            matches!(result, Err(TlsInterceptError::ServerConfigFailed(_))),
            "expected Err(ServerConfigFailed) for empty cert pem, got: {result:?}"
        );
    }

    /// Same fail-closed contract, the key-parsing leg: `build_server_config`
    /// parses `leaf.key_pem` via `PrivateKeyDer::from_pem_slice` *after* the
    /// cert PEM already parsed successfully, so this exercises a different
    /// branch than the cert-PEM tests above — a valid cert paired with a
    /// broken key must still fail closed rather than build a config with
    /// no usable private key.
    #[test]
    fn build_server_config_fails_closed_on_garbage_key_pem() {
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let mut leaf = ca
            .issue_leaf_for_host("bound.example.com")
            .unwrap()
            .certificate;
        leaf.key_pem = "this is not pem at all".to_string();

        let result = build_server_config(&leaf);
        assert!(
            matches!(result, Err(TlsInterceptError::ServerConfigFailed(_))),
            "expected Err(ServerConfigFailed) for garbage key pem, got: {result:?}"
        );
    }

    #[test]
    fn build_server_config_fails_closed_on_empty_key_pem() {
        let ca = SandboxCertificateAuthority::generate().unwrap();
        let mut leaf = ca
            .issue_leaf_for_host("bound.example.com")
            .unwrap()
            .certificate;
        leaf.key_pem = String::new();

        let result = build_server_config(&leaf);
        assert!(
            matches!(result, Err(TlsInterceptError::ServerConfigFailed(_))),
            "expected Err(ServerConfigFailed) for empty key pem, got: {result:?}"
        );
    }

    /// "Test through the caller, not just the helper": an invalid host
    /// (here, empty) must make `terminate_and_forward` itself fail — before
    /// the origin is ever dialed, and before a leaf is even minted — not
    /// merely make some inner helper return an error in isolation. A unit
    /// test on `SandboxCertificateAuthority::issue_leaf_for_host` alone
    /// would not prove the *caller* (`terminate_and_forward`) actually
    /// surfaces that failure fail-closed instead of, say, dialing the
    /// origin first. Mirrors `client_handshake_failure_never_dials_the_
    /// origin`'s fake-origin/timeout-probe machinery so "no dial happened"
    /// is observed directly, not inferred from the `Err` return alone.
    ///
    /// The empty host is rejected at `issue_leaf_for_host` itself (`ca.rs`'s
    /// `host.is_empty()` check), the very first fallible step in
    /// `terminate_and_forward_with_timeout` — so this test additionally
    /// pins the strongest form of "before": no leaf is minted at all, not
    /// just "minted but never sent to the origin."
    #[tokio::test]
    async fn invalid_host_fails_before_the_origin_is_dialed() {
        let host = "";

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin_saw_a_connection = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(300), origin_listener.accept()).await
        });

        let ca = SandboxCertificateAuthority::generate().unwrap();
        let config = TlsInterceptConfig::new(
            ca,
            HashSet::from([host.to_string()]),
            connector_trusting_nothing(),
        );
        let cached_leaf_count_before = config.cached_leaf_count();

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let result =
                terminate_and_forward(stream, Vec::new(), host, origin_addr, &config).await;
            (result, config.cached_leaf_count())
        });

        // Connects but never sends a byte — irrelevant here, since the
        // invalid-host failure happens before the server task ever reads
        // from this socket.
        let _raw_client = TcpStream::connect(proxy_addr).await.unwrap();

        let (result, cached_leaf_count_after) =
            tokio::time::timeout(Duration::from_secs(5), server_task)
                .await
                .expect("server task must finish")
                .expect("server task did not panic");
        assert!(
            matches!(result, Err(TlsInterceptError::LeafMintFailed { .. })),
            "expected Err(LeafMintFailed) for an empty host, got: {result:?}"
        );
        assert_eq!(
            cached_leaf_count_after, cached_leaf_count_before,
            "an invalid host must never mint a leaf certificate"
        );

        let origin_result = origin_saw_a_connection
            .await
            .expect("origin probe task did not panic");
        assert!(
            origin_result.is_err(),
            "origin must never be dialed when the host is invalid (fail-closed before dial)"
        );
    }

    /// `from_system_roots`'s fail-closed empty-store branch lives in
    /// `from_root_store` precisely so it is deterministically testable
    /// without depending on — or faking — the real OS trust store being
    /// empty. An empty `RootCertStore` reaching this point must always be
    /// `Err(TrustRootsUnavailable)`, never a silent `Ok` connector that
    /// verifies against nothing.
    #[test]
    fn from_root_store_fails_closed_on_an_empty_store() {
        let result = VerifiedOriginConnector::from_root_store(rustls::RootCertStore::empty());
        match result {
            Err(TlsInterceptError::TrustRootsUnavailable(_)) => {}
            Err(other) => {
                panic!("expected Err(TrustRootsUnavailable), got a different Err: {other}")
            }
            Ok(_) => panic!(
                "expected Err(TrustRootsUnavailable) for an empty root store, got Ok — an \
                 empty store must never silently produce a connector that verifies against \
                 nothing"
            ),
        }
    }
}
