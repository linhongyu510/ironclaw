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
};

use rustls::pki_types::ServerName;
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
#[allow(dead_code)] // consumed by egress_proxy's W6 wiring; not wired in this slice
static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

#[allow(dead_code)] // consumed by egress_proxy's W6 wiring; not wired in this slice
fn ensure_crypto_provider_installed() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Errors from the TLS-termination seam. Every variant is a **fail-closed**
/// signal to the caller: `egress_proxy::handle_connect` treats any `Err`
/// here as "close the connection," never "fall back to a plaintext tunnel."
#[allow(dead_code)] // consumed by egress_proxy's W6 wiring; not wired in this slice
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
#[allow(dead_code)] // fields consumed by egress_proxy's W6 wiring; not wired in this slice
pub(crate) struct TlsInterceptConfig {
    ca: SandboxCertificateAuthority,
    bound_hosts: HashSet<String>,
    /// See the struct-level `# WARNING` above: this MUST be built from a
    /// real trusted root store in production (e.g. `rustls-native-certs`),
    /// and MUST NEVER use `dangerous()`, a verifier that skips verification,
    /// or an empty root store. Getting this wrong turns the whole TLS
    /// interception seam into a silent MITM against our own users.
    origin_connector: TlsConnector,
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
        }
    }

    /// D1's predicate: is `host` one this proxy instance terminates TLS for?
    /// Case-insensitive to match `egress_proxy::host_allowed`'s own
    /// normalization. Everything not in this set stays an opaque tunnel —
    /// see the module doc's D1 section.
    #[allow(dead_code)] // consumed by egress_proxy's W6 wiring; not wired in this slice
    pub(crate) fn is_bound(&self, host: &str) -> bool {
        self.bound_hosts.contains(&host.to_ascii_lowercase())
    }

    /// Test/introspection seam: how many hosts this config's CA currently
    /// holds a cached leaf certificate for — D1's assertion surface for "an
    /// unbound host must never have a leaf minted for it," independent of
    /// whether traffic merely *looked* like it flowed correctly.
    #[cfg(test)]
    #[allow(dead_code)] // consumed by egress_proxy's own tests; not exercised in this slice
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
#[allow(dead_code)] // consumed by egress_proxy's W6 wiring; not wired in this slice
pub(crate) async fn terminate_and_forward(
    client: TcpStream,
    leftover: Vec<u8>,
    host: &str,
    dial_addr: SocketAddr,
    config: &TlsInterceptConfig,
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
    let mut client_tls = acceptor
        .accept(client_with_leftover)
        .await
        .map_err(|error| TlsInterceptError::ClientHandshakeFailed(error.to_string()))?;

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
            host: host.to_string(),
            reason: error.to_string(),
        }
    })?;
    let mut origin_tls = config
        .origin_connector
        .connect(server_name, origin_stream)
        .await
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
#[allow(dead_code)] // consumed by egress_proxy's W6 wiring; not wired in this slice
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
#[allow(dead_code)] // consumed by egress_proxy's W6 wiring; not wired in this slice
struct LeadingBytes<S> {
    leftover: Vec<u8>,
    leftover_pos: usize,
    inner: S,
}

impl<S> LeadingBytes<S> {
    #[allow(dead_code)] // consumed by egress_proxy's W6 wiring; not wired in this slice
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
    use std::time::Duration;
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
            terminate_and_forward(stream, Vec::new(), host, origin_addr, &config).await
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
}
