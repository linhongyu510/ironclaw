use super::*;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::UnixTime;
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use x509_parser::prelude::*;

/// Test-only certificate verifier that accepts anything — used by
/// [`invalid_sni_host_fails_before_the_origin_is_dialed`] purely to let a
/// real rustls client complete its handshake against a leaf certificate
/// whose SAN (a padded, untrimmed host) cannot itself be turned into a
/// `ServerName` to check against; the property under test is the *server*
/// side's dial-vs-validate ordering, not client-side certificate
/// verification, so skipping verification here does not weaken the
/// assertion. `dangerous()`/`with_custom_certificate_verifier` are banned
/// in production `sandbox_process/` code by
/// `reborn_tls_verification_escape_hatches.rs`, which exempts standalone
/// `tests.rs` files precisely for cases like this one.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

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
        let result = terminate_and_forward(stream, Vec::new(), host, origin_addr, &config).await;
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

/// The empty-host case above never reaches `ServerName::try_from` at all —
/// `ca.rs`'s `host.is_empty()` check rejects it first, at the leaf-mint
/// step, so it cannot prove the *ordering* between the origin dial and the
/// SNI-host validation. This test needs a host that reaches the leaf mint
/// and client handshake successfully but still fails `ServerName::
/// try_from`. `ca.rs::validate_dns_host` used to supply one for free (its
/// hand-rolled charset check accepted a leading/trailing hyphen that
/// `ServerName::try_from` rejects) — that divergence was closed by
/// delegating `validate_dns_host` to `rustls_pki_types::DnsName` (see
/// `ca::tests::leading_hyphen_label_is_rejected`), so a host that is
/// syntactically a valid DNS name no longer works here.
///
/// What still diverges — independent of DNS-name *syntax* — is
/// canonicalization: `SandboxCertificateAuthority::issue_leaf_for_host`
/// trims and lowercases `host` before validating and minting (so the
/// leaf's own SAN/CN is the canonical form), but this module's SNI check a
/// few lines below constructs `ServerName::try_from` from the *original,
/// untrimmed* `host` parameter. A host with incidental leading/trailing
/// whitespace — the exact input the trimming was added to tolerate, per
/// `issue_leaf_for_host`'s own doc comment — is therefore still accepted
/// at the mint step and still rejected at the SNI-parse step below. That
/// is a real, separate defect (the SNI value sent toward the origin should
/// be built from the same canonical host the leaf was minted for, not
/// re-derived from the raw parameter) that this PR does not fix, but it
/// keeps this test's premise genuinely true: the leaf mint and client
/// handshake below succeed and this test still reaches
/// `terminate_and_forward_with_timeout`'s SNI-validation step. It pins two
/// things together: `Err(InvalidSniHost)` (correctness) AND that the
/// origin listener never observed a connection (the ordering fix) — the
/// exact combination `invalid_host_fails_before_the_origin_is_dialed`
/// cannot prove, because it short-circuits before either the dial or the
/// validation is reached.
#[tokio::test]
async fn invalid_sni_host_fails_before_the_origin_is_dialed() {
    let host = "  padded-sni-host.example.com  ";

    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin_listener.local_addr().unwrap();
    let origin_saw_a_connection = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_millis(300), origin_listener.accept()).await
    });

    let ca = SandboxCertificateAuthority::generate().unwrap();
    // Confirm the premise: `ca.rs` trims and accepts this host as a
    // mintable DNS SAN, so the leaf mint and client handshake below
    // succeed and this test actually reaches the SNI-validation step, not
    // `LeafMintFailed`.
    ca.issue_leaf_for_host(host)
        .expect("ca.rs must accept a padded host (after trimming) as a mintable host");

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

    let client = TcpStream::connect(proxy_addr).await.unwrap();
    // A real rustls client handshake against our CA-signed leaf, using a
    // verifier that accepts anything (see `NoVerify`'s doc) — the leaf's
    // SAN is the padded (untrimmed) `host`, which cannot itself be turned into
    // a `ServerName` for the client to check against, so client-side cert
    // verification is not what this test is proving. The SNI value passed
    // here is arbitrary: `build_server_config`'s comment notes the server
    // side never consults it.
    ensure_crypto_provider_installed();
    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost").unwrap();
    let _ = connector.connect(server_name, client).await;

    let result = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task must finish")
        .expect("server task did not panic");
    assert!(
        matches!(result, Err(TlsInterceptError::InvalidSniHost { .. })),
        "expected Err(InvalidSniHost) for a padded (untrimmed) SNI host, got: {result:?}"
    );

    let origin_result = origin_saw_a_connection
        .await
        .expect("origin probe task did not panic");
    assert!(
        origin_result.is_err(),
        "origin must never be dialed when the SNI host fails validation \
         (fail-closed before dial) — this is the ordering bug: before the \
         fix, the origin WAS dialed here because `TcpStream::connect` ran \
         before `ServerName::try_from`"
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
