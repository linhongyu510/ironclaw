//! Tests for the sandbox TLS-termination seam (`super`), split into their own
//! file so `tls_intercept.rs` stays a production-sized module — the same
//! `#[cfg(test)] mod tests;` shape `credential_firewall` and `credential_swap`
//! already use in this directory.
//!
//! Two tiers live here on purpose. The phase-1 tests drive the interception
//! mechanism itself (our CA's leaf is what the client sees; a failed client
//! handshake never dials the origin). The phase-2 tests drive the credential
//! swap end to end through a real rustls client and a real TLS origin, because
//! the invariant they pin — the real secret reaches the origin and nothing the
//! container can observe — is only meaningful across the whole boundary.

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

/// `read_request_head`'s three fail-closed/framing paths, exercised directly
/// against the function rather than through the full TLS harness — cheap,
/// and these are exactly the framing-boundary decisions
/// `a_pipelined_second_request_cannot_borrow_the_first_requests_authorization`
/// established matter for correctness.
mod read_request_head_framing {
    use super::*;

    /// Exceeding the cap without ever seeing the terminator must fail
    /// closed rather than keep growing the buffer forever.
    #[tokio::test]
    async fn over_the_size_cap_without_a_terminator_is_request_head_too_large() {
        let (mut client, mut server) = tokio::io::duplex(128 * 1024);
        let body = vec![b'a'; MAX_REQUEST_HEAD_BYTES + 1];
        let writer = tokio::spawn(async move {
            server.write_all(&body).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let error = read_request_head(&mut client).await.unwrap_err();

        assert!(matches!(
            error,
            TlsInterceptError::RequestHeadTooLarge { .. }
        ));
        writer.await.unwrap();
    }

    /// EOF after some bytes were buffered but before `\r\n\r\n` was seen is
    /// a distinct failure from `Ok(None)` (EOF before any byte at all): the
    /// client sent a partial, unusable head rather than simply not
    /// connecting.
    #[tokio::test]
    async fn eof_after_a_partial_head_is_malformed_request_head() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            server
                .write_all(b"GET /x HTTP/1.1\r\nHost: h")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });

        let error = read_request_head(&mut client).await.unwrap_err();

        assert!(matches!(error, TlsInterceptError::MalformedRequestHead));
        writer.await.unwrap();
    }

    /// EOF before any byte at all is not malformed — it's simply no
    /// request, e.g. a client that connected and disconnected.
    #[tokio::test]
    async fn eof_before_any_byte_is_ok_none() {
        let (mut client, server) = tokio::io::duplex(64);
        drop(server);

        let result = read_request_head(&mut client).await.unwrap();

        assert!(result.is_none());
    }

    /// The four-byte terminator itself must be found even when it straddles
    /// two separate reads — the scan re-examines the whole accumulated
    /// buffer each iteration, not just the newly read chunk.
    #[tokio::test]
    async fn a_terminator_split_across_two_reads_is_still_found() {
        // An 8-byte duplex buffer forces `read_request_head`'s internal
        // 4096-byte-chunk reads to actually arrive in several small pieces,
        // so the `\r\n\r\n` terminator (which starts mid-way through the
        // head) straddles at least two of its `client.read()` calls.
        let (mut client, mut server) = tokio::io::duplex(8);
        let trailing = b"trailing-bytes".to_vec();
        let payload = [b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n".as_slice(), &trailing].concat();
        let writer = tokio::spawn(async move {
            server.write_all(&payload).await.unwrap();
            server.shutdown().await.unwrap();
        });

        let (head, rest) = read_request_head(&mut client)
            .await
            .unwrap()
            .expect("a well-formed head arrives");
        assert_eq!(head, b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n");

        // Whatever of `trailing` hadn't yet arrived when the terminator was
        // found is still sitting in the pipe for the next reader (the
        // scrubbing relay) to pick up — `read_request_head` only reports
        // what it already had, never blocks to slurp more.
        let mut remainder = rest;
        client.read_to_end(&mut remainder).await.unwrap();
        assert_eq!(remainder, trailing);
        writer.await.unwrap();
    }
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
    CapabilityId, ExtensionId, InvocationId, NetworkMethod, ResourceScope, SecretHandle, TenantId,
    UserId,
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
    format!("GET /repos/x HTTP/1.1\r\nHost: {BOUND_HOST}\r\nAuthorization: token {token}\r\n\r\n")
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
