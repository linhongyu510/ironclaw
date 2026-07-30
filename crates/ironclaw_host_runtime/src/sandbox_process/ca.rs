//! Internal per-tenant CA for the sandbox egress proxy (W5 — design doc
//! `docs/plans/2026-07-26-sandbox-credential-firewall-design.md` §4).
//!
//! Generates a root key/cert pair **in memory only**, at construction, and
//! signs short-lived leaf certificates for hosts the credential firewall
//! (W6) intercepts. The root private key never touches disk, is never
//! serialized anywhere this module returns to a caller, and is never part
//! of anything mounted into a container — only
//! [`SandboxCertificateAuthority::root_certificate_pem`] (the public trust
//! anchor) is meant to reach the container filesystem, as a read-only
//! bind mount (W5's remaining trust-distribution work, see the design
//! doc's `update-ca-certificates` note). This is the same "secret material
//! never enters the container, in any form, even transiently" invariant
//! the rest of the credential firewall enforces, applied to the CA itself.
//!
//! **W6 is the consumer, not built yet.** Nothing in this crate calls
//! [`SandboxCertificateAuthority`] today; the proxy's TLS termination for
//! bound hosts will call [`SandboxCertificateAuthority::issue_leaf_for_host`]
//! per intercepted CONNECT, per the design doc's D1/W6 gating.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use base64::Engine as _;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls_pki_types::DnsName;
use time::{Duration as CertValidityDuration, OffsetDateTime};

use crate::RuntimeProcessError;

/// Default validity window for a leaf certificate, and the default cache
/// TTL — short by design so a leaked leaf key (a mounted-into-container
/// artifact, unlike the root) is only useful for a bounded window. The
/// cache TTL intentionally matches the cert's own validity: caching a leaf
/// past its `not_after` would just hand back an already-expired cert.
#[allow(dead_code)] // consumed by W6; not wired yet
pub(crate) const DEFAULT_LEAF_TTL: Duration = Duration::from_secs(5 * 60);

/// Clock-skew allowance applied to `not_before` so a cert issued a moment
/// ago is never rejected as "not yet valid" by a container whose clock
/// runs slightly behind the host's.
const NOT_BEFORE_SKEW: CertValidityDuration = CertValidityDuration::minutes(5);

/// Root CA validity window. The root is regenerated fresh in memory on
/// every process start (see the module doc and [`SandboxCertificateAuthority::generate`]),
/// so this only has to comfortably outlive one process's lifetime — cross-restart
/// rotation is W6/operational wiring, not this unwired primitive's job.
const ROOT_VALIDITY: CertValidityDuration = CertValidityDuration::days(30);

/// Upper bound on the number of distinct hosts a CA instance caches leaf
/// certificates for at once. Bounded so a proxy terminating TLS for an
/// unbounded number of distinct SNI hosts cannot grow this cache without
/// limit; the oldest-issued entry is evicted first once the bound is hit.
#[allow(dead_code)] // consumed by W6; not wired yet
pub(crate) const DEFAULT_MAX_CACHE_ENTRIES: usize = 256;

/// A leaf certificate issued for exactly one host: PEM cert + PEM private
/// key, both the *leaf's* material only. The root private key never
/// appears in either field.
#[derive(Clone)]
#[allow(dead_code)] // consumed by W6; not wired yet
pub(crate) struct LeafCertificate {
    pub(crate) host: String,
    pub(crate) cert_pem: String,
    pub(crate) key_pem: String,
}

impl std::fmt::Debug for LeafCertificate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omit `key_pem`: it is the leaf's private key material
        // and must never persist in logs or panic output, even though (unlike
        // the root key) it is a bounded, short-lived, container-scoped
        // artifact this design otherwise accepts.
        formatter
            .debug_struct("LeafCertificate")
            .field("host", &self.host)
            .field("cert_pem", &self.cert_pem)
            .finish_non_exhaustive()
    }
}

/// [`SandboxCertificateAuthority::issue_leaf_for_host`]'s result. Exposes
/// whether the leaf came from the bounded cache or was freshly minted —
/// useful to a future caller deciding whether a live connection needs a
/// newly-issued cert pushed to it, and to this module's own cache tests.
#[derive(Debug, Clone)]
#[allow(dead_code)] // consumed by W6; not wired yet
pub(crate) struct IssuedLeaf {
    pub(crate) certificate: LeafCertificate,
    pub(crate) cache_hit: bool,
}

struct CachedLeaf {
    // Not `Arc`-wrapped: nothing here shares this pointer between callers —
    // `cached_leaf` immediately dereferences and clones the value out, and
    // the fresh-issuance path already clones before inserting. Plain
    // ownership avoids indirection that solves no aliasing problem.
    leaf: LeafCertificate,
    inserted_at: Instant,
    /// When this cache entry stops being live, in this process's monotonic
    /// clock. Computed once at mint time from the leaf's *actual* (possibly
    /// root-capped, see [`SandboxCertificateAuthority::mint_leaf`]) `not_after`
    /// — never derived from `leaf_ttl` alone. A leaf minted late in the
    /// root's life can have a real certificate lifetime shorter than
    /// `leaf_ttl`; keying cache expiry off `leaf_ttl` directly would let the
    /// cache keep serving that leaf after its certificate (and root) have
    /// actually expired.
    expires_at: Instant,
}

/// In-memory root CA plus a bounded, TTL-scoped cache of per-host leaf
/// certificates. See the module doc for the "root key never leaves the
/// host" invariant this type exists to uphold: the root signing key lives
/// only in the private `issuer` field below, and no method on this type
/// returns it.
#[allow(dead_code)] // consumed by W6; not wired yet
pub(crate) struct SandboxCertificateAuthority {
    root_cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
    /// The root's own `not_after`. A leaf's validity must never outlive its
    /// trust anchor — see [`Self::mint_leaf`]'s cap — so this is kept
    /// alongside `issuer` (whose `params` field, carrying the same value,
    /// is moved-from and no longer independently readable once wrapped in
    /// `Issuer`).
    root_not_after: OffsetDateTime,
    leaf_ttl: Duration,
    max_cache_entries: usize,
    cache: Mutex<HashMap<String, CachedLeaf>>,
}

impl std::fmt::Debug for SandboxCertificateAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omit `issuer` (carries the root private key —
        // `rcgen::Issuer`'s own `Debug` already elides key material, but
        // this type never even calls that impl) and `cache` (leaf private
        // keys are also secret-shaped). Neither belongs in a log line.
        formatter
            .debug_struct("SandboxCertificateAuthority")
            .field("leaf_ttl", &self.leaf_ttl)
            .field("max_cache_entries", &self.max_cache_entries)
            .finish_non_exhaustive()
    }
}

impl SandboxCertificateAuthority {
    /// Generates a fresh root key + self-signed CA certificate **in
    /// memory** and returns a CA ready to issue leaf certs, using the
    /// production leaf TTL and cache bound. The root private key lives
    /// only in this process's memory for the lifetime of the returned
    /// value — it is never written to disk, never serialized, and never
    /// handed to a caller.
    #[allow(dead_code)] // consumed by W6; not wired yet
    pub(crate) fn generate() -> Result<Self, RuntimeProcessError> {
        Self::generate_with(DEFAULT_LEAF_TTL, DEFAULT_MAX_CACHE_ENTRIES)
    }

    /// Same as [`Self::generate`] with an explicit leaf TTL and cache
    /// bound — the seam this module's own tests use to exercise TTL
    /// expiry and eviction without waiting on the production defaults.
    #[allow(dead_code)] // exercised by this module's own tests; W6 may call it directly later
    pub(crate) fn generate_with(
        leaf_ttl: Duration,
        max_cache_entries: usize,
    ) -> Result<Self, RuntimeProcessError> {
        let mut params = CertificateParams::new(Vec::new()).map_err(ca_error)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "IronClaw Sandbox Egress CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "IronClaw");
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        let now = OffsetDateTime::now_utc();
        params.not_before = now
            .checked_sub(NOT_BEFORE_SKEW)
            .ok_or_else(|| ca_range_error("root not_before"))?;
        params.not_after = now
            .checked_add(ROOT_VALIDITY)
            .ok_or_else(|| ca_range_error("root not_after"))?;

        let root_not_after = params.not_after;
        let root_key = KeyPair::generate().map_err(ca_error)?;
        // `self_signed` only borrows `params` — signing happens before
        // `params` moves into `Issuer::new` just below.
        let root_cert = params.self_signed(&root_key).map_err(ca_error)?;
        let root_cert_pem = root_cert.pem();
        let issuer = Issuer::new(params, root_key);

        Ok(Self {
            root_cert_pem,
            issuer,
            root_not_after,
            leaf_ttl,
            max_cache_entries,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The CA's public trust anchor — the only artifact of this CA meant
    /// to reach a container (read-only bind-mount + `SSL_CERT_FILE` and
    /// friends is W5's remaining trust-distribution work). Contains no
    /// private key material; see this module's
    /// `root_certificate_pem_never_contains_key_material` test.
    #[allow(dead_code)] // consumed by W6; not wired yet
    pub(crate) fn root_certificate_pem(&self) -> &str {
        &self.root_cert_pem
    }

    /// Builds the container-side TLS trust bundle: the platform's real
    /// system root certificates (via `rustls-native-certs`, the same source
    /// `tls_intercept::VerifiedOriginConnector::from_system_roots` trusts
    /// for verifying the *real* origin when re-originating a bound host's
    /// TLS connection) concatenated with this CA's own public root
    /// certificate, both PEM-encoded.
    ///
    /// This is the artifact `egress_proxy::bind_sandbox_egress_proxy_with_tls_intercept`
    /// bind-mounts read-only into every sandbox container (W5's CA
    /// trust-distribution work, this module's own doc comment). Contains
    /// **no private key material** — it is built purely from `native.certs`
    /// (public DER certificates) and [`Self::root_cert_pem`] (itself never
    /// containing the root's private key, which lives only in the
    /// process-local `issuer` field and is never returned by any method on
    /// this type). See `container_trust_bundle_pem_contains_no_key_material`.
    ///
    /// System roots are included, not just this CA's own root: a container
    /// only has intercepted (bound-host) connections signed by our CA — every
    /// other allowed host (any wildcard-matched allowlist entry, since
    /// `bound_hosts` is exact-match only) stays an opaque, un-terminated
    /// tunnel, so the container's own TLS client verifies THAT origin's real
    /// certificate directly. For an OpenSSL-linked client (`curl`, `git`,
    /// Python's `ssl` module), `SSL_CERT_FILE` REPLACES the default trust
    /// store rather than extending it — a bundle containing only our CA
    /// would make every non-intercepted HTTPS request fail cert
    /// verification the moment `SSL_CERT_FILE` is set.
    ///
    /// Fails closed (`Err`, never a silently empty bundle) when the system
    /// trust store yields zero usable roots — mirrors
    /// `VerifiedOriginConnector::from_system_roots`'s identical fail-closed
    /// posture for the same underlying data source. The caller
    /// (`bind_sandbox_egress_proxy_with_tls_intercept`) propagates this as
    /// `EgressProxyError::TlsInterceptSetupFailed`, so a broken/empty host
    /// trust store fails the whole sandbox-profile boot rather than shipping
    /// containers a trust bundle that can never intercept anything.
    pub(crate) fn build_container_trust_bundle_pem(&self) -> Result<String, RuntimeProcessError> {
        let native = rustls_native_certs::load_native_certs();
        for error in &native.errors {
            // `debug!`, not `warn!`/`info!` — see the identical rationale on
            // `VerifiedOriginConnector::from_system_roots`: an internal
            // diagnostic on a background boot path, never REPL/TUI-visible
            // status.
            tracing::debug!(
                "sandbox CA: error loading a system root cert for the container trust bundle: {error}"
            );
        }
        if native.certs.is_empty() {
            return Err(RuntimeProcessError::ExecutionFailed(
                "sandbox CA: system trust store yielded zero usable root certificates; \
                 refusing to build a container trust bundle without them"
                    .to_string(),
            ));
        }
        let mut bundle = String::new();
        for cert in &native.certs {
            bundle.push_str(&der_to_pem(cert.as_ref()));
        }
        bundle.push_str(&self.root_cert_pem);
        Ok(bundle)
    }

    /// Returns a leaf certificate for `host`: a live cached one if present,
    /// or a freshly minted (and cached) one otherwise. Every leaf's only
    /// SAN is the requested host, and the cache is keyed by the
    /// canonicalized (trimmed, lowercased) host string — issuing for one
    /// host can never hand back a cert valid for another, and case/padding
    /// variants of the same host share one cache entry.
    #[allow(dead_code)] // consumed by W6; not wired yet
    pub(crate) fn issue_leaf_for_host(
        &self,
        host: &str,
    ) -> Result<IssuedLeaf, RuntimeProcessError> {
        // Normalize once, at the boundary: DNS names are case-insensitive
        // and an intercepted CONNECT's SNI/host can carry incidental
        // whitespace or a trailing root-zone dot. Trimming only the
        // emptiness *check* while minting and caching on the untrimmed,
        // original-case string (the prior behavior) would bake padding into
        // the SAN/CN and let case variants of the same host multiply cache
        // entries — on a bounded, oldest-first-eviction cache, that lets a
        // peer choosing SNI case variants evict unrelated live entries.
        // Every downstream use (cache key, SAN, CN) shares this one
        // canonical form. This is the same [`normalize_host`] callers
        // upstream of this CA (e.g.
        // `tls_intercept::terminate_and_forward_with_timeout`) apply before
        // they ever call here — see that function's doc for why a *second*
        // independent normalization here still matters even once callers
        // normalize first: this method must stay safe to call with a raw,
        // unnormalized host on its own. `None` (empty/whitespace-only/
        // all-dots input) is rejected here rather than silently coerced to
        // an empty string that could reach the length/DNS-syntax checks
        // below with different semantics than callers expect.
        let Some(host) = normalize_host(host) else {
            return Err(RuntimeProcessError::ExecutionFailed(
                "sandbox CA: host must not be empty".to_string(),
            ));
        };
        // `rcgen` accepts arbitrary ASCII strings as a DNS SAN — it does not
        // itself reject control characters, wildcards, or oversized input.
        // A network-controlled CONNECT host reaches this call, so the CA
        // must validate it is a plausible DNS name before spending a key
        // generation and signing pass on it. (The length bound above is
        // re-checked here too, post-trim, since trimming can only shrink
        // the string — this second check is what actually enforces the
        // bound on the canonical form.)
        validate_dns_host(&host)?;
        let now = Instant::now();
        if let Some(certificate) = self.cached_leaf(&host, now) {
            return Ok(IssuedLeaf {
                certificate,
                cache_hit: true,
            });
        }

        let (leaf, expires_at) = self.mint_leaf(&host, now)?;
        self.insert_and_evict(host, leaf.clone(), now, expires_at);
        Ok(IssuedLeaf {
            certificate: leaf,
            cache_hit: false,
        })
    }

    /// Test/introspection seam: how many hosts currently hold a cached
    /// leaf, without exposing the cache's contents.
    #[cfg(test)]
    pub(crate) fn cached_entry_count(&self) -> usize {
        self.lock_cache().len()
    }

    /// Test/introspection seam: how much longer a just-cached host's entry
    /// has to live, so a test can pin that the cache's own TTL clock tracks
    /// the leaf's actual (possibly root-capped) expiry rather than the raw
    /// `leaf_ttl` alone.
    #[cfg(test)]
    pub(crate) fn cached_leaf_ttl_remaining(&self, host: &str) -> Option<Duration> {
        let cache = self.lock_cache();
        let entry = cache.get(host)?;
        Some(
            entry
                .expires_at
                .saturating_duration_since(entry.inserted_at),
        )
    }

    fn cached_leaf(&self, host: &str, now: Instant) -> Option<LeafCertificate> {
        let mut cache = self.lock_cache();
        let entry = cache.get(host)?;
        if now >= entry.expires_at {
            cache.remove(host);
            return None;
        }
        Some(entry.leaf.clone())
    }

    fn mint_leaf(
        &self,
        host: &str,
        now_instant: Instant,
    ) -> Result<(LeafCertificate, Instant), RuntimeProcessError> {
        let mut params = CertificateParams::new(vec![host.to_string()]).map_err(ca_error)?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let now = OffsetDateTime::now_utc();
        params.not_before = now
            .checked_sub(NOT_BEFORE_SKEW)
            .ok_or_else(|| ca_range_error("leaf not_before"))?;
        let leaf_ttl = CertValidityDuration::try_from(self.leaf_ttl).map_err(|error| {
            RuntimeProcessError::ExecutionFailed(format!(
                "sandbox CA: leaf ttl out of range: {error}"
            ))
        })?;
        let requested_not_after = now
            .checked_add(leaf_ttl)
            .ok_or_else(|| ca_range_error("leaf not_after"))?;
        // A leaf must never outlive its own trust anchor: the root is
        // regenerated fresh per process start (see the module doc) and has
        // its own fixed `ROOT_VALIDITY`, so a leaf minted late in the root's
        // life would otherwise carry a `not_after` past the point at which
        // nothing can validate it against the root anymore.
        params.not_after = requested_not_after.min(self.root_not_after);
        if params.not_after <= params.not_before {
            return Err(RuntimeProcessError::ExecutionFailed(
                "sandbox CA: root certificate has expired; cannot issue a leaf".to_string(),
            ));
        }

        // The cache's TTL clock must track this leaf's *actual* not_after
        // (post root-cap), not the raw `leaf_ttl` the caller/default
        // requested — see `CachedLeaf::expires_at`'s doc. Converts the
        // wall-clock `not_after` into a monotonic instant relative to this
        // call's own `now_instant`, so `cached_leaf` can compare like against
        // like.
        let remaining = if params.not_after > now {
            params.not_after - now
        } else {
            CertValidityDuration::ZERO
        };
        let remaining_std = Duration::try_from(remaining).unwrap_or(Duration::ZERO);
        let expires_at = now_instant
            .checked_add(remaining_std)
            .unwrap_or(now_instant);

        let leaf_key = KeyPair::generate().map_err(ca_error)?;
        let cert = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(ca_error)?;

        Ok((
            LeafCertificate {
                host: host.to_string(),
                cert_pem: cert.pem(),
                key_pem: leaf_key.serialize_pem(),
            },
            expires_at,
        ))
    }

    fn insert_and_evict(
        &self,
        host: String,
        leaf: LeafCertificate,
        now: Instant,
        expires_at: Instant,
    ) {
        let mut cache = self.lock_cache();
        cache.insert(
            host,
            CachedLeaf {
                leaf,
                inserted_at: now,
                expires_at,
            },
        );
        // Bounded eviction: drop the oldest-inserted entry until back
        // within budget, one at a time (cache sizes here are small, so an
        // O(n) scan per eviction is cheap and needs no extra ordering
        // structure to keep in sync with the map).
        while cache.len() > self.max_cache_entries {
            let oldest = cache
                .iter()
                .min_by_key(|(_, cached)| cached.inserted_at)
                .map(|(host, _)| host.clone());
            match oldest {
                Some(host) => {
                    cache.remove(&host);
                }
                None => break,
            }
        }
    }

    fn lock_cache(&self) -> MutexGuard<'_, HashMap<String, CachedLeaf>> {
        self.cache
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// The one definition of "the host" for the entire sandbox egress/TLS-
/// interception seam: trimmed of surrounding whitespace, stripped of any
/// trailing DNS root-zone dot(s), and lowercased. DNS names are
/// case-insensitive and `pypi.org.` is a legal, equivalently-resolving FQDN
/// for `pypi.org`, so every consumer that decides identity from a host
/// string — the CONNECT-target parse and hostname allowlist check
/// (`egress_proxy::handle_connect`, `egress_proxy::host_allowed`), the
/// bound-hosts set and its lookup (`tls_intercept::TlsInterceptConfig::new`/
/// `is_bound`/`bind`), leaf-cert mint/cache key
/// ([`SandboxCertificateAuthority::issue_leaf_for_host`]), and the SNI value
/// threaded to the origin dial (`tls_intercept::terminate_and_forward_with_timeout`)
/// — must canonicalize through this exact function. Independently-normalizing
/// call sites is precisely how two asymmetries shipped here before: the
/// leaf-mint/SNI-dial one this function originally replaced (one side
/// trimmed+lowercased, the other did neither), and a second one where
/// `host_allowed` stripped a trailing dot but the bound-hosts lookup did
/// not — a `CONNECT pypi.org.` then passed the allowlist as `pypi.org` but
/// missed the (dot-free) bound-hosts entry, silently falling through to an
/// unintercepted opaque tunnel. One chokepoint removes the class, not just
/// one instance of it.
///
/// Returns `None` — reject, don't silently canonicalize — for input that
/// normalizes to nothing meaningful: empty, all-whitespace, or all-dots
/// (`"."`, `".."`, ...) input. Turning `"."` into `""` and then matching an
/// empty-string entry somewhere downstream would be a new bug of exactly
/// the same shape this function exists to prevent; a host that means
/// nothing after normalization must fail the caller's decision, never
/// coerce into an empty string that could accidentally participate in one.
pub(crate) fn normalize_host(host: &str) -> Option<String> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

/// PEM-encodes a single DER certificate: `-----BEGIN CERTIFICATE-----`,
/// standard base64 wrapped at 64 columns, `-----END CERTIFICATE-----`.
/// Base64's output alphabet (`A-Za-z0-9+/=`) is pure single-byte ASCII, so
/// slicing `encoded` at fixed byte offsets below can never land inside a
/// multi-byte character — unlike the general "never byte-slice
/// user/external text" rule this crate otherwise enforces, `encoded` is
/// this function's own programmatically generated output, not user or
/// external text.
fn der_to_pem(der: &[u8]) -> String {
    const LABEL_BEGIN: &str = "-----BEGIN CERTIFICATE-----\n";
    const LABEL_END: &str = "-----END CERTIFICATE-----\n";
    const LINE_WIDTH: usize = 64;

    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::with_capacity(
        LABEL_BEGIN.len() + LABEL_END.len() + encoded.len() + encoded.len() / LINE_WIDTH + 1,
    );
    pem.push_str(LABEL_BEGIN);
    let mut start = 0;
    while start < encoded.len() {
        let end = (start + LINE_WIDTH).min(encoded.len());
        pem.push_str(&encoded[start..end]);
        pem.push('\n');
        start = end;
    }
    pem.push_str(LABEL_END);
    pem
}

fn ca_error(error: rcgen::Error) -> RuntimeProcessError {
    RuntimeProcessError::ExecutionFailed(format!("sandbox CA: {error}"))
}

fn ca_range_error(field: &str) -> RuntimeProcessError {
    RuntimeProcessError::ExecutionFailed(format!(
        "sandbox CA: {field} computation overflowed the valid date range"
    ))
}

/// Bound on total DNS name length (RFC 1035 §3.1): 253 visible characters
/// (255 octets on the wire, minus the length-prefix and root-label bytes).
/// Kept as an explicit pre-check only so an oversized host is rejected
/// before the `DnsName` parse below runs — `DnsName::try_from_str` enforces
/// the identical bound (its own `MAX_NAME_LENGTH`) as part of the delegated
/// validation, so this can never reject something that check would accept.
const MAX_DNS_HOST_LEN: usize = 253;

/// Rejects hosts `rcgen` itself would accept as a DNS SAN but that are not
/// syntactically valid DNS names. Delegates the actual syntax check to
/// `rustls_pki_types::DnsName` — the same type `ServerName::try_from`
/// (`tls_intercept.rs`'s SNI-host check, which runs before this CA's leaf
/// is used to dial the origin) constructs internally — rather than
/// hand-rolling a second copy of RFC 1035 label syntax. Two independently
/// maintained DNS-name validators drift (this crate already collapsed one
/// such duplicate, the trusted-variant list on PR #6747), and here that
/// drift is dangerous specifically because this function's `Ok` gates a
/// real (if short-lived, if bounded) certificate mint: a host this
/// function accepted that `ServerName::try_from` then rejected would burn
/// a mint on a host that can never complete interception. Delegating means
/// a host this function accepts is *by construction* one `ServerName::
/// try_from` also accepts — including case and padding, since both this
/// function's caller and `terminate_and_forward_with_timeout` canonicalize
/// through the same [`normalize_host`] before either the mint or the SNI
/// conversion runs. `host` is expected to already be trimmed and lowercased
/// by the caller.
fn validate_dns_host(host: &str) -> Result<(), RuntimeProcessError> {
    if host.len() > MAX_DNS_HOST_LEN {
        return Err(RuntimeProcessError::ExecutionFailed(format!(
            "sandbox CA: host exceeds the maximum DNS name length of {MAX_DNS_HOST_LEN}"
        )));
    }
    if host.contains('*') {
        return Err(RuntimeProcessError::ExecutionFailed(
            "sandbox CA: wildcard hosts are not permitted".to_string(),
        ));
    }
    DnsName::try_from_str(host).map_err(|error| {
        // The public error is intentionally sanitized (no attacker-influenced
        // host content echoed back), but the parse cause must not simply
        // vanish — `RuntimeProcessError::ExecutionFailed` here gates
        // certificate minting, so a discarded cause would make a real
        // validator regression undebuggable. See
        // `.claude/rules/error-handling.md`'s `map_err(|_| ...)` rule.
        tracing::debug!("sandbox CA: host failed DnsName parse: {error}");
        RuntimeProcessError::ExecutionFailed(
            "sandbox CA: host is not a syntactically valid DNS name".to_string(),
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests;
