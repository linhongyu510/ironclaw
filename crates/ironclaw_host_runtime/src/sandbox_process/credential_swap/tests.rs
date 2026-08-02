//! Unit coverage for the decision logic behind the swap. The end-to-end
//! properties (the real secret reaching the origin and never the container,
//! the two refusals, D1) are pinned through the real TLS path in
//! `super::super::tls_intercept`'s tests — this module covers only the pieces
//! that path cannot vary cheaply: token scanning at the exact-length
//! boundary, and each individual reason a resolvable placeholder is stripped
//! instead of swapped.

use super::*;

use ironclaw_host_api::{
    ids::{CapabilityId, ExtensionId, InvocationId, SecretHandle},
    resource::ResourceScope,
};
use ironclaw_secrets::{CredentialPathPolicy, SecretMaterial};

use super::super::credential_firewall::{
    StagedCredentialObligation, StagedCredentialObligationSource, StagedObligationLease,
};

// `pub(crate)`: `tls_intercept`'s caller-level ordering test (CR-004) reuses
// both constants so its granted-swap assertion checks for the exact same
// secret/host this module's own tests do, instead of inventing a second
// pair that could silently drift from these.
pub(crate) const REAL_SECRET: &str = "ghp-REAL-SECRET-MATERIAL-nsQ82hd7";
pub(crate) const HOST: &str = "bound.example.com";

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).unwrap()
}

fn user(value: &str) -> UserId {
    UserId::new(value).unwrap()
}

fn provider(value: &str) -> ExtensionId {
    ExtensionId::new(value).unwrap()
}

fn scope_for(tenant_id: &TenantId, user_id: &UserId) -> ResourceScope {
    ResourceScope {
        tenant_id: tenant_id.clone(),
        user_id: user_id.clone(),
        agent_id: None,
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

fn policy(path: &str, method: NetworkMethod) -> CredentialTargetPolicy {
    CredentialTargetPolicy {
        scheme: "https".to_string(),
        host: HOST.to_string(),
        port: None,
        path: CredentialPathPolicy::Prefix(path.to_string()),
        methods: vec![method],
    }
}

fn far_future() -> Instant {
    Instant::now() + std::time::Duration::from_secs(3600)
}

/// `pub(crate)`: reused as-is by `tls_intercept`'s caller-level ordering
/// test (CR-004), which needs a real granted `SandboxCredentialSwap` driven
/// through the actual `terminate_and_forward` — see this module's own doc
/// for why the end-to-end properties belong there, not here.
pub(crate) struct Fixture {
    pub(crate) swap: SandboxCredentialSwap,
    pub(crate) token: String,
    pub(crate) tenant_id: TenantId,
    pub(crate) user_id: UserId,
    /// Keeps the staged grant alive — `StagedObligationLease::drop` revokes
    /// it (see that type's doc). `pub(crate)` (not `_`-only-private) so a
    /// caller outside this module, like `tls_intercept`'s CR-004 test, can
    /// destructure `Fixture` and hold this for the lifetime of its own
    /// scope instead of the grant being revoked the instant the fixture is
    /// unpacked.
    pub(crate) lease: StagedObligationLease,
}

/// One staged grant for `(tenant-a, user-a, <grant_provider>)` covering
/// `policy`, plus a placeholder minted for `(tenant-a, user-a, <token_provider>)`.
/// Every strip-reason test varies exactly one of those inputs.
pub(crate) fn fixture(
    token_provider: &str,
    grant_provider: &str,
    policy: CredentialTargetPolicy,
) -> Fixture {
    let tenant_id = tenant("tenant-a");
    let user_id = user("user-a");
    let registry = Arc::new(CredentialPlaceholderRegistry::new());
    let token = registry
        .get_or_create(&tenant_id, &user_id, &provider(token_provider))
        .expect("placeholder mints")
        .as_str()
        .to_string();
    let firewall = Arc::new(SandboxCredentialFirewall::new());
    let injections = RuntimeSecretInjectionStore::new();
    let scope = scope_for(&tenant_id, &user_id);
    let capability = CapabilityId::new("sandbox.shell").unwrap();
    let handle = SecretHandle::new("github-token").unwrap();
    injections
        .insert(
            &scope,
            &capability,
            &handle,
            SecretMaterial::from(REAL_SECRET.to_string()),
        )
        .expect("staged material inserts");
    let lease = firewall.stage(
        &tenant_id,
        &user_id,
        StagedCredentialObligation::new(
            StagedCredentialObligationSource {
                scope,
                capability_id: capability,
                provider_or_extension_id: provider(grant_provider),
                secret_handle: handle,
            },
            vec![policy],
            std::time::Duration::from_secs(600),
        ),
    );
    Fixture {
        swap: SandboxCredentialSwap::new(registry, firewall, injections),
        token,
        tenant_id,
        user_id,
        lease,
    }
}

fn head_with(token: &str, method: &str, path: &str) -> Vec<u8> {
    format!("{method} {path} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: token {token}\r\n\r\n")
        .into_bytes()
}

fn rewrite(fixture: &Fixture, head: &[u8]) -> String {
    let rewritten = fixture
        .swap
        .rewrite_request_head(
            head,
            HOST,
            Some((&fixture.tenant_id, &fixture.user_id)),
            far_future(),
        )
        .expect("attributed lookup within deadline must not be a connection denial");
    String::from_utf8(rewritten.bytes().to_vec()).expect("rewritten head is utf-8")
}

#[test]
fn a_matching_grant_substitutes_the_real_secret_for_the_placeholder() {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    let rewritten = rewrite(&fixture, &head_with(&fixture.token, "GET", "/repos/x"));

    assert!(rewritten.contains(REAL_SECRET));
    assert!(!rewritten.contains(&fixture.token));
}

/// The token belongs to a *different* provider than the staged grant. Both
/// credentials are the same user's own, so nothing about tenancy catches
/// this — only the provider check does.
#[test]
fn a_grant_for_another_provider_never_satisfies_this_placeholder() {
    let fixture = fixture("npm", "github", policy("/repos", NetworkMethod::Get));
    let rewritten = rewrite(&fixture, &head_with(&fixture.token, "GET", "/repos/x"));

    assert!(!rewritten.contains(REAL_SECRET));
    assert!(!rewritten.contains(&fixture.token));
}

#[test]
fn a_path_outside_the_grants_target_policy_is_stripped_not_swapped() {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    let rewritten = rewrite(&fixture, &head_with(&fixture.token, "GET", "/admin/keys"));

    assert!(!rewritten.contains(REAL_SECRET));
    assert!(!rewritten.contains(&fixture.token));
}

#[test]
fn a_method_outside_the_grants_target_policy_is_stripped_not_swapped() {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    let rewritten = rewrite(&fixture, &head_with(&fixture.token, "DELETE", "/repos/x"));

    assert!(!rewritten.contains(REAL_SECRET));
    assert!(!rewritten.contains(&fixture.token));
}

/// A method `NetworkMethod` does not model cannot be checked against a
/// policy, so it must never be treated as covered.
#[test]
fn an_unmodelled_method_is_stripped_rather_than_assumed_covered() {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    let rewritten = rewrite(&fixture, &head_with(&fixture.token, "OPTIONS", "/repos/x"));

    assert!(!rewritten.contains(REAL_SECRET));
    assert!(!rewritten.contains(&fixture.token));
}

/// User B presenting user A's placeholder: the registry resolves it (it is a
/// real token), but it is not this connection's. Never swap, and never let it
/// through either.
#[test]
fn a_placeholder_owned_by_another_user_is_stripped() {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    let other_tenant = tenant("tenant-a");
    let other_user = user("user-b");

    let rewritten = fixture
        .swap
        .rewrite_request_head(
            &head_with(&fixture.token, "GET", "/repos/x"),
            HOST,
            Some((&other_tenant, &other_user)),
            far_future(),
        )
        .expect("a cross-user token is a grant decision, not a connection denial");
    let text = String::from_utf8(rewritten.bytes().to_vec()).unwrap();

    assert!(!text.contains(REAL_SECRET));
    assert!(!text.contains(&fixture.token));
}

/// An absolute-form request line pointing at a different authority than the
/// CONNECT host must not be reconciled into a match.
#[test]
fn an_absolute_form_target_for_another_authority_is_rejected() {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    let head = format!(
        "GET https://evil.example.com/repos/x HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: token {}\r\n\r\n",
        fixture.token
    )
    .into_bytes();

    let rewritten = rewrite(&fixture, &head);

    assert!(!rewritten.contains(REAL_SECRET));
}

/// CONNECTION-DENIAL must propagate out of the swap unchanged, never be
/// softened into "no grant, strip and forward".
#[test]
fn an_unattributed_connection_is_a_connection_denial_not_a_strip() {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));

    let error = fixture
        .swap
        .rewrite_request_head(
            &head_with(&fixture.token, "GET", "/repos/x"),
            HOST,
            None,
            far_future(),
        )
        .expect_err("an unattributed connection carrying a placeholder must be denied");

    assert_eq!(error, SandboxCredentialFirewallError::AttributionFailed);
}

/// A head with no placeholder at all must not consult the firewall — an
/// uncredentialed public request through a bound host cannot be allowed to
/// fail on an attribution problem that has no bearing on it (D5).
#[test]
fn a_head_without_a_placeholder_is_untouched_even_when_unattributed() {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    let head = format!("GET /repos/x HTTP/1.1\r\nHost: {HOST}\r\n\r\n").into_bytes();

    let rewritten = fixture
        .swap
        .rewrite_request_head(&head, HOST, None, far_future())
        .expect("no placeholder means no firewall lookup, so no connection denial");

    assert_eq!(rewritten.bytes(), head.as_slice());
    assert_eq!(rewritten.report(), &SandboxCredentialSwapReport::default());
}

/// Exact-length enforcement, both directions, plus the charset rule. This is
/// the host-protection property from `CREDENTIAL_PLACEHOLDER_SUFFIX_LEN`'s own
/// doc comment: untrusted container bytes must not be able to present an
/// arbitrarily long `icsbx_...` run and drive work on the host.
#[test]
fn only_an_exactly_sized_alphanumeric_suffix_is_a_placeholder_candidate() {
    let exact = format!("icsbx_{}", "a".repeat(32));
    let too_long = format!("icsbx_{}", "a".repeat(33));
    let way_too_long = format!("icsbx_{}", "a".repeat(4096));
    let too_short = format!("icsbx_{}", "a".repeat(31));
    let non_alnum = format!("icsbx_{}!", "a".repeat(31));

    assert_eq!(placeholder_candidates(exact.as_bytes()).len(), 1);
    assert_eq!(placeholder_candidates(too_long.as_bytes()).len(), 0);
    assert_eq!(placeholder_candidates(way_too_long.as_bytes()).len(), 0);
    assert_eq!(placeholder_candidates(too_short.as_bytes()).len(), 0);
    assert_eq!(placeholder_candidates(non_alnum.as_bytes()).len(), 0);

    // Delimited on both sides is the normal case, and two in one buffer are
    // both found without overlapping.
    let embedded = format!("Authorization: token {exact}\r\nX-Second: {exact}\r\n");
    assert_eq!(placeholder_candidates(embedded.as_bytes()).len(), 2);
}

/// Every model-visible string this module produces goes through
/// `LeakDetector` first. The CONNECT host is container-controlled, so a
/// container that names a placeholder-shaped host would otherwise put a
/// live-looking token straight into a model-visible annotation.
#[test]
fn the_grant_denial_annotation_is_leak_scrubbed() {
    let hostile_host = format!("icsbx_{}", "b".repeat(32));
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    // No matching target ⇒ stripped ⇒ an annotation is produced.
    let rewritten = fixture
        .swap
        .rewrite_request_head(
            &head_with(&fixture.token, "GET", "/admin/keys"),
            &hostile_host,
            Some((&fixture.tenant_id, &fixture.user_id)),
            far_future(),
        )
        .expect("grant denial is a decision, not a connection denial");

    let annotation = rewritten
        .report()
        .annotation
        .as_deref()
        .expect("a stripped placeholder must produce an annotation");
    assert!(
        !annotation.contains(&hostile_host),
        "the container-controlled host must be scrubbed out of model-visible text: {annotation}"
    );
    assert_eq!(rewritten.report().stripped, 1);
    assert_eq!(rewritten.report().swapped, 0);
}

/// The rewritten head holds real secret material, so its `Debug` must never
/// print it — the exact failure shape an earlier review of this subsystem
/// found twice (a derived `Debug` on a leaf certificate printing a private
/// key, and one on a staged obligation printing a secret handle).
#[test]
fn rewritten_head_debug_never_prints_the_secret() {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    let rewritten = fixture
        .swap
        .rewrite_request_head(
            &head_with(&fixture.token, "GET", "/repos/x"),
            HOST,
            Some((&fixture.tenant_id, &fixture.user_id)),
            far_future(),
        )
        .expect("grant applies");

    // The swap really happened — otherwise this test would pass vacuously.
    assert!(String::from_utf8_lossy(rewritten.bytes()).contains(REAL_SECRET));

    let debug_output = format!("{rewritten:?}");
    assert!(!debug_output.contains(REAL_SECRET), "{debug_output}");
    assert!(!debug_output.contains(&fixture.token), "{debug_output}");
}

/// The swap itself holds the registry (token → tenant/user) and the material
/// store; neither may be printed.
#[test]
fn swap_debug_never_prints_identity_or_material() {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    let debug_output = format!("{:?}", fixture.swap);

    assert!(!debug_output.contains(REAL_SECRET));
    assert!(!debug_output.contains(&fixture.token));
    assert!(!debug_output.contains("tenant-a"));
}

/// `scrub_prefix` sees the streaming carry buffer one read at a time, so a
/// candidate whose match window ends exactly at the buffer's current end has
/// not actually been confirmed exact-length yet — the byte that would prove
/// it (alphanumeric ⇒ a longer, non-placeholder run; anything else ⇒ genuinely
/// exact) simply has not been read. It must not be committed (stripped or
/// passed through as "inside") until a future read confirms it one way or the
/// other, or EOF (`min_hold_back == 0`) makes "no more bytes" a fact rather
/// than a guess.
#[test]
fn scrub_prefix_does_not_commit_a_candidate_still_unconfirmed_at_the_buffer_end() {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    // The carry buffer is exactly the placeholder token, nothing more —
    // indistinguishable, from this buffer alone, from the first 38 bytes of a
    // 39-byte alphanumeric run that is NOT a placeholder.
    let buffer = fixture.token.clone().into_bytes();
    let min_hold_back = PLACEHOLDER_TOKEN_LEN.saturating_sub(1);

    let (scrubbed, consumed) = fixture.swap.scrub_prefix(&buffer, min_hold_back);

    assert_eq!(
        consumed, 0,
        "a candidate unconfirmed at the buffer's end must not be committed yet"
    );
    assert!(scrubbed.is_empty());
}

/// End-to-end version of the above through the public relay path: a real
/// placeholder immediately followed (no delimiter) by one more alphanumeric
/// byte is a 39-char run, which is NOT a valid placeholder by the exact-length
/// rule — so it must reach the origin byte-for-byte untouched, even when the
/// extra byte arrives in a later read than the token itself.
#[tokio::test]
async fn a_placeholder_immediately_followed_by_more_alnum_bytes_across_a_read_boundary_is_never_stripped()
 {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    let payload = format!("{}Z", fixture.token).into_bytes();

    let (scrubbed, consumed) = fixture.swap.scrub_prefix(
        &payload[..PLACEHOLDER_TOKEN_LEN],
        PLACEHOLDER_TOKEN_LEN.saturating_sub(1),
    );
    assert_eq!(
        consumed, 0,
        "must hold back rather than guess at the buffer edge"
    );
    assert!(scrubbed.is_empty());

    // The next read supplies the disambiguating byte. The whole 39-byte run
    // must now pass through untouched: it was never a placeholder to begin
    // with.
    let (scrubbed, consumed) = fixture.swap.scrub_prefix(&payload, 0);
    assert_eq!(consumed, payload.len());
    assert_eq!(
        scrubbed.as_ref(),
        payload.as_slice(),
        "a 39-byte alphanumeric run must never be partially stripped as an exact-length placeholder"
    );
}

#[tokio::test]
async fn the_relay_scrubber_removes_a_placeholder_split_across_two_reads() {
    let fixture = fixture("github", "github", policy("/repos", NetworkMethod::Get));
    let payload = format!("prefix {} suffix", fixture.token).into_bytes();
    // A duplex pipe with a tiny buffer forces the token across reads.
    let (mut client, mut server) = tokio::io::duplex(8);
    let writer_task = tokio::spawn(async move {
        server.write_all(&payload).await.unwrap();
        server.shutdown().await.unwrap();
    });

    let mut out: Vec<u8> = Vec::new();
    fixture
        .swap
        .relay_scrubbing_placeholders(Vec::new(), &mut client, &mut out)
        .await
        .expect("scrubbing relay completes");
    writer_task.await.unwrap();

    let text = String::from_utf8(out).unwrap();
    assert!(!text.contains(&fixture.token), "{text}");
    assert_eq!(text, "prefix  suffix");
}
