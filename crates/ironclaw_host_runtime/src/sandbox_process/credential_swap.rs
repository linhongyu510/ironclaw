//! Placeholder → real-secret substitution at the sandbox egress boundary —
//! W6 **phase 2** (design doc
//! `docs/plans/2026-07-26-sandbox-credential-firewall-design.md` §2.2,
//! §2.3, §3.4, D5).
//!
//! Phase 1 (`super::tls_intercept`) proved the interception mechanism:
//! terminate TLS for a bound host with a leaf minted from the internal CA,
//! re-originate TLS to the real upstream, and copy the decrypted bytes
//! through **unmodified**. This module is the piece that makes the design's
//! central invariant true for the first time:
//!
//! > Secret material must never enter the container, in any form, even
//! > transiently. Secrets always live in the SecretStore.
//!
//! The container is handed only an inert `icsbx_…` placeholder
//! ([`ironclaw_secrets::CredentialPlaceholderToken`]). It writes that
//! placeholder into whatever config its CLI reads, and the CLI sends it to a
//! bound host. This module sees the decrypted request, recognizes the
//! placeholder, decides whether the connection's `{tenant, user}` is
//! entitled to the real credential, and — only then, only host side, only in
//! the outbound direction — replaces the placeholder bytes with the real
//! secret before the request reaches the origin.
//!
//! # The two refusals are different, on purpose
//!
//! [`SandboxCredentialFirewall::authorize`] has two failure shapes and they
//! must never collapse into one branch:
//!
//! - `Ok(`[`SandboxCredentialDecision::NoGrant`]`)` — **GRANT-DENIAL** (D5).
//!   The connection was validly attributed and the lookup completed; there is
//!   simply no live grant. Strip the placeholder, forward the request bare,
//!   annotate. The origin's own 401 is a better error than breaking a public
//!   `git clone` that never needed a credential.
//! - `Err(`[`SandboxCredentialFirewallError`]`)` — **CONNECTION-DENIAL**.
//!   Attribution failed, or the deadline passed. Refuse the connection
//!   outright; nothing is forwarded, and the origin is never even dialed
//!   (`tls_intercept::terminate_and_forward` calls this *before* it dials).
//!
//! Everything that is not a positively-authorized swap degrades to *strip*,
//! never to *forward the placeholder through*: an unresolvable token, a token
//! owned by a different user, a provider mismatch, a target the grant does not
//! cover, or missing staged material all take the same strip path.
//!
//! # Bounded work over untrusted bytes
//!
//! The placeholder format is exact — [`CREDENTIAL_PLACEHOLDER_PREFIX`] plus
//! *exactly* [`CREDENTIAL_PLACEHOLDER_SUFFIX_LEN`] ASCII-alphanumeric
//! characters — and that exactness is a host-protection property, not a
//! stylistic one (see the constant's own doc comment). [`placeholder_candidates`]
//! preserves it: each byte position costs O(1), a candidate is rejected the
//! moment it is longer or shorter than the exact length, and only candidates
//! that both parse *and* resolve in the registry ever cause a map lookup or an
//! allocation. Container input cannot drive unbounded hashing or map growth.
//!
//! # Keep-alive: swap the first request, scrub the rest
//!
//! Matching a grant's [`CredentialTargetPolicy`] requires the request's method
//! and path, so a swap can only be made where those are known. This slice
//! parses exactly one request head (the first on the connection) and swaps
//! there. For every byte after it, [`SandboxCredentialSwap::relay_scrubbing_placeholders`]
//! removes any *registry-resolvable* placeholder it sees rather than letting
//! it through, so "the placeholder never leaves the boundary" holds for the
//! whole connection, not just its first request. The cost is honest and worth
//! stating: a second request on a keep-alive connection gets its placeholder
//! stripped rather than swapped, so it sees the origin's 401 — the same
//! D5-shaped failure as a grant denial. Swapping on later requests needs full
//! HTTP framing (bodies, chunked encoding, pipelining) and is deliberately not
//! in this slice.
//!
//! # Not wired to production
//!
//! Nothing constructs a [`SandboxCredentialSwap`] outside tests.
//! `TlsInterceptConfig` carries an `Option<SandboxCredentialSwap>` that only
//! tests populate, matching how `attribution`'s resolver and the firewall
//! itself already ship. Production wiring is profile-gated and lands later.

use std::{
    borrow::Cow,
    sync::{Arc, LazyLock},
    time::Instant,
};

use ironclaw_host_api::{NetworkMethod, TenantId, UserId};
use ironclaw_safety::LeakDetector;
use ironclaw_secrets::{
    CREDENTIAL_PLACEHOLDER_PREFIX, CREDENTIAL_PLACEHOLDER_SUFFIX_LEN,
    CredentialPlaceholderRegistry, CredentialPlaceholderToken, CredentialTargetPolicy,
};
use secrecy::{ExposeSecret, SecretSlice};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::obligations::RuntimeSecretInjectionStore;

use super::credential_firewall::{
    SandboxCredentialDecision, SandboxCredentialFirewall, SandboxCredentialFirewallError,
    StagedCredentialObligation,
};

/// Total byte length of a registry-issued placeholder token.
const PLACEHOLDER_TOKEN_LEN: usize =
    CREDENTIAL_PLACEHOLDER_PREFIX.len() + CREDENTIAL_PLACEHOLDER_SUFFIX_LEN;

/// Shared leak detector for every model-visible string this module produces.
/// Memoized for the same reason `production::model_visible_cause_scrubber`
/// memoizes its own: building one compiles the whole regex set, and this runs
/// on a per-connection path.
fn model_visible_scrubber() -> &'static LeakDetector {
    static DETECTOR: LazyLock<LeakDetector> = LazyLock::new(LeakDetector::new);
    &DETECTOR
}

/// Runs `text` through [`LeakDetector`] before it may reach a log line, an
/// error string, or `DispatchError::Script`'s `model_visible_cause`.
///
/// Every string this module builds embeds at least one container-controlled
/// value (the CONNECT host), so this is not defensive theater: a container
/// that dials `CONNECT icsbx_<32>:443` would otherwise put a
/// placeholder-shaped token straight into a model-visible diagnostic. Commit
/// `5fa99590b` established this discipline for the sandbox *success* path;
/// this is the same discipline on the *error/annotation* path.
pub(crate) fn scrub_for_model_visibility(text: &str) -> String {
    let (scrubbed, _) = model_visible_scrubber().redact_all_secrets(text);
    scrubbed
}

/// What a rewrite did, for audit/annotation. Carries counts and host-authored
/// text only — never request bytes, never secret material, never a placeholder
/// token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(dead_code)] // fields consumed by the sandbox dispatch annotation path (D5); not wired yet
pub(crate) struct SandboxCredentialSwapReport {
    /// Placeholders replaced with real secret material.
    pub(crate) swapped: usize,
    /// Placeholders removed without substitution (D5 grant-denial, provider
    /// mismatch, cross-user token, target not covered, material missing).
    pub(crate) stripped: usize,
    /// Model-visible annotation for the stripped case, already
    /// [`scrub_for_model_visibility`]-scrubbed. `None` when nothing was
    /// stripped.
    pub(crate) annotation: Option<String>,
}

/// A request head after rewriting. The bytes may contain real secret material,
/// so they live in a [`SecretSlice`]: zeroized on drop, and its `Debug` prints
/// only the type name. There is deliberately no `Display`, no `Serialize`, and
/// no accessor that hands out an owned `Vec<u8>`.
pub(crate) struct RewrittenRequestHead {
    bytes: SecretSlice<u8>,
    report: SandboxCredentialSwapReport,
}

impl RewrittenRequestHead {
    /// Borrows the rewritten bytes for the single narrow purpose of writing
    /// them to the origin socket. Mirrors `egress::credential`'s comment on
    /// `expose_secret`: the borrow does not outlive the write.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.expose_secret()
    }

    #[allow(dead_code)] // consumed by the dispatch annotation path (D5); not wired yet
    pub(crate) fn report(&self) -> &SandboxCredentialSwapReport {
        &self.report
    }
}

impl std::fmt::Debug for RewrittenRequestHead {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the bytes: after a successful swap they contain the real
        // secret verbatim, and after a strip they still contain whatever the
        // container put in its headers. Only the (secret-free) report and a
        // length are safe.
        formatter
            .debug_struct("RewrittenRequestHead")
            .field("len", &self.bytes.expose_secret().len())
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}

/// The swap itself: placeholder registry (token → owner), credential firewall
/// (owner → live grants), and the staged-material store the granted obligation
/// points into.
///
/// No trait, no port — one implementation, same reasoning as
/// [`SandboxCredentialFirewall`]'s own module doc.
#[allow(dead_code)] // constructed by tests; production construction is future profile-gated wiring
pub(crate) struct SandboxCredentialSwap {
    placeholders: Arc<CredentialPlaceholderRegistry>,
    firewall: Arc<SandboxCredentialFirewall>,
    secret_injections: RuntimeSecretInjectionStore,
}

impl std::fmt::Debug for SandboxCredentialSwap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No field is printed: the registry maps tokens to tenant/user
        // identity and the injection store holds material. Mirrors
        // `SandboxCredentialFirewall`'s own redacted `Debug`.
        formatter
            .debug_struct("SandboxCredentialSwap")
            .finish_non_exhaustive()
    }
}

impl SandboxCredentialSwap {
    #[allow(dead_code)] // constructed by tests; production wiring is future
    pub(crate) fn new(
        placeholders: Arc<CredentialPlaceholderRegistry>,
        firewall: Arc<SandboxCredentialFirewall>,
        secret_injections: RuntimeSecretInjectionStore,
    ) -> Self {
        Self {
            placeholders,
            firewall,
            secret_injections,
        }
    }

    /// Rewrites one decrypted request head bound for `host`.
    ///
    /// `identity` is the proxy's already-resolved attribution outcome for the
    /// connection (`None` = attribution failed) and `deadline` bounds the
    /// firewall lookup — both are passed straight through to
    /// [`SandboxCredentialFirewall::authorize`], whose `Err` is returned here
    /// unchanged so the caller's CONNECTION-DENIAL branch stays the caller's
    /// decision, not something this function can soften into a `NoGrant`.
    ///
    /// A head with no *registry-resolvable* placeholder never consults the
    /// firewall at all and is returned byte-identical: an uncredentialed
    /// request to a bound host (D5's public-clone case) must not be able to
    /// fail on an attribution problem that has no bearing on it.
    pub(crate) fn rewrite_request_head(
        &self,
        head: &[u8],
        host: &str,
        identity: Option<(&TenantId, &UserId)>,
        deadline: Instant,
    ) -> Result<RewrittenRequestHead, SandboxCredentialFirewallError> {
        let candidates = self.resolvable_candidates(head);
        if candidates.is_empty() {
            return Ok(RewrittenRequestHead {
                bytes: SecretSlice::from(head.to_vec()),
                report: SandboxCredentialSwapReport::default(),
            });
        }

        // CONNECTION-DENIAL propagates unchanged — nothing below runs, and
        // the caller never dials the origin.
        let decision = self.firewall.authorize(identity, deadline)?;
        // `authorize` only returns `Ok` for an attributed connection, so an
        // identity is present on every path from here down.
        let Some((tenant_id, user_id)) = identity else {
            return Err(SandboxCredentialFirewallError::AttributionFailed);
        };
        let target = request_target(head, host);

        // Two passes on purpose. Resolving every substitution first lets the
        // output buffer be allocated at its EXACT final size, so pushing the
        // secret into it can never trigger a `Vec` growth — a growth would
        // copy the secret to a fresh allocation and free the old one without
        // zeroizing it, leaving a plaintext copy on the heap that nothing
        // owns. The intermediate materials are `SecretMaterial`, which
        // zeroizes itself when this function returns.
        let substitutions: Vec<Option<ironclaw_secrets::SecretMaterial>> = candidates
            .iter()
            .map(|candidate| {
                self.material_for(candidate, &decision, tenant_id, user_id, target.as_ref())
            })
            .collect();
        let mut report = SandboxCredentialSwapReport::default();
        // `saturating_sub`, not `-`: candidates are non-overlapping slices of
        // `head`, so this cannot underflow today — but a wrapping usize here
        // would become a colossal `with_capacity` and abort the process, which
        // is a bad way to learn that the scanner's invariant broke.
        let mut output_len = head.len();
        for substitution in &substitutions {
            output_len = output_len.saturating_sub(PLACEHOLDER_TOKEN_LEN);
            match substitution {
                Some(material) => {
                    output_len += material.expose_secret().len();
                    report.swapped += 1;
                }
                None => report.stripped += 1,
            }
        }

        let mut output = Vec::with_capacity(output_len);
        let mut cursor = 0usize;
        for (candidate, substitution) in candidates.iter().zip(&substitutions) {
            output.extend_from_slice(&head[cursor..candidate.offset]);
            cursor = candidate.offset + PLACEHOLDER_TOKEN_LEN;
            if let Some(material) = substitution {
                output.extend_from_slice(material.expose_secret().as_bytes());
            }
        }
        output.extend_from_slice(&head[cursor..]);
        // Pins the length computation above against the splice below: if they
        // ever disagree, `with_capacity` was wrong and the buffer grew
        // mid-splice, which is exactly the un-zeroized-copy hazard the two
        // passes exist to avoid. (Asserting against `capacity()` instead would
        // be wrong — `with_capacity` may legitimately over-allocate.)
        //
        // `debug_assert_eq!`, not `assert_eq!`: this repo bans panic-on-
        // reachable-input in production code (`scripts/check_no_panics.py`;
        // see `.claude/rules/error-handling.md`), and a real `assert_eq!` here
        // would let a future accounting bug turn into a host-process crash
        // reachable from sandboxed-container-controlled bytes — trading one
        // hazard (an un-zeroized copy, only possible if this invariant is
        // ever violated) for a worse, always-live one (a DoS any container
        // could trigger on demand). The two-pass exact-capacity construction
        // above is what actually prevents the growth/copy hazard; this assert
        // is a development-time regression pin on that construction, not the
        // mechanism that makes it safe.
        debug_assert_eq!(output.len(), output_len);

        if report.stripped > 0 {
            report.annotation = Some(scrub_for_model_visibility(&format!(
                "a sandbox credential placeholder was presented to {host} but no live grant \
                 covered this request; it was removed and the request was forwarded without \
                 credentials"
            )));
        }
        tracing::debug!(
            // `host` is container-controlled, so it is scrubbed even here:
            // tracing output is not a model-visible channel, but it is a
            // channel, and the design doc's leak-pattern (W13) exists exactly
            // so a placeholder that escapes anywhere is caught.
            host = %scrub_for_model_visibility(host),
            swapped = report.swapped,
            stripped = report.stripped,
            "sandbox credential swap applied to request head"
        );
        Ok(RewrittenRequestHead {
            bytes: SecretSlice::from(output),
            report,
        })
    }

    /// Resolves one candidate placeholder to the real secret material to
    /// substitute, or `None` to strip it. Every `None` path is a deliberate
    /// fail-closed strip, never a "forward the placeholder anyway".
    fn material_for(
        &self,
        candidate: &ResolvedPlaceholder,
        decision: &SandboxCredentialDecision,
        tenant_id: &TenantId,
        user_id: &UserId,
        target: Option<&RequestTarget>,
    ) -> Option<ironclaw_secrets::SecretMaterial> {
        // Cross-user placeholder: user B presenting user A's token. The
        // registry resolved it, so it is a real token — it is simply not
        // this connection's. Strip, never swap.
        if candidate.owner.tenant_id != *tenant_id || candidate.owner.user_id != *user_id {
            tracing::debug!(
                "sandbox credential swap: placeholder owner does not match the attributed \
                 connection; stripping"
            );
            return None;
        }
        let SandboxCredentialDecision::Grant(obligations) = decision else {
            return None;
        };
        // Without a parseable method+path there is no way to evaluate
        // `CredentialTargetPolicy`, and an unevaluated policy must never be
        // treated as satisfied.
        let target = target?;
        let obligation = obligations.iter().find(|obligation| {
            self.obligation_covers(
                obligation,
                &candidate.owner.provider_or_extension_id,
                target,
            )
        })?;
        match self.secret_injections.clone_material(
            &obligation.source.scope,
            &obligation.source.capability_id,
            &obligation.source.secret_handle,
        ) {
            Ok(material) => material,
            Err(error) => {
                // `RuntimeSecretInjectionStoreError` is host-authored (lock
                // poisoning / TTL bookkeeping) and carries no request bytes,
                // but it is scrubbed anyway: this is exactly the error path
                // the discipline exists for.
                tracing::debug!(
                    error = %scrub_for_model_visibility(&error.to_string()),
                    "sandbox credential swap: staged material unavailable; stripping placeholder"
                );
                None
            }
        }
    }

    fn obligation_covers(
        &self,
        obligation: &StagedCredentialObligation,
        provider: &ironclaw_host_api::ExtensionId,
        target: &RequestTarget,
    ) -> bool {
        if obligation.source.provider_or_extension_id != *provider {
            return false;
        }
        obligation
            .allowed_targets
            .iter()
            .any(|policy: &CredentialTargetPolicy| policy.matches(&target.method, &target.url))
    }

    /// Every placeholder occurrence in `bytes` that both parses and resolves
    /// to a registry owner. A token that parses but is unknown to the registry
    /// is left alone: it was never minted here, so it is just an arbitrary
    /// string the container chose to send, and rewriting it would corrupt
    /// traffic without protecting anything.
    fn resolvable_candidates(&self, bytes: &[u8]) -> Vec<ResolvedPlaceholder> {
        placeholder_candidates(bytes)
            .into_iter()
            .filter_map(|(offset, token)| match self.placeholders.resolve(&token) {
                Ok(Some(owner)) => Some(ResolvedPlaceholder { offset, owner }),
                Ok(None) => None,
                Err(error) => {
                    tracing::debug!(
                        error = %scrub_for_model_visibility(&error.to_string()),
                        "sandbox credential swap: placeholder registry unavailable"
                    );
                    None
                }
            })
            .collect()
    }

    /// Emits a prefix of `buffer` with every registry-resolvable placeholder
    /// in it removed, and reports how many input bytes that prefix consumed.
    ///
    /// `min_hold_back` is how many trailing bytes must stay unconsumed
    /// because a token could still be straddling the end of what has been
    /// read so far. `min_hold_back == 0` means EOF: no more bytes are ever
    /// coming, so "no byte after this candidate" is a fact, not a guess.
    ///
    /// The subtle part — and the bug this shape exists to prevent — is that
    /// the *scan* must run over the whole buffer, not over the prefix: a
    /// token starting just before the hold-back boundary is fully present in
    /// `buffer` but invisible to a scan of the prefix alone, so scanning the
    /// prefix would emit its first bytes verbatim and leave the rest to be
    /// scrubbed later, letting a mangled-but-recognizable token cross the
    /// boundary. Any candidate straddling the boundary therefore *extends*
    /// the consumed prefix to cover it whole.
    ///
    /// A second, easy-to-miss instance of the same class of bug: a candidate
    /// whose match window ends exactly at `buffer.len()` has its exact-length
    /// check satisfied by "there is no byte at this position *yet*" — true of
    /// the buffer read so far, but not proof the run does not continue when
    /// more bytes arrive. Extending `boundary` to cover such a candidate
    /// before that next byte is known would commit (strip or pass through) a
    /// candidate that a single following alphanumeric byte would disqualify
    /// as a placeholder entirely (see the module doc's "bounded work" and
    /// `only_an_exactly_sized_alphanumeric_suffix_is_a_placeholder_candidate`).
    /// So while more bytes may still arrive (`min_hold_back > 0`), such a
    /// candidate is left out of `boundary` instead — held back whole, to be
    /// re-evaluated once the next read confirms it one way or the other.
    fn scrub_prefix<'a>(&self, buffer: &'a [u8], min_hold_back: usize) -> (Cow<'a, [u8]>, usize) {
        let candidates = self.resolvable_candidates(buffer);
        let mut boundary = buffer.len().saturating_sub(min_hold_back);
        for candidate in &candidates {
            let end = candidate.offset + PLACEHOLDER_TOKEN_LEN;
            if candidate.offset < boundary && end > boundary {
                if min_hold_back > 0 && end == buffer.len() {
                    // Unconfirmed: hold back the candidate whole rather than
                    // risk stripping/passing a run that isn't actually
                    // exact-length once the next byte is known.
                    boundary = candidate.offset;
                } else {
                    boundary = end;
                }
            }
        }
        let inside: Vec<&ResolvedPlaceholder> = candidates
            .iter()
            .filter(|candidate| candidate.offset + PLACEHOLDER_TOKEN_LEN <= boundary)
            .collect();
        if inside.is_empty() {
            // The overwhelmingly common case on the relay path: borrow rather
            // than copy every chunk of an upload just to pass it through.
            return (Cow::Borrowed(&buffer[..boundary]), boundary);
        }
        let mut output = Vec::with_capacity(boundary);
        let mut cursor = 0usize;
        for candidate in inside {
            output.extend_from_slice(&buffer[cursor..candidate.offset]);
            cursor = candidate.offset + PLACEHOLDER_TOKEN_LEN;
        }
        output.extend_from_slice(&buffer[cursor..boundary]);
        (Cow::Owned(output), boundary)
    }

    /// Relays `reader` → `writer` (container → origin), removing any
    /// registry-resolvable placeholder on the way.
    ///
    /// A token can straddle two reads, so the last `PLACEHOLDER_TOKEN_LEN - 1`
    /// bytes read are held back rather than written immediately; the carry is
    /// bounded by that constant plus one read, so a container cannot grow it.
    /// Flushed in full at EOF.
    /// `initial` is any byte the caller already read off the client but has
    /// not forwarded — in practice whatever arrived behind the first request
    /// head in the same segment. It is scrubbed like everything else rather
    /// than written through, which is what stops a pipelined request from
    /// carrying a placeholder past the boundary.
    pub(crate) async fn relay_scrubbing_placeholders<R, W>(
        &self,
        initial: Vec<u8>,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut carry: Vec<u8> = initial;
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            let read = reader.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            carry.extend_from_slice(&chunk[..read]);
            let consumed = {
                let (scrubbed, consumed) =
                    self.scrub_prefix(&carry, PLACEHOLDER_TOKEN_LEN.saturating_sub(1));
                writer.write_all(&scrubbed).await?;
                consumed
            };
            carry.drain(..consumed);
        }
        if !carry.is_empty() {
            let (scrubbed, _) = self.scrub_prefix(&carry, 0);
            writer.write_all(&scrubbed).await?;
        }
        writer.flush().await?;
        writer.shutdown().await?;
        Ok(())
    }
}

struct ResolvedPlaceholder {
    offset: usize,
    owner: ironclaw_secrets::CredentialPlaceholderOwner,
}

/// The method + absolute URL a request head addresses, used to evaluate
/// [`CredentialTargetPolicy`].
struct RequestTarget {
    method: NetworkMethod,
    url: String,
}

/// Parses the request line of `head` into a policy-checkable target. Returns
/// `None` for anything that is not a well-formed HTTP request line with a
/// method [`NetworkMethod`] models — an unmodelled method (e.g. `OPTIONS`)
/// cannot be checked against a policy, so it must not be swapped for.
fn request_target(head: &[u8], host: &str) -> Option<RequestTarget> {
    let line_end = head
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(head.len());
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.split(' ');
    let method = match parts.next()? {
        "GET" => NetworkMethod::Get,
        "POST" => NetworkMethod::Post,
        "PUT" => NetworkMethod::Put,
        "PATCH" => NetworkMethod::Patch,
        "DELETE" => NetworkMethod::Delete,
        "HEAD" => NetworkMethod::Head,
        _ => return None,
    };
    let request_target = parts.next()?;
    // The CONNECT tunnel already pinned the host, and `host` is what the leaf
    // certificate was minted for — so the authority always comes from `host`,
    // never from an absolute-form request line the container could point
    // somewhere else. An absolute-form target whose authority disagrees is
    // rejected rather than reconciled.
    let path_and_query = if let Some(rest) = request_target.strip_prefix("https://") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if !authority.eq_ignore_ascii_case(host) {
            return None;
        }
        format!("/{path}")
    } else if request_target.starts_with('/') {
        request_target.to_string()
    } else {
        return None;
    };
    Some(RequestTarget {
        method,
        url: format!("https://{host}{path_and_query}"),
    })
}

/// Every syntactically valid placeholder token in `bytes`, with its byte
/// offset.
///
/// Enforces the format **exactly** (see the module doc's "bounded work"
/// section): the prefix, then exactly [`CREDENTIAL_PLACEHOLDER_SUFFIX_LEN`]
/// ASCII-alphanumeric characters, and the byte immediately after must not be
/// ASCII-alphanumeric — so a longer run is rejected outright rather than
/// silently truncated to a valid prefix of itself. Work per byte position is
/// O(1) and bounded by the fixed token length.
fn placeholder_candidates(bytes: &[u8]) -> Vec<(usize, CredentialPlaceholderToken)> {
    let prefix = CREDENTIAL_PLACEHOLDER_PREFIX.as_bytes();
    let mut found = Vec::new();
    let mut index = 0usize;
    while index + PLACEHOLDER_TOKEN_LEN <= bytes.len() {
        if !bytes[index..].starts_with(prefix) {
            index += 1;
            continue;
        }
        let end = index + PLACEHOLDER_TOKEN_LEN;
        let suffix = &bytes[index + prefix.len()..end];
        let exact_length = bytes
            .get(end)
            .is_none_or(|next| !next.is_ascii_alphanumeric());
        if !exact_length || !suffix.iter().all(u8::is_ascii_alphanumeric) {
            index += 1;
            continue;
        }
        match std::str::from_utf8(&bytes[index..end]).map(CredentialPlaceholderToken::parse) {
            Ok(Ok(token)) => {
                found.push((index, token));
                index = end;
            }
            _ => index += 1,
        }
    }
    found
}

#[cfg(test)]
mod tests;
