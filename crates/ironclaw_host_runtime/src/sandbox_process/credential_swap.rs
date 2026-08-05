//! Placeholder authorization at the sandbox egress boundary —
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
//! bound host. This module recognizes the placeholder and resolves the exact
//! live authority window. The HTTP adapter converts that authority into a
//! staged credential injection request; only the canonical host HTTP egress
//! service may read and inject real material before origin I/O.
//!
//! # The two refusals are different, on purpose
//!
//! [`SandboxCredentialFirewall::authorize`] has two failure shapes and they
//! must never collapse into one branch:
//!
//! - `Ok(`[`SandboxCredentialDecision::NoGrant`]`)` — **GRANT-DENIAL**.
//!   A placeholder-bearing request has no authority and fails closed before
//!   host egress. Requests without placeholders retain the direct relay.
//! - `Err(`[`SandboxCredentialFirewallError`]`)` — **CONNECTION-DENIAL**.
//!   Attribution failed, or the deadline passed. Refuse the connection
//!   outright; nothing is forwarded, and the origin is never even dialed
//!   (`tls_intercept::terminate_and_forward` calls this *before* it dials).
//!
//! Everything that is not positively authorized is rejected before origin
//! I/O; a placeholder is never forwarded through the direct path.
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
//! # Keep-alive: mediate the first credentialed request, scrub later bytes
//!
//! Matching a grant's [`CredentialTargetPolicy`] requires a framed method and
//! URL. The adapter handles one credentialed HTTP/1.1 request and closes the
//! connection after its sanitized response. The direct uncredentialed relay
//! retains [`SandboxCredentialSwap::relay_scrubbing_placeholders`] so a later
//! pipelined placeholder cannot escape while fuller multi-request framing is
//! out of scope.
//!
//! # Shared production runtime and static credential windows
//!
//! [`super::egress_proxy::bind_sandbox_egress_proxy_with_tls_intercept`]
//! consumes the caller-owned [`SandboxCredentialRuntime`] for every
//! production sandbox egress proxy. Composition threads that same runtime to
//! `HostRuntimeServices`, whose obligation handler and lifecycle store use
//! the runtime's exact [`RuntimeSecretInjectionStore`]. As of the
//! connection-attribution wiring in `egress_proxy::handle_connect`, that proxy
//! resolves the real `{tenant, user}` behind an intercepted connection's `peer_addr` via
//! the SAME `ConnectionAttributionResolver` composition shares with the exec
//! transport and the reaper. It combines that with the opaque invocation id
//! carried by host-generated proxy authentication and passes the exact identity as
//! [`super::tls_intercept::InterceptedConnection::identity`] — `Some` for an
//! attributed peer and valid invocation proxy identity, `None` when either
//! input is unavailable or invalid.
//! The obligation handler opens invocation-scoped windows from active,
//! host-owned static credential accounts and revokes them on completion or
//! abort. Placeholder issuance is intentionally separate: callers receive an
//! inert `icsbx_` token, while only the host-side window makes that token
//! usable for an exact reviewed target. A placeholder-bearing request resolves
//! to [`SandboxCredentialDecision::NoGrant`] when an attributed connection has
//! no live grant, or `Err(AttributionFailed)` when attribution failed. Both
//! refusals fail before origin I/O; neither forwards or substitutes the
//! placeholder.

use std::{
    borrow::Cow,
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex, OnceLock},
    time::{Duration, Instant},
};

use ironclaw_host_api::{
    action::NetworkMethod,
    http::RuntimeHttpEgress,
    ids::{CapabilityId, ExtensionId, InvocationId, SecretHandle, TenantId, UserId},
    resource::ResourceScope,
};
use ironclaw_safety::LeakDetector;
use ironclaw_secrets::{
    CREDENTIAL_PLACEHOLDER_PREFIX, CREDENTIAL_PLACEHOLDER_SUFFIX_LEN, CredentialBrokerError,
    CredentialPlaceholderRegistry, CredentialPlaceholderToken, CredentialTargetPolicy,
};
#[cfg(test)]
use secrecy::{ExposeSecret, SecretSlice};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::obligations::RuntimeSecretInjectionStore;

use super::credential_firewall::{
    SandboxCredentialConnectionIdentity, SandboxCredentialDecision, SandboxCredentialFirewall,
    SandboxCredentialFirewallError, StagedCredentialObligation, StagedCredentialObligationSource,
    StagedObligationLease,
};

pub(super) mod http_egress_adapter;

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
#[cfg(test)]
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
#[cfg(test)]
pub(crate) struct RewrittenRequestHead {
    bytes: SecretSlice<u8>,
    report: SandboxCredentialSwapReport,
}

#[cfg(test)]
impl RewrittenRequestHead {
    /// Borrows the rewritten bytes for the single narrow purpose of writing
    /// them to the origin socket. Mirrors `egress::credential`'s comment on
    /// `expose_secret`: the borrow does not outlive the write.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.expose_secret()
    }

    pub(crate) fn report(&self) -> &SandboxCredentialSwapReport {
        &self.report
    }
}

#[cfg(test)]
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

/// One host-owned credential presentation runtime shared by the obligation
/// staging path and the sandbox egress proxy. This is deliberately an opaque
/// concrete handle: it owns process-local presentation state, but it does not
/// own a secret store, choose accounts, or authorize bindings.
#[derive(Clone)]
pub struct SandboxCredentialRuntime {
    placeholders: Arc<CredentialPlaceholderRegistry>,
    firewall: Arc<SandboxCredentialFirewall>,
    secret_injections: Arc<RuntimeSecretInjectionStore>,
    windows: Arc<Mutex<HashMap<SandboxCredentialWindowKey, Vec<StagedObligationLease>>>>,
    /// Late-bound because the sandbox proxy is created before the host service
    /// graph finishes constructing its canonical HTTP egress service. The slot
    /// is process-local, shared by every runtime clone, and can be initialized
    /// exactly once; credentialed dispatch fails closed while it is empty.
    http_egress: Arc<OnceLock<Arc<dyn RuntimeHttpEgress>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SandboxCredentialWindowKey {
    tenant_id: TenantId,
    user_id: UserId,
    invocation_id: InvocationId,
    capability_id: CapabilityId,
}

impl SandboxCredentialWindowKey {
    fn new(scope: &ResourceScope, capability_id: &CapabilityId) -> Self {
        Self {
            tenant_id: scope.tenant_id.clone(),
            user_id: scope.user_id.clone(),
            invocation_id: scope.invocation_id,
            capability_id: capability_id.clone(),
        }
    }
}

pub(crate) struct SandboxStaticCredentialGrant {
    pub(crate) provider_or_extension_id: ExtensionId,
    pub(crate) secret_handle: SecretHandle,
    pub(crate) allowed_targets: Vec<CredentialTargetPolicy>,
}

impl SandboxCredentialRuntime {
    pub fn new() -> Self {
        Self::from_parts(
            Arc::new(CredentialPlaceholderRegistry::new()),
            Arc::new(SandboxCredentialFirewall::new()),
            RuntimeSecretInjectionStore::new(),
        )
    }

    fn from_parts(
        placeholders: Arc<CredentialPlaceholderRegistry>,
        firewall: Arc<SandboxCredentialFirewall>,
        secret_injections: RuntimeSecretInjectionStore,
    ) -> Self {
        Self {
            placeholders,
            firewall,
            secret_injections: Arc::new(secret_injections),
            windows: Arc::new(Mutex::new(HashMap::new())),
            http_egress: Arc::new(OnceLock::new()),
        }
    }

    /// Returns an inert, stable placeholder for a user's configured provider.
    /// Possession of this value grants no authority; a matching live window is
    /// still required at the proxy before any replacement can occur.
    pub fn placeholder_for(
        &self,
        scope: &ResourceScope,
        provider_or_extension_id: &ExtensionId,
    ) -> Result<CredentialPlaceholderToken, CredentialBrokerError> {
        self.placeholders
            .get_or_create(&scope.tenant_id, &scope.user_id, provider_or_extension_id)
    }

    pub(crate) fn open_static_window(
        &self,
        scope: &ResourceScope,
        capability_id: &CapabilityId,
        grants: Vec<SandboxStaticCredentialGrant>,
        ttl: Duration,
    ) {
        let key = SandboxCredentialWindowKey::new(scope, capability_id);
        let leases = grants
            .into_iter()
            .map(|grant| {
                self.firewall.stage(
                    &scope.tenant_id,
                    &scope.user_id,
                    StagedCredentialObligation::new(
                        StagedCredentialObligationSource {
                            scope: scope.clone(),
                            capability_id: capability_id.clone(),
                            provider_or_extension_id: grant.provider_or_extension_id,
                            secret_handle: grant.secret_handle,
                        },
                        grant.allowed_targets,
                        ttl,
                    ),
                )
            })
            .collect();
        self.windows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(key, leases);
    }

    pub(crate) fn close_static_window(&self, scope: &ResourceScope, capability_id: &CapabilityId) {
        self.windows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&SandboxCredentialWindowKey::new(scope, capability_id));
    }

    pub(crate) fn credential_swap(&self) -> SandboxCredentialSwap {
        SandboxCredentialSwap {
            runtime: self.clone(),
        }
    }

    pub(crate) fn secret_injection_store(&self) -> Arc<RuntimeSecretInjectionStore> {
        Arc::clone(&self.secret_injections)
    }

    /// Attaches the canonical host HTTP egress service after composition has
    /// finished building it. A second attachment is rejected and returns the
    /// caller's service unchanged; the first service can never be replaced.
    pub fn attach_http_egress(
        &self,
        service: Arc<dyn RuntimeHttpEgress>,
    ) -> Result<(), Arc<dyn RuntimeHttpEgress>> {
        self.http_egress.set(service)
    }

    /// Retrieval stays private to the credentialed sandbox adapter. Merely
    /// holding a `SandboxCredentialRuntime` does not expose a general-purpose
    /// host egress client to composition or the sandbox process transport.
    fn attached_http_egress(&self) -> Option<Arc<dyn RuntimeHttpEgress>> {
        self.http_egress.get().cloned()
    }
}

impl Default for SandboxCredentialRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SandboxCredentialRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxCredentialRuntime")
            .finish_non_exhaustive()
    }
}

/// The swap itself: placeholder registry (token → owner), credential firewall
/// (owner → live grants), and the staged-material store the granted obligation
/// points into.
///
/// No trait, no port — one implementation, same reasoning as
/// [`SandboxCredentialFirewall`]'s own module doc.
pub(crate) struct SandboxCredentialSwap {
    runtime: SandboxCredentialRuntime,
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

#[cfg(any(test, feature = "test-support"))]
mod runtime_identity_test_support {
    use super::*;

    impl SandboxCredentialRuntime {
        pub(crate) fn is_same_instance(&self, other: &Self) -> bool {
            Arc::ptr_eq(&self.placeholders, &other.placeholders)
                && Arc::ptr_eq(&self.firewall, &other.firewall)
                && Arc::ptr_eq(&self.secret_injections, &other.secret_injections)
                && Arc::ptr_eq(&self.windows, &other.windows)
                && Arc::ptr_eq(&self.http_egress, &other.http_egress)
        }
    }

    impl SandboxCredentialSwap {
        pub(crate) fn uses_runtime(&self, runtime: &SandboxCredentialRuntime) -> bool {
            self.runtime.is_same_instance(runtime)
        }
    }
}

impl SandboxCredentialSwap {
    pub(super) fn runtime_clone(&self) -> SandboxCredentialRuntime {
        self.runtime.clone()
    }

    /// Classifies whether an intercepted head must take the credentialed host
    /// egress path. Syntactic detection is intentionally broader than registry
    /// resolution: an unknown or cross-user placeholder-shaped token must fail
    /// closed in the adapter, never fall through to direct origin transport.
    pub(super) fn contains_syntactic_placeholder(&self, head: &[u8]) -> bool {
        !placeholder_candidates(head).is_empty()
    }

    /// Resolves one supported static `Authorization` placeholder into the
    /// exact staged source the canonical host HTTP egress service may inject.
    /// This method never reads or clones secret material.
    fn authorize_static_http_request(
        &self,
        head: &[u8],
        host: &str,
        identity: Option<SandboxCredentialConnectionIdentity<'_>>,
        deadline: Instant,
    ) -> Result<AuthorizedStaticCredentialUse, StaticCredentialAuthorizationError> {
        let candidates = self.resolvable_candidates(head);
        if candidates.len() != 1 {
            return Err(if candidates.is_empty() {
                StaticCredentialAuthorizationError::NoAuthority
            } else {
                StaticCredentialAuthorizationError::AmbiguousAuthority
            });
        }
        let candidate = &candidates[0];
        let authorization = static_authorization(head)
            .filter(|authorization| authorization.placeholder_offset == candidate.offset)
            .ok_or(StaticCredentialAuthorizationError::UnsupportedAuthorization)?;

        let decision = self.runtime.firewall.authorize(identity, deadline)?;
        let Some(identity) = identity else {
            return Err(SandboxCredentialFirewallError::AttributionFailed.into());
        };
        if candidate.owner.tenant_id != *identity.tenant_id
            || candidate.owner.user_id != *identity.user_id
        {
            return Err(StaticCredentialAuthorizationError::NoAuthority);
        }
        let target = request_target(head, host)
            .ok_or(StaticCredentialAuthorizationError::MalformedRequestTarget)?;
        let SandboxCredentialDecision::Grant(obligations) = decision else {
            return Err(StaticCredentialAuthorizationError::NoAuthority);
        };
        let mut matching = obligations.into_iter().filter(|obligation| {
            self.obligation_covers(
                obligation,
                &candidate.owner.provider_or_extension_id,
                &target,
            )
        });
        let obligation = matching
            .next()
            .ok_or(StaticCredentialAuthorizationError::NoAuthority)?;
        if matching.next().is_some() {
            return Err(StaticCredentialAuthorizationError::AmbiguousAuthority);
        }

        Ok(AuthorizedStaticCredentialUse {
            scope: obligation.source.scope,
            capability_id: obligation.source.capability_id,
            secret_handle: obligation.source.secret_handle,
            authorization_prefix: authorization.prefix,
            method: target.method,
            url: target.url,
        })
    }
}

#[cfg(test)]
mod rewrite_test_support {
    use super::*;

    impl SandboxCredentialSwap {
        /// Rewrites one decrypted request head for the legacy direct-swap
        /// regression suite. Production placeholder traffic uses the host
        /// HTTP egress adapter and never materializes secrets in this module.
        pub(crate) fn rewrite_request_head(
            &self,
            head: &[u8],
            host: &str,
            identity: Option<SandboxCredentialConnectionIdentity<'_>>,
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
            let decision = self.runtime.firewall.authorize(identity, deadline)?;
            // `authorize` only returns `Ok` for an attributed connection, so an
            // identity is present on every path from here down.
            let Some(identity) = identity else {
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
            let static_authorization_offset = static_authorization_placeholder_offset(head);
            let substitutions: Vec<Option<ironclaw_secrets::SecretMaterial>> = candidates
                .iter()
                .map(|candidate| {
                    self.material_for(
                        candidate,
                        static_authorization_offset == Some(candidate.offset),
                        &decision,
                        identity.tenant_id,
                        identity.user_id,
                        target.as_ref(),
                    )
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
            static_authorization: bool,
            decision: &SandboxCredentialDecision,
            tenant_id: &TenantId,
            user_id: &UserId,
            target: Option<&RequestTarget>,
        ) -> Option<ironclaw_secrets::SecretMaterial> {
            if !static_authorization {
                tracing::debug!(
                    "sandbox credential swap: placeholder is outside a supported Basic/Bearer \
                 authorization field; stripping"
                );
                return None;
            }
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
            let mut matching = obligations.iter().filter(|obligation| {
                self.obligation_covers(
                    obligation,
                    &candidate.owner.provider_or_extension_id,
                    target,
                )
            });
            let obligation = matching.next()?;
            if matching.next().is_some() {
                tracing::debug!(
                    "sandbox credential swap: multiple live bindings cover the same provider and \
                 target; stripping ambiguous placeholder"
                );
                return None;
            }
            match self.runtime.secret_injections.clone_material(
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
    }
}

impl SandboxCredentialSwap {
    fn obligation_covers(
        &self,
        obligation: &StagedCredentialObligation,
        provider: &ironclaw_host_api::ids::ExtensionId,
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
            .filter_map(
                |(offset, token)| match self.runtime.placeholders.resolve(&token) {
                    Ok(Some(owner)) => Some(ResolvedPlaceholder { offset, owner }),
                    Ok(None) => None,
                    Err(error) => {
                        tracing::debug!(
                            error = %scrub_for_model_visibility(&error.to_string()),
                            "sandbox credential swap: placeholder registry unavailable"
                        );
                        None
                    }
                },
            )
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

struct AuthorizedStaticCredentialUse {
    scope: ResourceScope,
    capability_id: CapabilityId,
    secret_handle: SecretHandle,
    authorization_prefix: &'static str,
    method: NetworkMethod,
    url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum StaticCredentialAuthorizationError {
    #[error("sandbox credentialed HTTP request has no live matching authority")]
    NoAuthority,
    #[error("sandbox credentialed HTTP request has ambiguous authority")]
    AmbiguousAuthority,
    #[error("sandbox credentialed HTTP request uses an unsupported authorization shape")]
    UnsupportedAuthorization,
    #[error("sandbox credentialed HTTP request has a malformed request target")]
    MalformedRequestTarget,
    #[error(transparent)]
    Firewall(#[from] SandboxCredentialFirewallError),
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

/// Returns the byte offset of the sole credential token when the request has
/// exactly one `Authorization` field and its value is precisely
/// `Basic <placeholder>` or `Bearer <placeholder>` (with optional HTTP OWS).
/// Any duplicate field, extra parameter, unsupported scheme, or non-header
/// occurrence remains scrub-only and can never receive secret material.
struct StaticAuthorization {
    placeholder_offset: usize,
    prefix: &'static str,
}

fn static_authorization(head: &[u8]) -> Option<StaticAuthorization> {
    let request_line_end = head.windows(2).position(|window| window == b"\r\n")?;
    let mut cursor = request_line_end.checked_add(2)?;
    let mut authorization_value = None;

    while cursor < head.len() {
        let relative_end = head[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")?;
        let line_end = cursor.checked_add(relative_end)?;
        if line_end == cursor {
            break;
        }
        let line = &head[cursor..line_end];
        let colon = line.iter().position(|byte| *byte == b':')?;
        if line[..colon].eq_ignore_ascii_case(b"authorization") {
            if authorization_value.is_some() {
                return None;
            }
            authorization_value = Some((cursor, colon + 1, line.len()));
        }
        cursor = line_end.checked_add(2)?;
    }

    let (line_start, mut value_start, mut value_end) = authorization_value?;
    let line = &head[line_start..line_start.checked_add(value_end)?];
    while value_start < value_end && matches!(line[value_start], b' ' | b'\t') {
        value_start += 1;
    }
    while value_end > value_start && matches!(line[value_end - 1], b' ' | b'\t') {
        value_end -= 1;
    }
    let value = &line[value_start..value_end];
    let scheme_end = value.iter().position(|byte| matches!(byte, b' ' | b'\t'))?;
    let scheme = &value[..scheme_end];
    let prefix = if scheme.eq_ignore_ascii_case(b"basic") {
        "Basic "
    } else if scheme.eq_ignore_ascii_case(b"bearer") {
        "Bearer "
    } else {
        return None;
    };
    let mut credential_start = scheme_end;
    while credential_start < value.len() && matches!(value[credential_start], b' ' | b'\t') {
        credential_start += 1;
    }
    let credential = &value[credential_start..];
    if credential.len() != PLACEHOLDER_TOKEN_LEN {
        return None;
    }
    let placeholder_offset = line_start
        .checked_add(value_start)?
        .checked_add(credential_start)?;
    Some(StaticAuthorization {
        placeholder_offset,
        prefix,
    })
}

#[cfg(test)]
fn static_authorization_placeholder_offset(head: &[u8]) -> Option<usize> {
    static_authorization(head).map(|authorization| authorization.placeholder_offset)
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
pub(super) fn placeholder_candidates(bytes: &[u8]) -> Vec<(usize, CredentialPlaceholderToken)> {
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
// `pub(crate)`, not private: `tls_intercept`'s caller-level ordering test
// (CR-004) reuses this module's `fixture` helper to build a real
// `SandboxCredentialSwap` rather than inventing a second fixture — see
// `tls_intercept/tests.rs`'s `credential_swap_tests` import.
pub(crate) mod tests;
