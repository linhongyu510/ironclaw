# Sandbox Credential Firewall — Design & Implementation Plan

**Status:** rev 11 — **static-auth skeleton implemented; user-facing placeholder retrieval remains.** This PR is deliberately limited to `Authorization: Bearer <placeholder>` and `Authorization: Basic <placeholder>`, where a Basic secret is already a presentation-ready Base64 payload in IronClaw's secret store. Arbitrary API-key headers, SigV4, inert AWS helper artifacts, credential-producing flows, and generalized request-authorizer plugins are follow-up work. Real credential material never enters the sandbox. The sandbox deployment profile is the sole lane-selection authority: it always installs the sandbox process binding, while every other profile omits it. There is no frontend toggle or persisted per-user sandbox setting. The host substitutes only after source attribution, an invocation-scoped shell window, an active single-secret `CredentialAccount`, a match through the account's existing target-policy matcher, and host-side secret staging. Any placeholder in a URL, body, arbitrary header, duplicate `Authorization` field, unsupported scheme, ambiguous account match, non-sandbox invocation, or expired/closed window is stripped rather than materialized.
**Date:** 2026-07-26. **Branch:** `sandbox/shell-integration` @ `33607ab88` (merged `origin/main` in via `a884f9420`, 12 commits; the branch is also 88 commits ahead / 28 commits behind `main` as of this revision — the rev 3 baseline of `eb667c786` is stale).
**Local-only doc** — `docs/plans/*` is never committed (except `composition-pubuse.snapshot`, a tracked ratchet fixture).
**Interactive architecture artifact:** [`2026-08-04-sandbox-credential-firewall-design-artifact.html`](2026-08-04-sandbox-credential-firewall-design-artifact.html) — separates the initial PR1 launch contract (profile-gated foreground shell, per-user persistence, network denied) from the follow-up egress and credentialed-CLI target architecture.

**PR1 Railway preview boundary (2026-08-04):** the IronClaw application must run exactly one replica. The Railway transport serializes a user's commands in-process and replaces one deterministic per-user checkpoint after each successful foreground command; it does not yet hold a distributed `(tenant_id,user_id)` lease. Multiple IronClaw replicas could independently restore and overwrite the same checkpoint, so horizontal application replicas are a follow-up. Railway's current CLI states that reusing a checkpoint name synchronously replaces the prior snapshot; the authenticated live canary must verify this write/restore/replace behavior before PR1 is called ready.

**Rev 2:** corrected an overclaim about what JIT blocks (§3.3) · added **D9** · resequenced W7/W8 before W6 · resized W1/W6/W10 · W1 second-consumer decision · streaming/body-buffering risk · fixed wrong type names · test matrix (§6).
**Rev 3:** 🔴 **new finding — cross-tenant symlink escape in the abstract-FS mount** (§1.5, fix in flight) · **D9 RESOLVED** — `enable_icc=false` + source-IP attribution, not per-user networks (§3.5) · **W1 second-consumer dissolved** — remove `capsh` only, file retirement separately · **cargo credential binding de-scoped from V1** (public crates.io works through the opaque tunnel; removes the riskiest compat blocker) · test rows 11-12 for icc.
**Rev 5:** recorded a real-Docker verification run (2026-07-26) — 164/164 passed, zero skips, upgrading §6 rows 1/11/12 to **verified executing**, not just "a test exists" · 🔴 **new open item (§5.7)** — the egress-proxy allowlist test fails end-to-end under colima (host proxy and container gateway are different machines); combined with the still-unverified DinD leg, the proxy has **no environment where real traffic has been observed working** · added **§1.8** — an end-to-end spike confirming the sandbox container plumbing (spawn, non-root exec, network attach) works today via direct composition call, with the agent-loop and reaper legs honestly marked unexercised · **W8 upgraded** from zero-code to a built refcounted-set staging primitive (`HashMap<StagingKey, HashMap<u64, _>>`, per-entry lease, two single-slot bugs fixed) — the shell-tool chokepoint itself is still unbuilt; this also **retires** the earlier "ceiling of 1 required by W8" justification now that the per-user ceiling is moving to 4.
**Rev 4:** re-issued against shipped code, not commit messages. **Banner corrected** — this is implementation-in-progress. Added the **§1.0 status table** (W0–W17). §1.4/§1.5 (root-mismatch + symlink escape, incl. the empty-tail fix) **confirmed landed** — `local.rs`'s `leaf_scoped` mount + `leaf_scoped_mount_rejects_bare_mount_root_request` test. **W1, W1.5, W13, W16 confirmed landed**; **W16 covers both the container and network posture halves**, as designed. **W7 and W1.5b are built and fully tested but wired to nothing** — ~1730 lines staged ahead of their consumer; said plainly here because prior status notes overstated them as "landed." **New blocker found: W6 also needs W5** (internal CA) — corrected critical path is **W8 → wire W1.5b into the proxy → W17 → give W7 a real caller → W5 → W6**; W8 is the true long pole (zero code, and the layering decision the proxy needs per §3.4). Deleted the dead `DockerProcessSandboxBackend` "(c) minimal" discussion in W1 — that backend was **deleted outright** (commit `44fe302d7`, issue #6686, still open), not left gated-off. Added **§1.6 unplanned work** (backend retirement; `origin/main` merge incl. the `ironclaw_extension_host` crate split; W7 hardening driven by PR #6689 review). Recorded two small orphaned-code items (the entrypoint's `broker-only` iptables branch; `scope_key::container_name_prefix`). §6 test matrix rows re-marked against actual coverage (4 of 13 genuinely covered, 2 partial, 7 blocked on unbuilt subjects). `rcgen` open item **resolved and removed** — confirmed absent from every `Cargo.toml` in the workspace. Recurring-pattern section extended to **six** instances, the newest (W17, attribution-cache reuse) the first to ship in a merged branch rather than being caught pre-merge.
**Rev 8:** **design change — how credentials reach CLIs in the sandbox, no code yet.** ~~W10's host-side config-seed writer~~ (six hardcoded formats: `.git-credentials`, `gh` hosts.yml, `.npmrc`, docker config, `CARGO_REGISTRY_TOKEN`, kubeconfig) is **superseded** — it does not scale past the six enumerated, and every new CLI would need a new writer. Replaced by an **agent-placed placeholder model**: two new host capabilities, `credential_request(provider, requested_by, proposed_host?)` (host-authored approval prompt, mints and returns `{ placeholder }`) and `credential_placeholder_get(provider)` (silent re-fetch of the same stable token for an already-connected provider) — the **agent**, not the host, writes the returned `icsbx_…` placeholder into whatever config each CLI reads, because config-format knowledge is exactly the long tail the host cannot scale to. Load-bearing property: **a placeholder is inert** — a lookup key, not a credential; writing one grants nothing, resolution is decided entirely at the proxy against a binding the agent does not control. Added **D10** (the host mints, the agent places — never the reverse) · new §3.1 threat, **wrong-host exfiltration** (why reviewed profiles beat prefill) · **W10 superseded and shrunk** M/L ~4-5d → S ~1d (env-var seeding for known providers becomes optional, largely redundant once the agent configures tools) · **W11 recast as a REDIRECT** — denying `gh auth login` is only defensible because `credential_request` is the supported alternative; must never ship before W10's replacement · **W12 grows into the security center of this design** — reviewed built-in profiles become load-bearing content, and its two binding-creation entry points (settings UI, agent request) must funnel through one authorization chokepoint · added **W18** (the two new agent-callable capabilities) · recorded an honest regression — **disconnect cascade degrades**, not breaks, because the host no longer knows where agent-written config lives and so cannot clean it up on disconnect · confirmed unaffected: D8, W6 phase 2, the CA, the firewall's staging/lease/TTL model, attribution, and §3.3's accepted envelope; also confirmed PR #6695 and PR #6723 are unaffected, landing entirely in unbuilt items.
**Rev 9:** **design change — credential presentation is broader than literal token substitution.** Added an explicit requirements/boundaries section (§0.1), split reviewed profiles into a guest bootstrap recipe plus a sealed host authorization transform, and added concrete interfaces/functions (§2.2b). **D8 changed:** SigV4 is supported by giving the guest a syntactically valid but inert AWS credential set (normally through `credential_process`) and having the host discard the inert signature and sign the exact authorized outbound request with host-side material. Static token/header swap remains one transform, not the architecture. Added the initialization and egress diagrams (§2.2c), strict SigV4 limits (§2.2d), and W19-W22. Explicitly prohibited giving the proxy `SecretStorePort`: the control plane/materializer owns secret access; the data plane receives only a one-request `AuthorizedCredentialUse`. STS/SSO/login responses that would return real credentials remain host-side or fail closed; S3 aws-chunked streaming, presigned URLs, event-stream, and ambiguous HTTP framing are deferred rather than partially supported. **Implementation update (2026-07-31): W19a is complete and focused checks pass; W19b/W20-W22 remain unimplemented.**
**Rev 10:** **PR scope reduced to the smallest safe static lane.** Only sole-field Basic/Bearer authorization substitution is implemented. The existing active `CredentialAccount` plus its exact `CredentialTargetPolicy` is the provisional host-owned binding for this skeleton; there is no model-selected account or target. The obligation handler stages only for `prepare` (never direct `satisfy`) and revokes on abort and every completion outcome, including post-dispatch failures. Rev 10 temporarily added a second user-setting gate; rev 11 removes it in favor of deployment-profile-only lane selection. Reviewed presentation profiles, arbitrary named API-key headers, account-selection UI, placeholder-request UX, and every signing authorizer remain follow-ups.
**Rev 11:** **deployment profile is the only sandbox enablement authority.** Removed the frontend toggle, operator-config route/capability, persisted per-user setting, and host-runtime double gate. `hosted-single-tenant-volume-sandboxed` installs and always uses one complete user-sandbox bundle (process port, activity/attribution, credential runtime, egress proxy, and workspace root); profile-owned sandbox components are rejected for every other deployment profile. The deployment may be single-tenant, but sandbox identity and persistence are always keyed by `(tenant_id, user_id)` so users inside one tenant never share a worker or workspace. There is no fallback that starts a second proxy with a fresh credential runtime, and a transport-connect failure explicitly shuts down the already-started proxy/VM relay. User-facing credential/account setup remains separate and cannot enable or disable process isolation.
**Rev 7:** **W6 phase 1 (TLS termination seam) LANDED** — `sandbox_process/tls_intercept.rs` mints leaves from W5's CA, completes a real rustls handshake with the sandboxed client, re-originates TLS to the origin, and copies decrypted bytes through **unmodified** (no parsing/injection — that's phase 2); D1 (unbound host stays opaque tunnel) holds and is tested at the CA; `ironclaw-reborn-architecture-review` verdict **SHIP**. `RuntimeKind::Sandbox` prereq slice also landed across 6 crates, no wildcard arms. Added **"W6 phase 2 — hard requirements"** subsection (§1.0a) recording three must-not-lose items surfaced while auditing the landed slice: (a) the production-services readiness gate whitelists `Sandbox` as a supported requirement but has no per-runtime missing-component check for it, and `registered_runtime_backends()` has no `sandbox_runtime` field — a silent readiness bypass waiting to happen; (b) untrusted container output reaching `model_visible_cause` on the sandbox `DispatchError::Script` path must go through `LeakDetector` (commit `5fa99590b`'s discipline) before phase 2 populates it from real stdout/stderr; (c) the production origin `TlsConnector` needs a real trusted root store — no existing test would catch a permissive one. §6 row 8 (`real_secret_never_appears_in_container`) noted as testable only after phase 2, since phase 1 forwards bytes unmodified.
**Rev 6:** 🔴 **corrected a factual overclaim — W0 was NOT landed as a blocking CI job.** The `sandbox-docker-tests` job (commit `29196c8fc`, "ci(sandbox): make docker-gated tests block in CI") exists only on this local unpushed branch (`sandbox/shell-integration`, 65 commits ahead of `origin/main`) — confirmed absent from `origin/main` (`git merge-base --is-ancestor 29196c8fc origin/main` → false; `git branch -r --contains 29196c8fc` → empty; `origin/main`'s `reborn-tests.yml` has no such job), and it has **never executed in GitHub Actions** (checked the last 40 workflow runs across all branches — the job name never appears). **Every docker-gated assertion this plan treats as CI-enforced is currently enforced nowhere**; the 164/164 zero-skip run recorded under rev 5 (§6) was a **local** run against colima, not a CI run. Corrected §1.0's W0 row, §3's W0 write-up, §6's preamble, and §8's closing line — all previously said or implied the job was landed/blocking. Also recorded (§5 item 7): a CI-gating decision made 2026-07-26 — the blanket `has_reborn_tests` gate was **rejected** by the user on cost grounds (~30 min added to nearly every PR, dominated by the 1.82GB `ironclaw-worker` image build); the job is being **narrowed** to sandbox-related paths plus unconditional runs on push-to-main and merge_group, with Buildx layer caching to cut build cost — **decided and in progress** (by another agent in this worktree), not yet landed.

---

## 0. What this is

The persistent per-user sandbox (Phase A/B/C) ships without credential delivery — a deliberate V1 cut. This specifies how credentials reach CLIs *running inside the sandbox* under one hard constraint:

> **Secret material must never enter the container, in any form, even transiently. Secrets always live in the SecretStore.**

**Reference:** Hermes agent Docker sandbox report (NousResearch/hermes-agent @ `339d9686`). Verdict: copy the credential-firewall *idea*; do **not** copy their exec identity, start-race handling, egress model, or test strategy — we already fixed all four.

### 0.1 Requirements and boundaries (rev 9)

These requirements are invariant across the container-backed providers in scope: a directly reachable Docker daemon and a Docker daemon inside a hosted Railway sandbox VM. Firecracker and other new isolation substrates are explicitly out of scope for this launch. The backend enforces process/filesystem isolation and the declared network posture; host-mediated egress, connection attribution, and interception-CA trust are required only for the later credential-enabled posture. The credential mechanism starts after those guarantees.

**Must hold:**

1. Real access keys, secret keys, refresh tokens, private keys, cookies, and derived reusable credentials exist only in IronClaw's host-side secret system.
2. Sandbox files, environment variables, helper output, process arguments, stdout/stderr, and model-visible results may contain only inert artifacts. An inert artifact is a lookup/presentation value with no authority at the origin.
3. In this PR's static lane, every authenticated request requires all of: selection of the sandbox deployment profile; an attributed sandbox principal; a live invocation-scoped shell window; one unambiguous active single-secret account for the placeholder provider; a matching exact target policy; and one sole Basic/Bearer `Authorization` field. Future presentation kinds additionally require a reviewed presentation profile. There is no user-controlled sandbox toggle.
4. The model may request a reviewed profile and place its inert artifact. It cannot author or widen the profile, destination, service, region, operation, or credential account.
5. Product auth/control plane owns account setup, profile selection, user confirmation, and binding lifecycle. `ironclaw_secrets` owns credential accounts and raw material. Host runtime owns active-window staging and request transformation. Composition only shares the same handles.
6. The egress proxy/data plane never receives `SecretStorePort` and never selects an account. It consumes a one-request `AuthorizedCredentialUse` produced by the host authority/materializer.
7. Unknown presentation kinds, unsupported protocol modes, malformed/ambiguous requests, token-producing responses, and signer failures fail closed. There is no fallback that forwards the guest's inert authentication material to the origin.
8. Audit records contain principal, invocation/window, account/profile identifiers, target, transform kind, and outcome; never raw material, inert artifact bytes, request bodies, or signed authorization values.

**Explicit non-goals for this PR:** arbitrary API-key header names; guest-side login/configure flows; SigV4 or any other request signing; guest-visible derived credentials; presigned URLs; streaming signatures; HTTP/2 or gRPC authentication transforms; SSH agent forwarding; and mTLS client-key exposure.

---

## 1. Current state (audited, cited)

### 1.0 Status at a glance — every work item, verified against code

| Item | Status | Evidence | Note |
|---|---|---|---|
| W0 · CI docker-gate job | 🔴 **BUILT LOCALLY, NOT ON MAIN, NEVER EXECUTED IN CI** | `sandbox-docker-tests` job added by commit `29196c8fc`; exists ONLY on the local unpushed `sandbox/shell-integration` branch (65 commits ahead of `origin/main`) — `git merge-base --is-ancestor 29196c8fc origin/main` → false, `git branch -r --contains 29196c8fc` → empty, `origin/main`'s `reborn-tests.yml` has no such job; the job "Reborn sandbox Docker tests" has never appeared in the last 40 workflow runs across all branches | **Every docker-gated assertion this plan treats as CI-enforced is currently enforced nowhere.** The 164/164 zero-skip run recorded 2026-07-26 (§6) was a LOCAL run against colima, not CI. See §5 item 7 — a CI-gating decision was made 2026-07-26 (blanket `has_reborn_tests` gate rejected on cost; job being narrowed to sandbox paths + push-to-main/merge_group, DECIDED + IN PROGRESS, not landed) |
| W1 · non-root init | ✅ **LANDED** | `exec_transport.rs`: `user: Some(SANDBOX_EXEC_USER)` on PID 1 and every exec; `cap_add: None` | `capsh` removed, one commit as planned |
| W1.5 · `enable_icc=false` (lateral isolation) | ✅ **LANDED** | `exec_transport.rs` sets the option on network create; colima-verified empirically | DinD leg still unverified (§5) |
| W1.5b · proxy source-IP attribution | 🟡 **BUILT, UNWIRED** | `sandbox_process/attribution.rs` exists, well tested (`ConnectionAttributionResolver`) — but `mod attribution;` is **private**, no re-export, **zero callers**; `egress_proxy.rs` never references it | not in `handle_connect` |
| W2 · `pids_limit`/CPU quota | ❌ **NOT STARTED** | `exec_transport.rs`: `pids_limit: None` always, comment says "carried even though nothing currently sets it" | |
| W3 · reaper spawn fails closed | ✅ **LANDED** | `sandbox_reaper_task.rs` | |
| W4 · container-ns PID for timeout kill | ❌ **NOT STARTED** | `exec_transport.rs` doc comment on `kill_exec_process_group`: kill "was ALREADY silently non-functional... confirmed empirically... reports 'No such process'"; explicitly "a pre-existing gap, not introduced here" | |
| W5 · internal CA | ✅ **LANDED (unwired)** | `sandbox_process/ca.rs`; `rcgen 0.14.8` + `time`, `x509-parser` dev-only; architecture-review verdict **SHIP**; 11 tests | root private key never leaves the process (hand-written `Debug` omits it; `root_certificate_pem()` returns only the public trust anchor, test-pinned to contain no `PRIVATE KEY` block) — still a W6 blocker until wired |
| W6 · proxy TLS termination + injection | 🟡 **PHASE 1 LANDED (unwired), PHASE 2 NOT STARTED** | `sandbox_process/tls_intercept.rs` — `TlsInterceptConfig{ca, bound_hosts, origin_connector}`, `terminate_and_forward()`: mints a leaf from W5's CA, completes a real rustls **server** handshake with the sandboxed client, re-originates TLS to the origin (SNI = host), copies decrypted bytes through **unmodified**; D1 holds — unbound host stays opaque `copy_bidirectional`, `cached_leaf_count() == 0` even with intercept configured, tested at the CA; fail-closed on every failure point (leaf mint, client handshake, origin dial, origin handshake), no plaintext fallback; new `rustls`/`tokio-rustls`/`rustls-pemfile` pinned to the workspace's existing `rustls 0.23`; `ironclaw-reborn-architecture-review` verdict **SHIP**; host normalization now happens once in `egress_proxy::handle_connect` (lowercased), feeding the allowlist check, dial address, `is_bound`, leaf mint, and origin `ServerName` | **Phase 2 (parsing + real injection) has not started — see §1.0a for the hard requirements it must carry forward.** Prereq `RuntimeKind::Sandbox` slice also landed across 6 crates, explicit arms everywhere (no `_ =>`); included in `runtime_reuses_staged_credentials`; sandbox dispatch errors ride `DispatchError::Script` (`RuntimeLane::Process`, same as Script); `apply_credential_injections`/`validate_sources_for_request` bumped `pub(super)`→`pub(crate)`. Non-obvious catch: `surface.rs`'s `ALL_RUNTIME_KINDS` const feeds `CapabilitySurfacePolicy::allow_all()` and is **not** a match site — omitting `Sandbox` there would have compiled clean and silently made sandbox capabilities invisible under allow-all |
| W7 · placeholder registry + session wiring | 🟡 **BUILT, UNWIRED** | `ironclaw_secrets/src/placeholder.rs` — `mint_on_first_use` and the registry are solid, tested extensively (`placeholder/tests.rs`) — but every call site is in that crate's own tests; no request path calls it | PR #6689, open against `main` |
| W8 · obligation-staging chokepoint | 🟡 **STAGING PRIMITIVE BUILT, still no shell-tool chokepoint** | staging map reworked **refcounted-set**: `HashMap<StagingKey, HashMap<u64, StagedCredentialObligation>>` + `AtomicU64` entry id; `stage()` returns a lease carrying its own entry id; revoke/`Drop` removes only that entry; `authorize()` returns `Grant(Vec<StagedCredentialObligation>)`, target matching deferred to W6's proxy (`CredentialTargetPolicy::matches`); two single-slot bugs fixed + regression-tested (stale lease revoking a newer grant; second `stage()` clobbering a live sibling) | required because the per-user sandbox ceiling is moving 1→4, making concurrent same-`(tenant,user)` staging the normal path — **retires** the earlier "ceiling of 1 is required by W8's attribution staging" justification; ceiling is now a capacity/fair-share choice, not a security constraint. Chokepoint mirroring `activation_credential_requirements` for the shell tool itself still does not exist — true long pole remains open |
| W9 · reuse `apply_credential_injections` | ❌ **NOT STARTED** | still `pub(super)` in `egress/credential.rs`, not visible from `sandbox_process` | |
| ~~W10 · host-side config-seed writer~~ | ❌ **NOT STARTED, SUPERSEDED (rev 8)** | | Six-format host writer does not scale; replaced by agent-placed placeholders (see W18). Env-var seeding for known providers survives as OPTIONAL, shrunk M/L~4-5d → S~1d |
| W11 · login guard | ❌ **NOT STARTED — now a REDIRECT (rev 8)** | | Denying `gh auth login` etc. is only defensible because `credential_request` (W18) is the supported alternative; guard message must name it. **Never ship before W18 lands** |
| W12 · binding model + UI | ❌ **NOT STARTED — GROWS (rev 8)** | | Reviewed built-in profiles become load-bearing SECURITY CONTENT (path 1's safety depends on the profile pinning the host); two binding-creation entry points (settings UI + agent request via W18) must funnel through ONE authorization chokepoint |
| W18 · `credential_placeholder_get` + `credential_request` 🆕 (rev 8) | ❌ **NOT STARTED** | `SandboxCredentialRuntime::placeholder_for` is the internal mint/re-fetch primitive only | No model-facing capability exists yet; do not claim CLI auth UX is complete |
| W19 · shared credential runtime + shell window 🆕 (rev 9) | 🟡 **STATIC SKELETON BUILT** | One shared runtime; `BuiltinObligationHandler::prepare` stages enabled users' qualifying active accounts; invocation-keyed leases revoke on abort and all completion outcomes; direct `satisfy` does not open a window | Uses existing account target policy as the provisional static binding. W12 profiles/UI remain required before broader presentation kinds |
| W20 · reviewed presentation profiles + inert AWS artifact 🆕 (rev 9) | ❌ **NOT STARTED** | | Sealed host profiles; minimal account/profile/version binding; AWS `credential_process` helper returns inert values only |
| W21 · bounded host-side SigV4 authorizer 🆕 (rev 9) | ❌ **NOT STARTED** | | One bounded HTTP/1.1 request; exact target/profile validation; host re-signs with a one-request authorized use |
| W22 · credential-producing response guard 🆕 (rev 9) | ❌ **NOT STARTED** | | Blocks STS/SSO/token-producing operations until an explicit capture-to-SecretStore transform exists |
| W13 · leak pattern for placeholders | ✅ **LANDED** | `icsbx_` pattern in `leak_detector::default_patterns()` | |
| W14 · revoke-on-recycle | ❌ **NOT STARTED** | | |
| W15 · approval-on-first-use | ❌ **NOT STARTED (tracked, Priority 3)** | | |
| W16 · posture pinned-at-create (container + network) | ✅ **LANDED, both halves** | `exec_transport.rs`: `security_posture_stamp`/`security_posture_fields` recycle stale containers; `verify_existing_egress_network_posture` fails closed when an existing network's options don't match | closes the exact gap rev 3 flagged for the network half |
| W17 · attribution-cache reuse across teardown | 🟡 **WIRED INTO TEARDOWN; RESOLVER STILL NEVER CONSTRUCTED IN PRODUCTION** | `attribution.rs`'s `invalidate()` now has real (non-test) callers at all three sites W17's own fix shape named: `exec_transport.rs`'s stale-posture recycle (`recycle_stale_container`, reached from `RebornScopedSandboxCommandTransport::run_command` → `ensure_container`), and `reaper.rs`'s `stop_container`/`remove_container` best-effort teardown paths. Docker-gated test `recycle_stale_container_invalidates_attribution_for_the_released_ip` exercises the exec-transport path end to end; the two reaper call sites have no test exercising them yet | **Not fully closed.** All three calls are gated behind `Option<Arc<ConnectionAttributionResolver>>`, populated only via `with_attribution_resolver` — which has **zero callers anywhere** (no test, no production composition), so the option is `None` everywhere today and these calls are currently inert. They activate automatically once W1.5b's own wiring constructs the resolver and threads it through both sites — W17 is no longer a distinct step ahead of W1.5b, it's the same remaining wiring effort. Even once wired, an in-flight `resolve()` can still write a stale entry back after `invalidate()` fires: the reuse window is collapsed toward zero, not eliminated, and stays bounded by the cache TTL |

**§1.4 (`/workspace` root mismatch)** and **§1.5 (cross-tenant symlink escape, incl. the empty-tail fail-closed gap)** are also **✅ LANDED** — see below; they were "in flight" in rev 3 and are confirmed shipped now.

### 1.0a 🆕 W6 phase 2 — hard requirements (must not be lost)

These surfaced while auditing the phase-1 slice above. None are blocking phase 1's SHIP verdict; all three **must** be closed before or alongside phase 2 (parsing + real credential injection), or the firewall's guarantees quietly stop holding.

**(a) Production-wiring readiness gate is currently blind to Sandbox.** `crates/ironclaw_host_runtime/src/services/production_services.rs:159-201` whitelists `RuntimeKind::Sandbox` in its match as a supported requirement, but the per-runtime `if config.requires_runtime(RuntimeKind::X) { push_missing(...) }` checks below only cover Script/Mcp/Wasm/FirstParty — there is **no** Sandbox branch. Paired gap: `crates/ironclaw_host_runtime/src/services.rs:842-855`'s `registered_runtime_backends()` builds its `Vec` by hand and has no `sandbox_runtime` field. **Consequence: the moment `required_runtime_backends` includes `Sandbox`, the readiness gate reports zero missing components even with no sandbox backend wired — a silent readiness bypass.** Dormant today only because nothing sets it. Both sites **must** be fixed together, in the same change that introduces the `sandbox_runtime` backend field. This is the **third** instance of the same failure shape in this program (alongside the per-user ceiling two production builders never wired, and the CI docker job that was never on main) — see §8's "Recurring pattern to watch."

**(b) Untrusted container output must be scrubbed before it reaches `model_visible_cause`.** Sandbox dispatch errors ride `DispatchError::Script { model_visible_cause, .. }`. Today nothing constructs `RuntimeKind::Sandbox`, so no container output flows there. When phase 2 starts populating that field from real container stdout/stderr, raw untrusted output **must** be scrubbed first — the existing discipline is commit `5fa99590b`, which routes sandboxed command output through `LeakDetector`. Losing the invariant on the error path after protecting the success path would be an especially easy miss.

**(c) The production origin `TlsConnector` must use a real trusted root store.** Carried forward from the warning already in `tls_intercept.rs`: there is no production connector yet; every existing test supplies its own. **No existing test would catch a permissive production connector** — verified. Building it with an empty/permissive root store, `dangerous()`, or a verifier that skips verification turns this credential firewall into a working MITM against our own users' egress. This must be an explicit review item on the composition/wiring PR, because the suite will stay green either way.

### 1.1 DONE and production-wired

| Dimension | State | Citation |
|---|---|---|
| Persistent container keyed `{tenant,user}` | ✅ | `user_key.rs:30-49`, `exec_transport.rs:45-88` |
| Readiness gate before exec | ✅ 5s/100ms | `exec_transport.rs:118-163` |
| Two-stage reaper + unconditional forced-recycle | ✅ idle 900s→stop; 7d→remove; 7d age→recycle | `reaper.rs:198-250` |
| Exec identity uid 1000 on **every** exec | ✅ fg, bg, liveness, kill | `exec_transport.rs:430-431,452,572,674` |
| `cap_drop: ALL` + `no-new-privileges` + `readonly_rootfs` | ✅ | `exec_transport.rs:329-359` |
| Egress **topological** (`internal:true`, no default route) | ✅ 10.200.0.0/24 gw .1 | `broker.rs:34-65`, `exec_transport.rs:176-243` |
| CONNECT allowlist + port pin + dial-time private-IP deny | ✅ RFC1918, 169.254/16, CGNAT, ULA, 0.0.0.0/8, v4-mapped | `egress_proxy.rs:103-126,441-645` |
| Sandbox output → `LeakDetector` | ✅ every exec | `process_output.rs:413-431` |
| Secret material reachable from container | ❌ **NO** — verified disjoint (§1.3) | |

### 1.2 MISSING / partial (rev 4: W3/root-init since resolved — see §1.0; W0 is built locally but rev 6 corrects that it is NOT resolved as a CI-enforced gate, see §1.0)

| Gap | Severity | Note |
|---|---|---|
| **Cross-container reachability now blocked (W1.5); proxy attribution built but unwired (W1.5b)** | 🟡 | See **D9**. Isolation landed; the attribution resolver that would let the proxy safely inject a credential has no caller yet. |
| No `pids_limit`, no CPU quota | ⚠️ | still `None`; `cpu_shares` = weight, not ceiling — **W2, not started** |
| Timeout process-group kill non-functional | ⚠️ | host-ns PID doesn't map into container ns; documented pre-existing gap in `exec_transport.rs` — **W4, not started** |
| Concurrency ceiling tenant-wide not per-user | ⚠️ | `sandbox_quota.rs:69-72` |
| Credential delivery | ❌ | this doc — W5/W6/W7-wiring/W8/W9/W10/W11/W12/W14, none started or wired |

### 1.3 Secret-store isolation — VERIFIED SAFE

```
<local_runtime_root>/
├── reborn-local-dev.db              ← secret ciphertext   NOT mounted (sibling)
├── users/                            ← abstract-FS /workspace  ⚠️ §1.4
└── sandbox-workspaces/users/<sha256{tenant,user}>   ← CONTAINER BIND (leaf only)
```

Master key = `IRONCLAW_REBORN_SECRET_MASTER_KEY` **env only**, never on disk for this profile, fails closed (`deployment.rs:717-749`); never in container env (`broker.rs:193-240` pushes endpoints only). Docker socket **not** bound. Bind is the per-user leaf; `mounts=None` always ⇒ **no `MountView` grant applies to the container bind** (`exec_transport.rs:323`, `mounts.rs:79-85`). `LocalDev` **cannot** enable the sandbox (`resolver.rs:325-343`).

### 1.4 ✅ LANDED — `/workspace` root mismatch

Was: abstract-FS mounted `<root>/users`; container bound `<root>/sandbox-workspaces/users/<digest>` — **different trees**, so `read_file`/`write_file` and the shell never saw each other's files. Cause: CLI passed plain `local_runtime_root` to the build input while the container path added `sandbox-workspaces`.

**Fix landed:** CLI owns `SANDBOX_WORKSPACES_SUBDIR` (`runtime/mod.rs`), threaded via `RebornHostBindings::with_sandbox_workspaces_root()` into `RebornProductionBuildContext` (`ironclaw_reborn_composition/src/factory.rs`); `mount_sandbox_user_workspace_root` roots at `context.sandbox_workspaces_root.join("users")`, fail-closed if unset while sandboxed. It landed together with §1.5, as required.

### 1.5 ✅ LANDED — cross-tenant symlink escape fix

`/workspace` is mounted **once at boot at the SHARED parent** `users_root` (`factory.rs:1978-1979`). Per-invocation narrowing (`sandbox_user_workspace_mount_view`) constrains the **virtual path string only** — never what a symlink *resolves to*. `ensure_contained` (`ironclaw_filesystem/src/local.rs:82-137`) checks `starts_with(mount.host_root)`, and `host_root` is the shared parent:

```
user A shell:  ln -s ../<digest-B>/secret.txt evil
host:          read_file("/workspace/evil")
               → canonicalizes to users_root/<digest-B>/secret.txt
               → starts_with(users_root) ✅ PASSES     ← cross-tenant read
```

**Was proven empirically** — returned `Ok(b"user-b-only")` pre-fix. Outside-root escapes (`/etc/passwd`) were already correctly rejected; only same-mount cross-user escapes leaked.

**Was inert only because of §1.4's bug** (disjoint trees ⇒ host never traversed container-planted symlinks). Landing §1.4 alone would have made this live — both landed together, as required.

**Fix landed:** `LocalMount::leaf_scoped` roots the mount at the caller's own digest **leaf** so the existing containment check pins to it — one boundary, no second check to keep in sync, and it makes the abstract mount agree with the container bind (already leaf-only, `exec_transport.rs`, `mounts.rs`). Regression tests cover cross-user symlink rejection on **both** `resolve_existing` and `resolve_for_write` (separate paths), and outside-root escapes still rejected.

⚠️ This also revised the assessment of the earlier P1 fix (`21a642d12`): it prevented *addressing* another user's path, not *symlinking* to it. Shared-parent mount + virtual-path narrowing was not sufficient containment. Pre-existing TOCTOU at `local.rs:127-133` is separate, narrower, already tracked — out of scope.

**✅ LANDED — empty-tail containment gap inside the fix (thermo, rev 3 finding).** `resolve_joined` narrowed `containment_root` only when `tail` was non-empty; a request for the **bare mount root** (`/workspace`, no tail) on a `leaf_scoped` mount fell through to `containment_root = host_root` — the full shared parent, i.e. exactly the boundary the fix removes. Now: `mount.leaf_scoped && tail.is_empty()` **fails closed** (`FilesystemError::PathOutsideMount`). Test `leaf_scoped_mount_rejects_bare_mount_root_request` in `local.rs` pins it.

**Pattern worth naming:** this was the third instance of *isolation asserted rather than enforced* — alongside D9 (shared network) and the unvalidated E1 topology (§5.2). See §8 for the now-extended list of six.

### 1.6 🆕 Unplanned work that landed since rev 3

- **`DockerProcessSandboxBackend` retired** (commit `44fe302d7`, −1643 lines net; tracking issue [#6686](https://github.com/nearai/ironclaw/issues/6686), still open). This was rev 3's "(c) minimal" decision under W1 — leave the dead backend's CA/iptables branches gated-off rather than delete them. It has since been deleted outright, not left gated-off; see the corrected W1 section in §4.
- **`origin/main` merged into the branch** (`a884f9420`, 12 commits), including a refactor moving roughly 137 files into a new `ironclaw_extension_host` crate. The branch is now 88 commits ahead / 28 behind `main` — the rev 3 baseline (`eb667c786`) is stale; treat any file:line citation against that commit with suspicion and re-verify.
- **Hardening inside W7 beyond its original spec**, driven by external review on PR #6689 (open against `main`, now 1920+/71− at time of writing — larger than its ~1329-line rev-3 estimate): lease refcounting, a multi-bind placeholder index, poisoned-lock recovery, a TOCTOU fix, a **Critical**-severity `finish_lease` standing-grant leak fix, session expiry defaulted-and-capped at 30 minutes, and a P0 simplification collapsing the session-lifecycle mutexes into a single `Mutex<SessionState>` (which deleted two near-duplicate revoke methods and a hand-documented lock-ordering rule it made unnecessary).

### 1.7 🆕 Known dead code to track (small, not urgent)

- `docker/process-sandbox-entrypoint.sh` — the `IRONCLAW_EGRESS_LOCKDOWN=broker-only` branch (~65 lines incl. its header comment) is orphaned by the backend deletion; nothing anywhere sets that env var today. **Keep** the part of the comment explaining why the persistent path must never call `update-ca-certificates` (readonly rootfs, non-root uid 1000 execution) — that reasoning is still live guidance for W5's CA trust distribution.
- `scope_key.rs::container_name_prefix()` (~4 lines) — has no callers outside its own module's tests; orphaned by the ephemeral→persistent container move.
- `mounts.rs::resolve_grant` (~line 148) — shared-parent `starts_with` containment, same bug class as §1.5's cross-tenant symlink escape. Dead today: `with_local_mount_source` (the only way to populate `RebornSandboxMountSources`) has zero production call sites; production `prepare_container_binds` always passes `mounts=None`. Doc comment added at the site (rev 4); needs leaf-scoping (see `ironclaw_filesystem::local`'s `leaf_scoped`/`containment_root`) before any future caller wires it. See §5 item 5.

### 1.8 🆕 2026-07-26 spike — sandbox container plumbing works end to end TODAY

Calling the production `ironclaw_reborn_composition::user_sandbox_process_binding` directly (throwaway test, run then deleted) spawned a real container and ran `echo hello-from-sandbox && whoami && hostname` → `exit_code=0`, output contained `hello-from-sandbox`, `whoami=sandbox` (non-root, confirming W1), hostname = container id. Independently cross-checked with `docker ps`/`docker inspect`: container `241471940dff` (`ironclaw-reborn-sandbox-user-9f10b490ef6a94b642ee0243`) running, `user=1000:1000`, attached to the pinned `ironclaw-sandbox-egress` network.

Profile selection: env var `IRONCLAW_REBORN_PROFILE=hosted-single-tenant-volume-sandboxed` (`ironclaw_reborn_config/src/profile.rs:6`, resolved in `boot.rs::resolve_from_env`); the CLI wires it via `build_sandboxed_local_runtime_services_input` (`ironclaw_reborn_cli/src/runtime/mod.rs:816`).

**Limits — record honestly:**
- The full CLI/agent-loop path was **NOT** exercised — no LLM provider credentials in this environment, so `ironclaw run` can't drive the agent loop that calls the shell tool. Environment gap, not a code gap.
- The **reaper was not exercised** — it runs inside the serve/runtime loop, which a standalone binding call doesn't start, so the container stayed `Up` until manual cleanup.

---

## 2. Architecture

### 2.1 Integration principle

Credential policy + injection already exist for extension/MCP egress. The sandbox is a **third caller with a different interception point** — not a new credential system.

```
╔═ POLICY + SECRET CORE — EXISTS ══════════════════════════════════════╗
║ SecretStore ──────── master key (env, host memory only)              ║
║ CredentialSession ── scope·capability_id·extension_id·secret_handles ║
║                      ·allowed_targets·expires_at·max_uses            ║
║                      `ironclaw_secrets/src/lib.rs:371-382`  ✅       ║
║ CredentialTargetPolicy::matches(method,url)                          ║
║   scheme+host+port+path(Exact|Prefix)+method, NO wildcards           ║
║                      `lib.rs:321-355`  ✅                            ║
║ RuntimeCredentialTarget  Header{name,prefix}·QueryParam·             ║
║   PathPlaceholder·BodyJsonPointer   `ironclaw_host_api::http`  ✅    ║
║ apply_credential_injections()  `egress/credential.rs:113` pub(super) ║
║ SecretMaterial ───── zeroize-on-drop                                 ║
╚════════════════════════╤═════════════════════════════════════════════╝
      EXTENSION ✅        MCP ✅        SANDBOX SHELL (NEW)
      host builds req    host builds   CONTAINER builds req
      → inject → send    → inject      → proxy intercepts → SAME inject
```

**Corrections vs rev 1** (thermo): the type is `RuntimeCredentialTarget`, *not* `RuntimeCredentialInjection` (that name doesn't exist). The entry point is `apply_credential_injections` (**plural**, `pub(super)`) — **not visible** from `sandbox_process::egress_proxy`; needs a visibility bump or extraction. `InMemoryCredentialBroker`/`CredentialSessionStore` **are** wired into DI (`host_runtime/src/services.rs:53,150,431-433`, `readiness.rs`) — the accurate claim is **nobody calls `create_session`/`consume_session_use` outside `ironclaw_secrets`' own tests**, i.e. wired but never used to mint.

### 2.2 End-to-end flow

```
 shell{cmd:"gh pr create"} → CAPABILITY DISPATCH (resolve bindings · audit)
        │
        ▼  container holds ONLY a stable placeholder (icsbx_7f3a…)
 git/gh sends: Authorization: token icsbx_7f3a…
        ▼
 PROXY (only route off-host)
   ├ host on a binding?  no → opaque tunnel, untouched ✅
   └ yes → terminate TLS (per-tenant CA)
           ├ live session for this invocation? no → JIT mint via policy port
           ├ CredentialTargetPolicy.matches(method,url)   ✅ built
           ├ consume_session_use (TTL, max_uses)          ✅ built
           ├ apply_credential_injections(&mut req)        ✅ built
           └ re-encrypt ─────────────────────▶ origin
   placeholder + no valid grant → STRIP, forward bare, annotate
   placeholder NEVER leaves the boundary
```

### 2.2a 🆕 Rev 8 — agent-placed placeholders (`credential_request` / `credential_placeholder_get`)

**Supersedes W10's six-format host writer** (§4 W10, ~~struck through~~ below) — that does not scale past the six enumerated formats, and every new CLI needs its own writer. New flow:

```
1. agent → credential_request(provider, requested_by, proposed_host?)
     → host-authored approval PROMPT (reuses the approval-gate machinery,
       GateResumeDisposition, auth-resume paths — not a bespoke dialog)
     → user supplies the real secret + confirms the destination
     → secret lands in SecretStore, HOST-SIDE
     → returns { placeholder }
2. already connected? agent → credential_placeholder_get(provider)
     → same stable token, { placeholder, connected }, NO prompt
3. agent WRITES that icsbx_… placeholder into whatever config the CLI
   reads — it already knows every tool's format; that is exactly the
   knowledge the host cannot scale to
4. CLI sends the placeholder → bound host's proxy + firewall swap it
   for the real secret at the boundary — UNCHANGED from §2.2/§2.3
```

**Load-bearing property: a placeholder is INERT.** It is a lookup key, not a credential — writing one grants nothing; whether it resolves is decided entirely at the proxy against a binding the agent does not control.

**The host MINTS, the agent PLACES — never the reverse.** The agent must never invent the placeholder string. The registry's contract is one stable token per `{tenant, user, provider}`: a self-chosen value per call produces N tokens per provider and makes revocation/cleanup chase all of them; the registry resolves token→owner globally, so independently-chosen values can collide and make that lookup ambiguous; and the agent gains no capability from choosing the bytes — see D10.

**§3.1's guard still holds without exception**: "the model can never create or widen a binding." The agent may REQUEST; the USER authorizes; scope comes from a reviewed profile or the user's own confirmation, **never** from an agent-supplied parameter.

**Two paths, and only two:**
- **Known provider** (the common path) — agent supplies only the provider id; host resolves host/path/method from a reviewed built-in profile (W12). Any `proposed_host` is **ignored entirely**, not validated-then-used.
- **Unknown provider** — agent may PREFILL `proposed_host`, rendered unverified and editable, with the consequence stated in the host's own words (e.g. *"Requests to X will be intercepted and your credential attached"*). User confirms or corrects the destination.

**Agent-supplied text is untrusted context, never a host assertion.** `requested_by` may be shown as a clearly-labeled, quoted, agent-supplied field — it must never land where it reads as the host asserting something, and the agent must not author the prompt's framing or justification copy.

**Rate limit:** one pending `credential_request` per user at a time — an agent that can emit prompts in a loop trains the user to dismiss them.

**🆕 New threat this motivates — wrong-host exfiltration** (full writeup in §3.1): a prompt-injected agent proposes a binding for an attacker-controlled host, the user approves, and the proxy then injects the user's REAL credential into requests to the attacker's server. This is why reviewed profiles (which pin the host so the agent cannot propose one at all) are strongly preferred over prefill.

**Honest regression (do not soften):** W12's design cleans host-seeded configs on disconnect, precisely to avoid "permanent 403 while `gh` claims it is logged in." With agent-written configs, **the host does not know where they are** and cannot clean them. It degrades rather than breaks — the placeholder is inert, and D5 strips-and-forwards-bare so the tool gets a plain 401 from the origin — but the confusing-failure problem the plan called out returns. Two partial mitigations, neither as good as host-owned cleanup: (1) make D5's annotation genuinely informative ("this credential is no longer connected") so the agent can self-correct; (2) have the placeholder-issuing capability (W18) record a breadcrumb ("agent placed this for tool X") so disconnect can at least tell the user which tools to reconfigure. This is a conscious trade for deleting six format writers — see W10/W12 in §4.

**Rev 9 correction:** the CA, firewall staging/lease/TTL model, attribution (W1.5b/W17), and §3.3's accepted envelope remain unchanged. D8 does not: signed HTTP protocols such as SigV4 can use the same inert-artifact model when the host can parse the complete request and apply a reviewed host-side authorizer. SSH and unsupported signing/streaming modes still require a dedicated mediated protocol lane or fail closed. A transformed token must never merely surface as a confusing origin 401: the profile either names a supported host transform or request admission rejects it before origin contact.

**Two things age well under this change:** `authorize()` returning the full live obligation set (§3.4) is *more* right now — multiple live providers per user becomes the normal case, not an edge case; and the distinct denial types (D5) are exactly what let stale agent-written configs degrade gracefully instead of breaking outright.

**Open PRs unaffected.** Neither PR #6695 (leaf containment + per-user identity primitives) nor PR #6723 (CA + credential firewall) is invalidated by this change — it lands entirely in unbuilt items.

### 2.2b Rev 9 — one presentation contract, sealed host transforms

"Credential injection" is retained as the historical name for W6's header-swap slice, but the durable abstraction is **credential presentation**:

```
reviewed profile
    ├── guest bootstrap recipe
    │     what inert artifact/helper output lets this CLI start
    └── host authorization transform
          how one authorized outbound request is authenticated
```

The profile set is a sealed host-owned enum. No extension, model, sandbox process, or downloaded plugin may install executable signer code or construct an unreviewed variant.

```rust
enum CredentialPresentationProfile {
    Header(HeaderPresentationProfile),
    Basic(BasicPresentationProfile),
    AwsSigV4(AwsSigV4PresentationProfile),
    OAuthBearer(OAuthBearerPresentationProfile),
    OriginMtls(OriginMtlsPresentationProfile),
    // Separate protocol lane; not part of HTTP V1:
    SshAgent(SshAgentPresentationProfile),
}

struct CredentialPresentationBinding {
    account_id: CredentialAccountId,
    profile_id: CredentialPresentationProfileId,
    profile_version: CredentialPresentationProfileVersion,
    artifact_id: GuestCredentialArtifactId,
    status: CredentialPresentationBindingStatus,
}

struct GuestCredentialArtifact {
    artifact_id: GuestCredentialArtifactId,
    fields: RedactedJson, // inert values only
    expires_at: Option<Timestamp>,
    profile_version: CredentialPresentationProfileVersion,
}
```

`CredentialPresentationBinding` is deliberately minimal. It does not duplicate `CredentialAccount`: account ownership/status, provider identity, real secret handles, and allowed credential targets remain in `ironclaw_secrets::CredentialAccount`.

The implementation may use concrete structs rather than traits until a crate boundary or second production implementation requires a trait. These are the required function-level seams:

```rust
// Product-auth/control plane. May create or select an account and persist a
// binding, but returns only an inert artifact to the sandbox-facing caller.
async fn issue_guest_artifact(
    caller: AuthenticatedCaller,
    reviewed_profile: CredentialPresentationProfileId,
    account: CredentialAccountId,
) -> Result<GuestCredentialArtifact, CredentialPresentationError>;

// Shell dispatch chokepoint. Opens one host-owned, RAII credential window
// from host-derived enabled bindings. Drop/revoke is primary; TTL is backstop.
fn open_shell_credential_window(
    principal: SandboxPrincipal,
    invocation: InvocationId,
    enabled_bindings: Vec<CredentialPresentationBindingId>,
    deadline: Instant,
) -> Result<ShellCredentialWindowLease, CredentialPresentationError>;

// Proxy/data-plane decision. No SecretStorePort and no account selection.
fn authorize_presented_request(
    principal: SandboxPrincipal,
    window: &ActiveShellCredentialWindow,
    artifact: PresentedCredentialArtifact,
    request: &OutboundRequestMetadata,
) -> Result<AuthorizedCredentialUse, CredentialPresentationError>;

// Host authority/materializer. Consumes a one-request authorization and
// applies the sealed profile transform. Raw material is borrowed only inside
// this call and is zeroized/revoked on every exit path.
async fn authenticate_outbound_request(
    authorized: AuthorizedCredentialUse,
    request: ParsedOutboundRequest,
) -> Result<HostAuthenticatedRequest, CredentialPresentationError>;

// Present only for explicitly reviewed token-producing APIs. The default is
// fail-closed, not pass-through.
async fn sanitize_credential_response(
    authorized: &AuthorizedCredentialUse,
    response: ParsedOriginResponse,
) -> Result<SandboxVisibleResponse, CredentialPresentationError>;
```

`AuthorizedCredentialUse` is opaque, non-serializable, scoped to one request, bound to principal/window/account/profile/version/target, and unusable after consumption or deadline. It is not a reusable secret handle. The proxy may hold the concrete data-plane service, but must not hold `SecretStorePort`, `CredentialAccountStore`, or raw `SecretMaterial`.

### 2.2c Rev 9 — initialization and egress diagrams

#### New CLI/profile initialization

```
 model/agent                  trusted host                         sandbox filesystem
     │                            │                                        │
     ├─ credential_request ──────▶│ Product auth + reviewed profile         │
     │  (profile id only)         ├─ user confirms account/profile         │
     │                            ├─ real material ──▶ SecretStore          │
     │                            ├─ CredentialAccount                      │
     │                            ├─ presentation binding                   │
     │                            └─ mint inert artifact                    │
     │◀─ GuestCredentialArtifact ─┤                                        │
     ├──────────────────────────────── write CLI-specific config ─────────▶│
     │                            │                               inert bytes only
```

For AWS, the agent normally writes:

```ini
[profile ironclaw]
credential_process = /usr/local/bin/ironclaw-credential-helper aws <artifact-id>
region = us-west-2
```

The helper runs inside the sandbox and returns a syntactically valid but inert `Version`/`AccessKeyId`/`SecretAccessKey`/optional `SessionToken`/`Expiration` JSON object. This follows AWS CLI's documented external credential-process contract: <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html>.

#### Initialized CLI egress

```
 shell dispatch                         sandbox                         trusted host
      │                                    │                                │
      ├─ open ShellCredentialWindow ──────▶│                                │
      │  (host-derived bindings + TTL)     ├─ CLI reads inert config/helper │
      │                                    ├─ signs with inert AWS key      │
      │                                    └─ proxy-only TLS egress ───────▶│
      │                                                                     ├─ attribute principal
      │                                                                     ├─ resolve artifact/binding
      │                                                                     ├─ require live window
      │                                                                     ├─ check account/profile/version
      │                                                                     ├─ check host/service/region/op
      │                                                                     ├─ materialize one use
      │                                                                     ├─ discard inert signature
      │                                                                     ├─ sign exact request on host
      │                                                                     └─ send to AWS
      │◀──────────────────────── sanitized response ────────────────────────┤
      └─ revoke/drop window                                                  │
```

The load-bearing predicate is:

```
inert artifact
+ attributed principal
+ active shell credential window
+ matching account/profile/version
+ reviewed target/service/region/operation
+ supported unambiguous request framing
= one host-authenticated request
```

### 2.2d Rev 9 — SigV4 authorizer requirements

`AwsSigV4PresentationProfile` pins, as reviewed host data: AWS partition, exact endpoint patterns, allowed services, allowed regions, allowed methods/path classes, maximum buffered body size, and permitted payload-signing mode. The sandbox cannot override those fields. Host/CONNECT authority, HTTP `Host`, credential scope, and profile endpoint must agree; a value supplied in the guest's inert `Authorization` header is untrusted input, never policy.

For an authorized bounded request, the host signer removes every guest authentication field (`Authorization`, `X-Amz-Security-Token`, signing date, and payload hash where applicable), canonicalizes the exact final request, and signs with the selected host-side AWS access key/secret/session token. SigV4's credential scope and HMAC derivation bind date, region, service, canonical headers, and payload: <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html>.

**Initial supported framing:** one HTTP/1.1 request per intercepted connection; no simultaneous `Transfer-Encoding` and `Content-Length`; no duplicate/non-numeric length; no obs-fold; bounded complete body; no upgrade; no tunnel after the first request. Any ambiguity closes the connection without contacting the origin.

**Initial denials:**

- S3 `aws-chunked` streaming (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) because every chunk has a chained signature and lengths/encoding must be rewritten: <https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming.html>.
- Presigned URLs/query authentication until a separate query re-sign transform exists.
- AWS event-stream signing, WebSocket upgrades, HTTP/2, gRPC, and protocol upgrades.
- Guest-side `aws configure`, `aws sso login`, and credential-producing STS operations. `AssumeRole` returns a real access key, secret key, and session token; forwarding that response would violate §0: <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html>.

SSO login, role assumption, and refresh occur on the host before the shell invocation. A future explicitly reviewed response transformer may capture a token-producing response into SecretStore and return a new inert child artifact, but V1 blocks such responses rather than attempting generic redaction.

### 2.2e Rev 9 — integration with the existing capability/obligation path

The implementation must reuse the existing authorization lifecycle rather than teaching `SandboxCommandTransport` about product auth. Live code establishes these facts:

- `CapabilityObligationRequest` carries the authoritative `ExecutionContext`, including `invocation_id`, tenant, user, scope, and capability id.
- `BuiltinObligationHandler::prepare` already resolves `InjectCredentialAccountOnce`, leases real material from SecretStore, and inserts it into `RuntimeSecretInjectionStore` before dispatch.
- `complete_dispatch` and `abort` are the existing post-dispatch cleanup chokepoints.
- `CommandExecutionRequest` intentionally carries only placement-neutral process data. It has no authorization obligations or approved binding set and must not grow product-auth policy fields.

Therefore the live window belongs beside the existing staged handoff:

```
CapabilityHost authorization
   └─ obligations for builtin.shell / builtin.cli_session
        (host policy derives enabled bindings; model does not supply them)
          │
          ▼
BuiltinObligationHandler::prepare
   ├─ account resolver → source handle + account/profile/target metadata
   ├─ SecretStore lease/consume → RuntimeSecretInjectionStore
   └─ SandboxCredentialFirewall::stage(invocation_id, binding metadata)
          │
          ▼
first-party shell handler → RuntimeProcessPort → SandboxCommandTransport
          │
          ▼
proxy authorizes attributed request against the same staged runtime
          │
          ▼
complete_dispatch / abort
   ├─ discard staged secret material
   └─ remove/drop every invocation-window lease
```

Required contract adjustment: today's `RuntimeCredentialAccessSecret` returns only `{scope, handle}`. Sandbox presentation also needs host-authored account id, provider/profile/version, and allowed targets. Replace or extend it with a typed resolved grant rather than re-querying account state from the proxy:

```rust
struct RuntimeCredentialAccessGrant {
    source_scope: ResourceScope,
    source_handle: SecretHandle,
    account_id: CredentialAccountId,
    provider_or_extension_id: ExtensionId,
    presentation_binding_id: CredentialPresentationBindingId,
    presentation_profile_id: CredentialPresentationProfileId,
    presentation_profile_version: CredentialPresentationProfileVersion,
    allowed_targets: Vec<CredentialTargetPolicy>,
}
```

The host authorizer/binding policy emits the account obligations for `builtin.shell` and `builtin.cli_session` from the user's enabled reviewed bindings. The handler resolves those obligations and stages grants. The process request and Docker transport remain unaware of credentials.

Window cleanup may be implemented as a handler-owned map of RAII leases keyed by the authoritative `ExecutionContext::invocation_id`; `prepare` inserts only after every required stage succeeds, and both `complete_dispatch` and `abort` remove/drop the exact invocation entry. TTL remains the process-crash/abandoned-entry backstop. The key must include invocation identity, not only `(scope, capability_id)`, because concurrent shell calls can share both.

### 2.3 Placeholder vs grant lifetime (the persistent-container answer)

```
CONTAINER      ─────────────────────────────────────▶ days
/workspace/.home  hosts.yml: icsbx_7f3a…  ← STABLE, inert alone (survives REMOVE)
INVOCATIONS    ▓▓▓▓      ▓▓▓▓▓▓▓▓▓     ▓▓▓
GRANTS         ├─┤       ├───────┤     (none)
PROXY          swap 403  swap    403    403
```

- **Placeholder**: stable per `{tenant,user,provider}`, **host-minted, agent-placed** (rev 8, §2.2a — supersedes the earlier "host-seeded" wording), persists across recycle, inert without a live session.
- **Grant** (`CredentialSession`): per `(invocation × binding)`, JIT-minted at first use, **explicitly revoked on dispatch completion**.

Config is written once by the agent, never rewritten per invocation; the agent cannot distinguish "authenticated" from "not currently granted" by reading the filesystem. (Rev 8: the host no longer knows where that config lives, which is why disconnect-cleanup degrades — see §2.2a.)

**✅ RESOLVED (thermo-nuclear ruling) — W8 grant lifetime.** `stage()` returns an RAII guard whose `Drop` calls `revoke`, mirroring `ironclaw_secrets`' `CredentialSessionLease`; explicit `revoke(self)` on the fast path, `Drop` as the structural backstop for error/timeout-via-dropped-future/panic-via-unwind. Worth preserving: caller discipline alone already failed once in the sibling mechanism — PR #6689 fixed a Critical standing-grant leak in `finish_lease`. Adopted now because `stage()` has zero callers, so it is free; retrofitting after W6 means auditing every exit path. TTL per D4: caller supplies invocation-timeout + 30s grace; `StagedCredentialObligation::new` clamps to `MAX_GRANT_TTL` (30 min, reusing `ironclaw_secrets::create_session`'s existing cap) as the numeric backstop. **Guard = primary bound, TTL = ceiling.** Also record the completed W8 hardening: expired entries are now reclaimed on read (were checked-but-never-removed, an unbounded-growth finding), with a test that observes map size rather than just the returned decision.

---

## 3. Decisions

| # | Decision | Chosen | Rationale |
|---|---|---|---|
| **D1** | MITM scope | **Narrow** — terminate only for bound hosts; all else opaque | Universal MITM makes the CA a confidentiality risk for *all* egress with no benefit. No-MITM can't inject over HTTPS. |
| **D2** | Authorization path | **Capability-dispatch obligation**, not a sandbox lease bypass | Production forbids direct `SecretStoreLease`; only staged obligations. An exception for the least-trusted context reintroduces that bypass. ⚠️ **mechanics unresolved — see §3.4** |
| **D3** | Model chooses credential? | **No.** Bindings are config; authorization is **JIT per (invocation × binding)**, bounded by host+path+method | Staging all bindings = standing grant. Model-declared = prompt injection picks credentials. ⚠️ **what this does NOT block: §3.3** |
| **D4** | Grant bounds | **Explicit revoke on invocation completion (primary)** · TTL = invocation timeout + 30s grace, cap 30min (backstop) · `max_uses` ~10k anomaly guard | Count bounds break `npm install` (hundreds of calls) or aren't controls. Fixed TTL kills long builds mid-flight leaving corrupt state. |
| **D5** | Uncredentialed request to bound host | **Strip placeholder, forward bare, annotate output** | 403 breaks *public* clone/install in background jobs. Origin's 401 is the better error. Placeholder must never leave the boundary. |
| **D6** | Credential per provider or per consumer | **Share the provider credential**; binding policy is the control. Keep the seam for provider-derived child tokens later | `ProviderId` is already shared across extensions. Sandbox never *holds* it, so blast-radius argument mostly evaporates. Many providers issue one key. |
| **D7** | Where a binding lives | **Two layers**: provider+auth recipe = extension manifest (`auth` surface, tools optional); binding = **child record under the provider** | A binding has no install lifecycle/version/trust tier. Setup routes through Layer 1, preserving `credential_name`/`extension_name` by construction. |
| **D8** | Signed/handshake credentials | **Sealed host authorizer when the full protocol operation is safely mediable; otherwise dedicated host-side tool/protocol proxy or deny. Never put the real key in the sandbox.** | SigV4 can be re-signed from the exact bounded HTTP request using an inert guest credential. mTLS can be originated by the host proxy. SSH needs a separate destination/operation-scoped signing lane. Streaming/chained/ambiguous variants fail closed. |
| **D9** | **Network topology + proxy attribution** | ✅ **RESOLVED: one network with `enable_icc=false` + source-IP attribution.** NOT per-user networks | Per-user networks cap at ~254 users on a /24 (needs carving a /16 into /28s), add create/destroy latency, and introduce a new dangling-resource class — we have already watched containers and phantom dirs accumulate. `enable_icc=false` is a one-line option on the network we already create, blocks container↔container while preserving container→gateway. Source IP is sound **over TCP** because a spoofed SYN's SYN-ACK returns to the spoofed address — blind spoofing cannot complete a handshake, and icc=false removes any path to intercept the return leg. Placeholder is the second factor. See §3.5. |
| **D10** 🆕 **rev 8** | **How a credential reaches a CLI in the sandbox** | **Agent-placed placeholders + host-authored approval gate** (§2.2a, W18) | Rejected: host-side config-seed writers for N formats — does not scale past the six enumerated (W10); every new CLI is a new writer. The format knowledge lives with the agent; the identifier and the authority live with the host. A placeholder is inert, so placement confers nothing. |

### 3.1 Guards for user-authored bindings

Host mandatory + narrow (**reject wildcards / bare TLDs**) · the binding **is** the allowlist entry (only way to widen MITM scope) · **user-scoped, never tenant-wide** · **model can never create or widen a binding** · never default path/method to `*` · ship narrow reviewed built-in profiles (*this is where the security lives*) · audit every use (invocation+host+path+method+provider, never material).

**🆕 Wrong-host exfiltration (rev 8) — the reason profiles beat prefill.** The dangerous field is the **destination**, not an over-broad path on a legitimate host. A prompt-injected agent proposes a binding for an attacker-controlled host (e.g. `api.githubb.com`); the user approves; the proxy then injects the user's **real** credential into requests to the attacker's server. The credential firewall becomes the exfiltration channel — authorized by the user's own approval. This is why reviewed profiles (§2.2a, W12) — which pin the host so the agent cannot propose one at all — are strongly preferred over prefill, and why, when prefill is unavoidable (unknown provider), the destination must be unmissable in host-authored words.

### 3.2 Accepted residual risks

1. **A live window is a live window** — see §3.3.
2. **Binding a host decrypts all traffic to it**, including public traffic that never needed a credential (we can't know before terminating TLS). Mitigate: bind the narrowest host that works (`api.github.com`, not `github.com`); audit termination.
3. **Policy bounds capability, not intent.** An authorized read by a manipulated model is still authorized.
4. **Envelope authoring quality is the real control.** Careless `PATCH /repos/*` can change repo visibility.
5. 🆕 **Body injection breaks streaming for bound hosts.** `BodyJsonPointer` requires buffering the body; today `copy_bidirectional` streams zero-copy. A large `git push` / upload to a *bound* host becomes fully buffered. Mitigate: use body injection only where required (header injection covers `git`/`gh`/`npm`/`pip`/`cargo`/`docker`); stream-through when the binding needs no body rewrite.

### 3.3 🆕 CORRECTION — what JIT does NOT block

Rev 1 justified D2 with: *"the staged obligation for `npm install` carries no github target, so a malicious postinstall gets 403."* **That is wrong under D3's JIT model.** Grants are minted by *what is actually contacted*, so any process running during an active invocation can mint a grant for **any** of the user's bindings:

```
shell{cmd:"npm install"}  ← invocation active
  └─ postinstall: curl api.github.com  (BOUND host, placeholder readable)
       └─ proxy: bound + placeholder + active invocation → JIT mint → SWAP
```

| D2+D3 **does** block | **Does not** block |
|---|---|
| Grants persisting between invocations (Option A would) | A malicious process *during* an active invocation reaching any bound host |
| Background/detached processes while no invocation window is live | A surviving same-user process deliberately observing and using a later invocation's live authority |
| Anything outside host+path+method | |

**The real control is the envelope + short TTL + audit, not command-scoping.** The persistent sandbox is one same-UID user trust domain: a process can inspect sibling process state, so an invocation token inherited through proxy environment is useful correlation and prevents accidental reuse of an old closed window, but it is not a hard boundary against a malicious surviving process during a later live window. Hard command isolation would require a fresh PID/user/container boundary or terminating prior descendants, both separate product decisions. Options considered: (a) accept + narrow envelopes ✅ chosen; (b) per-command binding predicate — **rejected**, brittle (`bash -c`, `xargs`, aliases) and the proxy can't see which binary opened the socket — it looks like security and isn't; (c) approval on first use of a binding per invocation — effective, real friction — **offer as opt-in for high-value bindings**.

### 3.4 ✅ D2 mechanics — RESOLVED (thermo-nuclear ruling)

**Mechanics:** the proxy holds a plain `Arc<SandboxCredentialFirewall>` — no trait, no port, no callback, no channel, no second chokepoint. One new field on `BoundEgressAllowlistProxy` alongside the `Arc<NetworkPolicy>` it already carries, threaded through `bind()` identically. Constructed once in `sandbox_egress_proxy_task.rs`'s `spawn_sandbox_egress_proxy` — the same `Arc` must be shared with wherever capability dispatch calls `stage`, so both read/write one instance. The accept loop's currently-discarded `peer_addr` becomes input to `ConnectionAttributionResolver::resolve(peer_ip)`, whose `ConnectionAttribution::{Attributed,Unattributed}` maps directly onto the `Option<(&TenantId,&UserId)>` `authorize` already takes — that is the W1.5b wiring, not a new abstraction.

**Why the layering concern is now moot:** it was legitimate only while W8 was unbuilt. Now that it is a concrete same-crate struct, the dependency edge is `sandbox_process → sandbox_process` — no new crate edge, so the architecture-review requirement is satisfied by that fact alone. (The `rcgen` edge from W5 is the one that still needed review; it got a SHIP verdict.)

**Fail-closed is already implemented and tested:** `authorize(identity, deadline)` returns `Err(LookupTimedOut)` (CONNECTION-DENIAL) when the deadline has passed, pinned by `expired_deadline_denies_the_connection_even_when_a_grant_is_staged`. Remaining W6 work is computing a real deadline instead of the test's `far_future_deadline()`.

**NOT to build:** no `trait SandboxCredentialFirewallPort`/`dyn`; no second staging map or proxy-local grant cache; no async callback/RPC for this edge.

### 3.5 🆕 D9 detail — topology and attribution

```
        ironclaw-sandbox-egress 10.200.0.0/24
   ┌────────┬────────┬────────┐
   │ user A │ user B │ user C │  ← same L2, no policy between them
   └───┬────┴───┬────┴───┬────┘
       └────────┼────────┘
                ▼  10.200.0.1:PORT  ← ONE proxy, all tenants
```

Two problems: **(1) lateral reachability** between containers; **(2) attribution** — with credentials the proxy must know whose secret to inject. Placeholder-as-sole-identity is weak if a container can obtain another's.

| Option | Isolation | Cost | Verdict |
|---|---|---|---|
| (a) per-user internal network | strongest — no lateral path | /24 caps ~254 users; carve /16 into /28s; create/destroy latency; new dangling-resource class | **rejected** — operational cost for what (d) gives free |
| (b) per-user proxy bind (own port) | container knows only its port | port management; **doesn't stop lateral traffic**; ports are discoverable by scanning the gateway | rejected |
| (c) source-IP attribution alone | none | spoofable in isolation | insufficient alone |
| **(d) `enable_icc=false` + (c)** ✅ | **no lateral path; attribution sound over TCP** | one option on the network we already create | **CHOSEN** |

```
 ironclaw-sandbox-egress   internal:true   enable_icc=FALSE
   ┌────────┬────────┬────────┐
   │ user A │ user B │ user C │
   └───┬────┴───┬────┴───┬────┘
       ✗────────✗────────✗      ← container↔container BLOCKED
       └────────┼────────┘
                ▼  10.200.0.1:PORT   ← gateway still reachable
       proxy: source IP → docker inspect → labels → {tenant,user}
```

**Why source-IP is sound here** (it usually isn't): establishing a TCP connection requires completing a handshake; a spoofed SYN's SYN-ACK returns to the *spoofed* address. Blind spoofing cannot complete it, and `enable_icc=false` removes any path to intercept the return leg. The placeholder is a second factor.

**Implementation:** `sandbox_egress_network_create_options` — add `com.docker.network.bridge.enable_icc=false`.
**⚠️ Verify before relying on it** (cheap, colima is available): confirm icc=false actually blocks container↔container **and** preserves gateway reachability, **and** that it holds under DinD in CI. If it does not, fall back to (a). Tests §6 rows 1-3, 11-12.

---

## 4. Work items

Ordered. Each: fix shape · test-first spec (red→green) · size · risk. Per `ironclaw-issue-bugfix` Phase 2, **no production edit lands before a failing test proves the behavior.**

> **Standing constraint for every thermo/plan review below:** "No over-engineering. Prefer the simplest direct fix that follows repo boundaries and deletes or avoids complexity. Do not demand abstraction unless it makes the code materially simpler."

### PRIORITY 0 — verification gap (blocks trusting everything)

**W0 · CI builds the sandbox image and runs docker-gated tests as a BLOCKING job** — 🔴 **BUILT LOCALLY, NOT ON MAIN, NEVER EXECUTED IN CI (corrected rev 6)**
- **Evidence:** `reborn-tests.yml` on this local branch has a `sandbox-docker-tests` job that builds `Dockerfile.process-sandbox` and runs the docker-gated suites (`sandbox_exec_transport_docker`, `sandbox_reaper_docker`, `sandbox_workspace_fs_parity_docker`, `sandbox_cross_tenant_escape`, `reborn_integration_sandbox_egress_proxy`, others), with `IRONCLAW_REQUIRE_DOCKER_TESTS=1` and a roll-up gate that treats it as non-skippable — **but the commit that added it (`29196c8fc`) exists only on this local unpushed `sandbox/shell-integration` branch.** It is not on `origin/main` (`git merge-base --is-ancestor 29196c8fc origin/main` → false; `git branch -r --contains 29196c8fc` → empty; `origin/main`'s `reborn-tests.yml` has no such job), and it has never run in GitHub Actions — the job "Reborn sandbox Docker tests" does not appear in the last 40 workflow runs across all branches.
- **Consequence — say it plainly:** every docker-gated assertion this plan treats as CI-enforced (§6) is currently enforced nowhere. The bugs this job was written to catch (the cap bug, exec-as-root bug, start race) were fixed under W1/W16, but they are exercised only by local developer runs against colima, not by CI.
- **2026-07-26 CI-gating decision (DECIDED, IN PROGRESS — not landed):** a blanket `has_reborn_tests` gate that would run this job on nearly every PR was rejected by the user on cost grounds — it adds roughly 30 minutes to nearly every PR, dominated by the 1.82GB `ironclaw-worker` image build. The job is being narrowed to sandbox-related paths plus unconditional runs on push-to-main and merge_group, with Buildx layer caching to cut the build cost. This narrowing is in progress by another agent in this worktree; it has not shipped. See §5 item 7.

### PRIORITY 1 — hardening + foundations (V1)

**W1 · Eliminate the root init window** — ✅ **LANDED**
- `DockerProcessSandboxBackend` — the second consumer rev 2/3 debated gating vs. deleting — **has since been deleted outright** (commit `44fe302d7`, tracked by issue [#6686](https://github.com/nearai/ironclaw/issues/6686), still open for any residual follow-up). Not gated-off as rev 3's "(c) minimal" decision predicted; retired. `ironclaw_process_sandbox/src/docker.rs` no longer exists in the tree.
- **Fix shape landed as planned:** Dockerfile drops the trailing `USER root`; entrypoint no longer execs `capsh`; `exec_transport.rs` sets `user: Some(SANDBOX_EXEC_USER)` (uid/gid 1000) on the container's own init (PID 1) as well as every exec, and `cap_add: None`.
- **Test:** container-limits test asserts `cap_add` empty and PID 1 itself runs uid 1000 (not just exec identity).

**W15 · Approval-on-first-use for high-value bindings** — ❌ **NOT STARTED.** S/M ~2d — **Priority 3, explicitly deferred but TRACKED**
- The named mitigation for §3.3's accepted residual (in-invocation lateral reach). Without a work item it evaporates. Per-invocation, per-binding human approval at the **tool-call layer** (never at the socket — blocking a TCP request on a human decision hangs `git push`). Opt-in per binding, for sensitive ones only.
- **If not built, §3.2 risk #1 stands unmitigated beyond envelope+TTL+audit — say so to the user rather than implying it's covered.**

**W1.5 · D9 — lateral isolation (network half)** — ✅ **LANDED.** `enable_icc=false` is on `sandbox_egress_network_create_options`; colima-verified empirically (blocks container↔container TCP and ICMP, preserves gateway reach). DinD leg still unverified (§5). **W16's network posture-check landed alongside it**, so an existing network lacking the option is no longer silently accepted.

**W1.5b · D9 — proxy attribution (unwired)** — 🟡 **BUILT, NOT WIRED.** `sandbox_process/attribution.rs`'s `ConnectionAttributionResolver` (source IP → `docker inspect` → container labels → `{tenant,user}`, cached, fails closed on duplicate-IP or malformed labels) is implemented and unit-tested, but `mod attribution;` is private with zero callers — `egress_proxy.rs`'s `handle_connect` never invokes it. **This is now a named blocker on the critical path**: nothing can safely inject a credential (W6) until the proxy actually calls this resolver. See W17 below for a bug found inside it (cache-reuse across teardown) that must be fixed before it is wired in.

**W2 · `pids_limit` + CPU quota** — ❌ **NOT STARTED.** S ~0.5d. **Fail closed** if unsupported (Hermes' all-or-nothing warning-only probe is a named anti-pattern). Extend the same `docker inspect` test.

**W3 · Reaper spawn fails loudly** — ✅ **LANDED.** `sandbox_reaper_task.rs`.

**W4 · Container-namespace PID for timeout kill** — ❌ **NOT STARTED.** M ~1-2d. `exec_transport.rs`'s own doc comment now names this explicitly as a pre-existing, still-open gap: the host-namespace PID Docker reports for an exec doesn't resolve inside the container's PID namespace, so the timeout kill is confirmed non-functional (`kill -KILL` on a live process reports "No such process" and the process survives); a timed-out job's process group is only ever reclaimed when the container is later recycled.

### PRIORITY 2 — credential firewall (V1.1)

🔴 **Rev 4 correction — W6's gating was incomplete.** Rev 3 gated W6 on W1.5 + W7 + W8 only. **W5 (internal CA) is also a hard W6 blocker** — TLS termination cannot issue leaf certs without a CA to sign them from, and W5 has not started. The real critical path, accounting for what has actually landed:

> **W8 (chokepoint, zero code today, unblocked) → wire W1.5b into the proxy → W17 (fix the attribution-cache reuse bug first) → give W7 a real caller → W5 (internal CA) → W6 (TLS termination + injection).**

W8 is the true long pole: it is the layering decision the proxy needs settled per §3.4, and nothing blocks starting it today.

**W5 · Internal CA (per tenant)** — ❌ **NOT STARTED.** S ~2d + spike
- `rcgen` (**new dep — run `ironclaw-reborn-architecture-review` before landing**). Private key in `SecretStore`, **never mounted**. **Persist** (a CA regenerated per process restart invalidates every running container's bundle). Rotate ~30d + on demand, picked up at container start, **never mid-container**. Leaf certs per bound host, in-memory, short TTL.
- **Trust distribution — do NOT use `update-ca-certificates`** (fails under `readonly_rootfs`; with `set -eu` it aborts the entrypoint). Host builds `system_roots + our_CA`, bind-mounts **read-only**, sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, **and `NODE_EXTRA_CA_CERTS`** (Node ignores the others). Concatenation mandatory — `SSL_CERT_FILE` *replaces* the trust store.
- 🔻 **Cargo credential binding DE-SCOPED from V1** (was a blocking spike). Public crates.io works fine through the **opaque tunnel** — no binding, no MITM, no credential. A cargo binding buys only *private registry* auth, which is rare, while being the riskiest compat item in the matrix. Run the spike as **information, not a gate** (test `CARGO_HTTP_CAINFO` / `http.cainfo`, which cargo honors for its libcurl path); if it works, add the binding later as a freebie.
- **V1 bindings that matter:** `git` / `gh` (the stated use case), `npm`, `docker`. All have well-understood CA knobs.
- **Compat matrix (test, don't assume):** curl/git (OpenSSL) low · pip/Python medium (`certifi` varies) · Node ⚠️ needs `NODE_EXTRA_CA_CERTS` · Go/`gh` low · cargo — deferred · cert-pinning 🔴 (must fall back to opaque tunnel).

**W7 · Placeholder registry + session wiring** — 🟡 **BUILT AND TESTED, WIRED TO NOTHING**
- `ironclaw_secrets/src/placeholder.rs` has the stable placeholder store keyed `{tenant,user,provider}`, separate from the session store; `CredentialSession` looked up **by placeholder**; `InMemoryCredentialBroker::mint_on_first_use` does the JIT mint; explicit revoke is covered on multiple exit paths including panic/timeout, per its own extensive test module (`placeholder/tests.rs`). **But `mint_on_first_use` has zero callers outside that crate's own tests** — no request path (shell exec, proxy, or otherwise) calls it yet.
- **Shipped ahead of spec**, driven by external review on PR #6689 (open against `main`): lease refcounting, a multi-bind placeholder index, poisoned-lock recovery, a TOCTOU fix, a fixed **Critical** `finish_lease` standing-grant leak, session expiry defaulted+capped at 30 min, and a P0 simplification collapsing the session-lifecycle mutexes into one `Mutex<SessionState>` (deleting two near-duplicate revoke methods and a hand-documented lock-ordering rule it made unnecessary). See §1.6.
- **Remaining work is exactly "give it a caller"** — wire `mint_on_first_use` into the request path once W8's chokepoint exists.

**W8 · Obligation staging chokepoint for the shell tool** — ❌ **NOT STARTED — the true long pole**
- No chokepoint mirroring `activation_credential_requirements` exists for the shell tool. **This is also the port the proxy will call for JIT (§3.4)** — reuse, don't invent a second. Fail closed on timeout. Zero code today; nothing blocks starting it, and everything else on the critical path (wiring W1.5b, W17, W7, W5, W6) sits behind it.
- **✅ Grant-lifetime mechanics RESOLVED (thermo-nuclear ruling) ahead of build — see §2.3.** `stage()` returns an RAII guard (`Drop` → `revoke`, mirroring `ironclaw_secrets`' `CredentialSessionLease`); TTL (D4: invocation timeout + 30s grace, clamped to `MAX_GRANT_TTL` 30min) is the numeric backstop, the guard is the primary bound. Adopt the guard now, before `stage()` has any caller — retrofitting after W6 means auditing every exit path, and PR #6689's Critical `finish_lease` leak already proved caller discipline alone isn't enough in the sibling mechanism.

**W6 · Proxy TLS termination for bound hosts** — ❌ **NOT STARTED** — **L/XL ~7-10d** — *the real work, highest risk* — **⛔ GATED ON W1.5b (wired) + W17 + W7 (wired) + W8 + W5** (attribution must exist and be wired before credentials are injected, or a request cannot be safely tied to a user; the CA must exist to terminate TLS at all; the session store and mint path must exist and be reachable for W6's own test plan — "origin observes the real secret" — to be able to pass)
- Extend `handle_connect` (today still opaque `copy_bidirectional` in `egress_proxy.rs`): bound host ⇒ SNI-driven leaf cert, terminate, inject, re-encrypt. Non-bound path **unchanged**.
- 🔺 **Carve into its own module** (e.g. `sandbox_process/tls_intercept.rs`) **from day one** — `egress_proxy.rs` is already large and mixes DNS resolution, private-IP denial, and plain-HTTP handling; adding cert-minting + MITM is over the thermo ceiling. This is the boring fix, not speculative abstraction.
- **Test:** docker-gated — (a) origin observes the **real** secret, (b) container-visible config/`env` has **only** the placeholder, (c) unbound host stays an opaque tunnel (assert no leaf issued).

**W9 · Reuse `apply_credential_injections`** — ❌ **NOT STARTED.** S/M ~1-2d. Still needs a **visibility bump or extraction** (`pub(super)` in `egress/credential.rs`, not visible from `sandbox_process`); extract to a shared location rather than growing that file further.

~~**W10 · Host-side config-seed writer**~~ — ❌ **NOT STARTED, SUPERSEDED (rev 8).** 🔻 resized M/L~4-5d → **S ~1d**
- ~~Host writes placeholders into `/workspace/.home` at container create (idempotent, once per `{user,provider}`): `.git-credentials`, `~/.config/gh/hosts.yml`, `.npmrc`, `~/.docker/config.json`, `CARGO_REGISTRY_TOKEN`, kubeconfig. **Never** the agent, never in-container `login`. Rewrite `git@host:`→`https://host/`.~~
- ~~Six genuinely different serialization targets with different idempotency/escaping rules, interacting with W12's disconnect cascade. An `enum ConfigFormat` + one writer per format is the **right** amount of structure here (six real formats, not one abstraction pretending to be six).~~
- **Superseded by D10/W18 (§2.2a):** does not scale past the six enumerated formats — every new CLI is a new writer, and the format knowledge properly belongs to the agent, not the host. **What remains, OPTIONAL:** env-var seeding of the SAME placeholder for known providers at container create — largely redundant once the agent configures tools via W18, and covers only the narrow case of a tool that reads its credential from the environment before the agent has run. The real remaining work moved to W18 (the placeholder-issuing capability).

**W11 · Login guard** — ❌ **NOT STARTED — now a REDIRECT (rev 8).** S ~1d. Deny `gh auth login` / `npm login` / `docker login` / `git config credential.helper` with a guiding message. Otherwise a real token lands in `/workspace`, which **persists**. Scope is unchanged, but denying login is only defensible because `credential_request` (W18) is the supported alternative — the guard's message **must name it**. **Never ship W11 before W18 lands**, or users can neither authenticate nor be given credentials.

**W12 · Binding model + UI** — ❌ **NOT STARTED — GROWS INTO THE SECURITY CENTER OF THIS DESIGN (rev 8).** M ~3d, size likely undercounted now. Provider-scoped child records (D7); built-in profiles as first-party data; validation at bind time (unknown/unconnected provider → reject); **cascade on disconnect** (disable bindings, clean seeded configs — else permanent 403 while `gh` claims it's logged in; rev 8 degrades this, see §2.2a).
- **Rev 8 growth:** reviewed built-in profiles are no longer just convenience data — they are **load-bearing security content**, because path 1's (known-provider) safety depends entirely on the profile pinning the host so the agent cannot propose one (§3.1's wrong-host exfiltration threat). Each profile now needs a security review, not just code review.
- **Rev 8 growth:** bindings now have **two creation entry points** — the settings UI and the agent's `credential_request` (W18) — which **must** funnel through **one** authorization chokepoint. Cite the repo's recurring "one chokepoint per decision" lesson: two creation paths with separate checks is exactly how a silent fail-open ships.

**W18 · `credential_placeholder_get` + `credential_request` capabilities** 🆕 **(rev 8)** — ❌ **NOT STARTED.**
- The two agent-callable tools from §2.2a. `credential_request(provider, requested_by, proposed_host?)` triggers a host-authored approval prompt (reusing `GateResumeDisposition` and the existing auth-resume paths, not a bespoke dialog), mints the placeholder on approval, and stores the real secret host-side in the SecretStore. `credential_placeholder_get(provider)` returns the same stable token with no prompt when already connected.
- Goes through normal capability dispatch/authorization/approval — no new bypass. Rate-limited to one pending request per user at a time.
- Known-provider path resolves host/path/method from a W12 built-in profile and **ignores** any `proposed_host` entirely; unknown-provider path renders `proposed_host` as unverified/editable with the destination stated in the host's own words.
- This is the real remaining work W10 used to represent — the placeholder-issuing capability, not a per-format writer.

**W19 · Shared sandbox credential runtime + shell window** 🆕 **(rev 9)** — 🟡 **STATIC SKELETON BUILT.**
- **W19a — shared plumbing — ✅ BUILT 2026-07-31:** `SandboxCredentialRuntime` is one opaque concrete handle containing the placeholder registry, `SandboxCredentialFirewall`, and `RuntimeSecretInjectionStore`. `user_sandbox_process_binding` constructs it before proxy spawn and returns the same clone to the CLI/composition input. `bind_sandbox_egress_proxy_with_tls_intercept` requires that caller-owned runtime and no longer constructs empty stores. `HostRuntimeServices::with_sandbox_credential_runtime` installs its exact injection-store `Arc` and rebuilds `ProcessObligationLifecycleStore` around it, preserving the event sink. The runtime owns no `SecretStorePort` and exposes no account-selection API.
- **W19b — static live-window skeleton — ✅ BUILT 2026-08-02; profile authority corrected 2026-08-03:** `BuiltinObligationHandler::prepare` is installed only for the sandbox deployment profile, selects only active single-secret accounts with non-empty target policies, stages host-side material, and opens invocation-keyed RAII leases. Direct `satisfy` never opens a window. `complete_dispatch` cleans up on success and every post-dispatch failure; `abort` also revokes. `SandboxCommandTransport` remains credential-unaware. No per-user setting can bypass or disable the selected runtime lane.
- **Deliberate skeleton boundary:** an existing `CredentialAccount` and its exact target policy are the host-owned binding. Only a sole Basic/Bearer `Authorization` field may materialize. W12 must add reviewed profiles/UI before arbitrary named headers, richer account selection, or any signing transform.
- The proxy receives the concrete data-plane handle only. It does not receive `SecretStorePort`, `CredentialAccountStore`, or a model-selected account id.
- **Caller-level tests:** W19a proves obligation services and proxy share one runtime and rejects a separately constructed runtime; W19b proves a production-shaped shell call opens a window visible to that proxy, success/error/timeout revoke, and an attributed request without a live window never materializes.

**W20 · Reviewed presentation profiles + inert AWS artifact** 🆕 **(rev 9)** — ❌ **NOT STARTED; DEPENDS ON W12/W18/W19.**
- Add the sealed `CredentialPresentationProfile` variants and minimal presentation binding from §2.2b. Reuse `CredentialAccount`; do not create a second account/secret-handle record.
- Add an AWS profile whose endpoint/service/region/operation bounds are first-party reviewed data. The known-provider request accepts only profile id + account selection; no agent-supplied host/service/region field.
- Extend the host-minted artifact registry from provider-only identity to binding/profile/version identity. Return AWS-compatible inert fields through a sandbox helper implementing the documented `credential_process` JSON protocol. The helper has no socket/secret access and can operate from the persisted inert artifact alone.
- **Tests:** artifact is stable for one binding/version, rotates when binding version changes, cannot resolve cross-principal, contains no stored secret bytes, and remains origin-inert without an active window.

**W21 · Bounded host-side SigV4 authorizer** 🆕 **(rev 9)** — ❌ **NOT STARTED; DEPENDS ON W19/W20.**
- Parse exactly one bounded HTTP/1.1 request and reject every ambiguity listed in §2.2d before origin dial. The existing first-head-only swap is not sufficient because SigV4 covers the final headers and payload.
- Resolve the inert AWS access-key artifact to a presentation binding, authorize it through the active window, compare CONNECT host + HTTP Host + credential scope against the reviewed profile, then consume one `AuthorizedCredentialUse`.
- Use the maintained AWS SigV4 implementation already present transitively in the workspace (`aws-sigv4`) rather than hand-rolling canonicalization/HMAC. Add it as a direct dependency of the owning crate and pin behavior with AWS's published examples plus a caller-path origin verification test.
- Remove all inert signing fields, sign the exact final request with host-side material, and zeroize/drop material on every exit. No fallback forwards the inert signature.
- **Tests:** AWS published signing vector; wrong host/service/region/method/path denied before origin; expired/no window denied; origin sees a valid real signature while sandbox files/env/helper output contain only inert values; signer error never contacts origin.

**W22 · Credential-producing response guard** 🆕 **(rev 9)** — ❌ **NOT STARTED; REQUIRED BEFORE BROAD AWS PROFILE.**
- Default-deny reviewed endpoints/operations whose responses can mint reusable credentials. Initial AWS profile blocks STS `AssumeRole`, SSO login/token, and equivalent credential-producing calls from the sandbox.
- Response bytes pass through the existing secret/leak detector before sandbox visibility. Detection is defense in depth; operation denial is the authority boundary.
- A future token-capture transform must be explicit per operation: parse the typed response, persist real child material to SecretStore, create a child presentation binding, and return only a new inert artifact. Generic regex replacement is not acceptable.
- **Tests:** STS request is rejected before origin; a misconfigured origin response containing known real material is blocked/redacted fail-closed; ordinary non-credential AWS responses still pass.

**W13 · Leak pattern for placeholders** — ✅ **LANDED.** Fixed prefix (`icsbx_`) into `leak_detector::default_patterns()`.

**W14 · Revoke-on-recycle** — ❌ **NOT STARTED.** S ~1d. Invalidate sessions for `{tenant,user}` on teardown, hooked into the reaper path.

**W16 · container security posture is pinned at create and never re-evaluated** — ✅ **LANDED, both container and network halves** — **cross-cutting: gates the rollout of W1, W1.5, W2, W5**
- **Evidence:** `ensure_container` (`exec_transport.rs:45-88`) selects an existing container by **label filter only** — `[existing] => ensure_running(...)`. No image digest, no config, no posture check. A container created under the old posture is reused indefinitely.
- **Consequence:** every container-config hardening in Priority 1 applies **only to newly created containers**. After W1 deploys, already-running per-user containers keep root PID 1 with `SETPCAP/SETUID/SETGID` until something recycles them — up to **7d** under the current reaper policy (idle 900s→stop; 7d→remove; 7d age→forced recycle). Same for W2's `pids_limit`/CPU quota, W1.5's `enable_icc=false` network, and W5's CA bundle mount. "W1 landed" ≠ "no root init windows in production."
- **This is the same pattern the workstream keeps hitting:** posture asserted at one point in time rather than enforced continuously. It was surfaced only because a stale container silently reused an old image during W1's test run and produced an impossible-looking result.
- **Fix shape:** stamp a posture/config generation label at create; in `ensure_container`, recycle rather than reuse when the stamp does not match the current expected value. Cheap, one place, and it makes every future container-config change self-deploying.
- **Test:** a container created with a stale posture label is destroyed and recreated, not reused; a matching one is reused untouched.
- 🔴 **Same defect on the NETWORK, and there it is permanent.** `ensure_egress_network` (`exec_transport.rs:176-193`) treats `is_network_already_exists_error` as success and returns `Ok(())` **without inspecting the existing network's options**. Unlike containers, the egress network is never recycled by the reaper — nothing ever recreates it. ⇒ **W1.5's `enable_icc=false` would be a silent no-op on every environment where `ironclaw-sandbox-egress` already exists**, which is all of them, including this dev box (verified live: `Internal=true Options={} Subnet=10.200.0.0/24`). D9's lateral-isolation guarantee would be *asserted in code and absent in reality* — the same pattern as §1.5/D9/§5.2, now inside the fix for D9 itself.
  **This landed as required — W16 shipped covering both halves before W1.5's isolation guarantee was relied on**, and the network posture check now fails closed (or recreates) when an existing network's options don't match. **Test landed:** an existing network lacking `enable_icc=false` is not silently accepted.

**W17 · attribution cache can misattribute across users for the TTL window** — 🟡 **WIRED INTO TEARDOWN, RESOLVER STILL NEVER CONSTRUCTED IN PRODUCTION** — S ~0.5-1d remaining — **the remaining risk is now the same wiring W1.5b needs, not a separate blocker**
- **Evidence:** `ConnectionAttributionResolver::resolve`'s cache-hit path (`sandbox_process/attribution.rs`) checks only `entry.inserted_at.elapsed() > cache_ttl`. On a hit it returns the stored attribution with **no re-verification** — not the container ID, not the labels.
- **Consequence:** for up to `cache_ttl` (default **5s**), a torn-down container's IP that Docker reassigns to a **different user's** container still resolves to the **previous** owner. Once W6 injects credentials on this, that is a **cross-user credential leak** — precisely the failure source-IP attribution exists to prevent. Confirmed by the implementing agent, not inferred.
- **What already fails closed (good, tested):** duplicate IP on two containers ⇒ `Unattributed`, never "first match" (`duplicate_ip_on_two_containers_refuses_to_guess`); malformed or partial label set ⇒ `Unattributed`, never a half-parsed identity (`malformed_label_value_is_rejected`, `partial_label_set_is_rejected_not_partially_parsed`).
- **The fix shape has now landed at all three call sites named below** — `invalidate(ip)` is wired into `exec_transport.rs`'s stale-posture recycle (`recycle_stale_container`) and into `reaper.rs`'s `stop_container`/`remove_container` best-effort teardown paths (reaper sweep + explicit removal; W16's posture-mismatch recycle is the exec-transport site). **But it is not yet live**: all three calls are gated behind `Option<Arc<ConnectionAttributionResolver>>`, populated only via `with_attribution_resolver`, which has zero callers anywhere — no production composition constructs a resolver and threads it in, so the option is `None` everywhere today. Alternative/additional idea not pursued: cache `(attribution, container_id)` and re-verify the container ID on hit — costs a Docker round trip per hit, largely defeating the cache.
- **Sequencing:** the remaining work is exactly W1.5b's own wiring (constructing the resolver and passing it via `with_attribution_resolver` to the proxy, the exec transport, and the reaper) — W17 is no longer a distinct step ahead of that, it activates automatically once W1.5b lands. It is still the sixth instance of *isolation asserted rather than enforced*, and the only one currently shipped in a merged branch, until that wiring lands.
- **Test:** `recycle_stale_container_invalidates_attribution_for_the_released_ip` (docker-gated) proves an IP whose container was torn down via the exec-transport recycle path, with a resolver manually wired in, does NOT resolve to the previous owner. No equivalent test exists yet for the two `reaper.rs` teardown paths.

### PRIORITY 3 — later

Dedicated host-side tools/protocol proxies for operations outside the bounded HTTP authorizer: S3 streaming uploads, presigned URLs, AWS event-stream, SSH agent operations, and protocol-pinned mTLS clients · provider-derived child tokens (D6 upgrade) · per-user concurrency ceiling. SSH forwarding remains opt-in and destination/operation scoped because it is a live signing oracle.

---

## 5. Open verification items

**None of these block implementation — all are verification, not decisions.**

1. ~~**Does `enable_icc=false` block container↔container while preserving gateway reachability, under colima AND DinD?**~~ ✅ **colima leg VERIFIED 2026-07-26** (empirically, not by reasoning):

   | Probe | Result |
   |---|---|
   | control network (icc default), A→B:8080 | `open` — connects |
   | `enable_icc=false`, A→B:8080 | **dropped** (5s timeout, not refused) |
   | `enable_icc=false`, A→B ICMP | **dropped** |
   | `enable_icc=false`, A→gateway:22 | `open` — **gateway reach preserved** |
   | network options | `{"com.docker.network.bridge.enable_icc":"false"}` |

   Listener liveness self-checked on B (`nc -zv 127.0.0.1 8080` → open), so the block is not a dead-listener artifact. Both networks `--internal`. ⇒ **W1.5 stays S/M; the per-user-network fallback (option (a)) is NOT triggered.**
   **Still open: the DinD/CI leg** — was intended to ride with W0, but W0 itself has never run in CI (see §1.0, corrected rev 6) — there is currently **no environment** where the DinD leg has been exercised at all.
2. **Is E1 internal-network topology actually enforced in DinD CI?** `broker.rs` admits it is not validated locally. Need a docker-real test asserting `curl 169.254.169.254` fails with **no route**, not a proxy 403 — different guarantees. Fallback if infeasible in DinD: in-container nftables — **do not improvise silently.** *(See §6 row 9 — the currently existing test proves the proxy's private-IP check, which is a different guarantee than "no route.")*
3. **Advisory-mode escape hatch.** `IRONCLAW_SANDBOX_HTTP_PROXY`/`_PORT` (`sandbox_boot.rs`) puts the container on normal bridge networking with env-var-only steering — Hermes' defeated-by-`unset` model. Not default, but reachable. Document loudly at the code site; consider an explicit "I know this is advisory" opt-in.
4. ~~**Is `apply_credential_injections` cleanly reusable** or does it need extraction? (visibility confirmed `pub(super)`; adaptation cost not fully traced)~~ ✅ **RESOLVED — direct header-swap reuse only, revised by rev 9.** `egress` and `sandbox_process` are sibling modules in ONE crate (`ironclaw_host_runtime`), so visibility is not the cost. The function's argument `RuntimeHttpEgressRequest` carries capability-dispatch context that the raw proxy does not have. W6's direct header swap may reuse its target-application logic after attribution and active-window authorization, but the proxy must not receive `SecretStorePort`. W19 shares the staged-material runtime with the shell chokepoint; the host materializer consumes a one-request `AuthorizedCredentialUse` and borrows raw material internally. W21 is a separate sealed transform because SigV4 signs the exact final request rather than injecting a literal value.
5. ~~**`RebornSandboxConfig` mount/volume surface** not line-by-line audited for a Hermes-style unvalidated passthrough. **Not found ≠ ruled out.**~~ ✅ **RESOLVED — audited field by field.** Default `/workspace` bind is SAFE: `workspace_root` is operator-only, and the per-invocation path `scope_key.rs:38` (`root/scopes/<sha256-of-typed-ResourceScope>`) is leaf-scoped BY CONSTRUCTION — only the tenant's own digest dir is ever bound, so there is no shared-parent symlink vector. Broker unix-socket binds (`broker.rs:111,185,350`) validate only absolute/no-colon/no-control-chars (no canonicalize, no symlink check) but have zero production callers (composition only uses the HTTP-proxy variant) — SAFE by non-use, needs hardening before any future caller. `RebornSandboxContainerIdentity`/`WorkspaceMode` are not mount surfaces. **One latent gap: `mounts.rs::resolve_grant` (~line 148) uses shared-parent `starts_with` containment with no symlink handling — same bug class as §1.5. Dead today (zero production callers), NEEDS-VALIDATION (leaf-scoping) before W10/W12 ever wires `with_local_mount_source`.** Severity if activated: cross-tenant, same class as §1.5.
6. ~~**`RuntimeKind` (`ironclaw_host_api/src/runtime.rs:23-31`) has no `Sandbox`/`Shell` variant** — `runtime_reuses_staged_credentials` (`egress/credential.rs:254`) matches only `Mcp | Wasm`, so single-use vs multi-call credential-reuse semantics for the sandbox lane are UNDECIDED.~~ ✅ **RESOLVED-as-decided (thermo-nuclear ruling), implementation deferred to when W6 starts.** Decision: add `RuntimeKind::Sandbox` and include it in `runtime_reuses_staged_credentials`'s `matches!` alongside `Mcp | Wasm` (multi-call reuse) — that predicate gates `clone_material` (multi-call) vs `take` (single-use), and one shell invocation makes many outbound calls, so single-use would 403 everything after the first. Do **not** map the sandbox lane onto `Mcp`/`Wasm` — `RuntimeKind` is an execution-lane identity consumed by audit records and dispatch-error selection; collapsing it would misclassify every such consumer. Blast radius (grepped, not estimated) — 8 compiler-enforced exhaustive-match sites: `ironclaw_host_runtime/src/production.rs:1359`, `services/production_services.rs:160`, `services/runtime_adapters.rs:1073`, `surface.rs:524`, `ironclaw_loop_host/src/capability_info.rs:261`, `ironclaw_extension_host/src/resolver.rs:158`, `ironclaw_capabilities/src/dispatch.rs:411`, `ironclaw_capabilities/src/registry.rs:191`, plus `egress/credential.rs:254`. NOT to build: no new `TrustClass` variant (`TrustClass::Sandbox` already exists at `runtime.rs:109` and means the right thing — different enum, different purpose); no generalized per-runtime "reuse policy" abstraction; and NEVER a `_ => false`/`_ => true` wildcard arm to dodge the compiler — every site gets an explicit arm. **Why deferred, not done now:** 2 of the 8 arms are not mechanical — whether sandbox errors get a dedicated `DispatchError::Sandbox` variant or ride an existing one belongs to whoever writes W6's error path; adding the variant now means guessing those arms in advance, across 6 crates of conflict surface.

~~**Does `cargo` honor `CARGO_HTTP_CAINFO`?**~~ ✅ **removed, resolved as moot** — cargo binding remains de-scoped from V1 regardless of the answer; not worth tracking as an open item.

~~**`rcgen` dependency question**~~ ✅ **removed, resolved** — `rcgen` appears in **no** `Cargo.toml` in the workspace; the earlier `Cargo.lock` hits that raised the question were `cranelift-srcgen` substrings, not `rcgen` itself. Nothing to reconcile; W5 will add the real dependency when it starts.

7. 🟡 **RESOLVED FAIL-CLOSED — `sandbox_egress_proxy_enforces_allowlist_through_composition` cannot run through the production topology under colima.** (`tests/integration/reborn_sandbox_egress_proxy.rs`)
   ```
   curl to the allowlisted host pypi.org should succeed through the egress proxy:
   curl: (7) Failed to connect to 10.200.0.1 port <ephemeral> after 0 ms
   ```
   **Root cause:** `EgressAllowlistProxy::bind` previously listened on `0.0.0.0` in the **host process** (macOS), while the container's only egress route is the `internal:true` `ironclaw-sandbox-egress` network whose gateway `10.200.0.1` is an interface **inside the colima Linux VM** — a different network namespace. The instant refusal came from the VM gateway, where nothing was listening.
   **Implemented boundary:** production now creates/verifies the internal network first and binds the proxy directly to its gateway address. A shared-namespace Linux host can bind it; Colima, Docker Desktop, and mounted-Docker-socket topologies fail profile boot with an explicit diagnostic instead of reporting a dead proxy as ready. There is no direct-network fallback and no forwarding sidecar that would erase source-IP attribution. `vm_backed_docker_topology_fails_closed` verifies this with real Colima. Supporting a separate daemon namespace remains follow-up design work requiring an attribution-preserving broker bridge.
   **Still open:** the supported shared-namespace Linux traffic path must execute in the Docker CI lane; rejecting Colima accurately does not substitute for an allowed/denied real-traffic run on Linux.

   **Related lifecycle defect fixed:** the synchronous CLI bridge used a temporary Tokio runtime to construct the proxy, so dropping that runtime also aborted the proxy task. The proxy now owns a dedicated runtime thread and explicit shutdown handle. `proxy_outlives_the_temporary_runtime_that_constructed_it` is daemon-free regression coverage; `production_proxy_outlives_sync_bootstrap_runtime` exercises the production composition caller with real Docker on supported Linux.

   🆕 **Rev 6 cross-reference — W0 is not a CI gate today.** The above "CI hasn't proven it" is not merely "unproven yet" — the docker-gated CI job that would run these suites (W0, §1.0) exists only on this local branch and has never executed in GitHub Actions at all, on any branch. So today there is no environment — local (colima, item 7) or CI (DinD, item 2) — where this proxy's real traffic path has been observed working end to end.

8. 🆕 **2026-07-26 CI-gating decision — DECIDED, IN PROGRESS, not yet landed.** A blanket `has_reborn_tests` gate that would run W0's `sandbox-docker-tests` job on nearly every PR was **rejected by the user** on cost grounds: it adds roughly 30 minutes to nearly every PR, dominated by building the 1.82GB `ironclaw-worker` image. Decision: narrow the job's trigger to sandbox-related paths, plus unconditional runs on push-to-main and `merge_group`, and add Buildx layer caching to reduce the build cost. This is in progress by another agent in this worktree — record it as decided-and-in-progress, not done. Until it lands (and is verified actually running in GitHub Actions, not just present in the workflow file — see W0's history of the reverse mistake), W0 stays 🔴 not-CI-enforced.

---

## 6. 🆕 Edge-case integration tests (required)

Each property gets a test that fails if the property breaks. 🔴 **Corrected rev 6: W0 has NOT landed as a CI job** — it exists only on this local branch and has never executed in GitHub Actions (§1.0). Docker-gated tests do **not** run as a blocking CI job today; every docker-gated assertion below is currently enforced only by whatever developer happens to run the suite locally, not by CI. The row states below still show real coverage is thin: only 4 of 13 rows are genuinely covered — and none of that coverage is CI-enforced yet.

**✅ 2026-07-26 real-Docker verification run.** Full docker-gated suite against a freshly rebuilt `ironclaw-worker:latest` (image id `5205c02b2ec0` → `d5f5e99112e4`, entrypoint change baked in): **164/164 passed, ZERO skips**, confirmed via `--nocapture` showing no runtime `SKIP:` lines. `sandbox_exec_transport_docker` 7/7 · `sandbox_reaper_docker` 3/3 · `sandbox_workspace_fs_parity_docker` 1/1 · `cli_session_docker` 3/3 · `--lib sandbox_process::` 150/150. Named properties confirmed genuinely executing (not gated out): `icc_disabled_blocks_container_to_container`, `icc_disabled_preserves_gateway_reachability`, `ensure_egress_network_fails_closed_on_posture_mismatch`, `ensure_container_recycles_stale_stamp_then_reuses_matching_stamp`, `recycle_stale_container_invalidates_attribution_for_the_released_ip`, `applied_container_limits_match_config_via_docker_inspect`, `persistent_container_starts_with_ssl_cert_file_but_no_lockdown`. This upgrades rows 1, 11, 12 below from "a test exists" to "verified running against a real daemon on the current image."

| # | Test | Asserts | Tier | Blocks | **Coverage (rev 4)** |
|---|---|---|---|---|---|
| 1 | `cross_user_containers_cannot_reach_each_other` | A's container cannot open TCP to B's container IP | docker-gated | W1.5/D9 | ✅ **verified executing** (2026-07-26 full docker-gated run, not just "a test exists") |
| 2 | `placeholder_from_another_user_is_rejected` | B presenting A's placeholder → 403, no swap, audit records mismatch | docker-gated | W1.5, W7 | ❌ no test — subject (W7 wiring, proxy attribution wiring) doesn't exist yet |
| 3 | `proxy_attributes_request_to_the_owning_user` | concurrent A+B requests each get **their own** credential, never crossed | docker-gated, concurrent | W1.5, W6 | ❌ no test — W6 doesn't exist |
| 4 | `grant_does_not_survive_the_invocation` | placeholder reused after the command returns → 403 | integration | W7 | ❌ no test — W7 has no caller to exercise this through |
| 5 | `background_process_gets_no_grant` | detached job's request → stripped, forwarded bare, annotated | docker-gated | W7, D5 | ❌ no test — same reason |
| 6 | `unbound_host_is_never_decrypted` | non-bound host stays an opaque tunnel; no leaf cert issued | docker-gated | W6, D1 | ❌ no test — W6 doesn't exist |
| 7 | `revoke_fires_on_every_exit_path` | success / error / timeout / panic each revoke (parameterized) | integration | W7 | 🟡 **partial** — proven at the primitive (`ironclaw_secrets`' own tests), not through a sandbox-shell caller (there is no caller yet) |
| 8 | `real_secret_never_appears_in_container` | container `env` + seeded configs contain only the placeholder while the origin observes the real secret | docker-gated | W6 — **the core invariant** | ❌ no test — 🆕 **now testable only after W6 phase 2 lands** (rev 7): phase 1's `terminate_and_forward` forwards decrypted bytes unmodified and never swaps a placeholder for a secret, so there is nothing yet for this row's assertion to observe |
| 9 | `imds_unreachable_from_shell` | `curl 169.254.169.254` fails with **no route**, not a proxy 403 | docker-gated | §5.2 | 🟡 **partial, and misleadingly so** — the existing test proves the **proxy's** private-IP dial-time check denies IMDS, not the **network-layer** "no route" this row demands. Different guarantees; the current test cannot distinguish "proxy caught it" from "there was never a path" |
| 10 | `public_clone_works_without_a_grant` | public `git clone` from a bound host succeeds with placeholder stripped | docker-gated | D5 | ❌ no test — no bindings exist (W12) |
| 11 | `icc_disabled_blocks_container_to_container` | A cannot open TCP to B's container IP on the egress network | docker-gated | W1.5/D9 | ✅ **verified executing** (2026-07-26 run) |
| 12 | `icc_disabled_preserves_gateway_reachability` | every container still reaches the proxy at the gateway (icc didn't over-block) | docker-gated | W1.5/D9 | ✅ **verified executing** (2026-07-26 run) |
| 13 | `cross_user_symlink_is_rejected_read_and_write` | symlink from A's workspace into B's is rejected by `resolve_existing` **and** `resolve_for_write`; outside-root escape still rejected | integration | §1.5 | ✅ **covered** |
| 14 | `shell_window_and_proxy_share_one_credential_runtime` | a grant staged by the production shell chokepoint is visible to the production proxy; a separately constructed runtime cannot see it | caller-level integration | W19 | ✅ handler-to-swap lifecycle test plus shared-runtime identity test |
| 15 | `shell_window_revokes_on_every_exit` | success, error, timeout, cancellation, and unwind each remove the live window before detached traffic can authenticate | caller-level integration | W19 | 🟡 abort, success, and post-dispatch failure are caller-tested; lease `Drop`/TTL cover abandonment, but a caller-level future-cancellation test remains |
| 16 | `aws_credential_process_returns_only_inert_material` | helper output is AWS-compatible, stable for the binding version, contains no real stored bytes, and has no origin authority alone | unit + caller-level | W20 | ❌ subject not built |
| 17 | `sigv4_origin_observes_real_host_signature_only` | sandbox request is signed with inert material; origin verifies the host-generated real signature; sandbox files/env/output never contain real material | docker-gated + loopback origin | W21 | ❌ subject not built |
| 18 | `sigv4_scope_mismatch_never_contacts_origin` | wrong host/service/region/method/path and expired/no window all fail before origin dial | caller-level integration | W21 | ❌ subject not built |
| 19 | `sigv4_ambiguous_or_streaming_request_fails_closed` | duplicate/invalid length, transfer+length, obs-fold, presign, aws-chunked, event-stream, upgrade, and over-limit body are denied | unit + caller-level | W21 | ❌ subject not built |
| 20 | `credential_producing_aws_operations_are_blocked` | STS/SSO/token-producing operations cannot return real credentials to the sandbox | caller-level integration | W22 | ❌ subject not built |

**Summary: 4/20 genuinely covered (rows 1, 11, 12, 13) — rows 1, 11, 12 were verified against a real daemon on 2026-07-26 — 2/20 partial with a real gap each (rows 7, 9), and 14/20 have no test because their subject does not exist yet. Rev 9's rows 14-20 are acceptance criteria, not claims of implementation.**

---

## 7. Implementation process (per `ironclaw-issue-bugfix`)

1. **Worktree per work item** off recent `origin/main`; leave the dirty main checkout alone.
2. **CodeGraph first** (`codegraph_context` → `codegraph_trace` → one `codegraph_explore`).
3. **Failing test before production code.** Integration tier preferred, driven through the harness at a seam — never `wait_for_status(Completed)` alone. Helper-only tests insufficient when a helper gates a side effect. Docker-gated: `#[path = "support/docker_gate.rs"]` + runtime `SKIP:`, never `#[ignore]`.
4. **Plan → thermo review → implement → `/code-review` + thermo → address → PR.**
5. **Gates:** `cargo fmt --all --check` · `clippy --all --benches --tests --examples` = 0 · `test -p ironclaw_reborn_composition --lib` · `-p ironclaw_host_runtime --lib` (expect 2 `trace_commons` NetworkDenied env failures; export `DOCKER_HOST` or an in-lib docker test false-fails) · `-p ironclaw_architecture` · `test --workspace --no-run`.
6. **CI no-panics check** rejects `.unwrap()`/`.expect()`/`unreachable!()` in production code.
7. **Never commit `docs/plans/*`** except `composition-pubuse.snapshot`.
8. **NEVER merge to main / push origin main / `--admin`.** Stop at merge-ready and report.

### Environment notes (hard-won)

- **colima**: `export DOCKER_HOST="unix://$HOME/.colima/default/docker.sock"` — bollard hardcodes `/var/run/docker.sock`; without this, docker tests fail `SocketNotFoundError`.
- Build the image: `docker build -f Dockerfile.process-sandbox -t ironclaw-worker:latest .`
- Set `TMPDIR` **inside your home directory** (virtiofs-mounted). macOS default TMPDIR is outside colima's mount ⇒ Docker creates root-owned phantom dirs **in the VM** and the entrypoint copies a ~400MB toolchain into each; this filled the VM disk. Clean: `colima ssh -- sudo sh -c 'rm -rf /private/var/folders/*/*/T/.tmp*'`.
- `IRONCLAW_DISABLE_OS_KEYCHAIN=1` on all test runs.
- In a worktree `.git` is a **file** — `test -f .git/MERGE_HEAD` false-negatives. Use `git rev-parse -q --verify MERGE_HEAD`.
- **Subagent stall epidemic:** 5+ agents died yield-waiting on long cargo builds. Brief them: *foreground only, wait inline, never background-then-yield*; pipe through `| tail -40`; prefer per-package over `--workspace`.

---

## 8. Verdict (thermo, rev 1) and status

Thermo verdict on rev 1: **not ready** — two blockers: (1) W1's second consumer, (2) W6 sequenced before its dependencies. Both addressed in rev 2. Thermo found **nothing to delete** — "the plan is lean by the standard the skill enforces… the risk profile runs the other direction: under-sizing and an unverified shared-resource assumption, not gold-plating."

### Rev 3 blocker status, updated for rev 4 — **implementation underway, no hard blockers on continuing**

| Was (rev 3) | Now (rev 4) |
|---|---|
| D9 undecided | ✅ **resolved and landed** — `enable_icc=false` (W1.5) shipped; colima-verified. Attribution code (W1.5b) exists but is **unwired** — see §1.0 |
| W1 blocked on second consumer | ✅ **landed** — the second consumer (`DockerProcessSandboxBackend`) was deleted outright (#6686), not gated-off. W1 shipped in one commit as planned |
| Cargo CA spike blocking W5 | ✅ de-scoped from V1 — public crates.io works through the tunnel. W5 itself has **not started** |
| Cross-tenant symlink escape (§1.5) | ✅ **landed**, incl. the empty-tail fail-closed sub-fix |
| `/workspace` root mismatch (§1.4) | ✅ **landed**, together with §1.5 as required |
| *(new)* W6 gating incomplete | 🔴 **corrected this revision** — W6 also needs W5 (internal CA); critical path is now W8 → wire W1.5b → W17 → give W7 a caller → W5 → W6 |
| *(new)* W7 status overstated | 🟡 W7 (and W1.5b) are **built and tested, wired to nothing** — flagged plainly this revision rather than counted as "landed" |

**Rev 9 implementation order against the current local branch:** finish/review the in-progress W6 phase-2 attribution + HTTP swap slice without claiming live credential delivery → ~~W19a shared runtime plumbing~~ **built** → W12 adds the reviewed profile/binding store and host authorizer policy → W19b opens invocation-keyed windows through the existing obligation prepare/complete/abort lifecycle → W18 exposes approved inert-artifact issuance → W20 adds versioned bindings and the AWS `credential_process` artifact → W21 adds bounded request framing and host-side SigV4 signing → W22 blocks credential-producing responses before the AWS profile is broadened. W2/W4 hardening and W11/W14/W15 remain independently tracked. Do not implement W21 ahead of W19b: a signer reachable only from tests is another "control that can never fire."

### Recurring pattern to watch

**Seven** separate instances of **isolation (or a safety property) asserted rather than enforced** have surfaced during this workstream:

1. The shared-parent `/workspace` mount (§1.5) — fixed.
2. The shared egress network before `enable_icc=false` (D9/W1.5) — fixed.
3. The unvalidated E1 IMDS topology (§5.2) — still open, only "no route" vs. "proxy denied" distinguishes it, and today's test can't tell the two apart (§6 row 9).
4. The empty-tail containment gap inside the §1.5 fix itself (a fourth instance found *inside* the fix for the third) — fixed.
5. The container **and** network posture pinned-at-create-never-reevaluated gap (W16) — fixed, both halves.
6. The attribution cache reusing a stale IP→user mapping across container teardown/reassignment (W17) — the first instance to ship in a **merged branch** rather than being caught in review before merge. The teardown call sites `invalidate()` needed have since landed (see item 7) — what remains is the TTL-bounded residual race (an in-flight `resolve()` can still write a stale entry back after invalidation fires), not a missing call site.
7. 🆕 **The attribution-cache invalidation itself, once "fixed" (W17): call sites landed, one path docker-gated-tested, and it still enforces nothing in production** — because every call site is gated on an `Option<Arc<ConnectionAttributionResolver>>` that nothing in production ever populates (`with_attribution_resolver` has zero callers anywhere — no test, no composition). This is a sharper variant than 1-5 above: those were **missing** code; this is code that is **present, correct, and unit/integration-tested in isolation**, and still fires never, because the thing its call sites depend on is never constructed. It reads as fixed at every level a reviewer would normally check — the call sites exist, a docker-gated test proves one of them works, the fix matches the shape the plan prescribed — and the only way to catch it is to ask who constructs the dependency the gate is checking, not just whether the call sites exist. **Generalizable lesson: verifying a control's call sites exist is not the same as verifying the control can fire — trace to the constructor of whatever the call site is gated on.**

The standing rule for this workstream holds: *an isolation claim is unproven until a test executes it* — which is also why **W0** sat at Priority 0 in the first place, and, per rev 6's correction, is itself the sharpest live example of the rule: W0 is built only on this local branch, has never been merged to `main`, and has never executed in CI, so every docker-gated claim in this document is currently proven only by a developer's local machine, not by CI. The critical path above still puts wiring and re-verification of W1.5b/W17 ahead of building W5/W6.
