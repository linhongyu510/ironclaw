# Sandbox program — session handoff

**Written:** 2026-07-28. **Reason:** prior session exhausted its 200-subagent cap.
**Local-only** — `docs/plans/*` is never committed. Keep it that way.

Primary worktree: `/Users/henry/worktrees/ironclaw/sandbox-shell-integration`
(branch `sandbox/shell-integration`, the dev trunk, head `9ebc40f53`).
Design doc: `docs/plans/2026-07-26-sandbox-credential-firewall-design.md` (rev 9,
untracked — **never commit it**).

---

## 0a. 2026-07-31 continuation update — credential presentation and SigV4

**2026-08-02 PR scope reduction:** SigV4 and other request-signing authorizers are
not part of this PR. The implementation target is the smallest safe static
skeleton: a sole `Authorization: Bearer <placeholder>` or
`Authorization: Basic <placeholder>` field, with a presentation-ready Basic
payload stored as the IronClaw secret. Arbitrary API-key header names and
W20-W22 remain follow-ups and must not add code or abstraction surface here.

The design now treats literal header substitution as one credential-presentation transform, not the whole mechanism. The invariant remains: real credentials never enter the sandbox and always live in IronClaw's secret system. The sandbox may persist only inert, syntactically compatible artifacts.

For AWS, the intended compatibility seam is an in-sandbox `credential_process` helper that returns an inert access-key id/secret/session-token shape. The AWS CLI signs with those inert values. The host proxy attributes the connection, resolves the inert artifact to a reviewed account/profile binding, requires a live shell credential window, validates host/service/region/operation, discards the inert signature, and signs the exact bounded request with host-side material. See design §0.1 and §2.2b-§2.2d.

**Hard boundaries added in rev 9:**

- The proxy/data plane must not receive `SecretStorePort` or select credential accounts.
- Product auth owns setup/account/profile admission; `ironclaw_secrets::CredentialAccount` remains the account record; host runtime owns active-window staging and request transforms; composition only shares handles.
- Profiles are a sealed host-owned enum. No agent/extension-provided signer code or agent-authored destination/service/region.
- Initial SigV4 is one bounded unambiguous HTTP/1.1 request. Presigned URLs, S3 aws-chunked/event-stream, upgrades, guest-side SSO/configure, and credential-producing STS responses fail closed.

**Current local implementation state (2026-08-02):** attribution, first-request
Basic/Bearer swapping, the shared `SandboxCredentialRuntime`, and the initial
live shell window are wired. The sandbox deployment profile is the sole
lane-selection authority; there is no frontend toggle or persisted per-user
sandbox setting. The window derives only from an active single-secret
`CredentialAccount` and its existing target policy. It is
opened only by obligation `prepare`, never direct `satisfy`, and is revoked on
abort plus every completion result. Unsupported/ambiguous presentation strips.
The profile now carries one opaque all-or-nothing sandbox bundle; composition
rejects profile-owned sandbox components on every other deployment profile and
never creates a fallback proxy with a different credential runtime. A failed
transport bootstrap explicitly shuts down the proxy/VM relay it already started.
The proxy still has no `SecretStorePort`. Focused swap, TLS-origin, lifecycle,
check, and clippy tests pass. User-facing approved placeholder retrieval (W18)
and reviewed profile/UI admission (W12) are still missing, so this is a secure
internal skeleton rather than finished CLI authentication UX.

**Next implementation order:**

1. Finish and verify the existing attribution/swap slice without claiming live credential delivery.
2. ~~W19a: construct one shared sandbox credential runtime for obligation services and the proxy; remove the proxy factory's fresh-empty-store construction.~~ **Built 2026-07-31.**
3. ~~W19b static skeleton: stage invocation-keyed RAII windows in `BuiltinObligationHandler::prepare`, install it only for the sandbox deployment profile, and revoke through every terminal path.~~ **Built 2026-08-02; profile authority corrected 2026-08-03.**
4. W18: expose approved retrieval of the inert static placeholder without weakening placeholder leak boundaries.
5. W12 follow-up: add reviewed profile/UI admission before arbitrary named headers or broader presentation kinds.
6. W20-W22: follow-up work outside this PR; no SigV4 or generalized authorizer framework here.

---

## 0. Do this first

**There is uncommitted work on disk that a fresh session will not know about.**

`/Users/henry/worktrees/ironclaw/pr-w6-tls-seam` (branch `sandbox/pr-w6-phase1-tls-seam`, PR #6740)
has one modified file:
`crates/ironclaw_architecture/tests/reborn_tls_verification_escape_hatches.rs`

It is a **finished, passing fix** (5/5 tests green) for a real security finding — see §3, item S1.
Commit and push it, or review then discard. Do not leave it to be clobbered.

`/Users/henry/worktrees/ironclaw/pr-readiness-gate` has 7 modified files that are a
**failed port — discard them.** See §2 for why it can't work yet.

---

## 1. Open PRs (all MERGEABLE, zero failing checks as of handoff)

| PR | Title | Size | Notes |
|---|---|---|---|
| #6740 | W6 phase 1 — TLS termination seam | +1359/−1 | 31 inline comments, most resolved; 7 findings from a fresh review outstanding (§3) |
| #6746 | Docker-connect retry, egress allowlist, shell limits | +728/−5 | transport slice 1; 7 unresolved threads |
| #6747 | `RuntimeKind::Sandbox` lane + credential reuse | +83/−14 | 7 unresolved threads |

**Merged today:** #6723 (CA + firewall primitives), #6695 (leaf containment + attribution/registry/user_key).

**Review-coverage gap, be aware:** #6746 lost 2 of 8 reviewers to the subagent cap and
#6747's review could not dispatch at all (single manual pass). Those two have
**thinner coverage than normal** — treat incoming comments on them as more likely to be real.

---

## 2. Branches ready to slice, and what blocks each

| Branch | Head | Blocked on |
|---|---|---|
| `sandbox/w6-phase2-credential-swap` | `54a5731bc` | #6740 merging |
| `sandbox/readiness-gate-sandbox-backend` | `5ac115002` | **#6747 merging** |
| `sandbox/pure-container-disposition` | `0106b3abc` | transport slice 3 |
| `sandbox/land-docker-ci-job` | clean at main | transport slice 5 (see §4) |

**Why the readiness gate could not be sliced:** it pattern-matches `RuntimeKind::Sandbox`,
which **did not exist on main**. Six of seven files patched textually clean and the build
still failed. Note the shape — the blocker was a *symbol* inside files that all exist on main.
File-level disjointness did not predict it. #6747 fixes this.

---

## 3. Outstanding work on #6740 (7 findings from review 4794212130)

**S1 — DONE, uncommitted (see §0).** The arch test's carve-out matched
`line.contains("fn from_system_roots")`, so a look-alike like `from_system_roots_untrusted`
inherited the exemption for its whole body — a `dangerous()` call inside it would pass the
gate. Now matches the exact identifier, with a regression test covering three impostor names
plus an end-to-end case.

*This was the **third** blind spot found in that one test today* (after non-string-aware
comment stripping, and silently swallowed I/O errors). A guard built to catch
"silently doesn't bind" has now silently-didn't-bound three times. **Treat that file as
suspect and review it adversarially rather than trusting it.**

**Straightforward, not started:**
- Malformed leaf-material tests (cert/key) asserting fail-closed, no origin connection started
- Invalid-host propagation test — fails before a leaf is minted or origin contacted
- Allowlist normalization: mixed-case host, empty allowlist
- PR body out of sync — says "601-line port", head is 755 lines; ratchet counts stale
- Missing per-tier Test Strategy section (repo template)
- Move the test suite to a sibling `tls_intercept/tests.rs`, matching merged `ca/tests.rs` and `credential_firewall/tests.rs`

**Needs a decision, not a fix:**
- **ALPN.** Reviewer wants h2 configured. **Push back candidate:** W6 phase 2 parses HTTP/1.1
  request heads to do the credential swap; negotiating h2 would silently break it. Absent ALPN
  may be load-bearing, not an oversight. Settle with `/thermo-nuclear-code-quality-review`.
- **Process-global rustls provider installed with the result ignored** — hidden
  initialization-order behavior in a library.
- **Per-connection TLS rebuild** with synchronous keygen on the tokio worker. Declined once as
  premature on unwired code; a second reviewer raised it independently, so it deserves a real answer.
- **Hostname logging** (already escalated, disposition = keep): `debug!`-level, host already
  scrubbed through `LeakDetector`, hostname is the key audit field. Revisit only if logs ship
  to a shared sink.

---

## 4. Transport decomposition — compile-proven, do not re-derive

Every slice below was proven by real `cargo build` in throwaway worktrees off `origin/main`.

| # | Contents | ~Lines | Depends on | State |
|---|---|---|---|---|
| 1 | `connect` + `network_allowlist` + `shell_limits` | ~670 | nothing | **PR #6746** |
| 2 | `egress_proxy` + `ironclaw_network` export + `tokio "net"` | ~1760 | **#6740 merged** | probed PASS |
| 3 | `exec_transport` + `container_ip_on_network` + `LABEL_PREFIX` + `shell_single_quote` + 3 broker consts | ~2260 | slice 1 | probed PASS |
| 4 | `reaper` + `sandbox_reaper_docker.rs` | ~1230 | slice 3 | probed PASS, zero extra symbols |
| 5 | wiring + the other 4 docker tests + the CI job | — | 1–4 | **not probed**, behavior change |

Slices 2 and 3 are independent of each other.

**Slice 3 exceeds 1500 lines — accept it.** The file is 875 production lines and 1346 test
lines. Move the inline tests to `exec_transport/tests.rs` (matching the merged convention) and
production lands at ~880. Do not invent a seam splitting create from exec; neither half means
anything alone.

**Traps that no import analysis finds** (all hit for real during probing):
- `network_allowlist` needs two `PATH_TERM_COLLISIONS` entries in **a different crate's** test
  (`reborn_extension_specificity.rs`) or the arch gate rejects `github.com`
- Trunk's `egress_proxy`/`tls_intercept` still call `rustls_pemfile` in 6 places →
  re-breaks `cargo deny` (`unmaintained = "workspace"` scope). #6740 already ported to
  `rustls-pki-types`; slice 2 must carry that. **This port is reasoned, not compiled — verify.**
- `exec_transport` and `attribution` both declare `#[path] mod docker_gate` → clippy
  "loaded as a module multiple times", fatal under `-D warnings`
- `docker_gate.rs`: trunk makes `docker_tests_required` private; main's `attribution_tests.rs`
  calls it. Copying trunk's file wholesale breaks the build.

**The docker CI job must land LAST, in slice 5.** Four of its five test targets drive
`RuntimeProcessPort::run_command` — the *wired* transport — so they are red alongside unwired
code. Only `sandbox_reaper_docker` can land early (slice 4). Landing the job sooner recreates
the permanently-red lane this exercise exists to avoid. `timeout-minutes: 30` is also
unverified against a cold-cache 1.8GB image build.

---

## 5. Settled decisions — do not relitigate

- **Keep-alive: only the first request on a connection is swapped**; later ones have their
  placeholder stripped and get a 401. Full HTTP framing rejected as larger and more dangerous.
  User confirmed. Follow-up if needed: strict per-request framing that **denies the connection**
  on any ambiguity (both `Content-Length` and `Transfer-Encoding`, duplicate/non-numeric length,
  line folding) rather than guessing.
- Stripping removes only the token bytes, leaving `Authorization: token `, not the whole header.
- Cross-user placeholder is stripped, not answered with a synthesized 403.
- **Docker-client trait seam REJECTED** (thermo). Of 23 gated tests only 6 are "did we build the
  right request", and launch-config assembly is already daemon-free. Tripwire if revisited:
  *a fake may answer only "which calls, what args"; the moment it must return process,
  filesystem, or network state, it is lying.*
  `applied_container_limits_match_config_via_docker_inspect` is mixed and holds the **only**
  assertion that PID 1 really runs as uid 1000 — "promoting" it deletes that.
- All sandbox slices land **unwired by design**, profile-gated later. `#[allow(dead_code)]`
  naming the real future consumer. **Never invent a fake caller** to silence a lint.

---

## 6. Open questions still unanswered

**#3 — the egress proxy has never been observed passing real traffic anywhere.** Not on a dev
machine (host proxy vs VM-internal gateway under colima), not in CI. Now understood as blocked
until slice 5. Every container-isolation claim rests on one laptop run.

**#4 — RESOLVED: sandbox is not an extension runtime kind.** The sandbox is a host-owned process
runtime lane and security boundary selected only by the deployment profile. Extensions may use
capabilities that execute through the selected lane, but no extension manifest may select a
sandbox provider, construct its lifecycle, or weaken its posture. Keep `ExtensionRuntime`,
`ExtensionRuntimeV2`, and `LifecycleExtensionRuntimeKind` free of a `Sandbox` variant.

**fd-rooted traversal.** All four containment escapes found in `ironclaw_filesystem::local` are
one family: pathname checks against a two-syscall reality. Convergent fix is
`openat`/`O_NOFOLLOW`/cap-std. Thermo ruled DEFER-as-its-own-designed-PR. #6695 has merged, so
`local.rs` is now free — this is **unblocked**.

---

## 7. Standing rules for the next session

- **Never merge to main, never push to origin/main, never `--admin`.** Stop at merge-ready.
- **Never `git stash`** — repo-global across ~34 worktrees, will clobber parallel lanes.
- **Never `git add -A`/`.`** — explicit paths only. **Never commit `docs/plans/*`.**
- No `.unwrap()`/`.expect()`/`unreachable!()`/`panic!()` in production code. `assert_eq!` is
  also banned there by `scripts/check_no_panics.py` — this is why `debug_assert_eq!` is used.
- `/code-review` always at **`low`** effort. Thermo only for contested *design* forks.
- `IRONCLAW_DISABLE_OS_KEYCHAIN=1` on all test runs.
- Ratchet counts come **from the test's own output**. Never guess, never weaken, trim, or
  `#[ignore]` an assertion.
- **Do not resolve review threads you did not open** — flagged as an unauthorized external
  state change earlier today. Reply, and leave resolution to a human.
- CI failures: diagnose the cause. Never "fix" a failing check by weakening a test.
- Known-failing test baseline: 2 `first_party_tools::trace_commons` onboard-guidance failures,
  plus any `SocketNotFoundError` (no Docker daemon locally). Anything else is yours.

### The lesson this program keeps re-teaching

**A control that compiles clean, reports healthy, and enforces nothing.** Five confirmed
instances, and the last two are the instructive ones:

- W17's attribution `invalidate()` — call sites landed, one docker-gated test passing, and it
  **still fires never**, because every call site is gated on an `Option<Arc<…>>` that
  `with_attribution_resolver` populates, and that method has **zero callers anywhere**.
- The TLS escape-hatch gate itself, three times over (§3, S1).

**Generalizable rule: verifying that a control's call sites exist is not the same as verifying
the control can fire.** Trace to the constructor of whatever the call site is gated on.

And: **the plan doc has been wrong about "landed" three times** (the W0 CI job, W17's wiring,
`RuntimeKind::Sandbox`). Always verify against `origin/main`, never the document.
