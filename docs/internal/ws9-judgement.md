# WS9 (bound the recovery) — judgment calls

Epic #6284, workstream 9. Recorded per instruction: every call I made where a
reasonable engineer could have chosen differently.

## 1. What I implemented vs audited

WS9's eleven boxes are two different kinds of work. Boxes 1–3 are a concrete
defect with a fix. Boxes 4–11 are an **audit** — "what happens when X fails?"
— whose deliverable is findings, not code.

I implemented 1–3 and audited 4–11. I did not write speculative fixes for
surfaces the audit found already covered.

## 2. The per-run budget bound (boxes 1–3) — implemented

**The defect.** `cleared_attempts()` returned `Self::default()`, wiping every
retry counter on any successful model call. That bounds a single stage but
leaves the **run** unbounded: a run alternating success and failure re-earns its
full budget forever. The worst case was never the ~41 model calls one stage
permits — it was unlimited, with `RetryProvider` tripling each underneath.

**Judgment: a monotonic counter rather than a redesign.** I added
`run_recovery_attempts`, which `cleared_attempts()` deliberately preserves,
instead of restructuring the per-class accounting. The per-stage reset exists
for a real reason (a later unrelated error must not inherit a previous stage's
attempts) and I did not want to disturb it. Cost: one more field on a
serialized struct.

**Judgment: default `120`.** Roughly three exhausted stages' worth of the
availability budget. Chosen so a legitimately long, hiccup-prone run is
unaffected while a pathological loop stops. **This number is a guess informed by
the existing per-stage bounds, not by production data.** If runs are observed
hitting it legitimately, raise it — the mechanism matters more than the value.

**Judgment: reused `LoopFailureKind::NoProgressDetected` rather than adding a
variant.** WS9 asks for "a terminal category for exhausting it that says so
honestly", and strictly this deserves its own kind. I did not add one because
`LoopFailureKind` is `#[non_exhaustive]` and crosses crates, so a new variant
touches the runner's name mapping, the failure-lane canonical list, the retry
disposition, and two user-facing summary tables — the exact chain that produced
three separate CI failures earlier in this epic. `NoProgressDetected` is the
closest honest existing meaning: the run consumed its recovery budget without
progressing. **A reviewer who wants the distinct category should say so; it is a
contained follow-up, not a rewrite.**

**Judgment: the run bound is checked BEFORE the per-class bound.** Otherwise a
class with remaining per-stage budget would retry past an exhausted run budget.

## 3. Boxes 4–9 (wasm / mcp / process / filesystem / approvals / triggers) — audited, no fix needed

Verified `RuntimeDispatchErrorKind` covers every shape these boxes name — guest
trap (`Guest`), memory limit (`Memory`), nonzero exit (`ExitFailure`), fuel and
quota (`Resource`), transport and server death (`Backend` / `Client` /
`Network`), manifest and runtime mismatch (`Manifest` / `UnsupportedRunner` /
`ExtensionRuntimeMismatch`).

I then checked every kind for **production producers**, the same check that
found `LlmError::ModelNotAvailable` dead in #6826. Result: all have producers
(lowest are `Memory`=2, `ExitFailure`=2, `Guest`=4, `InvalidResult`=4).

**Judgment: I did not write fault-injection tests per surface.** Proving that a
real WASM trap or a real MCP server death reaches the right kind needs fault
injection, which is exactly what #6134's fixture work is for. Asserting it with
hand-built mocks would test my mock, not the runtime — the failure mode this
epic has hit repeatedly. **The audit says the vocabulary and producers exist; it
does not prove each real fault maps correctly, and I am not claiming it does.**

## 4. Box 10 (hooks) — audited

The hooks middleware fails closed to `Resolution::Denied` with
`hook_gate_ref_unavailable`, which #6781 classified as
`DenyReason::InternalInvariantViolation` and #6792 gave a recovery hint. A hook
error surfaces to the model as a denial; it does not kill the run.

## 5. Box 11 (panics) — audited, gap identified, not closed

`scripts/check_no_panics.py` already exists, correctly excludes test modules,
and is enforced in CI.

**It only checks the diff** (`--base`/`--head`). Pre-existing panics on
run-critical paths are grandfathered and nobody has swept them.

**Judgment: I did not sweep the corpus.** Raw counts across the six
run-critical crates are in the thousands, dominated by inline test modules that
my grep could not exclude the way the real checker does. A credible sweep means
running the existing checker corpus-wide, triaging what it reports, and fixing
per-site — a workstream of its own, not a box to tick inside this PR. Filing it
is the honest move; pretending a grep count is an audit is not.

## 6. What I did not do

- No new `LoopFailureKind` variant (§2).
- No per-surface fault injection (§3).
- No corpus-wide panic sweep (§5).
- No change to the per-stage reset semantics.

Each is a deliberate scope call, and each is stated above with its reason rather
than left for a reviewer to discover.
