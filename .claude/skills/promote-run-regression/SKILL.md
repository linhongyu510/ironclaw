---
name: promote-run-regression
description: Use when converting a downloaded ironclaw.run_artifact.v1 or ironclaw.thread_artifact.v1 file, production incident, live-canary failure, or QA trajectory into a scrubbed deterministic regression test and recorded promotion evidence.
---

# Promote a Run into a Regression

Turn incident evidence into the lowest deterministic test that proves the broken user-visible rule. Treat the downloaded artifact as RED evidence, not as a golden trace to bless unchanged.

## Establish the contract

1. State the failure and expected outcome in Given/When/Then form.
2. Name the risk: local logic, cross-component behavior, model tool choice/request shape, browser behavior, provider/runtime behavior, or live drift.
3. Obtain a stable issue, incident, run, or pull-request URL for provenance. Do not land placeholder URLs.
4. Read `docs/internal/testing-playbook.md`, `.claude/rules/testing.md`, and the owning crate guidance before choosing the seam.

Re-verify the promotion tooling instead of assuming paths:

```bash
rg -n "import-reborn-run-artifact|check-reborn-qa-fixtures|Promoting failures" \
  scripts tests/fixtures/llm_traces/reborn_qa docs/internal
```

## Inspect without leaking

Inspect structure and counts before content. Do not print raw matches from credentials, emails, local paths, provider identifiers, or personal usernames.

```bash
jq '{
  schema,
  redaction,
  message_count: (.messages | length),
  kinds: (.messages | group_by(.kind) | map({kind: .[0].kind, count: length})),
  tools: [.messages[] | select(.tool_call != null) | .tool_call.capability_id]
}' /path/to/artifact.json
```

Require:

- schema `ironclaw.run_artifact.v1` or `ironclaw.thread_artifact.v1`;
- redaction pipeline `deterministic-trace-redactor-v1`;
- at least one replayable user message and finalized assistant response;
- a stable provenance URL and a canonical journey/regression id.

## Import into temporary review

Keep candidates outside the blessed fixture tree:

```bash
candidate_dir="$(mktemp -d)"
python3 scripts/import-reborn-run-artifact.py \
  /path/to/artifact.json \
  "$candidate_dir/scenario.candidate.json" \
  --source-url https://github.com/nearai/ironclaw/issues/NNNN \
  --owning-journey canonical-scenario-id
```

Review `_review.required_actions`, skipped runs, every placeholder, tool arguments, and result content. Independently replace personal usernames and provider-specific identifiers with stable fixture values. Never copy unbounded provider bodies when a compact semantic result proves the rule.

The importer deliberately creates review-required output. Do not commit `.candidate.json`, `_review`, empty `expects`, or null promotion evidence.

## Choose the lowest deterministic seam

- Put a local rule in the owning crate's unit/contract suite.
- Put a cross-component user outcome in the Reborn integration harness.
- Put model tool choice, call order, or request shape in `tests/fixtures/llm_traces/reborn_qa/` plus `tests/reborn_qa_recorded_behavior.rs`.
- Put browser-only behavior in `tests/e2e/`.
- Put provider/runtime semantics in the owning hermetic provider or runtime suite.
- Keep live canaries only for residual model/provider drift.

Do not force the whole trajectory into one fixture. One incident may promote into multiple tests at different owners, such as a capability-output contract, a result-reference contract, and a small model-choice fixture.

## Write assertions that would catch the incident

For tool-choice regressions, `tools_used` alone is insufficient. Assert the important combination:

- exact or bounded call count;
- allowed call order;
- required structured arguments;
- forbidden broad/redundant tools;
- caller-visible final outcome;
- side-effect readback when the workflow mutates external state.

Minimize the imported candidate to the intended successful route. Preserve the artifact SHA-256 and scrub pipeline under `_promotion.provenance` and `_promotion.scrub`. Replace `_review` with:

- `owning_journey`;
- `deterministic_test.command` and `.assertion`;
- `last_successful_replay.date`, `.commit`, and `.command`.

Use a two-commit evidence sequence when necessary: commit the fixture/test, run the exact command, then record that commit SHA in a follow-up metadata commit. Do not invent a self-referential future SHA.

## Prove RED, then GREEN

Apply the new assertions to the imported incident candidate or run the new caller test before the fix. Confirm failure for the original reason, not a parser/setup error. For a historical model trace, record the observed counts/order as RED evidence and show exactly which new assertion it violates.

Apply the smallest fix and run the same deterministic assertion. If a recorded fixture depends on external HTTP without captured exchanges, keep its regression at the contract seam and state that full runtime replay is not hermetic; do not pretend it ran.

Use the package-qualified recorded-behavior command:

```bash
python3 scripts/test-import-reborn-run-artifact.py
scripts/ci/check-reborn-qa-fixtures.sh
cargo test -p ironclaw_reborn_integration_tests \
  --test reborn_qa_recorded_behavior \
  contract_SCENARIO -- --exact
```

Then run the owning crate/caller tests selected by the testing playbook, `cargo fmt --all -- --check`, and `git diff --check`. Add architecture, backend, browser, or live tiers only when the risk requires them.

## Finish the promotion

Before committing:

```bash
find tests/fixtures/llm_traces/reborn_qa -name '*.candidate.json' -print
rg -n '"_review"|PENDING_REPLAY_COMMIT|PR_NUMBER' \
  tests/fixtures/llm_traces/reborn_qa --glob '*.json'
scripts/ci/check-reborn-qa-fixtures.sh
```

Complete every PR `Test Strategy` field. Include:

- source artifact schema and SHA-256;
- scrub review performed;
- original RED evidence;
- deterministic seam and exact assertion;
- exact GREEN command, commit, and date;
- omitted test tiers with `Not applicable: <reason>`;
- compatibility, rollback, and any non-hermetic limitation.
