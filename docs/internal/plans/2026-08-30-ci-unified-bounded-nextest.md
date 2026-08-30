# Unified Bounded Integration Execution

## Context

IronClaw now has a canonical Cargo-backed integration-test inventory and a
single non-push integration batch, but the selected batch still has two
execution mechanisms:

```text
registered flat targets  -> one cargo-nextest invocation
group directories        -> find/sed projection -> one cargo test per binary
```

The second path is slower and owns a second test-name projection. It also makes
the CI path harder to explain: selection comes from `Cargo.toml`, except when
group execution reconstructs names from directory basenames. PR #7980 made
that mismatch fail closed and left an explicit `ponytail:` marker for removing
the projection.

A representative merge-queue run on 2026-08-28 spent 20m21s in the combined
`IronClaw integration tests (selected)` job. Queue delay is a separate fleet
metric; this change must not add jobs or matrix legs that increase exposure to
runner allocation delay.

## Decision

For uninstrumented PR, merge-queue, and workflow-dispatch runs, execute every
inventory-selected integration target in **one** `cargo nextest run` process
with a fixed global test concurrency of four. Local guarded runs use that same
path when nextest is installed and retain one compatibility-only Cargo command
when it is not.

For push-to-main instrumented coverage, preserve the existing one-lane-per-job
`cargo llvm-cov` commands and LCOV artifact/report topology exactly.

```text
changed paths
    -> reborn_pr_test_plan.py
    -> selected inventory lanes
    -> integration_test_inventory.py --json
    -> exact registered targets for those lanes
       -> non-coverage: one nextest invocation, test-threads=4
       -> coverage: unchanged single-lane llvm-cov invocation
```

This extends the existing inventory and lane runner. It does not add a workflow,
matrix dimension, manifest, scheduler, shell worker pool, retry mode, or new
dependency.

## Goals

- One authoritative target projection from Cargo registration through
  execution.
- One CI execution/failure model for flat and group targets.
- A fixed concurrency ceiling that is independent of runner CPU count.
- All selected tests continue after individual failures.
- Fewer CI scripts, branches, environment variables, and cross-script contracts.
- Preserve the existing changed-path scope, required rollup, cache, toolchain,
  hermetic boundary, and main coverage contracts.
- Reduce the full uninstrumented integration job toward the organization goal
  of approximately ten minutes without increasing queue fan-out.

## Non-goals

- Changing which paths select integration lanes.
- Changing the four flat lanes or the dedicated `groups` lane in planner and
  coverage metadata.
- Changing push-to-main coverage instrumentation, LCOV artifacts, floors, or
  changed-line enforcement.
- Adding retries, splitting groups into matrix jobs, changing scenario order
  inside a top-level Rust test, or rewriting integration scenarios.
- Tuning Rust caches, toolchain pins, frontend setup, Postgres setup, root/crate
  buckets, E2E, or required-check rules.
- Promising control over external GitHub runner queue delay.

## Decision drivers and alternatives

### Selected: one bounded nextest pool

The existing lane runner already uses nextest for selected flat targets, the
repository pins nextest in CI, and the local quality gate already uses nextest.
Extending that path removes the custom
group scheduler rather than creating another one. A fixed `--test-threads 4`
cap bounds total integration-test concurrency, including flat and group tests.

Accepted consequence: nextest runs each top-level test in its own process,
whereas `cargo test` may run several top-level tests from one binary in one
process. Scenario ordering inside each top-level group test remains sequential.
The implementation must prove that separate top-level tests in every
`reborn_group_*` binary do not rely on shared process globals; otherwise this
decision is invalid and the work stops before the scheduling change.

### Rejected: separate flat and group pools

This can bound group concurrency independently, but retains two execution
phases, two failure joins, and group-specific orchestration after nextest is
already the canonical uninstrumented runner. Reconsider only if measured
resource contention or process-model incompatibility makes one pool unstable.

### Rejected: parallel shell/Cargo workers

This would require process supervision, signal forwarding, stable per-worker
logs, aggregate exit handling, and protection from concurrent Cargo locking.
Those are existing nextest responsibilities and would create a second scheduler.

### Do nothing

Keeping the current runner preserves the observed 20-minute-class integration
job and the independent group-name projection. It is safe but does not satisfy
the speed or comprehension goals.

## Assumptions and wrong-if conditions

The selected direction is wrong and must be reconsidered before merge if any of
these are observed:

- A `reborn_group_*` top-level test depends on process-global state created by a
  sibling top-level test in the same binary.
- Four concurrent integration tests cause repeatable OOM, database contention,
  timeout, nondeterministic failure, or materially worse tail latency.
- Nextest cannot preserve the complete selected target set or all-failure
  reporting with the pinned `cargo-nextest@0.9.143`.
- The implementation requires another target manifest, another workflow job, or
  a shell parallelism layer.
- Main coverage commands or artifact names must change to make the approach work.

If only the concurrency ceiling is too high, lower the single constant and
repeat the evidence. Do not restore a second runner unless the evidence shows
genuine phase isolation is required.

## Invariants to preserve

### Selection and topology

- Root `Cargo.toml` `[[test]]` registrations remain authoritative.
- Planner lanes come from `integration_test_inventory.py`.
- Unknown names, malformed records, invalid group registration paths, orphaned
  group directories, incomplete groups, missing entrypoints, and empty group
  topology fail closed.
- The executed target **set** exactly equals inventory records whose `lane` is
  selected. Execution order is deliberately delegated to nextest.
- Empty valid partitions remain successful no-ops; empty overall selection is
  rejected by the existing lane-input contract.

### Execution and failure

- CI fails loudly before Cargo when nextest is absent. Local guarded use keeps
  the repository's documented no-nextest compatibility contract by issuing
  one `cargo test --no-fail-fast` command over the identical selected target
  set; it never restores group-specific discovery or a per-group loop.
- Non-coverage CI uses one nextest invocation, `--profile ci`,
  `--test-threads 4`, `--ignore-rust-version`, and the existing outer timeout.
- `fail-fast = false` remains authoritative, and a fixture with multiple failing
  selected targets proves no target is suppressed.
- Selecting groups retains the existing group-topology preflight and 64 MiB
  `RUST_MIN_STACK` headroom. Because the invocation is unified, the same stack
  setting applies to all selected targets in that invocation.
- The current 28-minute group hang backstop moves to the canonical nextest
  profile as a `binary(~reborn_group_)` override with a 28-minute period and
  `terminate-after = 1`. The unit deliberately becomes one top-level test
  process rather than one whole Cargo test binary because nextest isolates
  top-level tests; the existing 45-minute outer batch timeout remains the
  final CI bound. When the compatibility-only local Cargo command includes a
  group lane, its whole batch receives a conservative 28-minute outer timeout;
  this is stricter than the retired 28-minute-per-binary loop and may stop later
  local targets after a hang, but it cannot weaken hang protection. Flat-only
  local fallback keeps the existing 45-minute outer bound. This is a named
  scheduling-policy change, not deleted plumbing.
- No retry is added. A surfaced failure remains a candidate regression.

### Event and workflow behavior

- PR and merge-group events keep one `selected` integration batch.
- Push keeps one matrix batch per selected lane and instrumented coverage.
- `Tests (Reborn)` remains the stable required rollup and continues validating
  skipped versus expected jobs.
- Cache keys, save policy, Rust setup action, nightly toolchain, frontend
  dependency setup, and Postgres image preparation stay unchanged.
- Queue delay and execution duration are reported separately.

### Hermetic/local behavior

- `run-hermetic-deterministic-suite.sh` remains the canonical local composition.
- Its `integration` and `groups` stages remain available, but delegate lane
  selection and execution to `reborn-coverage-lane-run.sh`.
- Its `all` stage invokes the unified non-coverage integration selection once.
- The default-deny environment boundary admits only the environment variables
  still required by the surviving runner.

## Planned final ownership

| Responsibility | Owner after this change |
|---|---|
| Parse Cargo integration registrations | `scripts/ci/lib/integration_test_inventory.py` |
| Validate inventory records and group topology | `scripts/ci/lib/integration_test_inventory.py` |
| Map changed paths to inventory lanes | `scripts/ci/reborn_pr_test_plan.py` |
| Convert selected lanes to exact target arguments | `scripts/ci/reborn-coverage-lane-run.sh`, consuming inventory JSON |
| Execute uninstrumented selected targets | one nextest/cargo command in `scripts/ci/reborn-coverage-lane-run.sh` |
| Execute instrumented selected lane | existing llvm-cov branch in the same lane runner |
| Own uninstrumented per-test timeout policy | `.config/nextest.toml` |
| Compose local deterministic stages | `scripts/ci/run-hermetic-deterministic-suite.sh`, delegating to the lane runner |

The following files are retired after every caller moves:

- `scripts/ci/run-reborn-group-tests.sh`
- `scripts/ci/reborn-coverage-int-tier-tests.sh`

## Implementation sequence

Each commit is either structural or behavioral.

### Commit 1: canonical selected-target projection — structural

1. Extend existing inventory contract tests before moving consumers:
   - preserve sorted Cargo argument output;
   - pin domain-folder registrations, malformed-entry filtering, duplicate
     registration behavior, group kind/lane records, and all current topology
     failures in `scripts/ci/test_integration_test_inventory.py`;
   - move any unique D1-D7 compatibility-wrapper cases from
     `scripts/ci/test-reborn-coverage.sh` into this owning Python suite.
2. Change `reborn-coverage-lane-run.sh` to read one
   `integration_test_inventory.py --json` document.
3. Read `partition_count` from that document rather than the
   `REBORN_COV_LANE_PARTITIONS` environment variable.
4. Use `jq` to select records whose typed `lane` occurs in
   `REBORN_COV_LANES_JSON`; build repeated `--test <name>` arguments from those
   records without prefix grep or modulo arithmetic in shell.
5. Keep the current non-coverage scheduling during this commit: flat nextest
   first, then the canonical sequential group runner. Keep coverage commands
   byte-for-byte equivalent apart from receiving names from JSON.
6. Make the output-LCOV positional argument conditional on coverage collection:
   coverage invocations must still supply it and fail closed when absent;
   non-coverage invocations need no dummy output path.
7. Update caller-level batch-runner tests to prove exact typed lane selection,
   partition-count ownership, empty-lane handling, invalid lanes, topology
   failure before Cargo, the conditional output-path contract, and unchanged
   llvm-cov arguments.

Checkpoint: all existing contract suites pass and command logs prove execution
behavior has not changed.

### Commit 2: canonical local callers — structural

1. Add a small `run_integration_lanes` function to
   `run-hermetic-deterministic-suite.sh`; it has three real callers:
   `integration`, `groups`, and `all`.
2. Make `integration` delegate lanes `[0,1,2,3]` to the lane runner and `groups`
   delegate `["groups"]`, preserving their public stage names and preparation.
3. Keep `all` behaviorally ordered as groups then flat integration in this
   structural commit; only the underlying target selection/executor boundary
   changes.
4. Remove the now-unused compatibility adapter
   `reborn-coverage-int-tier-tests.sh` and update classification, hermetic,
   workflow-contract, documentation, and fixture references.
5. Remove `REBORN_COV_LANE_PARTITIONS` from the workflow, local coverage
   ratchet, hermetic allowlist, and tests because the inventory owns it.
6. Have the three non-coverage hermetic stage callers invoke the lane runner
   without an LCOV path; coverage callers retain their existing output path.

Checkpoint: the hermetic contract proves all public stages reach the canonical
lane runner with the expected typed lanes; no production caller reconstructs
integration names.

### Commit 3: unified bounded nextest execution — behavioral

Red first in `test-ironclaw-integration-batch-runner.sh`:

1. A mixed `[0,"groups"]` selection must produce exactly one nextest command
   containing every selected flat and group target and `--test-threads 4`.
2. A groups-only selection must use that same nextest path, not the sequential
   runner.
3. A multi-failure fixture must show that both selected tests ran and the batch
   failed.
4. Missing nextest in CI must fail before Cargo with an actionable installation
   message. Missing nextest locally must issue one Cargo command with the same
   selected targets and `--no-fail-fast`; if groups are selected, the command
   must use the 28-minute whole-batch timeout.
5. Topology validation must still precede execution whenever groups are
   selected.
6. A group test that exceeds its canonical nextest timeout must be terminated
   and fail the batch; the outer batch timeout remains intact.

Then replace the flat/group execution branches with one selected-target command:

- nextest for every CI invocation and when installed locally;
- one inventory-selected Cargo command only as the established local
  no-nextest compatibility path;
- fixed global nextest concurrency of four;
- existing timeout and `--ignore-rust-version` behavior;
- 64 MiB stack headroom when the selection includes groups.

Add the group-binary timeout override to `.config/nextest.toml`, and update
`tests/integration/AGENTS.md` to state the actual boundary: one group binary
may contain multiple independent top-level tests; each top-level test creates
its own `RebornIntegrationGroup`, while scenarios within that instance run
sequentially and may share state. If inspection finds a top-level test that
depends on a sibling test's process state, stop before this change.

In the same behavioral commit, make the hermetic `all` stage request
`[0,1,2,3,"groups"]` once. The narrow `integration` and `groups` stages remain.

Checkpoint: the new runner contracts are green, and the old contracts fail
against the pre-change runner for the intended reasons.

### Commit 4: remove retired group orchestration — structural

1. Delete `scripts/ci/run-reborn-group-tests.sh`.
2. Remove `REBORN_GROUP_TEST_TIMEOUT` plumbing and allowlisting.
3. Remove sequential-runner assertions/stubs and replace them with canonical
   lane-runner assertions where still required.
4. Search workflows, scripts, tests, docs, and guidance for both deleted paths,
   the `ponytail:` marker, directory-to-name `find/sed`, and the retired timeout.
5. Update current documentation to describe one bounded non-coverage executor;
   historical documents remain unchanged only when they are explicitly marked
   as historical and do not claim to describe current behavior.

Checkpoint: both deleted files have zero live references, and aggregate tests
prove every behavior they backstopped is present in the surviving path.

## Expected file scope and cap

Expected production/configuration files:

- `scripts/ci/lib/integration_test_inventory.py` only if the existing JSON
  contract needs a minimal typed-selection adjustment;
- `scripts/ci/reborn-coverage-lane-run.sh`;
- `scripts/ci/run-hermetic-deterministic-suite.sh`;
- `scripts/ci/run-hermetic-test-process.sh`;
- `.config/nextest.toml`;
- `tests/integration/AGENTS.md`;
- `.github/workflows/reborn-tests.yml` only to remove the redundant partition
  environment input or align comments;
- `scripts/ci/reborn-local-coverage-ratchet.sh`;
- `scripts/ci/classify-test-scope.sh`;
- the two deleted adapter scripts.

Expected owning contract tests:

- `scripts/ci/test_integration_test_inventory.py`;
- `scripts/ci/test-ironclaw-integration-batch-runner.sh`;
- `scripts/ci/test-hermetic-test-process.sh`;
- `scripts/ci/test-reborn-coverage.sh`;
- `scripts/ci/test_reborn_pr_test_plan.py`;
- `scripts/ci/test-classify-test-scope.sh`;
- `scripts/ci/test-check-reborn-branch-coverage-flags.sh` only if its fixture
  needs the inventory JSON contract.

Cap: no more than 16 changed files excluding the two deletions and this plan,
no touched file may cross 1,000 lines because of the change, and the final
production/script diff must be net-deleting. If the cap does not hold, stop and
re-slice rather than adding helpers or widening scope.

## Verification

### Mechanical and contract suites

Run after each relevant commit, then together on the aggregate diff:

```bash
python3 scripts/ci/test_integration_test_inventory.py
scripts/ci/test-ironclaw-integration-batch-runner.sh
scripts/ci/test-hermetic-test-process.sh
scripts/ci/test-reborn-coverage.sh
python3 scripts/ci/test_reborn_pr_test_plan.py
python3 scripts/ci/test_ws12_workflow_contracts.py
scripts/ci/test-classify-test-scope.sh
scripts/ci/test-check-reborn-branch-coverage-flags.sh
python3 scripts/ci/lib/integration_test_inventory.py --validate-group-topology .
bash -n scripts/ci/reborn-coverage-lane-run.sh \
  scripts/ci/run-hermetic-deterministic-suite.sh \
  scripts/ci/run-hermetic-test-process.sh
git diff --check
```

Do not weaken or delete a failing assertion merely because the old runner is
gone. Enumerate what the deleted wrapper backstopped and preserve each behavior
at the surviving caller boundary.

### Process-model audit before behavior change

Inspect every `tests/integration/group_*/main.rs` top-level test. Record whether
it creates its own `RebornIntegrationGroup`, runtime, temporary storage, and env
guards. If any sibling top-level test depends on another's process state, stop
and choose the separate-pool design instead.

Use the pinned nextest to list the exact group tests and prove the inventory
target set equals nextest's selected binary set before running them.

### Repeated stability proof

Run the canonical groups selection three consecutive times with nextest
concurrency four. Every run must pass without retry:

```bash
for run in 1 2 3; do
  REBORN_COV_COLLECT=false \
  REBORN_COV_LANES_JSON='["groups"]' \
    scripts/ci/reborn-coverage-lane-run.sh
done
```

Then run one full local uninstrumented selection:

```bash
REBORN_COV_COLLECT=false \
REBORN_COV_LANES_JSON='[0,1,2,3,"groups"]' \
  scripts/ci/reborn-coverage-lane-run.sh
```

These commands intentionally omit an LCOV path: Commit 1 makes that argument
mandatory only when `REBORN_COV_COLLECT=true`. The batch-runner contract suite
must prove both the no-argument non-coverage path and the fail-closed missing
coverage-output path.

If Docker or another documented local prerequisite is unavailable, report that
exact gap; do not replace the real proof with mocks.

### GitHub execution and timing proof

Before merge-queue entry, dispatch the existing `Tests (Reborn)` workflow on
the PR branch in its full uninstrumented shape. Run it three times without
reruns or retries and record for each:

- workflow creation time;
- integration job start time;
- integration job completion time;
- queue delay (`startedAt - createdAt`);
- execution duration (`completedAt - startedAt`);
- cache outcome;
- test result.

Success requires:

- all three integration jobs pass;
- zero group-test flakes or retries;
- execution-duration median at or below 10 minutes;
- no execution duration above 12 minutes;
- one integration job and no added matrix legs on non-push events.

Queue delay is reported but is not presented as execution improvement. If the
execution threshold fails, inspect setup-versus-test timing. Do not broaden this
PR into cache/toolchain work; either lower the bounded concurrency if contention
is the cause or mark the speed claim unmet and reconsider the next slice.

### Coverage invariance

Use the batch-runner fixtures to capture the `cargo llvm-cov` command before and
after and assert the selected target set, lane count, output path, branch flags,
and artifact naming are unchanged. Run the coverage contract suite, but do not
run an instrumented full workspace merely to validate uninstrumented scheduling
unless a command-shape difference is detected.

## Compatibility, rollout, rollback, and ownership

This changes CI scheduling only. Product behavior, persistence, schemas,
release artifacts, and test scenario definitions are unchanged.

Rollout is the PR branch itself plus three explicit workflow-dispatch runs
before merge-queue entry. The merge queue remains the authoritative combined
candidate gate; push-to-main coverage remains the exhaustive instrumented
confirmation.

Rollback is code-only: revert commits 3 and 4 to restore the sequential group
runner, or revert the whole PR to restore all old adapters. No data migration or
compatibility window exists. The CI maintainers own the concurrency constant
in the lane runner; it is not a user-facing configuration surface.

## Completion criteria

The slice is complete only when:

- inventory JSON is the sole production source for selected integration target
  names;
- PR/merge-queue uninstrumented execution is one bounded nextest invocation;
- the sequential group runner, compatibility selector, `find/sed` projection,
  group timeout plumbing, and stale references are deleted;
- planner, workflow matrix, required rollup, and push coverage behavior are
  unchanged;
- all mechanical and caller-level contract suites pass;
- process-model inspection and repeated local group runs find no hidden
  cross-test dependency;
- three GitHub full uninstrumented runs meet the stability and duration gates;
- final production/script changes are net-deleting and remain inside the file
  cap, including the nextest timeout contract and corrected group guidance.
