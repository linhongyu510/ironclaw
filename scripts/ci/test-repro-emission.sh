#!/usr/bin/env bash
# Self-tests for Pattern A REPRO emission: quality_gate.sh and
# run-hermetic-deterministic-suite.sh must each print
# "REPRO: <exact failing invocation>" when a gate/stage they run fails.
# preflight-gates.sh's REPRO emission is already covered by
# scripts/ci/test-preflight-gates.sh (Task 1) — not duplicated here.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
failures=0
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }

make_sandbox() {
    sandbox="$(mktemp -d)"
    mkdir -p "$sandbox/bin" "$sandbox/scripts/ci"
    cp "$REPO_ROOT/scripts/ci/quality_gate.sh" "$sandbox/scripts/ci/quality_gate.sh"
    cp "$REPO_ROOT/scripts/ci/run-hermetic-deterministic-suite.sh" \
        "$sandbox/scripts/ci/run-hermetic-deterministic-suite.sh"
    mkdir -p "$sandbox/scripts/ci/lib"
    cp "$REPO_ROOT/scripts/ci/lib/run-cargo-ci-env.sh" "$sandbox/scripts/ci/lib/run-cargo-ci-env.sh"
    printf '#!/usr/bin/env bash\necho "ran $*" >>"$REPRO_TEST_LOG"\nexit 1\n' \
        >"$sandbox/scripts/ci/run-hermetic-test-process.sh"
    chmod +x "$sandbox/scripts/ci/run-hermetic-test-process.sh"
    echo "$sandbox"
}

# 1. quality_gate.sh: a failing fmt check prints REPRO for exactly that line.
sandbox="$(make_sandbox)"
cat >"$sandbox/bin/cargo" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = "fmt" ]; then exit 1; fi
exit 0
STUB
chmod +x "$sandbox/bin/cargo"
set +e
output="$(cd "$sandbox" && env PATH="$sandbox/bin:/usr/bin:/bin" \
    bash scripts/ci/quality_gate.sh 2>&1)"
status=$?
set -e
[ "$status" -ne 0 ] || fail "quality_gate.sh must fail when fmt fails"
grep -qF "REPRO: cargo fmt --all -- --check" <<<"$output" \
    || fail "quality_gate.sh must print the exact failing command as REPRO"

# 2. run-hermetic-deterministic-suite.sh: a failing stage prints REPRO with
#    the stage + its own args (fixed args reconstructed via "$@").
sandbox="$(make_sandbox)"
set +e
output="$(cd "$sandbox" && env REPRO_TEST_LOG="$sandbox/log" \
    PATH="$sandbox/bin:/usr/bin:/bin" \
    bash scripts/ci/run-hermetic-deterministic-suite.sh rust-e2e architecture-boundaries 2>&1)"
status=$?
set -e
[ "$status" -ne 0 ] || fail "run-hermetic-deterministic-suite.sh must fail when the stage fails"
grep -qF "REPRO: bash scripts/ci/run-hermetic-deterministic-suite.sh rust-e2e architecture-boundaries" \
    <<<"$output" || fail "run-hermetic-deterministic-suite.sh must print the exact stage + args as REPRO"

# 3. quality_gate.sh: a failure INSIDE the run_cargo_ci wrapper function must
#    print the wrapper's own real argv as REPRO ("cargo clippy ..."), not
#    "run_cargo_ci cargo clippy ..." — run_cargo_ci is a function name that
#    does not exist outside this script, so BASH_COMMAND alone is not
#    paste-able. This is also exactly the case a regressed `set -E` would
#    break: without errtrace the ERR trap would not fire from inside
#    run_cargo_ci at all, and the script would exit with no REPRO line.
sandbox="$(make_sandbox)"
cat >"$sandbox/bin/cargo" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = "fmt" ]; then exit 0; fi
if [ "$1" = "clippy" ]; then exit 1; fi
exit 0
STUB
chmod +x "$sandbox/bin/cargo"
set +e
output="$(cd "$sandbox" && env PATH="$sandbox/bin:/usr/bin:/bin" \
    bash scripts/ci/quality_gate.sh 2>&1)"
status=$?
set -e
[ "$status" -ne 0 ] || fail "quality_gate.sh must fail when clippy fails"
grep -qF "REPRO: cargo clippy --locked --all --tests --examples --all-features -- -D warnings" <<<"$output" \
    || fail "a failure inside run_cargo_ci must print its own real argv as REPRO"
grep -qF "REPRO: run_cargo_ci" <<<"$output" \
    && fail "REPRO must never print the internal wrapper function name (not runnable outside the script)"

if [ "$failures" -gt 0 ]; then
    echo "test-repro-emission: $failures assertion(s) failed" >&2
    exit 1
fi
echo "test-repro-emission: OK"
