#!/usr/bin/env bash
# -E (errtrace): without it, the ERR trap below is NOT inherited into shell
# functions (run_cargo_ci, select_test_runner) — a failure inside them would
# abort the script via -e but silently skip the REPRO trap. Verified live:
# without -E, a failing `cargo fetch`/`cargo clippy` called through a helper
# function exits the script with no REPRO line at all.
set -Eeuo pipefail

# LAST_REPRO: set by a wrapper function (run_cargo_ci) right before it
# returns non-zero, to its own real argv. BASH_COMMAND at trap time would
# otherwise read "run_cargo_ci cargo clippy ..." — a function name that does
# not exist outside this script and so is not paste-able as a repro command.
LAST_REPRO=""

report_repro() {
    local status=$?
    trap - ERR
    if [ -n "${LAST_REPRO}" ]; then
        echo "REPRO: ${LAST_REPRO}" >&2
    else
        echo "REPRO: ${BASH_COMMAND}" >&2
    fi
    exit "${status}"
}
trap report_repro ERR

echo "==> fmt check"
cargo fmt --all -- --check

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/run-cargo-ci-env.sh"

# Delegates to the canonical scrub in scripts/ci/lib/run-cargo-ci-env.sh; the
# function NAME is kept so nothing else in this script has to change. On
# failure, records its own real argv into LAST_REPRO (see comment above) —
# `printf '%q '` makes it exactly what report_repro should print, not what
# BASH_COMMAND would (the wrapper's name).
run_cargo_ci() {
    LAST_REPRO=""
    local status=0
    # `cmd || status=$?`, not `if cmd; then ... fi; status=$?`: an `if` with
    # no `else` branch that took the false path resets $? to 0 at `fi`
    # regardless of the condition's real exit status — verified live — so a
    # post-if `$?` read would silently always capture 0 here.
    run_cargo_ci_env "$@" || status=$?
    if [ "${status}" -ne 0 ]; then
        LAST_REPRO="$(printf '%q ' "$@")"
    fi
    return "${status}"
}

echo "==> clippy (CI parity: all features, all warnings)"
run_cargo_ci cargo clippy --locked --all --tests --examples --all-features -- -D warnings

# Which runner executes the workspace tests.
#
# `cargo test` runs each test binary strictly sequentially — it parallelises
# *within* a binary but never across them. This workspace builds well over 400
# test binaries, the large majority finishing in under a second, so the gate
# spends most of its wall clock starting and tearing down processes one at a
# time. `cargo nextest` runs them in a single parallel pool instead.
#
# Coverage is equivalent: `--all-targets` expands to
# `--lib --bins --tests --benches --examples` and so has never included
# doctests, which nextest also does not run. This swap therefore changes
# scheduling only, not what is executed.
#
# nextest stays OPTIONAL. `tests/fixtures/llm_traces/README.md` documents that
# local development must keep working without it, so an absent binary falls
# back rather than failing. `.config/nextest.toml` already carries the
# repository's profiles and per-test slow-timeouts; CI's insta gate uses them.
#
#   auto (default) — nextest when installed, otherwise cargo test
#   nextest        — require nextest, fail if missing
#   cargo          — force the sequential runner
select_test_runner() {
    case "${IRONCLAW_GATE_TEST_RUNNER:-auto}" in
        cargo) echo "cargo" ;;
        nextest)
            if command -v cargo-nextest >/dev/null 2>&1; then
                echo "nextest"
            else
                echo "IRONCLAW_GATE_TEST_RUNNER=nextest requires cargo-nextest" >&2
                return 1
            fi
            ;;
        auto)
            if command -v cargo-nextest >/dev/null 2>&1; then
                echo "nextest"
            else
                echo "cargo"
            fi
            ;;
        *)
            echo "unknown IRONCLAW_GATE_TEST_RUNNER: ${IRONCLAW_GATE_TEST_RUNNER}" >&2
            return 1
            ;;
    esac
}

if [ "${IRONCLAW_PREPUSH_TEST:-1}" = "1" ]; then
    runner="$(select_test_runner)"
    if [ "$runner" = "nextest" ]; then
        echo "==> tests (nextest: workspace, all targets, all features; skip with IRONCLAW_PREPUSH_TEST=0)"
        run_cargo_ci cargo nextest run --locked --workspace --all-targets --all-features --no-fail-fast
    else
        echo "==> tests (cargo test: workspace, all targets, all features; skip with IRONCLAW_PREPUSH_TEST=0)"
        echo "    install cargo-nextest for a parallel run: https://nexte.st/docs/installation/"
        run_cargo_ci cargo test --locked --workspace --all-targets --all-features --no-fail-fast
    fi
fi
