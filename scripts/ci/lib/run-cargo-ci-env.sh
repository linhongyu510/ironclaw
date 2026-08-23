#!/usr/bin/env bash
# Canonical scrubbed-env wrapper for cargo (and any other) invocations that
# must not observe NEARAI_*/IRONCLAW_LLM_*/LLM_BACKEND credentials while a
# compile is in flight — build.rs and proc macros run arbitrary code from the
# dependency graph, so an unscrubbed compile is a real credential-exposure
# surface, not just a test-hygiene nicety.
#
# Extracted once a third caller crossed this repo's own rule-of-three
# duplication threshold (the comment that used to sit above
# scripts/preflight-gates.sh's copy said exactly this: "if a third caller
# appears, factor both into scripts/ci/lib/run-cargo-ci-env.sh"). The three
# call sites — .githooks/pre-push's run_ci_env, scripts/ci/quality_gate.sh's
# run_cargo_ci, and scripts/preflight-gates.sh's run_cargo_ci_scrubbed — keep
# their own function NAMES as thin wrappers delegating here, so neither
# existing callers nor in-flight sibling branches touching those files need
# to change.
#
# Copy the -u unset list and the set-vars verbatim if this file is ever
# edited; every caller's understanding of "scrubbed" depends on this exact
# list.
run_cargo_ci_env() {
    env \
        -u NEARAI_API_KEY \
        -u NEARAI_BASE_URL \
        -u NEARAI_SESSION_TOKEN \
        -u NEARAI_PROVIDER_ID \
        -u NEARAI_MODEL \
        -u IRONCLAW_LLM_PROVIDER \
        -u IRONCLAW_LLM_MODEL \
        -u LLM_BACKEND \
        IRONCLAW_DISABLE_OS_KEYCHAIN="${IRONCLAW_DISABLE_OS_KEYCHAIN:-1}" \
        CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}" \
        CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-0}" \
        RUST_MIN_STACK="${RUST_MIN_STACK:-67108864}" \
        "$@"
}
