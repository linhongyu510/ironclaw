#!/usr/bin/env bash
# Regression test for the fast-checks/cargo split.
#
# scripts/ci/test-hermetic-test-process.sh runs in `fast-checks`, which is
# deliberately cache-less and toolchain-light. Its nextest network-guard
# control shells out to cargo (nextest runs `cargo metadata`), which cannot
# resolve offline inside the hermetic wrapper without a warm registry --
# that reddened `Fast deterministic checks` and the required `Code Style`
# roll-up with "no matching package named `async-trait` found".
#
# The control is therefore opt-in. This test pins BOTH halves of that
# contract, using a PATH sandbox (same shape as test-quality-gate-runner.sh):
# a stub `cargo`/`cargo-nextest` that records any invocation and fails.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
under_test="${repo_root}/scripts/ci/test-hermetic-test-process.sh"
sandbox="$(mktemp -d)"
trap 'rm -rf "${sandbox}"' EXIT
marker="${sandbox}/cargo-was-invoked"
failures=0

assert_success() {
  local label="$1" status="$2"
  if [[ "${status}" -ne 0 ]]; then
    echo "FAIL: ${label}: expected exit 0, got ${status}" >&2
    failures=$((failures + 1))
  fi
}

assert_failure() {
  local label="$1" status="$2"
  if [[ "${status}" -eq 0 ]]; then
    echo "FAIL: ${label}: expected a non-zero exit, got 0" >&2
    failures=$((failures + 1))
  fi
}

assert_no_cargo_invocation() {
  local label="$1"
  if [[ -e "${marker}" ]]; then
    echo "FAIL: ${label}: invoked cargo. fast-checks has no warm registry," \
         "so this is the regression that reddened the required roll-up:" >&2
    cat "${marker}" >&2
    failures=$((failures + 1))
  fi
}

for stub in cargo cargo-nextest; do
  cat > "${sandbox}/${stub}" <<STUB
#!/usr/bin/env bash
echo "${stub} \$*" >> "${marker}"
exit 1
STUB
  chmod +x "${sandbox}/${stub}"
done

# 1. Default (the fast-checks shape): control skipped, script green, and
#    cargo never invoked even though it is on PATH.
PATH="${sandbox}:${PATH}" env -u IRONCLAW_HERMETIC_NEXTEST_CONTROL \
  bash "${under_test}" >"${sandbox}/default.log" 2>&1
assert_success "default run (fast-checks shape)" "$?"
assert_no_cargo_invocation "default run (fast-checks shape)"
if ! grep -q "control not requested" "${sandbox}/default.log"; then
  echo "FAIL: default run did not report that the control was skipped" >&2
  failures=$((failures + 1))
fi

# 2. Opted in without cargo-nextest under CI: must fail loudly rather than
#    silently skipping a control the lane explicitly asked for.
rm -f "${marker}"
missing="${sandbox}/no-nextest"
mkdir -p "${missing}"
cp "${sandbox}/cargo" "${missing}/cargo"
PATH="${missing}:/usr/bin:/bin" CI=true IRONCLAW_HERMETIC_NEXTEST_CONTROL=1 \
  bash "${under_test}" >"${sandbox}/optin.log" 2>&1
assert_failure "opted-in run with cargo-nextest missing under CI" "$?"

if [[ "${failures}" -ne 0 ]]; then
  echo "hermetic nextest-control gating: ${failures} failure(s)" >&2
  exit 1
fi
echo "hermetic nextest-control gating: OK"
