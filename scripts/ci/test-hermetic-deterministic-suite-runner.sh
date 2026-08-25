#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
under_test="${repo_root}/scripts/ci/run-hermetic-deterministic-suite.sh"
sandbox="$(mktemp -d)"
trap 'rm -rf "${sandbox}"' EXIT

mkdir -p \
  "${sandbox}/bin" \
  "${sandbox}/repo/scripts/ci/lib" \
  "${sandbox}/repo/tests/integration/group_fixture" \
  "${sandbox}/repo/tests/integration/group_unselected" \
  "${sandbox}/repo/frontend"
cp "${under_test}" "${sandbox}/repo/scripts/ci/run-hermetic-deterministic-suite.sh"
cp "${repo_root}/scripts/ci/lib/select-test-runner.sh" "${sandbox}/repo/scripts/ci/lib/select-test-runner.sh"
cp "${repo_root}/scripts/ci/run-reborn-group-tests.sh" "${sandbox}/repo/scripts/ci/run-reborn-group-tests.sh"
touch "${sandbox}/repo/tests/integration/group_fixture/main.rs"
touch "${sandbox}/repo/tests/integration/group_unselected/main.rs"
printf '{"packageManager":"pnpm@9.0.0"}\n' >"${sandbox}/repo/frontend/package.json"

cat >"${sandbox}/repo/scripts/ci/run-hermetic-test-process.sh" <<'STUB'
#!/usr/bin/env bash
shift
cd "${HERMETIC_TEST_REPO_ROOT}"
exec "$@"
STUB
cat >"${sandbox}/repo/scripts/ci/crate-dir.sh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "${HERMETIC_TEST_REPO_ROOT}"
STUB
cat >"${sandbox}/repo/scripts/ci/discover-reborn-package-crates.sh" <<'STUB'
#!/usr/bin/env bash
printf '["ironclaw_fixture"]\n'
STUB
cat >"${sandbox}/repo/scripts/ci/package-feature-flags.sh" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
cat >"${sandbox}/repo/scripts/ci/reborn-coverage-int-tier-tests.sh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' --test reborn_group_fixture --test reborn_integration_fixture
STUB
chmod +x "${sandbox}/repo/scripts/ci/"*.sh

cat >"${sandbox}/bin/cargo" <<'STUB'
#!/usr/bin/env bash
printf 'cargo %s\n' "$*" >>"${HERMETIC_TEST_LOG}"
if [[ "${HERMETIC_FAIL_GROUP:-0}" == "1" && "$*" == *'--test reborn_group_fixture'* ]]; then
  exit 1
fi
STUB
cat >"${sandbox}/bin/cargo-nextest" <<'STUB'
#!/usr/bin/env bash
printf 'nextest %s\n' "$*" >>"${HERMETIC_TEST_LOG}"
STUB
cp "${sandbox}/bin/cargo-nextest" "${sandbox}/cargo-nextest.stub"
cat >"${sandbox}/bin/docker" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
cat >"${sandbox}/bin/corepack" <<'STUB'
#!/usr/bin/env bash
printf 'corepack %s\n' "$*" >>"${HERMETIC_TEST_LOG}"
mkdir -p "${COREPACK_HOME:?}"
printf 'prepared by corepack\n' >"${COREPACK_HOME}/prepared-pnpm"
if [[ "${1:-}" == "pnpm" && "${2:-}" == "install" ]]; then
  mkdir -p node_modules
  printf 'prepared project dependencies\n' >node_modules/.hermetic-fixture
fi
exit 0
STUB
cat >"${sandbox}/bin/timeout" <<'STUB'
#!/usr/bin/env bash
while [[ "$1" == --* || "$1" == *[smhd] ]]; do
  case "$1" in
    --signal=*|--kill-after=*) shift ;;
    *) shift; break ;;
  esac
done
exec "$@"
STUB
chmod +x "${sandbox}/bin/"*

run_suite() {
  local stage="$1" ci_value="$2" with_nextest="$3" fail_group="${4:-0}" root_control="${5:-0}" corepack_mode="${6:-none}"
  local -a env_args=(
    env -u CI
    HERMETIC_TEST_REPO_ROOT="${sandbox}/repo"
    HERMETIC_TEST_LOG="${sandbox}/commands.log"
    HERMETIC_FAIL_GROUP="${fail_group}"
    IRONCLAW_HERMETIC_NEXTEST_CONTROL="${root_control}"
    PATH="${sandbox}/bin:/usr/bin:/bin"
  )
  [[ "${ci_value}" == set ]] && env_args+=(CI=true)
  [[ "${corepack_mode}" == caller ]] && env_args+=(COREPACK_HOME="${sandbox}/caller-corepack")
  if [[ "${with_nextest}" == no ]]; then
    rm -f "${sandbox}/bin/cargo-nextest"
  else
    cp "${sandbox}/cargo-nextest.stub" "${sandbox}/bin/cargo-nextest"
    chmod +x "${sandbox}/bin/cargo-nextest"
  fi
  "${env_args[@]}" bash "${sandbox}/repo/scripts/ci/run-hermetic-deterministic-suite.sh" "${stage}"
}

failures=0

: >"${sandbox}/commands.log"
if ! run_suite prepare-command unset no 0 1 >"${sandbox}/prepare-command.log" 2>&1; then
  echo "FAIL: prepare-command stage failed" >&2
  cat "${sandbox}/prepare-command.log" >&2
  failures=$((failures + 1))
elif ! grep -Fq 'corepack pnpm install --frozen-lockfile' "${sandbox}/commands.log"; then
  echo "FAIL: root-control preparation did not provision frontend dependencies for Rust build scripts" >&2
  cat "${sandbox}/commands.log" >&2
  failures=$((failures + 1))
fi

: >"${sandbox}/commands.log"
if ! run_suite prepare-command unset no 0 1 caller >"${sandbox}/prepare-command-caller-corepack.log" 2>&1; then
  echo "FAIL: prepare-command with caller-provided COREPACK_HOME failed" >&2
  cat "${sandbox}/prepare-command-caller-corepack.log" >&2
  failures=$((failures + 1))
elif [[ ! -f "${sandbox}/caller-corepack/prepared-pnpm" ]]; then
  echo "FAIL: caller-provided COREPACK_HOME was not populated" >&2
  failures=$((failures + 1))
elif [[ ! -f "${sandbox}/repo/frontend/node_modules/.hermetic-fixture" ]]; then
  echo "FAIL: prepared project dependencies were not left visible" >&2
  failures=$((failures + 1))
fi

: >"${sandbox}/commands.log"
if run_suite prepare-command unset no >"${sandbox}/prepare-command-no-frontend.log" 2>&1; then
  if grep -Fq 'corepack pnpm install --frozen-lockfile' "${sandbox}/commands.log"; then
    echo "FAIL: ordinary prepare-command installed frontend dependencies" >&2
    cat "${sandbox}/commands.log" >&2
    failures=$((failures + 1))
  fi
else
  echo "FAIL: ordinary prepare-command stage failed" >&2
  cat "${sandbox}/prepare-command-no-frontend.log" >&2
  failures=$((failures + 1))
fi

for stage in crates integration; do
  : >"${sandbox}/commands.log"
  if run_suite "${stage}" set no >"${sandbox}/${stage}-ci.log" 2>&1; then
    echo "FAIL: ${stage} silently fell back to cargo when nextest was absent in CI" >&2
    failures=$((failures + 1))
  elif ! grep -Fq 'cargo-nextest is required in CI' "${sandbox}/${stage}-ci.log"; then
    echo "FAIL: ${stage} did not explain the missing CI runner" >&2
    cat "${sandbox}/${stage}-ci.log" >&2
    failures=$((failures + 1))
  fi

  : >"${sandbox}/commands.log"
  if ! run_suite "${stage}" unset no >"${sandbox}/${stage}-local.log" 2>&1; then
    echo "FAIL: ${stage} lost the local cargo fallback" >&2
    cat "${sandbox}/${stage}-local.log" >&2
    failures=$((failures + 1))
  elif ! grep -Fq 'cargo test ' "${sandbox}/commands.log"; then
    echo "FAIL: ${stage} local fallback did not execute cargo test" >&2
    cat "${sandbox}/commands.log" >&2
    failures=$((failures + 1))
  fi
done

: >"${sandbox}/commands.log"
if run_suite integration set yes 1 >"${sandbox}/integration-group-failure.log" 2>&1; then
  echo "FAIL: integration returned success after a group suite failed" >&2
  failures=$((failures + 1))
else
  if ! grep -Fq 'cargo test -p ironclaw_integration_tests --test reborn_group_fixture' "${sandbox}/commands.log"; then
    echo "FAIL: integration did not preserve canonical cargo execution for group suites" >&2
    failures=$((failures + 1))
  fi
  if ! grep -F 'nextest ' "${sandbox}/commands.log" | grep -Fq 'reborn_integration_fixture'; then
    echo "FAIL: integration did not run flat suites after a group failure" >&2
    failures=$((failures + 1))
  fi
fi

: >"${sandbox}/commands.log"
if ! run_suite integration set yes >"${sandbox}/integration-nextest.log" 2>&1; then
  echo "FAIL: integration nextest caller sandbox failed" >&2
  cat "${sandbox}/integration-nextest.log" >&2
  failures=$((failures + 1))
else
  if grep -F 'nextest ' "${sandbox}/commands.log" | grep -Fq 'reborn_group_'; then
    echo "FAIL: integration pooled reborn_group_* under nextest" >&2
    failures=$((failures + 1))
  fi
  if ! grep -Fq 'cargo test -p ironclaw_integration_tests --test reborn_group_fixture' "${sandbox}/commands.log"; then
    echo "FAIL: integration did not preserve canonical cargo execution for group suites" >&2
    failures=$((failures + 1))
  fi
  if grep -Fq 'reborn_group_unselected' "${sandbox}/commands.log"; then
    echo "FAIL: integration broadened the selected group suites" >&2
    failures=$((failures + 1))
  fi
  if ! grep -F 'nextest ' "${sandbox}/commands.log" | grep -Fq 'reborn_integration_fixture'; then
    echo "FAIL: integration did not retain non-group suites in nextest" >&2
    failures=$((failures + 1))
  fi
fi

if [[ "${failures}" -ne 0 ]]; then
  echo "hermetic deterministic-suite runner: ${failures} failure(s)" >&2
  exit 1
fi
echo "hermetic deterministic-suite runner: OK"
