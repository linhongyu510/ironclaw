#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
under_test="${repo_root}/scripts/ci/run-reborn-group-tests.sh"
sandbox="$(mktemp -d)"
trap 'rm -rf "${sandbox}"' EXIT

mkdir -p \
  "${sandbox}/bin" \
  "${sandbox}/tests/integration/group_first" \
  "${sandbox}/tests/integration/group_second" \
  "${sandbox}/tests/integration/group_third"
touch \
  "${sandbox}/tests/integration/group_first/main.rs" \
  "${sandbox}/tests/integration/group_second/main.rs" \
  "${sandbox}/tests/integration/group_third/main.rs"

cat >"${sandbox}/bin/cargo" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${GROUP_RUNNER_LOG}"
if [[ "$*" == *"--test reborn_group_second"* ]]; then
  exit 23
fi
STUB
chmod +x "${sandbox}/bin/cargo"

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
chmod +x "${sandbox}/bin/timeout"

status=0
if output="$(
  cd "${sandbox}"
  PATH="${sandbox}/bin:/usr/bin:/bin" \
    GROUP_RUNNER_LOG="${sandbox}/cargo.log" \
    bash "${under_test}" 2>&1
)"; then
  echo "FAIL: a failed group suite did not make the runner fail" >&2
  status=1
fi

if [[ "${status}" -eq 0 ]]; then
  if [[ "${output}" != *"group suite failed: reborn_group_second"* ]]; then
    echo "FAIL: failed group suite was not reported" >&2
    status=1
  fi
  if ! grep -Fq -- '--test reborn_group_third' "${sandbox}/cargo.log"; then
    echo "FAIL: group runner stopped before the later suite" >&2
    status=1
  fi
fi

if [[ "${status}" -ne 0 ]]; then
  printf '%s\n' "${output}" >&2
  exit "${status}"
fi
echo "reborn group runner contract: OK"
