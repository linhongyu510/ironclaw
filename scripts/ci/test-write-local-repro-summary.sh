#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
under_test="${repo_root}/scripts/ci/write-local-repro-summary.sh"
sandbox="$(mktemp -d)"
trap 'rm -rf "${sandbox}"' EXIT

GITHUB_STEP_SUMMARY="${sandbox}/unset.md" "${under_test}" >/dev/null
grep -Fq "<no REPRO recorded — see the failing step output above>" \
  "${sandbox}/unset.md"

GITHUB_STEP_SUMMARY="${sandbox}/set.md" REPRO="cargo nextest run --profile ci" \
  "${under_test}" >/dev/null
grep -Fq "cargo nextest run --profile ci" "${sandbox}/set.md"

echo "local repro summary: OK"
