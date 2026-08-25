#!/usr/bin/env bash
set -euo pipefail

summary_path="${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY must name the job summary}"

{
  echo "### Local repro for this job"
  echo '```bash'
  if [[ -n "${REPRO:-}" ]]; then
    echo "${REPRO}"
  else
    echo "<no REPRO recorded — see the failing step output above>"
  fi
  echo '```'
} | tee -a "${summary_path}"
