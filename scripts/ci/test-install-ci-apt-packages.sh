#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
installer="${repo_root}/scripts/ci/install-ci-apt-packages.sh"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/ironclaw-apt-installer.XXXXXX")"
trap 'rm -rf -- "${fixture_root}"' EXIT

mock_bin="${fixture_root}/bin"
apt_calls="${fixture_root}/apt-calls"
update_count="${fixture_root}/update-count"
sleep_calls="${fixture_root}/sleep-calls"
mkdir -p "${mock_bin}"

cat > "${mock_bin}/sudo" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

command_name="$1"
shift
case "${command_name}" in
  find)
    exit 0
    ;;
  apt-get)
    printf '%s\n' "apt-get $*" >> "${APT_CALLS}"
    if [[ " $* " == *" update "* ]]; then
      count=0
      if [[ -f "${APT_UPDATE_COUNT}" ]]; then
        count="$(<"${APT_UPDATE_COUNT}")"
      fi
      count=$((count + 1))
      printf '%s\n' "${count}" > "${APT_UPDATE_COUNT}"
      [[ "${count}" -gt 1 ]]
      exit
    fi
    exit 0
    ;;
  *)
    echo "unexpected sudo command: ${command_name}" >&2
    exit 1
    ;;
esac
MOCK

cat > "${mock_bin}/sleep" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${SLEEP_CALLS}"
MOCK
chmod +x "${mock_bin}/sudo" "${mock_bin}/sleep"

PATH="${mock_bin}:${PATH}" \
APT_CALLS="${apt_calls}" \
APT_UPDATE_COUNT="${update_count}" \
SLEEP_CALLS="${sleep_calls}" \
  bash "${installer}" clang mold

apt_options="-o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 -o Acquire::Retries=2"
if [[ "$(grep -Fxc -- "apt-get ${apt_options} update" "${apt_calls}")" -ne 2 ]]; then
  echo "apt update must be time-bounded on every retry" >&2
  cat "${apt_calls}" >&2
  exit 1
fi
if ! grep -Fxq -- "apt-get ${apt_options} install -y clang mold" "${apt_calls}"; then
  echo "apt install must use the same bounded acquisition policy" >&2
  cat "${apt_calls}" >&2
  exit 1
fi
if [[ "$(cat "${sleep_calls}")" != "5" ]]; then
  echo "outer apt retry backoff changed unexpectedly" >&2
  exit 1
fi

echo "CI apt installer contract passed"
