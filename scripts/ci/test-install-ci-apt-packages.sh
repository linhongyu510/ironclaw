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
install_count="${fixture_root}/install-count"
mirror_edits="${fixture_root}/mirror-edits"
mkdir -p "${mock_bin}"

cat > "${mock_bin}/sudo" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

command_name="$1"
shift
if [[ "${command_name}" == "timeout" ]]; then
  printf '%s\n' "timeout $*" >> "${APT_TIMEOUT_CALLS}"
  expected_deadline="120s"
  if [[ " $* " == *" install "* ]]; then
    expected_deadline="300s"
  fi
  [[ "$1" == "--kill-after=5s" ]]
  [[ "$2" == "${expected_deadline}" ]]
  shift 2
  command_name="$1"
  shift
fi
case "${command_name}" in
  find)
    exit 0
    ;;
  test)
    [[ "$*" == "-f /etc/apt/apt-mirrors.txt" ]]
    ;;
  grep)
    [[ " $* " == *" azure.archive.ubuntu.com "* ]]
    ;;
  sed)
    printf '%s\n' "$*" >> "${MIRROR_EDITS}"
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
    if [[ " $* " == *" install "* ]]; then
      count=0
      if [[ -f "${APT_INSTALL_COUNT}" ]]; then
        count="$(<"${APT_INSTALL_COUNT}")"
      fi
      count=$((count + 1))
      printf '%s\n' "${count}" > "${APT_INSTALL_COUNT}"
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
APT_INSTALL_COUNT="${install_count}" \
APT_UPDATE_COUNT="${update_count}" \
APT_TIMEOUT_CALLS="${fixture_root}/apt-timeout-calls" \
MIRROR_EDITS="${mirror_edits}" \
SLEEP_CALLS="${sleep_calls}" \
  bash "${installer}" clang mold

apt_options="-o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 -o Acquire::Retries=2"
if [[ "$(grep -Fxc -- "apt-get ${apt_options} update" "${apt_calls}")" -ne 2 ]]; then
  echo "apt update must be time-bounded on every retry" >&2
  cat "${apt_calls}" >&2
  exit 1
fi
if [[ "$(grep -Fxc -- "apt-get ${apt_options} install -y clang mold" "${apt_calls}")" -ne 2 ]]; then
  echo "apt install must retry once with the same bounded acquisition policy" >&2
  cat "${apt_calls}" >&2
  exit 1
fi
timeout_calls="${fixture_root}/apt-timeout-calls"
if [[ "$(grep -Fxc -- "timeout --kill-after=5s 120s apt-get ${apt_options} update" "${timeout_calls}")" -ne 2 ]]; then
  echo "every apt update must have a 120-second whole-command deadline" >&2
  cat "${timeout_calls}" >&2
  exit 1
fi
if [[ "$(grep -Fxc -- "timeout --kill-after=5s 300s apt-get ${apt_options} install -y clang mold" "${timeout_calls}")" -ne 2 ]]; then
  echo "apt install must have a 300-second whole-command deadline" >&2
  cat "${timeout_calls}" >&2
  exit 1
fi
if ! grep -Fq -- "azure.archive.ubuntu.com/ubuntu#http://archive.ubuntu.com/ubuntu#g /etc/apt/apt-mirrors.txt" "${mirror_edits}"; then
  echo "GitHub's Azure mirror list must fall back to Ubuntu's canonical archive" >&2
  exit 1
fi
if [[ "$(cat "${sleep_calls}")" != $'5\n5' ]]; then
  echo "outer apt retry backoffs changed unexpectedly" >&2
  exit 1
fi

echo "CI apt installer contract passed"
