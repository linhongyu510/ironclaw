#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <apt-package>..." >&2
  exit 2
fi

# GitHub-hosted Ubuntu images carry Microsoft apt sources -- the Azure CLI repo
# (packages.microsoft.com/repos/azure-cli) and the prod repo
# (packages.microsoft.com/ubuntu/.../prod) -- that transiently return 403 /
# "no longer signed". When any of them breaks, `apt-get update` fails before CI
# can install the small linker packages these jobs need. None are required here,
# so strip every packages.microsoft.com source, not just the Azure CLI one.
while IFS= read -r -d '' source_file; do
  if sudo grep -q "packages.microsoft.com" "${source_file}"; then
    echo "Removing unavailable Microsoft apt source: ${source_file}" >&2
    sudo rm -f "${source_file}"
  fi
done < <(sudo find /etc/apt -type f \( -name "*.list" -o -name "*.sources" \) -print0)

# GitHub's mirror list currently points at azure.archive.ubuntu.com, which can
# accept a package download and then stop making progress for the rest of the
# job. Use Ubuntu's canonical archive so retries reach an independent mirror.
ubuntu_mirror_list=/etc/apt/apt-mirrors.txt
if sudo test -f "${ubuntu_mirror_list}" && \
  sudo grep -q "azure.archive.ubuntu.com" "${ubuntu_mirror_list}"; then
  echo "Replacing unavailable Azure Ubuntu mirror with archive.ubuntu.com" >&2
  sudo sed -i \
    's#http://azure.archive.ubuntu.com/ubuntu#http://archive.ubuntu.com/ubuntu#g' \
    "${ubuntu_mirror_list}"
fi

# Even with broken sources removed, the remaining mirrors occasionally return
# transient errors or accept a connection without ever completing it. Bound
# every acquisition so the outer retry loop can recover instead of consuming
# the entire job timeout inside one `apt-get` call.
apt_acquire_options=(
  -o Acquire::http::Timeout=15
  -o Acquire::https::Timeout=15
  -o Acquire::Retries=2
)
run_apt() {
  local deadline="$1"
  shift
  sudo timeout --kill-after=5s "${deadline}" apt-get "${apt_acquire_options[@]}" "$@"
}
update_ok=false
for attempt in 1 2 3; do
  if run_apt 120s update; then
    update_ok=true
    break
  fi
  echo "apt-get update failed (attempt ${attempt}/3); retrying in $((attempt * 5))s..." >&2
  sleep "$((attempt * 5))"
done
if [ "${update_ok}" != true ]; then
  echo "apt-get update failed after 3 attempts" >&2
  exit 1
fi

install_ok=false
for attempt in 1 2; do
  if run_apt 300s install -y "$@"; then
    install_ok=true
    break
  fi
  if [ "${attempt}" -lt 2 ]; then
    echo "apt-get install failed (attempt ${attempt}/2); retrying in $((attempt * 5))s..." >&2
    sleep "$((attempt * 5))"
  fi
done
if [ "${install_ok}" != true ]; then
  echo "apt-get install failed after 2 attempts" >&2
  exit 1
fi
