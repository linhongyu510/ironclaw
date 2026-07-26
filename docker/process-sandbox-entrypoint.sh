#!/bin/sh
set -eu

# NOTE on the two consumers sharing this image/entrypoint: the persistent
# per-user sandbox (`ironclaw_host_runtime::sandbox_process::exec_transport`)
# never sets IRONCLAW_EGRESS_LOCKDOWN and creates the container running
# directly as uid 1000 (see Dockerfile.process-sandbox / the W1 root-init-
# window fix), so the CA-install and iptables branches below are dead on
# that path by construction — and would fail outright now anyway, since
# `update-ca-certificates`/`iptables` need root.
# `ironclaw_process_sandbox::docker::DockerProcessSandboxBackend`
# (crates/ironclaw_process_sandbox/src/docker.rs:437-465, exercised by its
# own tests.rs:449-510) is the only consumer that sets `broker-only`
# lockdown. It has no production constructor (test-only) and already needs
# root + NET_ADMIN regardless of this change, so it is unaffected by the
# persistent path's move to a non-root init. These branches stay in place
# for that consumer — do not delete them assuming they are unreachable dead
# code.
if [ -n "${SSL_CERT_FILE:-}" ] && [ -f "${SSL_CERT_FILE}" ]; then
  cp "${SSL_CERT_FILE}" /usr/local/share/ca-certificates/ironclaw-broker.crt
  update-ca-certificates >/dev/null
fi

if [ "${IRONCLAW_EGRESS_LOCKDOWN:-}" = "broker-only" ]; then
  if [ -z "${IRONCLAW_BROKER_PROXY:-}" ]; then
    echo "IRONCLAW_BROKER_PROXY is required for broker-only lockdown" >&2
    exit 65
  fi

  broker_scheme="$(printf '%s' "${IRONCLAW_BROKER_PROXY}" | sed -E 's#^([a-zA-Z][a-zA-Z0-9+.-]*).*$#\1#')"
  broker_host="$(printf '%s' "${IRONCLAW_BROKER_PROXY}" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:]+).*$#\1#')"
  broker_port="$(printf '%s' "${IRONCLAW_BROKER_PROXY}" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://[^/:]+:([0-9]+).*$#\1#')"
  if [ "${broker_port}" = "${IRONCLAW_BROKER_PROXY}" ]; then
    if [ "${broker_scheme}" = "https" ]; then
      broker_port=443
    else
      broker_port=80
    fi
  fi

  if printf '%s' "${broker_host}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    broker_ips="${broker_host}"
  else
    broker_ips="$(awk -v host="${broker_host}" '
      $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
        for (i = 2; i <= NF; i++) {
          if ($i == host) {
            print $1
          }
        }
      }
    ' /etc/hosts)"
  fi
  if [ -z "${broker_ips}" ]; then
    echo "failed to resolve broker host from static container hosts" >&2
    exit 65
  fi

  iptables -P OUTPUT DROP
  iptables -A OUTPUT -o lo -j ACCEPT
  for broker_ip in ${broker_ips}; do
    iptables -A OUTPUT -p tcp -d "${broker_ip}" --dport "${broker_port}" -j ACCEPT
  done
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
fi

mkdir -p "$HOME" 2>/dev/null || true
[ -d /home/sandbox/.cargo ] && [ ! -d /workspace/.home/.cargo ] && cp -a /home/sandbox/.cargo /workspace/.home/.cargo 2>/dev/null || true
[ -d /home/sandbox/.rustup ] && [ ! -d /workspace/.home/.rustup ] && cp -a /home/sandbox/.rustup /workspace/.home/.rustup 2>/dev/null || true

exec "$@"
