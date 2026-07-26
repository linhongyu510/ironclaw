#!/bin/sh
set -eu

# NOTE on the two consumers sharing this image/entrypoint: both the
# CA-install and iptables branches below belong solely to
# `ironclaw_process_sandbox::docker::DockerProcessSandboxBackend`'s
# brokered-run mode (crates/ironclaw_process_sandbox/src/docker.rs:437-469,
# exercised by its own tests.rs:449-510) — the only consumer that sets
# `IRONCLAW_EGRESS_LOCKDOWN=broker-only`. `include_broker_ca()` and
# `needs_net_admin()` both alias `brokered_run()`, and `network_args()` sets
# the lockdown env under that same `brokered_run()`, so any caller that sets
# `SSL_CERT_FILE` via this path always sets the lockdown flag too — hence
# both branches are gated on the *same* flag here, not on `SSL_CERT_FILE`
# alone. That consumer has no production constructor (test-only) and already
# needs root + NET_ADMIN, so it is unaffected by the persistent path's move
# to a non-root init.
#
# The persistent per-user sandbox
# (`ironclaw_host_runtime::sandbox_process::exec_transport`) never sets
# IRONCLAW_EGRESS_LOCKDOWN and creates the container running directly as uid
# 1000 with a readonly rootfs (see Dockerfile.process-sandbox / the W1
# root-init-window fix), so gating the CA branch on the lockdown flag is
# required, not just documentation: that path's planned CA trust
# distribution (bind-mounting `system_roots + our_CA` and pointing
# `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`/`GIT_SSL_CAINFO`/
# `NODE_EXTRA_CA_CERTS` at it) sets `SSL_CERT_FILE` without the lockdown
# flag. If the CA branch fired on `SSL_CERT_FILE` alone, that `cp` into
# `/usr/local/share/ca-certificates/` would hit the readonly rootfs as a
# non-root user and fail; with `set -eu` above, that aborts the entrypoint
# and the container never starts. Do NOT install a CA via
# `update-ca-certificates` on the persistent path for this reason — any
# future trust distribution there must arrive as a bind-mounted bundle plus
# env vars, exactly as `DockerProcessSandboxBackend` already does.
if [ "${IRONCLAW_EGRESS_LOCKDOWN:-}" = "broker-only" ]; then
  if [ -n "${SSL_CERT_FILE:-}" ] && [ -f "${SSL_CERT_FILE}" ]; then
    cp "${SSL_CERT_FILE}" /usr/local/share/ca-certificates/ironclaw-broker.crt
    update-ca-certificates >/dev/null
  fi

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
