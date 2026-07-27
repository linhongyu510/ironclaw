#!/bin/sh
set -eu

# This entrypoint serves the persistent per-user sandbox
# (`ironclaw_host_runtime::sandbox_process::exec_transport`), which creates
# the container running directly as uid 1000 with a readonly rootfs (see
# Dockerfile.process-sandbox / the W1 root-init-window fix).
#
# Do NOT install a CA via `update-ca-certificates` in this entrypoint: that
# writes into `/usr/local/share/ca-certificates/`, which is on the readonly
# rootfs and unwritable by the non-root uid-1000 user. With `set -eu` above,
# a failed write there aborts the entrypoint and the container never starts
# — we hit exactly this failure mode once already. Any future CA trust
# distribution for this path must arrive as a bind-mounted bundle (system
# roots + our CA) plus env vars pointing at it
# (`SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`/`GIT_SSL_CAINFO`/
# `NODE_EXTRA_CA_CERTS`), never a `cp` + `update-ca-certificates` step here.

mkdir -p "$HOME" 2>/dev/null || true
[ -d /home/sandbox/.cargo ] && [ ! -d /workspace/.home/.cargo ] && cp -a /home/sandbox/.cargo /workspace/.home/.cargo 2>/dev/null || true
[ -d /home/sandbox/.rustup ] && [ ! -d /workspace/.home/.rustup ] && cp -a /home/sandbox/.rustup /workspace/.home/.rustup 2>/dev/null || true

exec "$@"
