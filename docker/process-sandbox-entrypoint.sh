#!/bin/sh
set -eu

# This entrypoint serves the persistent per-user sandbox
# (`ironclaw_host_runtime::sandbox_process::exec_transport`), which creates
# the container running directly as uid 1000 with a readonly rootfs (see
# Dockerfile.process-sandbox / the W1 root-init-window fix).
#
# PR1 has no egress or CA installation. Future trust distribution must remain
# host-mediated and must not require writes to the readonly root filesystem.

mkdir -p "$HOME" 2>/dev/null || true

exec "$@"
