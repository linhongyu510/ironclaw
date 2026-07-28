# Builds the REAL production `EgressAllowlistProxy`
# (crates/ironclaw_host_runtime/src/sandbox_process/egress_proxy.rs) into a
# standalone container image for the docker-real dual-homed isolation
# topology test (`tests/integration/reborn_sandbox_egress_proxy.rs`).
#
# `rust:latest` matches the host arch under colima (aarch64) so this never
# needs cross-compilation/QEMU emulation.
#
# Build (from repo root):
#   docker build -f docker/sandbox-egress-proxy.Dockerfile -t ironclaw-egress-proxy-standalone:test .

FROM rust:latest AS builder
WORKDIR /work
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/work/target \
    cargo build --release -p ironclaw_host_runtime --example egress_proxy_standalone \
    && cp /work/target/release/examples/egress_proxy_standalone /work/egress_proxy_standalone

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=builder /work/egress_proxy_standalone /usr/local/bin/egress_proxy_standalone
ENTRYPOINT ["/usr/local/bin/egress_proxy_standalone"]
