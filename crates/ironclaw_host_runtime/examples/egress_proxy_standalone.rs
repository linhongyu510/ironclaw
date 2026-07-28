//! Standalone binary wrapper around the REAL production
//! [`EgressAllowlistProxy`] (`crates/ironclaw_host_runtime/src/sandbox_process/egress_proxy.rs`),
//! for the docker-real dual-homed isolation topology exercised by
//! `tests/integration/reborn_sandbox_egress_proxy.rs`
//! (`sandbox_egress_proxy_dual_homed_isolation_topology`).
//!
//! This is NOT a reimplementation of the proxy: it constructs the exact same
//! `EgressAllowlistProxy` / `NetworkPolicy` types composition uses in
//! production and calls `.bind()` / `.serve()` on them unchanged. The only
//! thing this binary owns is turning two env vars into a `NetworkPolicy` and
//! a bind address, so it can run as the entrypoint of a small container image
//! built straight from this crate via `cargo build --release --example
//! egress_proxy_standalone`.
//!
//! Env vars:
//! - `EGRESS_PROXY_BIND_ADDR` — address to bind (default `0.0.0.0:8080`).
//! - `EGRESS_PROXY_ALLOWED_HOSTS` — comma-separated allowlisted hostnames
//!   (required; the production default `sandbox_network_policy()` allowlists
//!   real internet hosts like `pypi.org`, which do not exist in the
//!   hermetic dual-network topology this binary serves).

use ironclaw_host_api::{NetworkPolicy, NetworkTargetPattern};
use ironclaw_host_runtime::EgressAllowlistProxy;

#[tokio::main]
async fn main() {
    let bind_addr =
        std::env::var("EGRESS_PROXY_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let allowed_hosts = std::env::var("EGRESS_PROXY_ALLOWED_HOSTS")
        .expect("EGRESS_PROXY_ALLOWED_HOSTS must be set (comma-separated allowlisted hostnames)");

    let policy = NetworkPolicy {
        allowed_targets: allowed_hosts
            .split(',')
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(|host| NetworkTargetPattern {
                scheme: None,
                host_pattern: host.to_string(),
                port: None,
            })
            .collect(),
        deny_private_ip_ranges: true,
        max_egress_bytes: None,
    };

    eprintln!("egress_proxy_standalone: binding {bind_addr}, allowlist = {allowed_hosts}");
    let bound = EgressAllowlistProxy::new(policy)
        .bind(&bind_addr)
        .await
        .expect("egress_proxy_standalone: bind failed");
    eprintln!(
        "egress_proxy_standalone: bound at {}, serving",
        bound.local_addr()
    );

    // Never signals shutdown — the container is killed (docker stop/rm) by
    // the test harness rather than shut down gracefully from inside.
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    bound.serve(shutdown_rx).await;
}
