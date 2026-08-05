//! Standalone binary wrapper around the REAL production
//! [`EgressAllowlistProxy`] (`crates/ironclaw_host_runtime/src/sandbox_process/egress_proxy.rs`),
//! for the docker-real dual-homed isolation topology exercised by
//! `tests/integration/reborn_sandbox_egress_proxy.rs`
//! (`sandbox_egress_proxy_dual_homed_isolation_topology`,
//! `sandbox_egress_proxy_dual_homed_tls_interception`).
//!
//! This is NOT a reimplementation of the proxy: it calls the exact same
//! production factory composition uses
//! ([`bind_sandbox_egress_proxy_with_tls_intercept`]) with a `NetworkPolicy`
//! built from env vars, and `.serve()`s the result unchanged — so every
//! container built from this binary carries the real TLS-interception +
//! CA trust-distribution wiring, not a hand-rolled stand-in. The only thing
//! this binary owns is turning two env vars into a `NetworkPolicy` and a
//! bind address, so it can run as the entrypoint of a small container image
//! built straight from this crate via `cargo build --release --example
//! egress_proxy_standalone`.
//!
//! Env vars:
//! - `EGRESS_PROXY_BIND_ADDR` — address to bind (default `0.0.0.0:8080`).
//! - `EGRESS_PROXY_ALLOWED_HOSTS` — comma-separated allowlisted hostnames
//!   (required; the production default `sandbox_network_policy()` allowlists
//!   real internet hosts like `pypi.org`, which do not exist in the
//!   hermetic dual-network topology this binary serves).
//!
//! Writes the container trust bundle
//! ([`bind_sandbox_egress_proxy_with_tls_intercept`]'s `ca_bundle_pem` — no
//! private key material) to `/ca-bundle.pem` inside this binary's own
//! container before serving, so the test can `docker cp` it out and mount it
//! into the worker container exactly like production's
//! `exec_transport::user_container_launch_config` would.

use ironclaw_host_api::action::{NetworkPolicy, NetworkTargetPattern};
use ironclaw_host_runtime::bind_sandbox_egress_proxy_with_tls_intercept;

/// Host-side path (inside THIS binary's own container) the container trust
/// bundle is written to, for the test harness to `docker cp` out. Not the
/// same as `ironclaw_host_runtime`'s `CONTAINER_CA_BUNDLE_PATH` (that
/// constant is `pub(super)`-private and names where the WORKER container
/// mounts the bundle in production; this binary only ever writes it once,
/// to a path of its own choosing, for the test to retrieve).
const CA_BUNDLE_EXPORT_PATH: &str = "/ca-bundle.pem";

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
    // Standalone example, no Docker/composition wiring available here — runs
    // with no attribution resolver, same as any other no-Docker caller: every
    // intercepted connection's identity resolves to `None`, and the
    // credential firewall fails closed the moment a request carries a
    // placeholder.
    let binding = bind_sandbox_egress_proxy_with_tls_intercept(
        &bind_addr,
        policy,
        None,
        ironclaw_host_runtime::SandboxCredentialRuntime::new(),
    )
    .await
    .expect("egress_proxy_standalone: bind failed");
    std::fs::write(CA_BUNDLE_EXPORT_PATH, &binding.ca_bundle_pem)
        .expect("egress_proxy_standalone: writing the CA bundle export file failed");
    eprintln!(
        "egress_proxy_standalone: bound at {}, CA bundle exported to {CA_BUNDLE_EXPORT_PATH}, serving",
        binding.proxy.local_addr()
    );

    // Never signals shutdown — the container is killed (docker stop/rm) by
    // the test harness rather than shut down gracefully from inside.
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    binding.proxy.serve(shutdown_rx).await;
}
