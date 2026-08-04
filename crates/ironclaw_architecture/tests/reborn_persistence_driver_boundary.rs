//! Where the PostgreSQL driver is allowed to be named.
//!
//! `deadpool_postgres` is a third-party driver type. PROPOSAL §11.2.6 charters a
//! specific, small set of crates to hold it — the persistence substrates that
//! run SQL, plus the composition root, which is "the one app-layer crate
//! permitted a database driver". §6.3.2 additionally requires
//! `ironclaw_reborn_event_store` to **stop leaking `deadpool_postgres::Pool` in
//! its public API**; that crate owns the TLS/driver cone but its callers should
//! not have to name the driver to use it.
//!
//! Two assertions, because they fail for different reasons: one pins *which
//! crates* may link the driver at all (a shrink-only ratchet), the other pins
//! that event_store's own public surface is driver-free.

#[allow(dead_code)]
mod ratchet_support;

use std::{collections::BTreeSet, process::Command};

use ratchet_support::workspace_root;
use serde_json::Value;

/// Crates permitted a *normal* (non-dev) `deadpool-postgres` dependency.
///
/// Shrink-only. Adding a crate here means a new part of the tree links a
/// database driver, which is the thing §11.2.6 constrains — that is a design
/// decision, not a build fix, and it should be argued in review rather than
/// discovered later. Removing one is always fine.
///
/// Dev-dependencies are deliberately unconstrained: a test that stands up a
/// real Postgres pool to exercise a contract is not the driver spreading into
/// production build graphs.
const DRIVER_LINKED_CRATES: &[&str] = &[
    // Substrates that execute SQL directly.
    "ironclaw_auth",
    "ironclaw_filesystem",
    "ironclaw_hooks",
    "ironclaw_host_runtime",
    "ironclaw_triggers",
    // Owns the TLS/driver cone for durable event/audit logs (§6.3.2).
    "ironclaw_reborn_event_store",
    // The assembly root: opens each database once and wires the shared runtime
    // (§11.2.6). The one app-layer crate permitted a driver.
    "ironclaw_reborn_composition",
    // Diagnostic binary, excluded from default work.
    "ironclaw_stress",
];

#[test]
fn only_chartered_crates_link_the_postgres_driver() {
    let actual = normal_dependents_of("deadpool-postgres");
    let allowed: BTreeSet<String> = DRIVER_LINKED_CRATES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let added: Vec<_> = actual.difference(&allowed).cloned().collect();
    assert!(
        added.is_empty(),
        "these crates gained a normal `deadpool-postgres` dependency without being \
         chartered for a database driver (PROPOSAL §11.2.6): {added:?}. If that is \
         intended, add them to DRIVER_LINKED_CRATES with the reason — this list is \
         shrink-only on purpose."
    );

    let removed: Vec<_> = allowed.difference(&actual).cloned().collect();
    assert!(
        removed.is_empty(),
        "these crates no longer link `deadpool-postgres`: {removed:?}. That is good \
         news — drop them from DRIVER_LINKED_CRATES so the list keeps ratcheting down \
         instead of quietly permitting a re-add."
    );
}

/// §6.3.2: "stop leaking `deadpool_postgres::Pool` in the public API (wrap)".
///
/// The driver may still be *used* — this crate builds the pool and owns the TLS
/// policy — but only inside the private `postgres_backed` module. Anything
/// above it in the file is public surface, and naming the driver there puts a
/// third-party type in every caller's signature.
#[test]
fn event_store_names_the_driver_only_inside_its_private_backend_module() {
    let path = workspace_root().join("crates/ironclaw_reborn_event_store/src/lib.rs");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("readable event store lib.rs {path:?}: {error}"));
    let lines: Vec<&str> = source.lines().collect();

    let module_start = lines
        .iter()
        .position(|line| line.trim_start().starts_with("mod postgres_backed {"))
        .expect(
            "expected a private `mod postgres_backed {` in event store lib.rs — if the \
             backend module was renamed or split, update this gate rather than deleting it",
        );

    // A `pub mod` would make everything below it public surface too, which
    // would silently defeat the assertion beneath.
    assert!(
        !lines[module_start].trim_start().starts_with("pub "),
        "`postgres_backed` must stay private; a `pub mod` re-exports the driver cone \
         it exists to contain"
    );

    let leaks: Vec<String> = lines
        .iter()
        .enumerate()
        .take(module_start)
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && line.contains("deadpool_postgres")
        })
        .map(|(index, line)| format!("  lib.rs:{}: {}", index + 1, line.trim()))
        .collect();

    assert!(
        leaks.is_empty(),
        "`ironclaw_reborn_event_store` names `deadpool_postgres` in its public surface \
         (above the private `postgres_backed` module). Callers should receive \
         `ironclaw_filesystem::PostgresConnectionPool` instead — the driver cone belongs \
         to this crate and the filesystem substrate, not to their signatures (PROPOSAL \
         §6.3.2). Offending lines:\n{}",
        leaks.join("\n")
    );
}

/// Every crate with a normal (non-dev) dependency on `name`.
fn normal_dependents_of(name: &str) -> BTreeSet<String> {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(workspace_root())
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata emits valid JSON");
    let packages = metadata["packages"]
        .as_array()
        .expect("cargo metadata has a packages array");
    assert!(
        !packages.is_empty(),
        "cargo metadata returned no packages; this scan would vacuously pass"
    );

    packages
        .iter()
        .filter(|package| {
            package["dependencies"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|dependency| {
                    dependency["name"].as_str() == Some(name)
                        // `kind` is null for a normal dependency, "dev"/"build" otherwise.
                        && dependency.get("kind").and_then(Value::as_str).is_none()
                })
        })
        .filter_map(|package| package["name"].as_str().map(ToString::to_string))
        .collect()
}
