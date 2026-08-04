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
/// policy — but only inside the private `postgres_backed` module. Anywhere else
/// in the crate is reachable from its public surface, and naming the driver
/// there puts a third-party type into callers' signatures.
///
/// Scans **every** `.rs` file in the crate minus that one module *body*. An
/// earlier version scanned only `lib.rs` up to the module header, which left
/// two blind spots that made the gate weaker than its own docs claimed: items
/// *after* the module body, and every sibling file (`coalescing_sink.rs`,
/// `durable_log.rs`).
#[test]
fn event_store_names_the_driver_only_inside_its_private_backend_module() {
    let src = workspace_root().join("crates/ironclaw_reborn_event_store/src");
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&src)
        .unwrap_or_else(|error| panic!("readable event store src {src:?}: {error}"))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("readable entry under {src:?}: {error}"))
                .path()
        })
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .collect();
    files.sort();
    assert!(
        files.len() >= 2,
        "expected several source files in {src:?}, saw {} — this scan cannot be trusted",
        files.len()
    );

    let mut leaks = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("readable source {path:?}: {error}"));
        let exempt = private_backend_module_body(&source, path);
        for (index, line) in source.lines().enumerate() {
            if line.trim_start().starts_with("//") || !line.contains("deadpool_postgres") {
                continue;
            }
            if exempt.as_ref().is_some_and(|range| range.contains(&index)) {
                continue;
            }
            leaks.push(format!(
                "  {}:{}: {}",
                path.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
                index + 1,
                line.trim()
            ));
        }
    }

    assert!(
        leaks.is_empty(),
        "`ironclaw_reborn_event_store` names `deadpool_postgres` outside its private \
         `postgres_backed` module body. Callers should receive \
         `ironclaw_filesystem::PostgresConnectionPool` instead — the driver cone belongs \
         to this crate and the filesystem substrate, not to their signatures (PROPOSAL \
         §6.3.2). Offending lines:\n{}",
        leaks.join("\n")
    );
}

/// Line range of the private `postgres_backed` module *body*, if `source`
/// declares one. `None` when the file has no such module.
///
/// Brace-matched rather than delimited by the next `}` at some indentation, and
/// trivia-aware (line comments, nestable block comments, strings, raw strings,
/// char literals) so a brace inside a literal cannot end the body early — which
/// would silently re-expose part of the module to the scan, or hide part of the
/// file from it.
fn private_backend_module_body(
    source: &str,
    path: &std::path::Path,
) -> Option<std::ops::Range<usize>> {
    let lines: Vec<&str> = source.lines().collect();
    let header = lines
        .iter()
        .position(|line| line.trim_start().starts_with("mod postgres_backed {"))?;
    assert!(
        !lines[header].trim_start().starts_with("pub "),
        "{path:?}: `postgres_backed` must stay private; a `pub mod` re-exports the \
         driver cone it exists to contain"
    );

    let mut depth = 0usize;
    let mut in_block_comment = 0usize;
    for (offset, line) in lines.iter().enumerate().skip(header) {
        let bytes = line.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let rest = &bytes[i..];
            if in_block_comment > 0 {
                if rest.starts_with(b"/*") {
                    in_block_comment += 1;
                    i += 2;
                } else if rest.starts_with(b"*/") {
                    in_block_comment -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if rest.starts_with(b"//") {
                break;
            }
            if rest.starts_with(b"/*") {
                in_block_comment = 1;
                i += 2;
                continue;
            }
            if bytes[i] == b'r' {
                let mut hashes = 0usize;
                while bytes.get(i + 1 + hashes) == Some(&b'#') {
                    hashes += 1;
                }
                if bytes.get(i + 1 + hashes) == Some(&b'"') {
                    let terminator = format!("\"{}", "#".repeat(hashes));
                    let body = i + 2 + hashes;
                    match line[body..].find(&terminator) {
                        Some(n) => i = body + n + terminator.len(),
                        None => break,
                    }
                    continue;
                }
            }
            if bytes[i] == b'"' {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
                continue;
            }
            if bytes[i] == b'\'' {
                let escaped = bytes.get(i + 1) == Some(&b'\\');
                let close = if escaped { i + 3 } else { i + 2 };
                if bytes.get(close) == Some(&b'\'') {
                    i = close + 1;
                    continue;
                }
            }
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(header..offset + 1);
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
    panic!("{path:?}: unterminated `mod postgres_backed` body");
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

#[cfg(test)]
mod backend_module_body_tests {
    use super::private_backend_module_body;
    use std::path::Path;

    fn body(source: &str) -> Option<std::ops::Range<usize>> {
        private_backend_module_body(source, Path::new("fixture.rs"))
    }

    /// A driver mention *inside* the body is permitted — that is the whole
    /// point of keeping the cone somewhere.
    #[test]
    fn a_mention_inside_the_body_is_within_the_exempt_range() {
        let source = "pub fn a() {}\nmod postgres_backed {\n    use deadpool_postgres::Pool;\n}\n";
        let range = body(source).expect("module found");
        assert!(range.contains(&2), "line 3 (index 2) is inside the body");
    }

    /// The regression: an item *after* the body used to be invisible, because
    /// the old scan stopped at the module header.
    #[test]
    fn a_mention_after_the_body_is_outside_the_exempt_range() {
        let source = "mod postgres_backed {\n    fn inner() {}\n}\npub fn leak(p: deadpool_postgres::Pool) {}\n";
        let range = body(source).expect("module found");
        assert!(
            !range.contains(&3),
            "line 4 (index 3) is after the body and must be scanned"
        );
    }

    /// A brace inside a string literal must not close the body early — that
    /// would drag the rest of the file into the exempt range.
    #[test]
    fn a_brace_in_a_literal_does_not_end_the_body() {
        let source = "mod postgres_backed {\n    const A: &str = \"}\";\n    fn inner() {}\n}\npub fn leak(p: deadpool_postgres::Pool) {}\n";
        let range = body(source).expect("module found");
        assert_eq!(range, 0..4, "body must end at the real closing brace");
    }

    #[test]
    fn a_file_without_the_module_has_no_exempt_range() {
        assert!(body("pub fn a() {}\n").is_none());
    }
}
