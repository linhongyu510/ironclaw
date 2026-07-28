//! Regression gate for the `DiskFilesystem` local backend's fd-rooted
//! traversal fix (`crates/ironclaw_filesystem/src/local.rs`).
//!
//! The bug this fix closed had one shape every vulnerable function shared:
//! resolve a path, check containment against the *resolved path string*,
//! then hand that string to a **separate** `tokio::fs::*` syscall (`read`,
//! `OpenOptions::open`, `create_dir_all`, `remove_file`, …) that re-resolves
//! it from scratch — reopening a TOCTOU window between the check and the
//! act. The fix replaced every one of those with fd-relative `rustix`
//! syscalls (`openat`/`openat2`/`mkdirat`/`unlinkat`/`renameat`/`fstat`)
//! walked from an already-open, already-verified directory descriptor, so
//! there is no longer a path string for a later syscall to re-resolve.
//!
//! `tokio::fs::*` is therefore not just *a* smell in this file — it is
//! definitionally the vulnerable pattern, because every `tokio::fs::*`
//! entry point takes a path, not a descriptor. Pinning its absence at zero
//! is a narrow, mechanically-checkable proxy for "no pathname-check-then-
//! separate-syscall reintroduced", without trying to parse call graphs or
//! guess at future variations of the bug.
//!
//! Scoped to this one file, not the whole crate: `postgres.rs`/`libsql.rs`/
//! `db/` have no local-filesystem containment surface, and widening the
//! scan would either need per-file exceptions (rot magnet) or a
//! false-positive-prone heuristic. If a future backend gains its own
//! path-based local containment logic, it should get its own narrow gate
//! rather than this one growing broad and brittle.

use std::path::PathBuf;

fn local_backend_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(|workspace_root| {
            workspace_root
                .join("crates")
                .join("ironclaw_filesystem")
                .join("src")
                .join("local.rs")
        })
        .unwrap_or_default();
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

const VIOLATION_MESSAGE: &str = "crates/ironclaw_filesystem/src/local.rs must never call `tokio::fs::*` again: \
     every `tokio::fs::*` entry point takes a path string, and re-resolving a path \
     after an earlier containment check is exactly the TOCTOU pattern the fd-rooted \
     traversal fix (openat/openat2 walked from an open root descriptor) closed. If \
     you're adding a new local-backend operation, resolve it through the existing \
     `open_one`/`resolve_walk`/`descend_creating` primitives instead.";

/// The actual gate: `source` must contain zero `tokio::fs::*` calls.
fn assert_no_tokio_fs_path_resolution(source: &str) {
    assert!(!source.contains("tokio::fs::"), "{VIOLATION_MESSAGE}");
}

#[test]
fn local_backend_never_reintroduces_tokio_fs_path_based_resolution() {
    assert_no_tokio_fs_path_resolution(&local_backend_source());
}

/// Proves `assert_no_tokio_fs_path_resolution` — the exact function the test
/// above calls against the real file — actually fails on the pattern it
/// exists to catch, rather than passing vacuously. Takes the *real*
/// `local.rs` source (already gate-clean) and reintroduces one planted
/// `tokio::fs::*` call, matching the shape of the original bug
/// (`resolve_existing` handing a checked path to a separate `tokio::fs::read`
/// rather than acting on the fd it already has).
#[test]
#[should_panic(expected = "must never call `tokio::fs::*` again")]
fn gate_fails_on_a_planted_tokio_fs_reintroduction() {
    let mut source = local_backend_source();
    source.push_str(
        "\nasync fn planted_regression(path: PathBuf) -> std::io::Result<Vec<u8>> {\n\
         \x20\x20\x20\x20tokio::fs::read(path).await\n}\n",
    );
    assert_no_tokio_fs_path_resolution(&source);
}
