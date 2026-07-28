//! Regression gate for the `DiskFilesystem` local backend's fd-rooted
//! traversal fix (`crates/ironclaw_filesystem/src/local.rs` and its
//! `local/fd_resolve.rs` primitive submodule).
//!
//! The bug this fix closed had one shape every vulnerable function shared:
//! resolve a path, check containment against the *resolved path string*,
//! then hand that string to a **separate** syscall that re-resolves it from
//! scratch — reopening a TOCTOU window between the check and the act. The
//! fix replaced every one of those with fd-relative `rustix` syscalls
//! (`openat`/`openat2`/`mkdirat`/`unlinkat`/`renameat`/`fstat`) walked from
//! an already-open, already-verified directory descriptor, so there is no
//! longer a path string for a later syscall to re-resolve.
//!
//! **This is an allowlist, not a denylist**, on purpose. An earlier version
//! of this gate checked for the single literal substring `"tokio::fs::"` —
//! and was proven evadable in one line (`use tokio::fs as sneaky_alias;
//! sneaky_alias::read(path).await` passed vacuously), on top of never
//! catching `std::fs::*`, `std::os::unix::fs::*`, or raw `libc::openat` at
//! all. This repo's *other* architecture gate
//! (`reborn_tls_verification_escape_hatches.rs`) has silently failed to
//! bind four times, always the same shape: a denylist of one spelling of a
//! forbidden pattern, evaded by a different spelling of the same thing.
//! Spelling denylists are exactly the failure mode; an allowlist of the
//! sanctioned primitives is what's actually hard to evade, because it does
//! not matter *how* a forbidden call is spelled or imported — anything that
//! isn't on the allowlist fails the same way.
//!
//! **File scoping.** `local.rs`'s fd-rooted primitive layer was later
//! extracted into `local/fd_resolve.rs` — a module with, by design, zero
//! dependency on `DiskFilesystem`/`LocalMount`, so it has *even less* reason
//! than `local.rs` to ever reach for `tokio::fs` or a second path-based
//! lookup — and its mount-registration layer (`mount_local`,
//! `ensure_scoped_mount`, `resolve_mount_target`, `LocalMount`/
//! `MountTarget`) was later extracted again into `local/mount_registry.rs`
//! once the cross-tenant symlink-escape wiring fix and its fd-growth bound
//! added enough logic to that one area to earn its own file. All three files
//! are gated here, each against the same allowlist; `fd_resolve.rs` has no
//! `#[cfg(test)]` module of its own today, so its entire contents are
//! scanned as production code, while `mount_registry.rs` (like `local.rs`)
//! does have one, so only its production half is scanned (see
//! [`GATED_FILES`]/[`GatedFile`]).
//!
//! Scoped to these two files, not the whole crate: `postgres.rs`/
//! `libsql.rs`/`db/` have no local-filesystem containment surface, and
//! widening the scan would either need per-file exceptions (rot magnet) or
//! a false-positive-prone heuristic. If a future backend gains its own
//! path-based local containment logic, it should get its own narrow gate
//! rather than this one growing broad and brittle.

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(|path| path.to_path_buf())
        .unwrap_or_default()
}

/// Reads the gated file's *full* source, panicking loudly (not silently
/// passing) if the file is missing or unreadable — a gate that can't find
/// its target must never be mistaken for a gate that passed.
fn read_gated_file(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

/// One file this gate polices, and whether it is expected to carry its own
/// `#[cfg(test)]` module.
struct GatedFile {
    relative_path: &'static str,
    has_test_module: bool,
}

const GATED_FILES: &[GatedFile] = &[
    GatedFile {
        relative_path: "crates/ironclaw_filesystem/src/local.rs",
        has_test_module: true,
    },
    GatedFile {
        relative_path: "crates/ironclaw_filesystem/src/local/fd_resolve.rs",
        has_test_module: false,
    },
    GatedFile {
        relative_path: "crates/ironclaw_filesystem/src/local/mount_registry.rs",
        has_test_module: true,
    },
];

/// Returns the production-only slice of `source`: everything before the
/// outer `#[cfg(test)]` module boundary when `has_test_module` is true (test
/// fixture setup legitimately uses `std::fs::create_dir_all` and
/// `std::os::unix::fs::symlink` on the *host* temp directory to construct
/// escape scenarios — nothing to do with the production containment surface
/// this gate exists to police), or the whole file when it is false.
///
/// Fails loud (rather than silently scanning nothing or scanning too much)
/// if `has_test_module` is true but the marker isn't found, since a refactor
/// that removes or renames the test module would otherwise make this split
/// silently meaningless.
fn production_source(source: &str, has_test_module: bool) -> &str {
    const MARKER: &str = "#[cfg(test)]";
    if !has_test_module {
        return source;
    }
    let index = source
        .find(MARKER)
        .unwrap_or_else(|| panic!("expected to find `{MARKER}` marking the test module boundary"));
    &source[..index]
}

/// `std::fs::` function names permitted in production code, each with a
/// documented, checked-at-review-time reason it is not part of the
/// fd-rooted containment surface:
///
/// - `canonicalize`: used exactly once, in `local.rs`'s `mount_local_impl`,
///   which runs only at trusted mount-setup time (synchronous, not on the
///   async per-request path) to resolve the host root a mount is pinned to.
///   There is no request-time path string here for a symlink swap to race.
/// - `File`: `std::fs::File::from(fd)` (in `fd_resolve.rs`) converts an
///   already fd-rooted, already-verified `OwnedFd` into a
///   `std::io::Read`/`Write` handle for the bytes underneath it — it never
///   opens anything by path, so it cannot re-resolve or re-check
///   containment.
///
/// Checked against comment-stripped source (see [`strip_line_comments`]),
/// so doc-comment prose that merely *mentions* a `std::fs::*` name (e.g.
/// contrasting `remove_dir_all_fd` with `std::fs::remove_dir_all`'s
/// equally-recursive, uncapped shape) never has to be allowlisted just to
/// keep the gate green — only a live call counts.
const ALLOWED_STD_FS_FUNCTIONS: &[&str] = &["canonicalize", "File"];

/// The actual gate. Fails loud with a specific reason instead of a single
/// generic message, so a future failure immediately tells the reader which
/// file and which primitive was reintroduced.
fn assert_fd_rooted_allowlist(relative_path: &str, source: &str, has_test_module: bool) {
    let production = production_source(source, has_test_module);
    let production = strip_line_comments(production);
    let production = production.as_str();

    // `tokio::fs` is definitionally the vulnerable pattern: every
    // `tokio::fs::*` entry point takes a path, not a descriptor, and
    // pathname-check-then-separate-syscall is exactly the TOCTOU pattern
    // the fd-rooted traversal fix closed. Ban the substring `"tokio::fs"`
    // (not `"tokio::fs::"`) so this also catches the import line of an
    // aliasing evasion — `use tokio::fs as sneaky_alias;` — even though the
    // alias's own call sites (`sneaky_alias::read(...)`) contain no
    // `tokio::fs` text at all. The import is unconditionally banned because
    // production code never legitimately needs to import `tokio::fs` in
    // either gated file — every operation goes through the `rustix`-backed
    // primitives in `fd_resolve.rs`.
    assert!(
        !production.contains("tokio::fs"),
        "{relative_path} must never reference `tokio::fs` (including an \
         aliased `use tokio::fs as X`) in production code: every \
         tokio::fs::* entry point takes a path string, and re-resolving a \
         path after an earlier containment check is exactly the TOCTOU \
         pattern the fd-rooted traversal fix (openat/openat2 walked from an \
         open root descriptor) closed. Resolve new operations through the \
         existing open_one/resolve_walk/descend_creating primitives \
         instead."
    );

    // `std::os::unix::fs::*` (symlink, symlink_metadata's path-based
    // cousins, etc.) is entirely absent from production code today — every
    // symlink decision here is made against an already-open fd via
    // `rustix::fs::statat`/`AtFlags::SYMLINK_NOFOLLOW`, never by asking the
    // OS to resolve a path a second time. There is no allowlist entry
    // because there is no legitimate production use to allow.
    assert!(
        !production.contains("std::os::unix::fs::"),
        "{relative_path} must never call `std::os::unix::fs::*` in \
         production code — every symlink check here must go through \
         `open_one`'s fd-relative `O_NOFOLLOW`/`openat2` resolution, never a \
         second path-based OS lookup."
    );

    // Raw libc path syscalls bypass rustix's typed wrappers entirely and
    // would not be caught by either check above. `libc` is not even a
    // direct dependency of this crate today; the ban documents that this is
    // deliberate, not an oversight.
    assert!(
        !production.contains("libc::"),
        "{relative_path} must never call raw `libc::*` path syscalls in \
         production code — use the `rustix` wrappers \
         (`openat`/`openat2`/`mkdirat`/`unlinkat`/`renameat`/`statat`/`fstat`) \
         that back every existing primitive in `fd_resolve.rs`."
    );

    // `std::fs::*` is the narrowest, most evadable-by-denylist case of all —
    // it has two legitimate, already-audited uses across these two files
    // (see `ALLOWED_STD_FS_FUNCTIONS`'s doc). Rather than denylisting every
    // other spelling, allowlist the function names actually permitted and
    // fail on anything else.
    for function_name in find_std_fs_function_names(production) {
        assert!(
            ALLOWED_STD_FS_FUNCTIONS.contains(&function_name.as_str()),
            "{relative_path} calls `std::fs::{function_name}` in production \
             code, which is not on this gate's allowlist \
             ({ALLOWED_STD_FS_FUNCTIONS:?}). Every path-based filesystem \
             operation here must resolve through the fd-rooted \
             open_one/resolve_walk/descend_creating primitives instead of a \
             second, independently-resolved std::fs call."
        );
    }
}

/// Strips everything from the first `//` to the end of each line. A
/// deliberately blunt, line-oriented pass (not a full Rust tokenizer) that
/// is sufficient for these two files: neither has a `//` inside a string
/// literal or path today, and the point is only to keep doc-comment prose
/// (which legitimately discusses `tokio::fs`/`std::fs::*` by name when
/// explaining what this module *doesn't* do) from being indistinguishable
/// from a live call to this allowlist scanner.
fn strip_line_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| match line.find("//") {
            Some(index) => &line[..index],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Finds every `std::fs::<identifier>` occurrence in `source` and returns
/// the identifier that follows. A tiny hand-rolled scanner rather than a
/// regex dependency — this crate has no `regex` dev-dependency today and
/// the pattern is simple enough not to need one.
fn find_std_fs_function_names(source: &str) -> Vec<String> {
    const PREFIX: &str = "std::fs::";
    let mut names = Vec::new();
    let mut rest = source;
    while let Some(offset) = rest.find(PREFIX) {
        let after = &rest[offset + PREFIX.len()..];
        let end = after
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        names.push(after[..end].to_string());
        rest = &after[end..];
    }
    names
}

#[test]
fn local_backend_never_reintroduces_banned_path_resolution() {
    for gated in GATED_FILES {
        let source = read_gated_file(gated.relative_path);
        assert_fd_rooted_allowlist(gated.relative_path, &source, gated.has_test_module);
    }
}

// ---------------------------------------------------------------------
// Proof-of-binding: each of these plants exactly the evasion it claims to
// catch into the *real*, already-gate-clean source of a gated file, and
// asserts the gate fails with the expected message. Each takes the real
// file (proving no false positive against production code) and adds one
// violation (proving no false negative against that violation's shape).
// ---------------------------------------------------------------------

/// Inserts `addition` immediately *before* a gated file's outer
/// `#[cfg(test)]` module boundary — i.e. into the production half
/// `production_source` scans — rather than appending to the end of the
/// file, which would land past that boundary (inside the discarded test
/// half) and prove nothing. Shared by every gated file that carries its own
/// test module (`local.rs`, `mount_registry.rs`); `fd_resolve.rs` has none,
/// so its own proof-of-binding test appends directly instead.
fn plant_in_production(relative_path: &str, addition: &str) -> String {
    let source = read_gated_file(relative_path);
    let index = source.find("#[cfg(test)]").unwrap_or_else(|| {
        panic!("expected to find the `#[cfg(test)]` module boundary in {relative_path}")
    });
    let mut planted = String::with_capacity(source.len() + addition.len());
    planted.push_str(&source[..index]);
    planted.push_str(addition);
    planted.push('\n');
    planted.push_str(&source[index..]);
    planted
}

/// `local.rs`-specific alias retained for the existing tests below; equivalent
/// to `plant_in_production("crates/ironclaw_filesystem/src/local.rs", ...)`.
fn plant_in_local_rs_production(addition: &str) -> String {
    plant_in_production("crates/ironclaw_filesystem/src/local.rs", addition)
}

/// The exact evasion the pre-fix gate was proven vulnerable to: aliasing
/// `tokio::fs` on import so no call site spells out `tokio::fs::`.
#[test]
#[should_panic(expected = "must never reference `tokio::fs`")]
fn gate_fails_on_tokio_fs_alias_evasion() {
    let source = plant_in_local_rs_production(
        "\nuse tokio::fs as sneaky_alias;\n\
         async fn planted_alias_regression(path: std::path::PathBuf) -> std::io::Result<Vec<u8>> {\n\
         \x20\x20\x20\x20sneaky_alias::read(path).await\n}\n",
    );
    assert_fd_rooted_allowlist("crates/ironclaw_filesystem/src/local.rs", &source, true);
}

/// The original, unaliased spelling must still be caught too.
#[test]
#[should_panic(expected = "must never reference `tokio::fs`")]
fn gate_fails_on_direct_tokio_fs_call() {
    let source = plant_in_local_rs_production(
        "\nasync fn planted_regression(path: std::path::PathBuf) -> std::io::Result<Vec<u8>> {\n\
         \x20\x20\x20\x20tokio::fs::read(path).await\n}\n",
    );
    assert_fd_rooted_allowlist("crates/ironclaw_filesystem/src/local.rs", &source, true);
}

#[test]
#[should_panic(expected = "must never call `std::os::unix::fs::*`")]
fn gate_fails_on_planted_std_os_unix_fs_call() {
    let source = plant_in_local_rs_production(
        "\nfn planted_regression(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {\n\
         \x20\x20\x20\x20std::os::unix::fs::symlink(target, link)\n}\n",
    );
    assert_fd_rooted_allowlist("crates/ironclaw_filesystem/src/local.rs", &source, true);
}

#[test]
#[should_panic(expected = "must never call raw `libc::*` path syscalls")]
fn gate_fails_on_planted_raw_libc_call() {
    let source = plant_in_local_rs_production(
        "\nunsafe fn planted_regression(dirfd: i32, path: *const i8) -> i32 {\n\
         \x20\x20\x20\x20unsafe { libc::openat(dirfd, path, 0) }\n}\n",
    );
    assert_fd_rooted_allowlist("crates/ironclaw_filesystem/src/local.rs", &source, true);
}

/// `std::fs::*` outside the two allowlisted functions — e.g. a direct,
/// path-based `std::fs::remove_file` reintroduced by a future edit — must
/// fail even though `std::fs::` itself is not universally banned.
#[test]
#[should_panic(expected = "calls `std::fs::remove_file` in production code")]
fn gate_fails_on_planted_disallowed_std_fs_function() {
    let source = plant_in_local_rs_production(
        "\nfn planted_regression(path: &std::path::Path) -> std::io::Result<()> {\n\
         \x20\x20\x20\x20std::fs::remove_file(path)\n}\n",
    );
    assert_fd_rooted_allowlist("crates/ironclaw_filesystem/src/local.rs", &source, true);
}

/// The allowlisted `std::fs::canonicalize`/`std::fs::File` calls that
/// already exist in production code must not themselves trip the gate —
/// otherwise the allowlist would be indistinguishable from a ban that
/// happens to fail closed for the wrong reason.
#[test]
fn gate_does_not_flag_allowlisted_std_fs_calls() {
    for gated in GATED_FILES {
        let source = read_gated_file(gated.relative_path);
        // Would panic (via assert!) if an allowlisted call were rejected;
        // reaching the end of this loop is the assertion.
        assert_fd_rooted_allowlist(gated.relative_path, &source, gated.has_test_module);
    }
}

/// Proves the file-scoping actually extends to `fd_resolve.rs` — not just
/// cosmetically listed in `GATED_FILES` — by planting a `tokio::fs` import
/// directly into it (appended to the end of the file; `fd_resolve.rs` has
/// no `#[cfg(test)]` boundary to land past) and confirming the gate still
/// catches it there.
#[test]
#[should_panic(expected = "must never reference `tokio::fs`")]
fn gate_fails_on_planted_tokio_fs_in_fd_resolve_module() {
    let mut source = read_gated_file("crates/ironclaw_filesystem/src/local/fd_resolve.rs");
    source.push_str(
        "\nasync fn planted_regression(path: std::path::PathBuf) -> std::io::Result<Vec<u8>> {\n\
         \x20\x20\x20\x20tokio::fs::read(path).await\n}\n",
    );
    assert_fd_rooted_allowlist(
        "crates/ironclaw_filesystem/src/local/fd_resolve.rs",
        &source,
        false,
    );
}

/// Proves the file-scoping extends to the newest gated file,
/// `mount_registry.rs` (extracted from `local.rs` for FIX 4) — not just
/// cosmetically listed in `GATED_FILES` — by planting a direct `tokio::fs`
/// call into its production half (before the `#[cfg(test)]` boundary, via
/// [`plant_in_production`], since unlike `fd_resolve.rs` this file does have
/// its own test module) and confirming the gate still catches it there.
#[test]
#[should_panic(expected = "must never reference `tokio::fs`")]
fn gate_fails_on_planted_tokio_fs_in_mount_registry_module() {
    let source = plant_in_production(
        "crates/ironclaw_filesystem/src/local/mount_registry.rs",
        "\nasync fn planted_regression(path: std::path::PathBuf) -> std::io::Result<Vec<u8>> {\n\
         \x20\x20\x20\x20tokio::fs::read(path).await\n}\n",
    );
    assert_fd_rooted_allowlist(
        "crates/ironclaw_filesystem/src/local/mount_registry.rs",
        &source,
        true,
    );
}
