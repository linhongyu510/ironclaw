//! Regression gate for the `DiskFilesystem` local backend's fd-rooted
//! traversal fix (`crates/ironclaw_filesystem/src/local.rs`).
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
//! Scoped to the fd-rooted primitive module (`local.rs`), not the whole
//! crate: `postgres.rs`/`libsql.rs`/`db/` have no local-filesystem
//! containment surface, and widening the scan would either need per-file
//! exceptions (rot magnet) or a false-positive-prone heuristic. If a future
//! backend gains its own path-based local containment logic, it should get
//! its own narrow gate rather than this one growing broad and brittle.

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

/// Splits `source` into (production, test) at the file's outer
/// `#[cfg(test)]` module boundary, so the allowlist below is enforced only
/// against the fd-rooted resolution code that ships — not against test
/// fixture setup, which legitimately uses `std::fs::create_dir_all` and
/// `std::os::unix::fs::symlink` on the *host* temp directory to construct
/// escape scenarios, nothing to do with the production containment surface
/// this gate exists to police.
///
/// Fails loud (rather than silently scanning nothing or scanning
/// everything) if the marker isn't found, since a refactor that removes or
/// renames the test module would otherwise make this split silently
/// meaningless.
fn split_production_and_test(source: &str) -> (&str, &str) {
    const MARKER: &str = "#[cfg(test)]";
    let index = source
        .find(MARKER)
        .unwrap_or_else(|| panic!("expected to find `{MARKER}` marking the test module boundary"));
    (&source[..index], &source[index..])
}

/// `std::fs::` function names permitted in production code, each with a
/// documented, checked-at-review-time reason it is not part of the
/// fd-rooted containment surface:
///
/// - `canonicalize`: used exactly once, in `mount_local_impl`, which runs
///   only at trusted mount-setup time (synchronous, not on the async
///   per-request path) to resolve the host root a mount is pinned to. There
///   is no request-time path string here for a symlink swap to race.
/// - `File`: `std::fs::File::from(fd)` converts an already fd-rooted,
///   already-verified `OwnedFd` into a `std::io::Read`/`Write` handle for
///   the bytes underneath it — it never opens anything by path, so it
///   cannot re-resolve or re-check containment.
///
/// Checked against comment-stripped source (see [`strip_line_comments`]),
/// so doc-comment prose that merely *mentions* a `std::fs::*` name (e.g.
/// contrasting `remove_dir_all_fd` with `std::fs::remove_dir_all`'s
/// equally-recursive, uncapped shape) never has to be allowlisted just to
/// keep the gate green — only a live call counts.
const ALLOWED_STD_FS_FUNCTIONS: &[&str] = &["canonicalize", "File"];

/// The actual gate. Fails loud with a specific reason instead of a single
/// generic message, so a future failure immediately tells the reader which
/// primitive was reintroduced.
fn assert_fd_rooted_allowlist(source: &str) {
    let (production, _test) = split_production_and_test(source);
    let production = strip_line_comments(production);
    let production = production.as_str();

    // `tokio::fs` is definitionally the vulnerable pattern: every
    // `tokio::fs::*` entry point takes a path, not a descriptor, and
    // pathname-check-then-separate-syscall is exactly the bug this file
    // exists to never reintroduce. Ban the substring `"tokio::fs"` (not
    // `"tokio::fs::"`) so this also catches the import line of an
    // aliasing evasion — `use tokio::fs as sneaky_alias;` — even though the
    // alias's own call sites (`sneaky_alias::read(...)`) contain no
    // `tokio::fs` text at all. The import is unconditionally banned because
    // production code never legitimately needs to import `tokio::fs` in
    // this file — every operation goes through the `rustix`-backed
    // primitives below.
    assert!(
        !production.contains("tokio::fs"),
        "crates/ironclaw_filesystem/src/local.rs must never reference `tokio::fs` \
         (including an aliased `use tokio::fs as X`) in production code: every \
         tokio::fs::* entry point takes a path string, and re-resolving a path \
         after an earlier containment check is exactly the TOCTOU pattern the \
         fd-rooted traversal fix (openat/openat2 walked from an open root \
         descriptor) closed. Resolve new operations through the existing \
         open_one/resolve_walk/descend_creating primitives instead."
    );

    // `std::os::unix::fs::*` (symlink, symlink_metadata's path-based
    // cousins, etc.) is entirely absent from production code today — every
    // symlink decision in this file is made against an already-open fd via
    // `rustix::fs::statat`/`AtFlags::SYMLINK_NOFOLLOW`, never by asking the
    // OS to resolve a path a second time. There is no allowlist entry
    // because there is no legitimate production use to allow.
    assert!(
        !production.contains("std::os::unix::fs::"),
        "crates/ironclaw_filesystem/src/local.rs must never call \
         `std::os::unix::fs::*` in production code — every symlink check here \
         must go through `open_one`'s fd-relative `O_NOFOLLOW`/`openat2` \
         resolution, never a second path-based OS lookup."
    );

    // Raw libc path syscalls bypass rustix's typed wrappers entirely and
    // would not be caught by either check above. `libc` is not even a
    // direct dependency of this crate today; the ban documents that this is
    // deliberate, not an oversight.
    assert!(
        !production.contains("libc::"),
        "crates/ironclaw_filesystem/src/local.rs must never call raw `libc::*` \
         path syscalls in production code — use the `rustix` wrappers \
         (`openat`/`openat2`/`mkdirat`/`unlinkat`/`renameat`/`statat`/`fstat`) \
         that back every existing primitive in this file."
    );

    // `std::fs::*` is the narrowest, most evadable-by-denylist case of all —
    // it has two legitimate, already-audited uses in this file (see
    // `ALLOWED_STD_FS_FUNCTIONS`'s doc). Rather than denylisting every other
    // spelling, allowlist the function names actually permitted and fail on
    // anything else.
    for function_name in find_std_fs_function_names(production) {
        assert!(
            ALLOWED_STD_FS_FUNCTIONS.contains(&function_name.as_str()),
            "crates/ironclaw_filesystem/src/local.rs calls `std::fs::{function_name}` \
             in production code, which is not on this gate's allowlist \
             ({ALLOWED_STD_FS_FUNCTIONS:?}). Every path-based filesystem \
             operation here must resolve through the fd-rooted \
             open_one/resolve_walk/descend_creating primitives instead of a \
             second, independently-resolved std::fs call."
        );
    }
}

/// Strips everything from the first `//` to the end of each line. A
/// deliberately blunt, line-oriented pass (not a full Rust tokenizer) that
/// is sufficient for this file: `local.rs` has no `//` inside a string
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
    assert_fd_rooted_allowlist(&read_gated_file("crates/ironclaw_filesystem/src/local.rs"));
}

// ---------------------------------------------------------------------
// Proof-of-binding: each of these plants exactly the evasion it claims to
// catch into the *real*, already-gate-clean local.rs source, and asserts
// the gate fails with the expected message. Each takes the real file
// (proving no false positive against production code) and appends one
// violation (proving no false negative against that violation's shape).
// ---------------------------------------------------------------------

/// Inserts `addition` immediately *before* the outer `#[cfg(test)]` module
/// boundary — i.e. into the production half `split_production_and_test`
/// scans — rather than appending to the end of the file, which would land
/// past that boundary (inside the discarded test half) and prove nothing.
fn plant_in_production(addition: &str) -> String {
    let source = read_gated_file("crates/ironclaw_filesystem/src/local.rs");
    let index = source
        .find("#[cfg(test)]")
        .expect("expected to find the `#[cfg(test)]` module boundary in local.rs");
    let mut planted = String::with_capacity(source.len() + addition.len());
    planted.push_str(&source[..index]);
    planted.push_str(addition);
    planted.push('\n');
    planted.push_str(&source[index..]);
    planted
}

fn production_source_for_planting() -> String {
    read_gated_file("crates/ironclaw_filesystem/src/local.rs")
}

/// The exact evasion the pre-fix gate was proven vulnerable to: aliasing
/// `tokio::fs` on import so no call site spells out `tokio::fs::`.
#[test]
#[should_panic(expected = "must never reference `tokio::fs`")]
fn gate_fails_on_tokio_fs_alias_evasion() {
    let source = plant_in_production(
        "\nuse tokio::fs as sneaky_alias;\n\
         async fn planted_alias_regression(path: std::path::PathBuf) -> std::io::Result<Vec<u8>> {\n\
         \x20\x20\x20\x20sneaky_alias::read(path).await\n}\n",
    );
    assert_fd_rooted_allowlist(&source);
}

/// The original, unaliased spelling must still be caught too.
#[test]
#[should_panic(expected = "must never reference `tokio::fs`")]
fn gate_fails_on_direct_tokio_fs_call() {
    let source = plant_in_production(
        "\nasync fn planted_regression(path: std::path::PathBuf) -> std::io::Result<Vec<u8>> {\n\
         \x20\x20\x20\x20tokio::fs::read(path).await\n}\n",
    );
    assert_fd_rooted_allowlist(&source);
}

#[test]
#[should_panic(expected = "must never call `std::os::unix::fs::*`")]
fn gate_fails_on_planted_std_os_unix_fs_call() {
    let source = plant_in_production(
        "\nfn planted_regression(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {\n\
         \x20\x20\x20\x20std::os::unix::fs::symlink(target, link)\n}\n",
    );
    assert_fd_rooted_allowlist(&source);
}

#[test]
#[should_panic(expected = "must never call raw `libc::*` path syscalls")]
fn gate_fails_on_planted_raw_libc_call() {
    let source = plant_in_production(
        "\nunsafe fn planted_regression(dirfd: i32, path: *const i8) -> i32 {\n\
         \x20\x20\x20\x20unsafe { libc::openat(dirfd, path, 0) }\n}\n",
    );
    assert_fd_rooted_allowlist(&source);
}

/// `std::fs::*` outside the two allowlisted functions — e.g. a direct,
/// path-based `std::fs::remove_file` reintroduced by a future edit — must
/// fail even though `std::fs::` itself is not universally banned.
#[test]
#[should_panic(expected = "calls `std::fs::remove_file` in production code")]
fn gate_fails_on_planted_disallowed_std_fs_function() {
    let source = plant_in_production(
        "\nfn planted_regression(path: &std::path::Path) -> std::io::Result<()> {\n\
         \x20\x20\x20\x20std::fs::remove_file(path)\n}\n",
    );
    assert_fd_rooted_allowlist(&source);
}

/// The allowlisted `std::fs::canonicalize`/`std::fs::File` calls that
/// already exist in production code must not themselves trip the gate —
/// otherwise the allowlist would be indistinguishable from a ban that
/// happens to fail closed for the wrong reason.
#[test]
fn gate_does_not_flag_allowlisted_std_fs_calls() {
    let source = production_source_for_planting();
    // Would panic (via assert!) if either allowlisted call were rejected;
    // reaching the end of this function is the assertion.
    assert_fd_rooted_allowlist(&source);
}
