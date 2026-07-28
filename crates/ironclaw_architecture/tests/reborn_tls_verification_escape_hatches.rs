//! Zero-occurrence gate for TLS-verification escape hatches in the sandbox
//! egress proxy's TLS-interception seam (W6 phase 1, design doc
//! `docs/plans/2026-07-26-sandbox-credential-firewall-design.md` §4).
//!
//! `sandbox_process::tls_intercept::TlsInterceptConfig::origin_connector` is
//! what the proxy uses to verify the origin it re-originates TLS to, on
//! behalf of a sandboxed container that is deliberately never given the
//! real credential. If a production caller ever builds that connector with
//! `rustls::ClientConfig::dangerous()`, a custom `ServerCertVerifier` that
//! skips verification, or an empty `RootCertStore`, the interception seam
//! stops being a credential firewall and becomes a working, silent MITM
//! against our own users' egress traffic to every bound host.
//!
//! `VerifiedOriginConnector` (`sandbox_process::tls_intercept`) makes this
//! type-enforced: its only production constructor,
//! `VerifiedOriginConnector::from_system_roots`, builds from the platform's
//! real trust anchors and fails closed on an empty store; the escape hatch
//! (`VerifiedOriginConnector::for_test`) is `#[cfg(test)]` only. This test
//! is the second half of that guarantee — it pins the escape-hatch spellings
//! at **zero occurrences** in non-test code under `sandbox_process/`, so a
//! future caller cannot route *around* `VerifiedOriginConnector` and
//! hand-roll a permissive connector directly against `rustls` instead.
//!
//! **Test code is legitimately exempt.** `tls_intercept`'s own tests build
//! deliberately-empty and deliberately-single-root connectors
//! (`connector_trusting_nothing`, `connector_trusting_only`) to force the
//! fail-closed path deterministically — that is correct test behavior, not
//! the bug this gate exists to catch. The scan below excludes standalone
//! `tests.rs` files and truncates any file at its own `#[cfg(test)] mod
//! tests` marker, scanning only what precedes it.
//!
//! **Comments are exempt too**, same rule and same rationale as
//! `reborn_retired_failure_vocabulary.rs`: this module's own doc comments
//! (including this one) explain the ban by naming the exact escape-hatch
//! spellings, and prose explaining what is banned is worth keeping — only
//! live code is policed.
//!
//! **One sanctioned call site.** `RootCertStore::empty()` is also the
//! correct, ordinary way to *start* building any root store — including the
//! real one `VerifiedOriginConnector::from_system_roots` populates from the
//! platform's native certs before ever handing it to a `ClientConfig`. That
//! single, already-reviewed call site is scoped out by function body, not by
//! file — every other line in `sandbox_process/`, including everywhere else
//! in this same file, is still policed at zero, and `dangerous(`/
//! `with_custom_certificate_verifier` are never sanctioned anywhere, not
//! even inside `from_system_roots`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Escape-hatch spellings that would turn `origin_connector` permissive.
/// Any hit in non-test `sandbox_process/` code is a regression against the
/// invariant `VerifiedOriginConnector` exists to make unrepresentable.
const BANNED_PATTERNS: &[&str] = &[
    "dangerous(",
    "with_custom_certificate_verifier",
    "RootCertStore::empty()",
];

fn workspace_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/ironclaw_architecture -> crates -> workspace root
    path.pop();
    path.pop();
    path
}

fn sandbox_process_dir(root: &Path) -> PathBuf {
    root.join("crates/ironclaw_host_runtime/src/sandbox_process")
}

/// Blank out comment spans so prose about the banned spellings (this
/// module's own doc comments, and `tls_intercept`'s `# WARNING` block) stays
/// legal while code that actually calls them does not. Same algorithm as
/// `reborn_retired_failure_vocabulary.rs::strip_comments` — handles `//`
/// line comments and nested `/* … */` block comments, preserving line
/// numbers by replacing stripped bytes with spaces rather than deleting them.
fn strip_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut index = 0usize;
    let mut depth = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if depth > 0 {
            if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
                depth += 1;
                out.push(' ');
                out.push(' ');
                index += 2;
                continue;
            }
            if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                depth -= 1;
                out.push(' ');
                out.push(' ');
                index += 2;
                continue;
            }
            out.push(if byte == b'\n' { '\n' } else { ' ' });
            index += 1;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            depth = 1;
            out.push(' ');
            out.push(' ');
            index += 2;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                out.push(' ');
                index += 1;
            }
            continue;
        }
        out.push(byte as char);
        index += 1;
    }
    out
}

/// A standalone test file (`ca/tests.rs`, `credential_firewall/tests.rs`) is
/// pure test code end to end — excluded wholesale rather than line-scanned.
fn is_standalone_test_file(relative: &str) -> bool {
    relative.ends_with("/tests.rs") || relative.ends_with("\\tests.rs")
}

/// Files in this crate keep their `#[cfg(test)] mod tests { ... }` at the
/// end of the file (verified for every file under `sandbox_process/` that
/// declares one). Truncating the scan at that marker — rather than trying
/// to track brace depth — keeps the scan simple while still only policing
/// production code: everything from the marker onward is test-only, so
/// dropping it can only ever *hide* a hit inside `mod tests`, never invent
/// one in production code.
fn truncate_at_inline_test_module(contents: &str) -> &str {
    let mut previous_was_cfg_test = false;
    let mut offset = 0usize;
    for line in contents.lines() {
        let trimmed = line.trim();
        if previous_was_cfg_test && trimmed.starts_with("mod tests") {
            return &contents[..offset];
        }
        previous_was_cfg_test = trimmed == "#[cfg(test)]";
        // +1 for the '\n' the `lines()` iterator strips.
        offset += line.len() + 1;
    }
    contents
}

/// The line numbers (1-indexed, into `code_only`) covered by
/// `VerifiedOriginConnector::from_system_roots`'s body — the one place
/// `RootCertStore::empty()` is sanctioned (see the module doc's "one
/// sanctioned call site"). Only meaningful for `tls_intercept.rs`; callers
/// pass an empty set for every other file.
///
/// Uses simple brace-depth tracking from the `fn from_system_roots` line to
/// wherever that depth returns to zero. `code_only` has already had comments
/// blanked out, and the only braces inside the real function body are
/// balanced on the same line as the format strings that contain them (e.g.
/// `"...: {error}"`), so naive per-character counting does not desync.
fn sanctioned_from_system_roots_lines(relative: &str, code_only: &str) -> HashSet<usize> {
    let mut sanctioned = HashSet::new();
    if !relative.ends_with("sandbox_process/tls_intercept.rs") {
        return sanctioned;
    }
    let mut depth: i64 = 0;
    let mut inside = false;
    for (number, line) in code_only.lines().enumerate() {
        if !inside {
            if line.contains("fn from_system_roots") {
                inside = true;
            } else {
                continue;
            }
        }
        sanctioned.insert(number + 1);
        for byte in line.bytes() {
            match byte {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
        }
        if inside && depth <= 0 && line.contains('}') {
            break;
        }
    }
    sanctioned
}

fn scan_dir(root: &Path, dir: &Path, hits: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_dir(root, &path, hits);
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".rs") {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if is_standalone_test_file(&relative) {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let production_only = truncate_at_inline_test_module(&contents);
        let code_only = strip_comments(production_only);
        let sanctioned_lines = sanctioned_from_system_roots_lines(&relative, &code_only);
        for (number, line) in code_only.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            for pattern in BANNED_PATTERNS {
                if !line.contains(pattern) {
                    continue;
                }
                if *pattern == "RootCertStore::empty()" && sanctioned_lines.contains(&(number + 1))
                {
                    continue;
                }
                hits.push(format!("{relative}:{}: `{pattern}`", number + 1));
            }
        }
    }
}

#[test]
fn sandbox_process_never_hand_rolls_a_permissive_origin_connector() {
    let root = workspace_root();
    let mut hits = Vec::new();
    scan_dir(&root, &sandbox_process_dir(&root), &mut hits);
    hits.sort();
    hits.dedup();
    assert!(
        hits.is_empty(),
        "a TLS-verification escape hatch appeared in production sandbox_process/ \
         code. `origin_connector` re-originates TLS to the real upstream on \
         behalf of a sandboxed container that is deliberately never given the \
         real credential — a permissive connector here turns the interception \
         seam into a working, silent MITM against our own users. Build the \
         connector through `tls_intercept::VerifiedOriginConnector::from_system_roots` \
         instead (test code may still use `VerifiedOriginConnector::for_test` \
         and deliberately-empty/single-root connectors under `#[cfg(test)]`):\n{}",
        hits.join("\n")
    );
}

/// Proves the test-code exclusion is real, not just claimed: `tls_intercept`'s
/// own `connector_trusting_nothing` test helper — pure test code, unique to
/// `mod tests` — must disappear once the scan truncates at the inline test
/// module marker. (`RootCertStore::empty()` itself is *not* a safe marker
/// for this any more: `VerifiedOriginConnector::from_system_roots`, real
/// production code, legitimately calls it too — see the module doc's "one
/// sanctioned call site" — so this test pins truncation against a marker
/// that only ever appears in test code.) If this assertion ever fails, the
/// gate above is either scanning test code (false positives waiting to
/// force someone to weaken it) or not truncating correctly.
#[test]
fn the_scan_exempts_tls_intercepts_own_test_module() {
    let root = workspace_root();
    let path = sandbox_process_dir(&root).join("tls_intercept.rs");
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert!(
        contents.contains("fn connector_trusting_nothing"),
        "expected tls_intercept.rs's own tests to still define \
         `connector_trusting_nothing` — if this changed, this test needs a \
         different test-only fixture, not deletion"
    );
    let production_only = truncate_at_inline_test_module(&contents);
    assert!(
        !production_only.contains("connector_trusting_nothing"),
        "truncate_at_inline_test_module let test-only content leak into the \
         scanned production prefix"
    );
}

/// Proves the sanctioned-call-site carve-out is scoped to
/// `from_system_roots`'s own body, not the whole file: `tls_intercept.rs`
/// production code has exactly one `RootCertStore::empty()` call (inside
/// `from_system_roots`) and the scan above must report zero hits for it —
/// but the carve-out must not swallow a *different* line elsewhere in
/// production code. Regression-tests the exact bug the ratchet had before
/// this scoping existed: a file-wide exemption would have let a second,
/// unrelated `RootCertStore::empty()` call through unnoticed anywhere else
/// in this file.
#[test]
fn sanctioned_call_site_is_scoped_to_the_one_function_not_the_whole_file() {
    let root = workspace_root();
    let relative = "crates/ironclaw_host_runtime/src/sandbox_process/tls_intercept.rs";
    let path = root.join(relative);
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let production_only = truncate_at_inline_test_module(&contents);
    let code_only = strip_comments(production_only);
    let sanctioned_lines = sanctioned_from_system_roots_lines(relative, &code_only);
    let real_occurrences = code_only
        .lines()
        .filter(|line| line.contains("RootCertStore::empty()"))
        .count();
    assert_eq!(
        real_occurrences, 1,
        "expected exactly one production `RootCertStore::empty()` call (inside \
         `from_system_roots`); if a second one was added elsewhere in this file, \
         the sanctioned-lines carve-out must not silently cover it too"
    );
    assert_eq!(
        sanctioned_lines
            .iter()
            .filter(|line_number| {
                code_only
                    .lines()
                    .nth(**line_number - 1)
                    .is_some_and(|line| line.contains("RootCertStore::empty()"))
            })
            .count(),
        1,
        "the sanctioned line span should cover exactly the one \
         `RootCertStore::empty()` call inside `from_system_roots`"
    );
}
