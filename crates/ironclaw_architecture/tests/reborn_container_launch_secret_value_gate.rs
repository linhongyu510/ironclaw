//! Zero-occurrence gate: secret-store *value* types must never reach the
//! sandbox container-launch surface.
//!
//! `.claude/rules/safety-and-sandbox.md`, "Zero-exposure credentials":
//! "Capabilities, runtime lanes, containers, events, logs, and model context
//! carry credential references or redacted metadata." Real secret bytes must
//! never enter a sandbox container — not via environment, not via a
//! bind-mounted file, not via `docker exec` arguments, not via the writable
//! workspace.
//!
//! `crates/ironclaw_host_runtime/src/sandbox_process/exec_transport.rs` is
//! the ONE file that assembles what a container actually receives: it owns
//! both `user_container_launch_config` (builds the Docker `Config<String>` —
//! env, bind mounts, cmd — passed to container create) and `ensure_container`
//! / `exec_in_container` (the `docker exec` dispatch path). See
//! `crates/ironclaw_host_runtime/src/sandbox_process/exec_transport/tests`'s
//! `user_container_launch_config_never_leaks_staged_credential_material` for
//! the runtime seam test this gate backstops at the type level: that test
//! proves TODAY'S code does not leak; this gate makes it structurally hard
//! for a future change to *introduce* a leak by routing a raw secret value
//! into this file at all.
//!
//! **What this gate asserts.** Zero occurrences, in this file's non-test
//! code, of the identifiers that name or expose raw secret *material* —
//! `SecretMaterial` (`ironclaw_secrets`' alias for `secrecy::SecretString`),
//! bare `SecretString`, `ExposeSecret`/`.expose_secret()` (the only way to
//! read bytes out of either), and `RuntimeSecretInjectionStore` (the
//! in-process store those bytes are staged in, `ironclaw_host_runtime::
//! obligations`). None of these have any legitimate reason to appear in a
//! file whose job is building a container's launch config and exec
//! arguments — the file does not, and should not, ever need to *read* a
//! secret's contents.
//!
//! **What this gate deliberately does NOT assert**, per the task's scope
//! discipline (never add test-only wiring for behavior production does not
//! wire, and prefer a narrow honest check):
//!
//! - It does not cover `SecretHandle` (an opaque reference/id, not material —
//!   `ironclaw_host_api::SecretHandle` — legitimately flows through staging
//!   metadata) or `CredentialPlaceholderToken`/`icsbx_...` (the placeholder
//!   this file WOULD need to emit once W6 wires real credential injection;
//!   banning it would block the correct future fix).
//! - It does not cover other files under `sandbox_process/` (e.g. `mounts.rs`,
//!   `credential_swap.rs`, `credential_firewall.rs`) — those legitimately
//!   handle secret material as part of the (unwired) W6 credential-swap
//!   design and are out of scope for "the container-launch surface"
//!   specifically. A parallel container-construction path introduced
//!   elsewhere would not be caught by this gate.
//! - It is a lexical scan, not a type-system proof: a banned identifier
//!   renamed via `use SecretMaterial as Foo` would not be caught. This is
//!   the same limitation `reborn_tls_verification_escape_hatches.rs`
//!   accepts for the same reason (a narrow, provably-binding check over a
//!   broad one that cannot be proven).
//!
//! **Test code is exempt**, matching every existing ratchet in this crate:
//! this file's own runtime seam test constructs `SecretMaterial` and calls
//! `RuntimeSecretInjectionStore::new()`/`.insert()` deliberately, to stage
//! real material and prove the *production* code path never touches it.
//! Exemption is truncation-based, not filename-based (`exec_transport.rs` is
//! not a standalone `tests.rs`): every `#[cfg(test)] mod <name> { ... }`
//! inline block is stripped by brace-depth tracking (mirroring
//! `reborn_tls_verification_escape_hatches.rs`'s
//! `truncate_at_inline_test_module`, generalized here to match any module
//! name, not only `tests`, because this file also carries a second inline
//! test module, `footer_tests`) before the scan runs — never by trusting a
//! filename or a lone `#[cfg(test)]` line without also verifying it truly
//! gates a `mod` declaration.
//!
//! **Comments and string literals are exempt too** — this module's own doc
//! comments name every banned identifier in prose. Stripped via the crate's
//! shared `ratchet_support::strip_comments_and_strings` lexer, not a
//! hand-rolled comment stripper (a `//`-only stripper would misfire on the
//! several `http://`/`https://` and `"..."`-shaped strings this repository's
//! source already contains).

#[allow(dead_code)]
mod ratchet_support;

use std::path::PathBuf;

use ratchet_support::{strip_comments_and_strings, workspace_root};

/// Identifiers that name or expose raw secret material. Any occurrence in
/// this file's non-test code is a live regression against "containers carry
/// only opaque placeholders and references."
const BANNED_PATTERNS: &[&str] = &[
    "SecretMaterial",
    "SecretString",
    "ExposeSecret",
    "expose_secret",
    "RuntimeSecretInjectionStore",
];

fn container_launch_surface_file(root: &std::path::Path) -> PathBuf {
    root.join("crates/ironclaw_host_runtime/src/sandbox_process/exec_transport.rs")
}

/// Strips every `#[cfg(test)] mod <name> { ... }` inline body (brace-depth
/// tracked so an unbalanced `{`/`}` inside a string literal on the same line
/// as the opening brace cannot desync the depth count) and every `#[cfg(test)]
/// mod <name>;` external-file declaration out of `contents`, leaving
/// everything before and after each stripped span intact. See the module doc
/// for why this must not assume the marker sits at end-of-file, and must not
/// key off a hardcoded module name (`exec_transport.rs` has two: `tests` and
/// `footer_tests`).
fn truncate_cfg_test_inline_modules(contents: &str) -> String {
    let stripped = strip_comments_and_strings(contents);
    let mut previous_was_cfg_test = false;
    let mut result = String::with_capacity(contents.len());
    let mut lines = contents.lines().zip(stripped.lines()).peekable();
    while let Some((line, stripped_line)) = lines.next() {
        let trimmed = stripped_line.trim();
        let is_mod_decl = trimmed.starts_with("mod ") && trimmed.ends_with(';');
        let is_mod_open = trimmed.starts_with("mod ") && trimmed.ends_with('{');
        if previous_was_cfg_test && is_mod_decl {
            previous_was_cfg_test = false;
            continue;
        }
        if previous_was_cfg_test && is_mod_open {
            let mut depth: i64 = 0;
            for byte in stripped_line.bytes() {
                match byte {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
            }
            while depth > 0 {
                let Some((_, inner_stripped)) = lines.next() else {
                    break;
                };
                for byte in inner_stripped.bytes() {
                    match byte {
                        b'{' => depth += 1,
                        b'}' => depth -= 1,
                        _ => {}
                    }
                }
            }
            previous_was_cfg_test = false;
            continue;
        }
        previous_was_cfg_test = trimmed == "#[cfg(test)]";
        result.push_str(line);
        result.push('\n');
    }
    result
}

/// Scans `container_launch_surface_file` for [`BANNED_PATTERNS`], returning
/// one formatted hit per match (`relative:line: pattern`) plus the number of
/// non-empty code lines actually scanned — the caller asserts that count is
/// non-trivial so a silently-empty scan (the "reported success because it
/// examined nothing" failure mode named in the task) cannot pass unnoticed.
fn scan_container_launch_surface(root: &std::path::Path) -> (Vec<String>, usize) {
    let path = container_launch_surface_file(root);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {path:?}: {error}"));
    assert!(
        raw.len() > 10_000,
        "sanity check: {path:?} is suspiciously small ({} bytes) — is this still the right \
         file? (container-launch surface file, expected several thousand lines)",
        raw.len()
    );
    let production_only = truncate_cfg_test_inline_modules(&raw);
    let code_only = strip_comments_and_strings(&production_only);

    let mut hits = Vec::new();
    let mut scanned_lines = 0usize;
    for (index, line) in code_only.lines().enumerate() {
        if !line.trim().is_empty() {
            scanned_lines += 1;
        }
        for pattern in BANNED_PATTERNS {
            if line.contains(pattern) {
                hits.push(format!(
                    "crates/ironclaw_host_runtime/src/sandbox_process/exec_transport.rs:{}: banned pattern {pattern:?}",
                    index + 1
                ));
            }
        }
    }
    (hits, scanned_lines)
}

#[test]
fn container_launch_surface_never_references_raw_secret_value_types() {
    let root = workspace_root();
    let (hits, scanned_lines) = scan_container_launch_surface(&root);

    // Proves the scan actually opened and read real content, not an empty or
    // wrong file — the exact failure mode named in the task ("a gate that
    // reports success because it silently examined nothing").
    assert!(
        scanned_lines > 500,
        "scan examined only {scanned_lines} non-empty code lines — far fewer than \
         exec_transport.rs's known size; the scan is not reading the file it claims to cover"
    );
    eprintln!(
        "reborn_container_launch_secret_value_gate: scanned {scanned_lines} non-empty \
         production code lines in exec_transport.rs"
    );

    assert!(
        hits.is_empty(),
        "secret-store value types must never reach the container-launch surface \
         (zero-exposure credentials, .claude/rules/safety-and-sandbox.md):\n{}",
        hits.join("\n")
    );
}

/// Proves the truncation logic genuinely removes BOTH of this file's inline
/// test modules (`tests` and the differently-named `footer_tests`) rather
/// than only ever matching the literal string `mod tests`. A truncator that
/// only stripped `mod tests { ... }` would still correctly exempt this file's
/// main test module (which legitimately uses `SecretMaterial`) but would
/// leave `footer_tests` unstripped — currently harmless (it contains none of
/// the banned patterns), but that harmlessness is a fact about
/// `footer_tests`'s *content* today, not something this gate should rely on
/// silently. This test pins that both markers are found and stripped, at the
/// scanner level, independent of what either module currently contains.
#[test]
fn truncation_strips_every_named_inline_test_module_not_just_mod_tests() {
    let sample = "\
fn production_code() {}\n\
#[cfg(test)]\n\
mod tests {\n    \
    const X: &str = \"SecretMaterial\";\n\
}\n\
#[cfg(test)]\n\
mod footer_tests {\n    \
    const Y: &str = \"SecretString\";\n\
}\n\
fn more_production_code() {}\n";
    let truncated = truncate_cfg_test_inline_modules(sample);
    assert!(
        truncated.contains("production_code"),
        "production code before the test modules must survive truncation: {truncated:?}"
    );
    assert!(
        truncated.contains("more_production_code"),
        "production code after the test modules must survive truncation: {truncated:?}"
    );
    assert!(
        !truncated.contains("SecretMaterial"),
        "the `mod tests {{ ... }}` body must be stripped: {truncated:?}"
    );
    assert!(
        !truncated.contains("SecretString"),
        "the differently-named `mod footer_tests {{ ... }}` body must ALSO be stripped — a \
         truncator keyed only on the literal name `tests` would leave this one behind: \
         {truncated:?}"
    );
}
