#[allow(dead_code)]
mod ratchet_support;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;

const COMPOSITION_CRATE: &str = "ironclaw_reborn_composition";

use ratchet_support::workspace_root;

const SUBSTRATE_CRATES: &[&str] = &[
    "ironclaw_auth",
    "ironclaw_host_api",
    "ironclaw_storage",
    "ironclaw_filesystem",
    "ironclaw_events",
    "ironclaw_event_projections",
    "ironclaw_event_streams",
    "ironclaw_extensions",
    "ironclaw_authorization",
    "ironclaw_approvals",
    "ironclaw_approvals",
    "ironclaw_resources",
    "ironclaw_trust",
    "ironclaw_capabilities",
    "ironclaw_processes",
    "ironclaw_secrets",
    "ironclaw_network",
    "ironclaw_memory",
    "ironclaw_host_runtime",
    "ironclaw_mcp",
    "ironclaw_scripts",
    "ironclaw_wasm",
    "ironclaw_turns",
    "ironclaw_threads",
    "ironclaw_loop_host",
    "ironclaw_runner",
    "ironclaw_reborn_openai_compat",
    "ironclaw_telegram_extension",
    "ironclaw_product",
    "ironclaw_product",
    "ironclaw_triggers",
];

#[test]
fn no_substrate_crate_depends_on_composition_root() {
    let dependencies = workspace_dependencies();
    for substrate in SUBSTRATE_CRATES {
        let Some(actual) = dependencies.get(*substrate) else {
            continue;
        };
        assert!(
            !actual.iter().any(|dep| dep == COMPOSITION_CRATE),
            "{substrate} must not depend on {COMPOSITION_CRATE}; actual deps: {actual:?}"
        );
    }
}

#[test]
fn composition_root_is_workspace_member() {
    let dependencies = workspace_dependencies();
    assert!(dependencies.contains_key(COMPOSITION_CRATE));
}

#[test]
fn composition_public_api_is_service_shaped() {
    let lib = std::fs::read_to_string(
        workspace_root().join("crates/ironclaw_reborn_composition/src/lib.rs"),
    )
    .expect("composition lib readable");
    let input = std::fs::read_to_string(
        workspace_root().join("crates/ironclaw_reborn_composition/src/input.rs"),
    )
    .expect("composition input readable");
    let factory = std::fs::read_to_string(
        workspace_root().join("crates/ironclaw_reborn_composition/src/factory.rs"),
    )
    .expect("composition factory readable");
    let public_surface = format!("{lib}\n{input}\n{factory}");

    assert!(
        !lib.contains("pub use input::RebornStorageInput"),
        "composition service API must not re-export raw storage input types"
    );
    assert!(
        !input.contains("pub enum RebornStorageInput"),
        "RebornStorageInput must stay crate-private"
    );
    assert!(
        !input.contains("pub db:") && !input.contains("pub pool:"),
        "raw database handles must not be public struct/enum fields"
    );

    for forbidden in [
        "pub run_state_store",
        "pub approval_request_store",
        "pub capability_lease_store",
        "pub event_log",
        "pub audit_log",
        "pub secret_store",
        "pub network_enforcer",
        "pub process_services",
        "pub filesystem_root",
        "pub resource_governor",
        "LegacyBridgeMode",
    ] {
        assert!(
            !public_surface.contains(forbidden),
            "composition root public API must not expose `{forbidden}`"
        );
    }
}

/// The composition root owns assembly, not prompt text. Prompt content is a
/// behavior of the crate that puts it in front of a model, so it lives in that
/// crate's `prompts/` directory (`ironclaw_loop_host` for the system prompt and
/// the identity-context protocols; `ironclaw_skills`, `ironclaw_turns` and the
/// extension packages for theirs) — CHECKLIST WS6 "system-prompt content →
/// owning prompt asset", PROPOSAL §6.10.1, and the house rule that prompt
/// templates live in files inside the crate that owns the behavior.
///
/// Embedding *config-as-data* is still composition's charter, so this scan is
/// keyed on markdown, not on `include_str!` (`builtin_capability_policy.toml`
/// is deliberately unaffected).
#[test]
fn composition_root_embeds_no_prompt_content() {
    let crate_root = workspace_root().join("crates/ironclaw_reborn_composition");

    let sources = rust_sources(&crate_root.join("src"));
    // `rust_sources` now panics on an unreadable directory or entry, so an
    // *incomplete* walk is already loud. This floor covers the case that stays
    // silent: a walk that reads a perfectly good directory which is no longer
    // the crate — after the WS7 family move relocates `crates/…` under a family
    // directory, a stale path could resolve to something small and empty rather
    // than erroring.
    assert!(
        sources.len() >= 50,
        "expected the composition source walk to reach at least 50 files, saw {} — \
         the scan below cannot be trusted",
        sources.len()
    );

    let embedded_markdown: Vec<String> = sources
        .iter()
        .flat_map(|(path, contents)| {
            markdown_include_sites(contents)
                .into_iter()
                .map(|site| format!("{}: {site}", path.display()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        embedded_markdown.is_empty(),
        "the composition root must not embed markdown prompt content; move the asset \
         into the `prompts/` directory of the crate that owns the behavior and export \
         it as a `pub const` (see PROPOSAL §6.10.1). Offending sites:\n{}",
        embedded_markdown.join("\n")
    );

    // A prompt asset that is *shipped* but not yet embedded is the same debt one
    // commit earlier, so the directory itself is pinned rather than only its
    // `include_str!` call sites. Crate guides (`AGENTS.md` / `CLAUDE.md`) are
    // documentation, not prompt content.
    let shipped_markdown: Vec<String> = markdown_assets(&crate_root)
        .into_iter()
        .filter(|path| {
            !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    matches!(
                        name.to_ascii_uppercase().as_str(),
                        "AGENTS.MD" | "CLAUDE.MD" | "README.MD"
                    )
                })
        })
        .map(|path| path.display().to_string())
        .collect();
    assert!(
        shipped_markdown.is_empty(),
        "the composition root ships markdown assets that are not crate guidance; \
         prompt content belongs to its owning crate's `prompts/` directory. Found:\n{}",
        shipped_markdown.join("\n")
    );
}

/// Every `include_str!` / `include_bytes!` invocation in `contents` whose
/// argument names a markdown file, rendered as a normalized single line.
///
/// Scans from each macro-name occurrence to the end of its **statement** (the
/// next `;`) rather than to the first `)`. Parsing the argument is what makes
/// this class of gate leaky, and every leak is silent:
///   * `rustfmt` wraps a long argument onto its own line, so a per-line scan
///     misses it;
///   * `include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/prompt.md"))` closes
///     its *first* `)` before the path is ever seen, so a first-paren scan
///     misses it;
///   * `include_str !(…)` and a comment between the argument and the delimiter
///     are both legal and defeat naive tokenizing.
/// A statement-bounded span is immune to all three: whatever the nesting,
/// spacing, or line breaks, the path literal is inside it.
///
/// It errs toward **over**-reporting — a comment mentioning `.md` inside an
/// include statement is flagged. That direction is deliberate: a false positive
/// is a loud failure a human resolves in one line, a false negative is prompt
/// content silently back in the composition root.
fn markdown_include_sites(contents: &str) -> Vec<String> {
    let bytes = contents.as_bytes();
    let mut out = Vec::new();
    for macro_name in ["include_str", "include_bytes"] {
        let mut cursor = 0usize;
        while let Some(offset) = contents[cursor..].find(macro_name) {
            let start = cursor + offset;
            cursor = start + macro_name.len();

            // Whole identifier only: `my_include_str!` is a different macro.
            if start > 0 {
                let previous = bytes[start - 1];
                if previous.is_ascii_alphanumeric() || previous == b'_' {
                    continue;
                }
            }
            // `include_str` must actually be invoked as a macro; whitespace
            // between the name and `!` is legal Rust.
            let mut probe = cursor;
            while probe < bytes.len() && bytes[probe].is_ascii_whitespace() {
                probe += 1;
            }
            if bytes.get(probe) != Some(&b'!') {
                continue;
            }

            let statement_end = contents[start..]
                .find(';')
                .map(|end| start + end)
                .unwrap_or(contents.len());
            let statement = &contents[start..statement_end];
            if statement.to_ascii_lowercase().contains(".md") {
                out.push(statement.split_whitespace().collect::<Vec<_>>().join(" "));
            }
            cursor = statement_end;
        }
    }
    out
}

#[cfg(test)]
mod markdown_include_scan_tests {
    use super::markdown_include_sites;

    #[test]
    fn single_line_markdown_include_is_detected() {
        assert_eq!(
            markdown_include_sites("const A: &str = include_str!(\"../a/prompt.md\");").len(),
            1
        );
    }

    /// `rustfmt` wrapping a long path onto its own line used to make the site
    /// invisible to a per-line scan.
    #[test]
    fn multiline_markdown_include_is_detected() {
        assert_eq!(
            markdown_include_sites(
                "const A: &str = include_str!(\n    \"../../assets/prompts/a-very-long-name.md\"\n);",
            ),
            vec!["include_str!( \"../../assets/prompts/a-very-long-name.md\" )".to_string()]
        );
    }

    /// A nested argument macro closes an inner `)` before the path appears, so
    /// a first-paren scan reported clean.
    #[test]
    fn nested_argument_macro_is_detected() {
        assert_eq!(
            markdown_include_sites(
                "const A: &str = include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/prompt.md\"));",
            )
            .len(),
            1
        );
    }

    #[test]
    fn whitespace_before_the_bang_is_detected() {
        assert_eq!(
            markdown_include_sites("const A: &str = include_str !(\"../prompt.md\");").len(),
            1
        );
    }

    #[test]
    fn comment_inside_the_argument_does_not_hide_the_path() {
        assert_eq!(
            markdown_include_sites(
                "const A: &str = include_str!(\n    // seeded once at boot\n    \"../prompt.md\",\n);",
            )
            .len(),
            1
        );
    }

    #[test]
    fn uppercase_markdown_extension_is_detected() {
        assert_eq!(
            markdown_include_sites("const A: &[u8] = include_bytes!(\"../PROMPT.MD\");").len(),
            1
        );
    }

    /// Config-as-data stays composition's charter, so a non-markdown include is
    /// not a finding.
    #[test]
    fn non_markdown_include_is_not_a_finding() {
        assert!(
            markdown_include_sites(
                "const P: &str = include_str!(\"builtin_capability_policy.toml\");"
            )
            .is_empty()
        );
    }

    /// The macro name must be a whole identifier and must be invoked.
    #[test]
    fn similar_identifiers_are_not_findings() {
        assert!(markdown_include_sites("let my_include_str = \"a.md\";").is_empty());
        assert!(markdown_include_sites("let include_str_path = \"a.md\";").is_empty());
    }
}

/// Recursively collect every markdown file under `dir`, skipping build output.
///
/// Fails closed: an unreadable directory or entry panics rather than being
/// skipped, because "the walk could not see it" and "there is nothing there"
/// must not look the same to an ownership gate. Extensions are compared
/// case-insensitively so a `.MD` asset cannot slip past.
fn markdown_assets(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let read = std::fs::read_dir(&current)
            .unwrap_or_else(|error| panic!("readable directory {current:?}: {error}"));
        for entry in read {
            let entry =
                entry.unwrap_or_else(|error| panic!("readable entry under {current:?}: {error}"));
            let path = entry.path();
            let file_type = entry
                .file_type()
                .unwrap_or_else(|error| panic!("readable file type for {path:?}: {error}"));
            if file_type.is_dir() {
                if path.file_name().and_then(|name| name.to_str()) == Some("target") {
                    continue;
                }
                stack.push(path);
            } else if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Recursively collect `(path, contents)` for every `.rs` file under `dir`.
fn rust_sources(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        // Fail closed: this walk feeds ownership gates, and a skipped directory
        // makes "could not look" indistinguishable from "nothing there". The
        // file-contents read below has always panicked on failure; the
        // directory read now matches it.
        let read = std::fs::read_dir(&current)
            .unwrap_or_else(|error| panic!("readable directory {current:?}: {error}"));
        for entry in read {
            let entry =
                entry.unwrap_or_else(|error| panic!("readable entry under {current:?}: {error}"));
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                let contents = std::fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("readable rust source {path:?}: {error}"));
                out.push((path, contents));
            }
        }
    }
    out
}

fn workspace_dependencies() -> HashMap<String, Vec<String>> {
    cargo_metadata()["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .filter_map(package_dependencies)
        .collect()
}

fn cargo_metadata() -> Value {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .expect("cargo metadata");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("metadata json")
}

fn package_dependencies(package: &Value) -> Option<(String, Vec<String>)> {
    let name = package["name"].as_str()?.to_string();
    let dependencies = package["dependencies"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|dependency| {
            dependency
                .get("kind")
                .and_then(Value::as_str)
                .is_none_or(|kind| kind == "normal")
        })
        .filter_map(|dependency| dependency["name"].as_str())
        .filter(|name| name.starts_with("ironclaw_"))
        .map(ToString::to_string)
        .collect();
    Some((name, dependencies))
}
