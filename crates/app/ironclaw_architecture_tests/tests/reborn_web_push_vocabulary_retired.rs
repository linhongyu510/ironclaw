//! Zero-occurrence gate for the retired `web-push` channel identity
//! (unified channel model §13).
//!
//! The 2026-08-10 unified-channel-model train renamed the browser channel's
//! product identity `web-push` → `web-app`: the extension id, channel name,
//! catalog target id, package directory, and crate names all moved, and the
//! bespoke `/web-push/*` enrollment routes were deleted in favor of the
//! generic `/channels/{extension_id}/notifications` surface. This gate pins
//! the retired spelling at **zero occurrences** across Reborn code, the WebUI
//! frontend sources, packaged manifests, integration tests, and the embedded
//! `skills/` bundles — the same footing as `reborn_retired_taxonomy.rs` — so
//! neither the old identity nor a channel-specific route can be reintroduced
//! silently.
//!
//! What is *not* banned: the space-separated protocol prose "Web Push" /
//! "web push" (RFC 8030/8291/8292 is genuinely the Web Push protocol, and the
//! channel's package and domain crate speak it), and separator-free fixture
//! strings such as `webui-webpush-tenant` in tests. The ban is on the retired
//! *identifiers*: `web-push`, `web_push`, `WebPush`, `webPush`, `WEB_PUSH`.
//!
//! Sanctioned exceptions are path-scoped and each names the exact terms it
//! may carry. All but one exist because a PERSISTED coordinate deliberately
//! keeps the pre-rename bytes — renaming a storage key is data loss, not a
//! spelling fix:
//! - the `ironclaw_web_app` grammar decodes (never mints) the legacy
//!   `web-push/v1/` binding-ref prefix and keeps the `web_push_vapid`
//!   credential-handle value;
//! - its store keeps the `/web-push/subscriptions.json` document path;
//! - composition keeps the `/web-push` per-user mount alias those documents
//!   physically live under;
//! - the web-app manifest names the same persisted credential handle;
//! - the specificity gate's carve-out doc records the rename;
//! - this gate names every term on purpose.

#[allow(dead_code)]
mod ratchet_support;

use std::path::Path;

use ratchet_support::workspace_root;

/// The retired identity spellings. A hit outside the sanctioned paths is a
/// regression, not a style issue.
const RETIRED_TERMS: &[&str] = &["web-push", "web_push", "WebPush", "webPush", "WEB_PUSH"];

/// Path fragments allowed to reference the retired spelling, each with the
/// exact terms it may use. An empty term list means "every term" and is
/// reserved for this gate itself. Shrink-only, and pinned to reality:
/// [`sanctioned_paths_all_match_real_files`] fails when a fragment matches no
/// scanned file, so an exemption cannot outlive the code it exempts.
const SANCTIONED_PATHS: &[(&str, &[&str])] = &[
    // Persisted coordinates: legacy ref-prefix decode + credential-handle
    // value (grammar), document path (store).
    (
        "crates/domains/ironclaw_web_app/src/grammar.rs",
        &["web-push", "web_push"],
    ),
    (
        "crates/domains/ironclaw_web_app/src/store.rs",
        &["web-push"],
    ),
    // The per-user mount alias the enrollment documents physically live
    // under — it resolves to a physical subpath, so it keeps its spelling.
    ("crates/app/ironclaw_composition/src/lib.rs", &["web-push"]),
    // The persisted credential handle in the channel's own manifest.
    (
        "crates/extensions/packages/web-app/manifest.toml",
        &["web_push"],
    ),
    // The specificity gate's carve-out doc records the rename and names this
    // gate's file (which contains `web_push`).
    ("reborn_extension_specificity.rs", &["web-push", "web_push"]),
    // This gate names every term on purpose.
    ("reborn_web_push_vocabulary_retired.rs", &[]),
];

/// Sanity floor: far below the real scanned-file count, guarding only the
/// partial-tree shape where "no retired spelling found" would be
/// indistinguishable from "almost nothing was looked at".
const MIN_SCANNED_FILES: usize = 500;

fn sanctioned_terms(path: &str) -> Option<&'static [&'static str]> {
    SANCTIONED_PATHS
        .iter()
        .find(|(fragment, _)| path.contains(fragment))
        .map(|(_, terms)| *terms)
}

fn is_sanctioned(sanctioned: Option<&'static [&'static str]>, term: &str) -> bool {
    match sanctioned {
        None => false,
        Some([]) => true,
        Some(terms) => terms.contains(&term),
    }
}

/// A scan error is a gate failure, not a skip — same shape as
/// `reborn_retired_taxonomy.rs`. `dist/` is skipped beside `target/`: it is
/// git-ignored Vite build output, rebuilt from the scanned sources.
fn scan_dir(
    root: &Path,
    dir: &Path,
    hits: &mut Vec<String>,
    scanned: &mut Vec<String>,
) -> std::io::Result<()> {
    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name == "node_modules" || name == ".git" || name == "dist" {
                continue;
            }
            scan_dir(root, &path, hits, scanned)?;
            continue;
        }
        let is_rust = name.ends_with(".rs");
        let is_frontend = name.ends_with(".ts")
            || name.ends_with(".tsx")
            || name.ends_with(".mts")
            || name.ends_with(".mjs")
            || name.ends_with(".js");
        let is_manifest = name.ends_with(".toml");
        let is_guidance = name.ends_with(".json") || name.ends_with(".md");
        if !(is_rust || is_frontend || is_manifest || is_guidance) {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        scanned.push(relative.clone());
        let sanctioned = sanctioned_terms(&relative);
        let contents = std::fs::read_to_string(&path)
            .map_err(|error| std::io::Error::new(error.kind(), format!("{relative}: {error}")))?;
        for term in RETIRED_TERMS {
            if contents.contains(term) && !is_sanctioned(sanctioned, term) {
                hits.push(format!("{relative}: `{term}`"));
            }
        }
    }
    Ok(())
}

fn scan_workspace(root: &Path) -> std::io::Result<(Vec<String>, Vec<String>)> {
    let mut hits = Vec::new();
    let mut scanned = Vec::new();
    scan_dir(root, &root.join("crates"), &mut hits, &mut scanned)?;
    scan_dir(
        root,
        &root.join("tests/integration"),
        &mut hits,
        &mut scanned,
    )?;
    scan_dir(root, &root.join("skills"), &mut hits, &mut scanned)?;
    hits.sort();
    hits.dedup();
    Ok((hits, scanned))
}

#[test]
fn retired_web_push_spelling_stays_at_zero_occurrences() {
    let root = workspace_root();
    let (hits, scanned) = scan_workspace(&root).expect("workspace scan must complete");
    assert!(
        scanned.len() >= MIN_SCANNED_FILES,
        "scan covered only {} files (< {MIN_SCANNED_FILES}) — the walk is broken, so an empty \
         hit list proves nothing",
        scanned.len(),
    );
    assert!(
        hits.is_empty(),
        "retired `web-push` identity spelling found outside the sanctioned persisted-compat \
         paths — the channel is `web-app` now, and generic code names no channel at all:\n  {}",
        hits.join("\n  "),
    );
}

/// An exemption must not outlive the code it exempts: every sanctioned
/// fragment matches at least one scanned file, and every sanctioned file
/// still uses each term it is sanctioned for (otherwise the entry is stale
/// slack a later regression could hide inside).
#[test]
fn sanctioned_paths_all_match_real_files_and_carry_no_slack() {
    let root = workspace_root();
    let (_, scanned) = scan_workspace(&root).expect("workspace scan must complete");
    for (fragment, terms) in SANCTIONED_PATHS {
        let matches: Vec<&String> = scanned
            .iter()
            .filter(|path| path.contains(fragment))
            .collect();
        assert!(
            !matches.is_empty(),
            "sanctioned fragment `{fragment}` matches no scanned file — remove the stale entry",
        );
        for term in *terms {
            let still_used = matches.iter().any(|path| {
                std::fs::read_to_string(root.join(path.as_str()))
                    .map(|contents| contents.contains(term))
                    .unwrap_or(false)
            });
            assert!(
                still_used,
                "sanctioned fragment `{fragment}` no longer uses `{term}` — shrink the entry",
            );
        }
    }
}

/// §13's second assertion: the notification-setup and session-inbound routes
/// are generic — parameterized by `{extension_id}`, with no per-channel
/// pattern. Pinned against the descriptor source so a channel-named route
/// cannot come back under a vocabulary this gate does not ban.
#[test]
fn notification_setup_and_session_routes_stay_extension_id_parameterized() {
    let root = workspace_root();
    let descriptors = root.join("crates/product/ironclaw_webui/src/webui_v2/descriptors.rs");
    let contents = std::fs::read_to_string(&descriptors).expect("descriptors source reads");
    for pattern in [
        "\"/api/webchat/v2/channels/{extension_id}/messages\"",
        "\"/api/webchat/v2/channels/{extension_id}/notifications\"",
        "\"/api/webchat/v2/channels/{extension_id}/notifications/enable\"",
        "\"/api/webchat/v2/channels/{extension_id}/notifications/disable\"",
    ] {
        assert!(
            contents.contains(pattern),
            "expected the generic route pattern {pattern} in webui_v2/descriptors.rs — \
             per-channel routes were retired by the unified channel model",
        );
    }
}
