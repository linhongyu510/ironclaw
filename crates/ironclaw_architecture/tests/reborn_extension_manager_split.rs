//! CHECKLIST WS2 — the `ironclaw_extension_manager` split
//! (PROPOSAL §6.8.2 / §6.8.3).
//!
//! `ironclaw_extension_host` held two jobs at once: lifecycle **authority**
//! (the only writer of installation state and the active snapshot, ingress
//! verification, activation transactions) and the extension-management
//! **product face** that arrived with #6616/#6669 (lifecycle capabilities and
//! commands, the `LifecycleProductService`, admin/operator/skill capability
//! handlers, credential views, the extension hub). §6.8.3 splits the second
//! job into its own `products`-layer crate so the first can move *below*
//! product in WS2's layer flip.
//!
//! The split only buys that if the dependency runs one way. Three halves:
//!
//! - **The host never depends on the manager.** Checked at the manifest *and*
//!   at the source level, because a `#[cfg(test)]`-only or dev-dependency
//!   cycle would still be a cycle in the graph the layer flip has to satisfy.
//!   This is the load-bearing rule: if it breaks, the manager stops being a
//!   layer above and becomes a sibling with a back-edge.
//! - **Each half kept its own job.** The authority modules are still in the
//!   host and the product-face modules are only in the manager, so a later
//!   change cannot quietly drag a surface back across the line — in either
//!   direction.
//! - **The manager's residual `ironclaw_product` coupling is frozen and
//!   shrink-only.** `families/extensions.md` says the manager never depends on
//!   the conversation-facing product crate. It does today, in exactly seven
//!   files, and every one of them is a *product DTO or capability-id constant*
//!   that §6.1.3 assigns to `product_contracts` — not a workflow call. The
//!   list names the row that removes each, and a stale entry fails, so the
//!   edge can only get smaller.

// The shared walker is compiled per test binary; each binary uses a subset.
#[allow(dead_code)]
mod ratchet_support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use ratchet_support::{strip_comments_and_strings, workspace_root};

const HOST: &str = "ironclaw_extension_host";
const MANAGER: &str = "ironclaw_extension_manager";
const PRODUCT: &str = "ironclaw_product";

/// Modules that carry lifecycle **authority** and therefore stay in the host
/// (§6.8.2). Each is the reason the host cannot simply be absorbed.
const HOST_AUTHORITY_MODULES: &[(&str, &str)] = &[
    (
        "lifecycle.rs",
        "ExtensionHost — the only writer of installation state",
    ),
    (
        "generic_host.rs",
        "the generic host build and its bound snapshot",
    ),
    ("activation_transaction.rs", "activation transactions"),
    (
        "extension_ingress.rs",
        "the vendor-blind ingress router and verifier",
    ),
    (
        "install_policy.rs",
        "install/remove authorization decisions",
    ),
    (
        "product_lifecycle.rs",
        "ExtensionLifecycleManager — the lifecycle workflow every product-face \
         caller goes through. §6.8.3 says the manager 'never owns lifecycle \
         authority (calls extension_host)', and this is what it calls",
    ),
    (
        "channel_config.rs",
        "the ChannelConfigService core: manifest validation, the durable/secret \
         write split, and the §6.5 reactivate cycle. Only its product \
         projection moved",
    ),
    (
        "channel_pairing.rs",
        "the pairing service core §6.8.2 keeps here; five host modules consume it",
    ),
];

/// Modules that are the extension-management **product face** and therefore
/// live in the manager (§6.8.3), each with the inventory line that placed it.
const MANAGER_PRODUCT_FACE_MODULES: &[(&str, &str)] = &[
    ("admin_configuration.rs", "credential/admin views"),
    (
        "admin_configuration_capability.rs",
        "admin capability handler",
    ),
    (
        "channel_config_product_service.rs",
        "the `channel_config` product service",
    ),
    (
        "extension_lifecycle_capabilities.rs",
        "lifecycle commands/capabilities",
    ),
    ("extension_lifecycle_command.rs", "lifecycle commands"),
    ("ironhub.rs|ironhub", "the extension hub product surface"),
    (
        "lifecycle_product_service.rs",
        "the lifecycle product service",
    ),
    (
        "operator_config_capability.rs",
        "operator capability handler",
    ),
    (
        "skill_auto_activate_capability.rs",
        "skill-auto-activate capability handler",
    ),
    ("webui_extension_credentials.rs", "credential views"),
];

/// `ironclaw_extension_manager` production files that still name a symbol from
/// `ironclaw_product`, with the symbols and the row that removes each.
///
/// **Exact-match and shrink-only.** A new file fails; a stale row fails too,
/// so the entry is deleted in the change that removes the edge. The edge is
/// *legal* — both crates are `products`-layer, so this is a sideways
/// dependency, not the upward one WS2 exists to kill — but
/// `families/extensions.md` states the manager's target dependency set as
/// `product_contracts` + `extension_contracts` + `extension_registry` +
/// `extension_host`, and that is a fact this list keeps honest rather than
/// aspirational.
///
/// Every entry is a **DTO or capability-id constant**, not a workflow call.
/// That is the finding: the manager does not reach into product's workflow at
/// all; it reaches for vocabulary §6.1.3 already assigns to
/// `ironclaw_product_contracts` and that the WS1.4 sweep did not carry.
const MANAGER_PRODUCT_RESIDUE: &[(&str, &str)] = &[
    (
        "admin_configuration.rs",
        "ADMIN_CONFIGURATION_VIEW and the RebornAdminConfiguration* wire DTOs — \
         §6.1.3 product DTOs awaiting the product_contracts sweep",
    ),
    (
        "admin_configuration_capability.rs",
        "ADMIN_CONFIGURATION_REPLACE_CAPABILITY_ID — a capability-id constant",
    ),
    (
        "extension_lifecycle_capabilities.rs",
        "RebornChannelConnectStrategy — the connect-strategy DTO the host's \
         channel_lifecycle.rs also names, so it moves with §6.9.1's shed",
    ),
    (
        "test_support/lifecycle.rs",
        "lifecycle_auth_continuation_dispatcher — the production auth \
         continuation wiring a full-stack fixture must build; it goes when \
         AuthChallengeProvider inverts (auth vocabulary, port-inversion residue)",
    ),
    (
        "operator_config_capability.rs",
        "OPERATOR_CONFIG_SET_{AUTO_APPROVE,TOOL_PERMISSION}_CAPABILITY_ID — \
         capability-id constants",
    ),
    (
        "skill_auto_activate_capability.rs",
        "RebornSkillActionResponse + SKILL_AUTO_ACTIVATE_LEARNED_SET_CAPABILITY_ID \
         — a wire DTO and a capability-id constant",
    ),
    (
        "webui_extension_credentials.rs",
        "ExtensionCredentialSetupService and its request types — the port is \
         still declared in product because its vocabulary is ironclaw_auth \
         credential-account projections (port-inversion residue)",
    ),
];

/// Ceiling on the residue. Only ever moves down.
const MANAGER_PRODUCT_RESIDUE_BASELINE: usize = 7;

fn crate_src(root: &Path, name: &str) -> PathBuf {
    root.join("crates").join(name).join("src")
}

/// Every production `.rs` file under `dir`, relative to it.
///
/// Unlike the sibling scanners this **panics on an I/O error** rather than
/// skipping the entry. A scan that silently swallows a failed `read_dir` walks
/// a smaller tree and passes vacuously, which is the exact way a shrink-only
/// list stops protecting anything.
fn production_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

fn walk(base: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read_dir {}: {error}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| panic!("dir entry in {}: {error}", dir.display()));
        let path = entry.path();
        if path.is_dir() {
            if matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("target") | Some("tests")
            ) {
                continue;
            }
            walk(base, &path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if name == "tests.rs" || name.ends_with("_tests.rs") {
                continue;
            }
            let relative = path
                .strip_prefix(base)
                .unwrap_or_else(|error| panic!("strip {}: {error}", path.display()));
            out.push(relative.to_path_buf());
        }
    }
}

fn read(root: &Path, crate_name: &str, relative: &Path) -> String {
    let path = crate_src(root, crate_name).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn cargo_metadata() -> serde_json::Value {
    let manifest_path = workspace_root().join("Cargo.toml");
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(&manifest_path)
        .output()
        .unwrap_or_else(|error| panic!("failed to run cargo metadata: {error}"));
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata output must be JSON")
}

/// The load-bearing rule of the whole split.
#[test]
fn the_host_never_depends_on_the_manager() {
    let metadata = cargo_metadata();
    let packages = metadata["packages"]
        .as_array()
        .expect("cargo metadata packages");
    let host = packages
        .iter()
        .find(|package| package["name"].as_str() == Some(HOST))
        .unwrap_or_else(|| panic!("{HOST} must be a workspace member"));
    let manager_edges: Vec<String> = host["dependencies"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|dependency| dependency["name"].as_str() == Some(MANAGER))
        .map(|dependency| dependency["kind"].as_str().unwrap_or("normal").to_string())
        .collect();
    assert!(
        manager_edges.is_empty(),
        "{HOST} declares a {manager_edges:?} dependency on {MANAGER}. The split exists so the \
         host can move below product (PROPOSAL §12.1c); a back-edge of ANY kind — including a \
         dev-dependency for a fixture — puts the two crates in a cycle the layer flip cannot \
         satisfy. Move the code that needs the manager into the manager, or invert it behind a \
         port the host declares."
    );

    // Manifest silence is not enough: a `#[cfg(test)]` module naming the crate
    // would fail to compile today and mean somebody is mid-cycle tomorrow.
    let src = crate_src(&workspace_root(), HOST);
    let files = production_files(&src);
    assert!(
        files.len() >= 60,
        "expected to walk {HOST}'s source tree; found {} files — a broken path must fail \
         loudly rather than report a clean, vacuously passing scan",
        files.len()
    );
    let offenders: Vec<String> = files
        .iter()
        .filter(|relative| {
            strip_comments_and_strings(&read(&workspace_root(), HOST, relative)).contains(MANAGER)
        })
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        .collect();
    assert!(
        offenders.is_empty(),
        "{HOST} source names {MANAGER} in {offenders:?} — the host calls nothing in the manager"
    );
}

#[test]
fn each_half_of_the_split_kept_its_own_job() {
    let root = workspace_root();
    let host_files: BTreeSet<String> = production_files(&crate_src(&root, HOST))
        .iter()
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        .collect();
    let manager_files: BTreeSet<String> = production_files(&crate_src(&root, MANAGER))
        .iter()
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        .collect();

    let mut violations = Vec::new();
    for (module, why) in HOST_AUTHORITY_MODULES {
        if !host_files.contains(*module) {
            violations.push(format!(
                "{HOST} no longer holds {module} ({why}). Authority does not move to the \
                 manager — §6.8.3 says the manager calls the host, never replaces it"
            ));
        }
        if manager_files.contains(*module) {
            violations.push(format!(
                "{MANAGER} holds {module}, which is authority ({why})"
            ));
        }
    }
    for (module, why) in MANAGER_PRODUCT_FACE_MODULES {
        // A module may be a file or a directory; accept either spelling.
        let alternatives: Vec<&str> = module.split('|').collect();
        let in_manager = alternatives.iter().any(|name| {
            manager_files.contains(*name)
                || manager_files
                    .iter()
                    .any(|file| file.starts_with(&format!("{name}/")))
        });
        let in_host = alternatives.iter().any(|name| {
            host_files.contains(*name)
                || host_files
                    .iter()
                    .any(|file| file.starts_with(&format!("{name}/")))
        });
        if !in_manager {
            violations.push(format!(
                "{MANAGER} does not hold {module} ({why}) — the §6.8.3 inventory moved it there"
            ));
        }
        if in_host {
            violations.push(format!(
                "{HOST} still holds {module} ({why}) — a product-face module drifted back"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "WS2 extension_manager split violated (PROPOSAL §6.8.2/§6.8.3):\n{}",
        violations.join("\n")
    );
}

#[test]
fn manager_product_coupling_is_frozen_and_shrink_only() {
    let root = workspace_root();
    let src = crate_src(&root, MANAGER);
    let files = production_files(&src);
    assert!(
        files.len() >= 10,
        "expected to walk {MANAGER}'s source tree; found {} files",
        files.len()
    );

    let mut found = BTreeSet::new();
    for relative in &files {
        let code = strip_comments_and_strings(&read(&root, MANAGER, relative));
        // Match the crate path, not the prefix: `ironclaw_product_contracts`
        // is the *sanctioned* dependency and must never register here.
        if code.contains(&format!("{PRODUCT}::")) || code.contains(&format!("use {PRODUCT};")) {
            found.insert(relative.to_string_lossy().replace('\\', "/"));
        }
    }

    let frozen: BTreeMap<&str, &str> = MANAGER_PRODUCT_RESIDUE.iter().copied().collect();
    let mut violations = Vec::new();
    for file in found.iter() {
        if !frozen.contains_key(file.as_str()) {
            violations.push(format!(
                "{MANAGER}/src/{file} names {PRODUCT}. families/extensions.md gives the manager \
                 product_contracts + extension_contracts + extension_registry + extension_host \
                 and nothing else; if the symbol is a DTO or a capability id, move it to \
                 ironclaw_product_contracts (§6.1.3) rather than adding a row here"
            ));
        }
    }
    for file in frozen.keys() {
        if !found.contains(*file) {
            violations.push(format!(
                "{file} is listed as product residue but no longer names {PRODUCT} — delete its \
                 row in the same change"
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "WS2 manager product-residue rule violated:\n{}",
        violations.join("\n")
    );
    assert!(
        found.len() <= MANAGER_PRODUCT_RESIDUE_BASELINE,
        "the manager's product residue is shrink-only: {} > baseline {}",
        found.len(),
        MANAGER_PRODUCT_RESIDUE_BASELINE
    );
}

/// The scanner must be loud when it cannot walk, not quietly empty.
#[test]
#[should_panic(expected = "read_dir")]
fn the_scanner_fails_on_a_tree_it_cannot_walk() {
    let missing = workspace_root().join("crates/ironclaw_extension_manager/src/does-not-exist");
    let _ = production_files(&missing);
}

/// …and it must actually find files when it can, so "no offenders" is a real
/// result rather than an artefact of a filter that excludes everything.
#[test]
fn the_scanner_reads_the_trees_it_claims_to_scan() {
    let root = workspace_root();
    for (crate_name, floor) in [(HOST, 60usize), (MANAGER, 10)] {
        let files = production_files(&crate_src(&root, crate_name));
        assert!(
            files.len() >= floor,
            "{crate_name}: walked {} production files, floor {floor}",
            files.len()
        );
        assert!(
            files.iter().any(|file| file.ends_with("lib.rs")),
            "{crate_name}: the walk never reached lib.rs"
        );
    }
}
