//! Anti-slippage ratchet for the deployment-mode *branching* axis (§4.4 / §10
//! of `docs/reborn/contracts/runtime-profiles.md`).
//!
//! Its two siblings own deployment mode as a **type name**
//! (`reborn_standalone_typename_ratchet`, `reborn_deployment_mode_typename_ratchet`).
//! This one owns the behaviour those names were a symptom of: **code that
//! reads a deployment mode to decide what to do.**
//!
//! §4.4 is explicit that mode and lane get opposite treatment, and why:
//!
//! > A deployment mode must be branched on in exactly **zero** places past the
//! > composition edge — that is the whole §2.1 thesis — so giving it an enum
//! > would hand every crate an invitation to `match` on it (which is precisely
//! > how the 66-identifier `Standalone*` family grew).
//!
//! `RebornCompositionProfile` *is* such an enum. It survives as the CLI/env
//! parse artifact and as a display label; what must not survive is consumers
//! reading its variants to select behaviour. `DeploymentConfig` (§5.6) is where
//! a profile becomes data — substrate, traffic policy, readiness contract,
//! storage shape — and everything downstream reads those fields.
//!
//! ## What this freezes
//!
//! The **set** of production files under `crates/app/ironclaw_composition/src`
//! that name a `RebornCompositionProfile` variant. Set membership, not a count,
//! per §10: a count lets a new violation silently replace a retired one; only
//! set membership catches a *swap*. A file entering the set fails; a file
//! leaving it must be removed from the allowlist in the same PR, so the debt
//! can only shrink.
//!
//! This is deliberately coarser than "detect a `match`": variant paths are what
//! branching needs, and a line-based scan cannot reliably tell
//! `match p { Profile::X => .. }` from `if p == Profile::X` from
//! `matches!(p, Profile::X | ..)` — all three are the same debt.
//!
//! ## Definition of done
//!
//! The allowlist reaches `{deployment.rs}` — `DeploymentConfig::for_profile`,
//! the one place a profile name becomes deployment data. The remaining entries
//! and why each is still here are documented on the allowlist itself.
//!
//! **Owner:** the #6274 driver (Illia Polosukhin) — the person driving this
//! allowlist to `{deployment.rs}`. §10 requires every ratchet to name one; an
//! unowned ratchet is telemetry, not a gate.
//!
//! Scanner semantics: comments and string literals are stripped before
//! matching, so this file's own doc comment and fixtures do not self-trip.
//! Skips `tests/`, `examples/`, `benches/` trees and `*tests.rs` files —
//! test fixtures naming a profile are not production branching.

#[allow(dead_code)]
mod ratchet_support;

use std::collections::BTreeSet;
use std::path::Path;

// Crate paths are spelled flat (`crates/ironclaw_x/...`) and RESOLVED through
// the crate inventory, so the family move (PROPOSAL section 5) repoints them
// without editing the literals. Identity on today's tree - pinned by
// `reborn_crate_inventory.rs` (CHECKLIST WS10).
use ratchet_support::{crate_path, strip_comments_and_strings, workspace_root};
use syn::visit::{self, Visit};

/// Production files under composition `src/` allowed to name a
/// `RebornCompositionProfile` variant, each with the reason it is still here.
///
/// Sorted; entries are `src/`-relative with `/` separators.
const ALLOWLIST: &[(&str, &str)] = &[
    (
        "deployment.rs",
        "TARGET STATE — `DeploymentConfig::for_profile` is the one place a \
         profile name becomes deployment data (§4.4). This entry stays.",
    ),
    (
        "memory_binding.rs",
        "Maps the composition profile to a typed `MemoryDeploymentProfile` for \
         the fail-closed memory profile-binding certification policy (#3537): \
         production rejects unverified third-party bindings absent an admin \
         override; standalone permits them. The branch produces a typed \
         memory-deployment axis, not a raw label. Retires into `DeploymentConfig` \
         when it grows a memory-binding axis (#5264).",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileControlKind {
    Match,
    MatchesMacro,
    IfLet,
    Equality,
}

#[derive(Debug)]
struct ProfileControl {
    kind: ProfileControlKind,
    in_deployment_config_for_profile: bool,
}

#[derive(Default)]
struct ProfileControlVisitor {
    deployment_config_impl_depth: usize,
    for_profile_depth: usize,
    controls: Vec<ProfileControl>,
}

impl ProfileControlVisitor {
    fn record(&mut self, kind: ProfileControlKind) {
        self.controls.push(ProfileControl {
            kind,
            in_deployment_config_for_profile: self.deployment_config_impl_depth > 0
                && self.for_profile_depth > 0,
        });
    }
}

impl<'ast> Visit<'ast> for ProfileControlVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if is_cfg_test_item(&node.attrs) {
            return;
        }
        visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if is_cfg_test_item(&node.attrs) {
            return;
        }
        visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if is_cfg_test_item(&node.attrs) {
            return;
        }
        let deployment_config = matches!(
            node.self_ty.as_ref(),
            syn::Type::Path(path) if path.qself.is_none() && path.path.is_ident("DeploymentConfig")
        );
        if deployment_config {
            self.deployment_config_impl_depth += 1;
        }
        visit::visit_item_impl(self, node);
        if deployment_config {
            self.deployment_config_impl_depth -= 1;
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if is_cfg_test_item(&node.attrs) {
            return;
        }
        let for_profile = self.deployment_config_impl_depth > 0 && node.sig.ident == "for_profile";
        if for_profile {
            self.for_profile_depth += 1;
        }
        visit::visit_impl_item_fn(self, node);
        if for_profile {
            self.for_profile_depth -= 1;
        }
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if node
            .arms
            .iter()
            .any(|arm| pattern_contains_reborn_profile_variant(&arm.pat))
        {
            self.record(ProfileControlKind::Match);
        }
        visit::visit_expr_match(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        if node
            .mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "matches")
            && token_stream_contains_reborn_profile_variant(node.mac.tokens.clone())
        {
            self.record(ProfileControlKind::MatchesMacro);
        }
        visit::visit_expr_macro(self, node);
    }

    fn visit_expr_let(&mut self, node: &'ast syn::ExprLet) {
        if pattern_contains_reborn_profile_variant(&node.pat) {
            self.record(ProfileControlKind::IfLet);
        }
        visit::visit_expr_let(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_))
            && (expression_contains_reborn_profile_variant(&node.left)
                || expression_contains_reborn_profile_variant(&node.right))
        {
            self.record(ProfileControlKind::Equality);
        }
        visit::visit_expr_binary(self, node);
    }
}

fn is_cfg_test_item(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        let syn::Meta::List(list) = &attribute.meta else {
            return false;
        };
        list.path.is_ident("cfg")
            && matches!(
                syn::parse2::<syn::Meta>(list.tokens.clone()),
                Ok(syn::Meta::Path(path)) if path.is_ident("test")
            )
    })
}

fn path_is_reborn_profile_variant(path: &syn::Path) -> bool {
    path.segments
        .iter()
        .position(|segment| segment.ident == "RebornCompositionProfile")
        .is_some_and(|profile_segment| profile_segment + 1 < path.segments.len())
}

#[derive(Default)]
struct PatternProfileVariantFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for PatternProfileVariantFinder {
    fn visit_path(&mut self, node: &'ast syn::Path) {
        self.found |= path_is_reborn_profile_variant(node);
        visit::visit_path(self, node);
    }
}

fn pattern_contains_reborn_profile_variant(pattern: &syn::Pat) -> bool {
    let mut finder = PatternProfileVariantFinder::default();
    finder.visit_pat(pattern);
    finder.found
}

#[derive(Default)]
struct ExpressionProfileVariantFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for ExpressionProfileVariantFinder {
    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        self.found |= path_is_reborn_profile_variant(&node.path);
        visit::visit_expr_path(self, node);
    }
}

fn expression_contains_reborn_profile_variant(expression: &syn::Expr) -> bool {
    let mut finder = ExpressionProfileVariantFinder::default();
    finder.visit_expr(expression);
    finder.found
}

fn token_stream_contains_reborn_profile_variant(tokens: proc_macro2::TokenStream) -> bool {
    let tokens: Vec<proc_macro2::TokenTree> = tokens.into_iter().collect();
    for index in 0..tokens.len().saturating_sub(3) {
        let (
            proc_macro2::TokenTree::Ident(profile),
            proc_macro2::TokenTree::Punct(first_colon),
            proc_macro2::TokenTree::Punct(second_colon),
            proc_macro2::TokenTree::Ident(_variant),
        ) = (
            &tokens[index],
            &tokens[index + 1],
            &tokens[index + 2],
            &tokens[index + 3],
        )
        else {
            continue;
        };
        if profile == "RebornCompositionProfile"
            && first_colon.as_char() == ':'
            && second_colon.as_char() == ':'
        {
            return true;
        }
    }
    tokens.into_iter().any(|token| {
        matches!(token, proc_macro2::TokenTree::Group(group) if token_stream_contains_reborn_profile_variant(group.stream()))
    })
}

fn assert_only_deployment_config_for_profile_control(source: &str) {
    let file = syn::parse_file(source).unwrap_or_else(|error| panic!("parse source: {error}"));
    let mut visitor = ProfileControlVisitor::default();
    visitor.visit_file(&file);

    assert_eq!(
        visitor.controls.len(),
        1,
        "deployment.rs must contain exactly one profile-dependent control expression; found {:?}",
        visitor.controls
    );
    let control = &visitor.controls[0];
    assert_eq!(
        control.kind,
        ProfileControlKind::Match,
        "the sole profile-dependent control must be the DeploymentConfig::for_profile match; found {control:?}"
    );
    assert!(
        control.in_deployment_config_for_profile,
        "the sole profile-dependent control must be inside DeploymentConfig::for_profile; found {control:?}"
    );
}

fn is_scanned_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(".rs") && !name.ends_with("tests.rs")
}

fn collect(dir: &Path, root: &Path, found: &mut BTreeSet<String>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|err| panic!("read dir entry: {err}"));
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            // `*_tests` covers the inline test trees composition keeps beside
            // production modules (e.g. `factory/standalone_host_tests/`).
            if matches!(name, "tests" | "examples" | "benches" | "target")
                || name.ends_with("_tests")
            {
                continue;
            }
            collect(&path, root, found);
            continue;
        }
        if !is_scanned_file(&path) {
            continue;
        }
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        if !strip_comments_and_strings(&source).contains("RebornCompositionProfile::") {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        found.insert(relative);
    }
}

#[test]
fn deployment_mode_branching_allowlist_is_frozen_and_only_shrinks() {
    let root = crate_path(&workspace_root(), "crates/ironclaw_composition/src");
    let mut found = BTreeSet::new();
    collect(&root, &root, &mut found);

    let allowed: BTreeSet<String> = ALLOWLIST
        .iter()
        .map(|(path, _)| (*path).to_string())
        .collect();

    let new_debt: Vec<&String> = found.difference(&allowed).collect();
    assert!(
        new_debt.is_empty(),
        "new deployment-mode branching in composition: {new_debt:?}\n\
         A `RebornCompositionProfile` variant in a production file means code is \
         reading a deployment mode to decide what to do (§4.4). Add the axis to \
         `DeploymentConfig` and read that field instead. If the reference is a \
         display label with no behaviour attached, add the file to ALLOWLIST \
         with that justification."
    );

    let retired: Vec<&String> = allowed.difference(&found).collect();
    assert!(
        retired.is_empty(),
        "ALLOWLIST names files that no longer reference a composition profile: \
         {retired:?}\n\
         The ratchet may only shrink: delete these entries in the same PR that \
         retired them, so the allowlist keeps meaning what it says."
    );
}

#[test]
fn deployment_rs_is_the_target_state_entry() {
    // The definition of done is `{deployment.rs}`. Pin that the target entry is
    // present and documented as terminal, so a future cleanup does not
    // accidentally drive the allowlist to empty and delete the one place a
    // profile is *supposed* to become data.
    let target = ALLOWLIST
        .iter()
        .find(|(path, _)| *path == "deployment.rs")
        .expect("deployment.rs must stay on the allowlist as the target state");
    assert!(
        target.1.contains("TARGET STATE"),
        "deployment.rs's allowlist reason must mark it terminal, got: {}",
        target.1
    );
}

#[test]
fn deployment_rs_allows_only_the_deployment_config_profile_control() {
    let deployment = crate_path(
        &workspace_root(),
        "crates/ironclaw_composition/src/deployment.rs",
    );
    let source = std::fs::read_to_string(&deployment)
        .unwrap_or_else(|error| panic!("read {}: {error}", deployment.display()));

    assert_only_deployment_config_for_profile_control(&source);
}

#[test]
fn allowlist_is_sorted_and_unique() {
    let paths: Vec<&str> = ALLOWLIST.iter().map(|(path, _)| *path).collect();
    let mut sorted = paths.clone();
    sorted.sort_unstable();
    assert_eq!(
        paths, sorted,
        "ALLOWLIST must stay sorted for reviewability"
    );
    let unique: BTreeSet<&str> = paths.iter().copied().collect();
    assert_eq!(unique.len(), paths.len(), "ALLOWLIST has duplicate entries");
}

#[test]
fn scanner_strips_comments_and_strings() {
    // Self-test (§10: every check ships with its own self-test). Without
    // stripping, this ratchet's own doc comment would put it on the list.
    let source = r#"
        // RebornCompositionProfile::Standalone in a line comment
        /* RebornCompositionProfile::Production in a block comment */
        let label = "RebornCompositionProfile::Disabled";
    "#;
    let stripped = strip_comments_and_strings(source);
    assert!(
        !stripped.contains("RebornCompositionProfile::"),
        "stripped source still contains a variant path: {stripped}"
    );

    let real = "match profile { RebornCompositionProfile::Standalone => 1, _ => 0 }";
    assert!(
        strip_comments_and_strings(real).contains("RebornCompositionProfile::"),
        "real branching must survive stripping"
    );

    // Regression (2026-07-19 gemini review): a char literal containing `"` must
    // not open a string and swallow a following branch. Before the char-literal
    // handling, `'"'` flipped in_string and the DeploymentMode match after it
    // was hidden from the scan — a silent ratchet false negative.
    let with_char_literal = r#"
        let quote = '"';
        match profile { RebornCompositionProfile::Standalone => 1, _ => 0 }
    "#;
    assert!(
        strip_comments_and_strings(with_char_literal).contains("RebornCompositionProfile::"),
        "a `'\"'` char literal must not hide the branch after it"
    );
    // The char literal itself is dropped (it is not a lifetime), and a real
    // lifetime is preserved.
    assert!(!strip_comments_and_strings("let c = '\"';").contains('"'));
    assert!(strip_comments_and_strings("fn f<'a>(x: &'a str) {}").contains("'a"));
}

#[test]
fn syntax_aware_profile_control_scanner_ignores_cfg_test_items_structurally() {
    let source = r#"
        struct DeploymentConfig;
        impl DeploymentConfig {
            fn for_profile(profile: RebornCompositionProfile) {
                match profile { RebornCompositionProfile::Standalone => (), _ => () }
            }
        }
        fn unrelated() {
            // match selected_profile { RebornCompositionProfile::Production => (), _ => () }
            let profile_label = "matches!(selected_profile, RebornCompositionProfile::Production)";
            let _ = profile_label;
        }
        #[cfg(test)]
        mod tests {
            fn duplicate(selected_profile: RebornCompositionProfile) {
                match selected_profile { RebornCompositionProfile::Production => (), _ => () }
            }
        }
        #[cfg(test)]
        fn direct_test_helper(selected_profile: RebornCompositionProfile) {
            if selected_profile == RebornCompositionProfile::Production {}
        }
    "#;

    assert_only_deployment_config_for_profile_control(source);
}

#[test]
fn syntax_aware_profile_control_scanner_rejects_realistic_duplicate_forms() {
    let permitted = r#"
        struct DeploymentConfig;
        impl DeploymentConfig {
            fn for_profile(profile: RebornCompositionProfile) {
                match profile { RebornCompositionProfile::Standalone => (), _ => () }
            }
        }
    "#;
    let cases = [
        (
            "renamed match scrutinee",
            r#"
                fn bypass(selected_profile: RebornCompositionProfile) {
                    match selected_profile { RebornCompositionProfile::Production => (), _ => () }
                }
            "#,
        ),
        (
            "borrowed match scrutinee",
            r#"
                fn bypass(profile: &RebornCompositionProfile) {
                    match *profile { RebornCompositionProfile::Production => (), _ => () }
                }
            "#,
        ),
        (
            "matches macro",
            r#"
                fn bypass(selected_profile: RebornCompositionProfile) {
                    if matches!(selected_profile, RebornCompositionProfile::Production) {}
                }
            "#,
        ),
        (
            "std-qualified matches macro",
            r#"
                fn bypass(selected_profile: RebornCompositionProfile) {
                    if std::matches!(selected_profile, RebornCompositionProfile::Production) {}
                }
            "#,
        ),
        (
            "core-qualified matches macro",
            r#"
                fn bypass(selected_profile: RebornCompositionProfile) {
                    if core::matches!(selected_profile, RebornCompositionProfile::Production) {}
                }
            "#,
        ),
        (
            "if let",
            r#"
                fn bypass(selected_profile: RebornCompositionProfile) {
                    if let RebornCompositionProfile::Production = selected_profile {}
                }
            "#,
        ),
        (
            "struct pattern",
            r#"
                fn bypass(selected_profile: RebornCompositionProfile) {
                    if let RebornCompositionProfile::Production {} = selected_profile {}
                }
            "#,
        ),
        (
            "tuple struct pattern",
            r#"
                fn bypass(selected_profile: RebornCompositionProfile) {
                    match selected_profile { RebornCompositionProfile::Production(..) => (), _ => () }
                }
            "#,
        ),
        (
            "equality",
            r#"
                fn bypass(selected_profile: RebornCompositionProfile) {
                    if selected_profile == RebornCompositionProfile::Production {}
                }
            "#,
        ),
    ];

    for (name, duplicate) in cases {
        let source = format!("{permitted}\n{duplicate}");
        let failure = std::panic::catch_unwind(|| {
            assert_only_deployment_config_for_profile_control(&source);
        })
        .err()
        .unwrap_or_else(|| panic!("{name} must be rejected"));
        let message = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .unwrap_or("non-string panic payload");
        assert!(
            message.contains("profile-dependent control"),
            "unexpected {name} failure: {message}"
        );
    }
}
