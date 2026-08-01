//! CHECKLIST WS5 — the `conversations`/`threads` naming trap and the
//! `attachments` widening (PROPOSAL §6.4.1, §6.4.2, §6.4.9).
//!
//! Three rules, each pinning one half of that work so it cannot silently
//! regress:
//!
//! 1. **`ironclaw_conversations` and `ironclaw_threads` share no type name.**
//!    Discovered, not enumerated: every type either crate declares is compared
//!    against the other's, so a *new* collision is caught the day it is
//!    introduced rather than the day someone has to alias around it. Before
//!    this row the two crates shared five names — `SessionThreadService`,
//!    `AcceptInboundMessageRequest`, `AcceptedInboundMessage`,
//!    `AcceptedInboundMessageReplay`, `ThreadMessageRecord` — and the one file
//!    that had to hold both, composition's trusted-trigger submit, carried four
//!    `as Canonical…` aliases to say which was which. Names are the contract
//!    here: a caller that picks the wrong `accept_inbound_message` writes to the
//!    wrong store, and it still compiles.
//!
//! 2. **The external actor/conversation pair has one home**, and it is
//!    `ironclaw_extension_contracts` — not `ironclaw_conversations`, which used
//!    to carry a second, field-divergent copy (`thread_id`/`message_id` versus
//!    `topic_id`/`reply_target_message_id`) that `ironclaw_product` bridged with
//!    hand-written field-by-field translators. Neither the second definition nor
//!    the translators may come back. This complements
//!    `reborn_extension_contract_location_scan.rs`, whose `COLLISION_EXEMPT`
//!    carve-out for the pair was **deleted** rather than repointed when the
//!    duplicate went away; this file states the outcome positively so a
//!    re-introduction fails with the reason attached.
//!
//! 3. **`ironclaw_attachments` is the one home for the attachment ports and the
//!    size ceilings.** §6.4.9 widens it to hold "the single landing routine plus
//!    its ports" and "one home for the size-ceiling constants (webui/openai
//!    import them)"; the failure mode it closes is a transport advertising one
//!    ceiling while the landing routine enforces another. So the ports and the
//!    advertised-capabilities builder must be declared there and **not** in
//!    `ironclaw_product`.
//!
//! **What is deliberately not asserted:** that `ProjectScopedAttachmentReader`
//! moved. It cannot. It implements `ironclaw_loop_host::LoopAttachmentReadPort`
//! as well as `InboundAttachmentReader`, and `ironclaw_loop_host` is a
//! `loops`-layer crate a `substrates` crate may not depend on — and once the
//! struct moved, that impl would have neither side in `ironclaw_product`, so the
//! orphan rule forbids leaving it behind too. Test 3c pins the reader *in
//! product* for that reason, so "finishing the row" cannot quietly mean moving
//! it and dragging the loop tier into a substrate.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

// Only part of the shared ratchet module is reachable from this binary.
#[allow(dead_code)]
mod ratchet_support;

use ratchet_support::{TypeDefOccurrence, collect_type_defs, workspace_root};

const TYPE_KEYWORDS: &[&str] = &["trait ", "struct ", "enum "];

/// This scanner's own file, skipped so its fixtures do not look like
/// definitions.
const SELF_FILE: &str = "reborn_conversations_threads_attachments.rs";

fn is_rust_identifier(ident: &str) -> bool {
    let mut chars = ident.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// Every type, trait and enum a crate declares in its production source.
fn declared_names(root: &Path, crate_name: &str) -> BTreeSet<String> {
    let mut found: BTreeMap<String, Vec<TypeDefOccurrence>> = BTreeMap::new();
    let dir = root.join("crates").join(crate_name).join("src");
    assert!(
        dir.is_dir(),
        "{crate_name} must have a src/ directory; this scan is vacuous otherwise"
    );
    collect_type_defs(
        &dir,
        TYPE_KEYWORDS,
        &is_rust_identifier,
        &[SELF_FILE],
        &mut found,
    );
    assert!(
        !found.is_empty(),
        "no types were discovered in {crate_name} — the walk is broken, not the crate"
    );
    found.into_keys().collect()
}

/// Read a crate's production source as one string, with `//`-comments and
/// string literals removed, so a name in prose or in an error message never
/// counts as code.
fn stripped_production_source(root: &Path, crate_name: &str) -> String {
    fn walk(dir: &Path, out: &mut String) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|err| panic!("failed to read dir entry: {err}"));
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str());
                if matches!(name, Some("target" | "tests" | "examples" | "benches")) {
                    continue;
                }
                walk(&path, out);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
            out.push_str(&strip_comments_and_strings(&source));
            out.push('\n');
        }
    }

    let dir = root.join("crates").join(crate_name).join("src");
    let mut out = String::new();
    walk(&dir, &mut out);
    assert!(
        !out.trim().is_empty(),
        "{crate_name}'s production source scanned empty — the walk is broken"
    );
    out
}

/// Line-based comment/string stripping. Deliberately conservative: it removes
/// `//` line comments and double-quoted literals, which is what makes "the name
/// appears in a doc comment" and "the name appears in a panic message" not
/// count as a declaration.
fn strip_comments_and_strings(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.lines() {
        let mut in_string = false;
        let mut escaped = false;
        let mut kept = String::with_capacity(line.len());
        let bytes: Vec<char> = line.chars().collect();
        let mut index = 0;
        while index < bytes.len() {
            let ch = bytes[index];
            if in_string {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
                index += 1;
                continue;
            }
            if ch == '"' {
                in_string = true;
                index += 1;
                continue;
            }
            if ch == '/' && index + 1 < bytes.len() && bytes[index + 1] == '/' {
                break;
            }
            kept.push(ch);
            index += 1;
        }
        out.push_str(&kept);
        out.push('\n');
    }
    out
}

/// The five names that collided before this row, kept by name so the failure
/// message can say what the fix was the last time.
const HISTORIC_COLLISIONS: &[&str] = &[
    "SessionThreadService",
    "AcceptInboundMessageRequest",
    "AcceptedInboundMessage",
    "AcceptedInboundMessageReplay",
    "ThreadMessageRecord",
];

#[test]
fn conversations_and_threads_declare_no_name_in_common() {
    let root = workspace_root();
    let conversations = declared_names(&root, "ironclaw_conversations");
    let threads = declared_names(&root, "ironclaw_threads");

    // Non-vacuity: both sets must be substantial, or an empty intersection
    // proves nothing.
    assert!(
        conversations.len() > 20,
        "expected ironclaw_conversations to declare many types, found {}",
        conversations.len()
    );
    assert!(
        threads.len() > 20,
        "expected ironclaw_threads to declare many types, found {}",
        threads.len()
    );

    let shared: Vec<&String> = conversations.intersection(&threads).collect();
    let shared_count = shared.len();
    assert!(
        shared.is_empty(),
        "ironclaw_conversations and ironclaw_threads declare {shared_count} name(s) in common: {shared:?}\n\
         \n\
         These two crates are the audited worst naming trap in the Reborn tree \
         (PROPOSAL §6.4.1/§6.4.2): one owns external↔canonical *binding* and \
         idempotency, the other owns the canonical *transcript*. A shared name \
         means a caller can import the wrong one, call the same method, and \
         write to the wrong store — and it compiles. CHECKLIST WS5 discharged \
         five such names ({HISTORIC_COLLISIONS:?}) by renaming the conversations \
         side (`SessionThreadService` → `InboundConversationService`, the \
         `AcceptedInboundMessage*` family → `AcceptedConversationMessage*`, \
         `ThreadMessageRecord` → `ConversationMessageRecord`).\n\
         Rename the new one on whichever side is the weaker claim to it — do not \
         add an exemption here, and do not alias at the import site."
    );

    // The rename actually landed on the conversations side, and the canonical
    // transcript kept the names it had. Pinned so a later "fix" that renames
    // `ironclaw_threads` instead — which would churn ~70 files and lose the
    // argument — fails loudly.
    for name in HISTORIC_COLLISIONS {
        assert!(
            threads.contains(*name),
            "{name} must stay declared in ironclaw_threads: the transcript crate is the \
             stronger claim to the thread/message vocabulary, and the WS5 rename moved the \
             conversations side, not this one"
        );
        assert!(
            !conversations.contains(*name),
            "{name} is declared in ironclaw_conversations again — this is the exact collision \
             CHECKLIST WS5 removed"
        );
    }
    for name in [
        "InboundConversationService",
        "AcceptConversationMessageRequest",
        "AcceptedConversationMessage",
        "AcceptedConversationMessageReplay",
        "ConversationMessageRecord",
    ] {
        assert!(
            conversations.contains(name),
            "{name} is the post-rename name and must be declared in ironclaw_conversations; \
             if it was renamed again, update this list in the same change"
        );
    }
}

#[test]
fn the_external_ref_pair_is_declared_only_by_the_extension_contracts_crate() {
    let root = workspace_root();
    let pair = ["ExternalActorRef", "ExternalConversationRef"];

    let owner = declared_names(&root, "ironclaw_extension_contracts");
    for name in pair {
        assert!(
            owner.contains(name),
            "{name} must be declared in ironclaw_extension_contracts — it is the channel tier's \
             vocabulary (PROPOSAL §6.1.2). If it moved, repoint this test in the same change"
        );
    }

    let conversations = declared_names(&root, "ironclaw_conversations");
    for name in pair {
        assert!(
            !conversations.contains(name),
            "ironclaw_conversations declares its own {name} again.\n\
             \n\
             It used to, with *different fields*: `thread_id`/`message_id` where the canonical \
             type says `topic_id`/`reply_target_message_id`, and no `display_name`. \
             `ironclaw_product` bridged the two with hand-written field-by-field translators \
             (`conversation_actor_ref` / `conversation_conversation_ref`), which is how a \
             conversion could silently drop a field. CHECKLIST WS5 unified them and deleted the \
             translators; the durable record grammar is preserved by \
             `ironclaw_conversations::stored_refs`, not by a second type"
        );
    }

    // The translators themselves must not come back. Checked against stripped
    // source so the names surviving in prose (a module doc, this file) do not
    // count.
    let product = stripped_production_source(&root, "ironclaw_product");
    for translator in [
        "fn conversation_actor_ref",
        "fn conversation_conversation_ref",
    ] {
        assert!(
            !product.contains(translator),
            "ironclaw_product declares `{translator}` again — the field-by-field translator \
             CHECKLIST WS5 deleted. The two types are one type now; pass the value through"
        );
    }

    // And conversations must not become a second *import path* for the pair
    // (PROPOSAL §11.2.4's re-export trap).
    let conversations_source = stripped_production_source(&root, "ironclaw_conversations");
    for name in pair {
        assert!(
            !conversations_source.contains(&format!("pub use ids::{name}"))
                && !conversations_source.contains(&format!(
                    "pub use ironclaw_extension_contracts::external::{name}"
                )),
            "ironclaw_conversations re-exports {name} — consumers must import it from its owner, \
             `ironclaw_extension_contracts::external`, not through this crate"
        );
    }
}

#[test]
fn the_attachment_ports_and_size_ceilings_live_in_the_attachments_crate() {
    let root = workspace_root();
    let attachments = declared_names(&root, "ironclaw_attachments");
    let product = declared_names(&root, "ironclaw_product");

    // The ports and the advertised-ceiling DTO belong to the crate that owns
    // the landing routine (§6.4.9).
    for name in [
        "InboundAttachmentLander",
        "InboundAttachmentReader",
        "AttachmentCleanupReport",
        "AttachmentBudgets",
        "AttachmentCapabilities",
        "ProjectScopedAttachmentLander",
    ] {
        assert!(
            attachments.contains(name),
            "{name} must be declared in ironclaw_attachments (PROPOSAL §6.4.9: the landing \
             routine plus its ports, and one home for the size ceilings)"
        );
        assert!(
            !product.contains(name),
            "{name} is declared in ironclaw_product again — that is the three-crate spread \
             CHECKLIST WS5's `attachments widened` row closed. A transport that advertises a \
             ceiling and the routine that enforces it must read the same constant"
        );
    }

    // The builder is a free function, so the type walk cannot see it.
    let attachments_source = stripped_production_source(&root, "ironclaw_attachments");
    assert!(
        attachments_source.contains("pub fn attachment_capabilities"),
        "ironclaw_attachments must declare `attachment_capabilities()` — the advertised half of \
         the ceilings it enforces"
    );
    let product_source = stripped_production_source(&root, "ironclaw_product");
    assert!(
        !product_source.contains("fn product_attachment_capabilities"),
        "ironclaw_product declares `product_attachment_capabilities()` again — it moved to \
         ironclaw_attachments as `attachment_capabilities()`"
    );

    // 3c — the reader adapter deliberately stays in product. See the module doc.
    assert!(
        product.contains("ProjectScopedAttachmentReader"),
        "ProjectScopedAttachmentReader must stay declared in ironclaw_product: it also \
         implements ironclaw_loop_host::LoopAttachmentReadPort, and ironclaw_attachments is a \
         `substrates` crate that may not depend on the `loops` layer — moving it would either \
         invert a layer edge or orphan that impl"
    );
    assert!(
        !attachments.contains("ProjectScopedAttachmentReader"),
        "ProjectScopedAttachmentReader moved into ironclaw_attachments — check whether that \
         crate now depends on ironclaw_loop_host, which the layer matrix forbids"
    );
    let attachments_manifest =
        std::fs::read_to_string(root.join("crates/ironclaw_attachments/Cargo.toml"))
            .expect("ironclaw_attachments must have a manifest");
    assert!(
        !attachments_manifest.contains("ironclaw_loop_host"),
        "ironclaw_attachments must not depend on ironclaw_loop_host: `substrates` may not name \
         `loops`"
    );
}

/// Self-test: the strip must remove prose and literals but keep code, or every
/// assertion above that reads stripped source is measuring the wrong thing.
#[test]
fn the_source_strip_removes_prose_and_literals_but_not_code() {
    let stripped = strip_comments_and_strings(
        r#"
/// fn conversation_actor_ref in a doc comment
// fn conversation_actor_ref in a line comment
fn real_code() -> &'static str { "fn conversation_actor_ref in a literal" }
pub fn attachment_capabilities() -> u8 { 0 } // trailing fn conversation_actor_ref
"#,
    );
    assert!(
        !stripped.contains("fn conversation_actor_ref"),
        "prose and literals must not survive the strip: {stripped}"
    );
    assert!(stripped.contains("fn real_code"), "code must survive");
    assert!(
        stripped.contains("pub fn attachment_capabilities"),
        "code before a trailing comment must survive"
    );
}

/// Self-test for the declaration walk: a name only *mentioned* is not
/// discovered, and one actually declared is.
#[test]
fn the_declaration_walk_finds_declarations_not_mentions() {
    let root = workspace_root();
    let conversations = declared_names(&root, "ironclaw_conversations");
    assert!(
        conversations.contains("InboundTurnService"),
        "a type ironclaw_conversations really declares must be discovered"
    );
    assert!(
        !conversations.contains("ThreadScope"),
        "ThreadScope is only *named* by ironclaw_conversations' dependencies, never declared \
         there — if the walk reports it, the walk is matching references"
    );
}
