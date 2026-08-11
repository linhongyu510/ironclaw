//! Reborn integration — omp registration seam (issue #7392 slice 3).
//!
//! Drives the production first-party surface end to end through the REAL turn
//! stack (product workflow → turn coordinator → agent loop → real
//! `ironclaw_llm` decorator chain → scripted model at the vendor-SDK seam).
//!
//! 1. The model-visible tool surface advertises EXACTLY the pinned names
//!    `read`/`write`/`edit`/`glob`/`grep` with the pinned fixture schemas
//!    and descriptions (byte equality on the provider payload), while the
//!    old coding tools (`read_file`/`write_file`/`list_dir`/`apply_patch`)
//!    coexist under their derived names — the benchmark arm keeps both
//!    surfaces; only `builtin.glob`/`builtin.grep` are replaced (their
//!    canonical ids are reused by the omp engines).
//! 2. A scripted `read` → `edit` (with the returned hashline tag) → `read`
//!    chain flows the exact omp output shapes back as tool results
//!    (hashline header `[file#TAG]`, numbered rows; edit success header +
//!    preview), and the edit really mutates the workspace file.
//! 3. The derived spelling (`builtin__read`) still resolves for back-compat
//!    within the override seam.
//! 4. A gated omp `write` raises a real `BlockedApproval` gate through the
//!    ordinary approval path and persists after approval.
//!
//! The production-shaped harness selects the canonical omp-first package via
//! its focused coding-tools profile; there is no old/new factory split.
//!
//! Stack note: every test here runs on a dedicated 16 MiB-stack thread
//! ([`run_async_test_with_stack`]), mirroring `process_port.rs`'s
//! `live_shell_uses_local_process_port` and `reborn_sandbox_shell_turn.rs`.
//! The omp-selected harness builds through the production-shaped composition
//! (`build_production_shaped`), whose debug async-state-machine chain alone
//! consumes >2 MiB of stack — over the default 2 MiB libtest thread stack —
//! BEFORE any turn runs or tool definitions are read. It is a deep-but-bounded
//! flat chain, not recursion (the deepest build leaf is reached once, at
//! depth 0; the golden default-surface tests ride the lighter hand-built
//! runtime path and do not overflow). CI covers the whole integration tier
//! with an 8 MiB `RUST_MIN_STACK` lane env; locally the 16 MiB thread matches
//! the existing convention for this exact build class.

#[allow(dead_code)]
#[path = "support/mod.rs"]
mod reborn_support;
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;

use reborn_support::builder::RebornIntegrationHarness;
use reborn_support::group::RebornIntegrationGroup;
use reborn_support::reply::RebornScriptedReply;
use serde_json::json;
use std::future::Future;
use support::omp_coding_contract::{rendered_tool_prompt, tool_prompt, tool_schema};

/// The five omp tools and their pinned provider names (must match the
/// fixture manifest's `tool_names` subset for `read`/`write`/`edit`/`glob`/
/// `grep`).
const OMP_TOOLS: [(&str, &str); 5] = [
    ("builtin.read", "read"),
    ("builtin.write", "write"),
    ("builtin.edit", "edit"),
    ("builtin.glob", "glob"),
    ("builtin.grep", "grep"),
];

/// The pinned model-visible description for `tool` (the fixture prompt bytes
/// the registration seam embeds). `read` uses the rendered prompt; the
/// others the verbatim prompt files.
fn pinned_description(tool: &str) -> String {
    rendered_tool_prompt(tool).unwrap_or_else(|| tool_prompt(tool))
}

fn output_text(value: &serde_json::Value) -> String {
    value
        .get("output")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("omp tool result carries an output text: {value}"))
        .to_string()
}

/// The omp surface advertises exactly the pinned names, schemas, and
/// descriptions on the model-visible provider payload, with the old tools
/// coexisting under their derived names.
#[test]
fn omp_surface_advertises_exact_names_schemas_and_descriptions() {
    run_async_test_with_stack(
        "omp_surface_advertises_exact_names_schemas_and_descriptions",
        || async {
            let h = RebornIntegrationHarness::test_default()
                .with_omp_coding_tools()
                .script([RebornScriptedReply::text("surface captured")])
                .build()
                .await
                .expect("harness builds");
            h.submit_turn("list your tools")
                .await
                .expect("turn completes");

            let definitions = h.scripted_llm.captured_tool_definitions();
            let definitions = definitions.into_iter().flatten().collect::<Vec<_>>();
            assert!(
                !definitions.is_empty(),
                "the model request must carry tool definitions"
            );

            let mut seen = std::collections::HashMap::new();
            for definition in &definitions {
                seen.entry(definition.name.clone())
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
                if let Some((_, pinned_name)) = OMP_TOOLS
                    .iter()
                    .find(|(_, pinned_name)| *pinned_name == definition.name)
                {
                    let tool = pinned_name;
                    assert_eq!(
                        definition.parameters,
                        tool_schema(tool),
                        "schema for omp tool {tool} must byte-match the pinned fixture"
                    );
                    assert_eq!(
                        definition.description,
                        pinned_description(tool),
                        "description for omp tool {tool} must byte-match the pinned fixture prompt"
                    );
                }
            }

            // The five omp names are advertised EXACTLY once each.
            for (_, pinned_name) in OMP_TOOLS {
                assert_eq!(
                    seen.get(pinned_name),
                    Some(&1),
                    "omp tool {pinned_name} must be advertised exactly once"
                );
            }

            // Retired coding tools and derived glob/grep spellings are absent.
            for retired in [
                "builtin__read_file",
                "builtin__write_file",
                "builtin__list_dir",
                "builtin__apply_patch",
                "builtin__glob",
                "builtin__grep",
                "builtin__result_read",
            ] {
                assert!(
                    !seen.contains_key(retired),
                    "retired tool {retired} must not remain after the atomic cutover"
                );
            }
        },
    );
}

/// A scripted `read` → `edit` (anchored on the read's hashline tag) → `read`
/// chain through the real capability path: exact omp output shapes flow back
/// as tool results and the edit really mutates the workspace file.
#[test]
fn omp_read_edit_read_chain_flows_exact_shapes() {
    run_async_test_with_stack("omp_read_edit_read_chain_flows_exact_shapes", || async {
        let content = "line1\nline2\nline3\n";
        let changed = "line1\nCHANGED\nline3\n";
        let tag = ironclaw_extension_support::coding::omp::harness::compute_file_hash(content);

        let h = RebornIntegrationHarness::test_default()
            .with_omp_coding_tools()
            .script([
                RebornScriptedReply::tool_call("read", json!({ "path": "/workspace/foo.txt" })),
                RebornScriptedReply::tool_call(
                    "edit",
                    json!({ "input": format!("[/workspace/foo.txt#{tag}]\nPUT 2:\n+CHANGED\n") }),
                ),
                RebornScriptedReply::tool_call("read", json!({ "path": "/workspace/foo.txt" })),
                RebornScriptedReply::text("edited"),
            ])
            .build()
            .await
            .expect("harness builds");
        // Seed the workspace file the omp tools will read/edit (the harness
        // workspace root backing the /workspace mount).
        let path = h
            .capability_recorder
            .workspace_file_path("foo.txt")
            .expect("host-runtime harness exposes the workspace root");
        std::fs::write(&path, content).expect("seed workspace file");
        h.submit_turn("read, edit, read the file")
            .await
            .expect("turn completes");

        // Read #1 saw the ORIGINAL content (numbered rows, hashline header).
        h.assert_tool_result_contains("[foo.txt#")
            .await
            .expect("read result carries the hashline header");
        h.assert_tool_result_contains("1:line1")
            .await
            .expect("read result carries numbered rows");
        h.assert_tool_result_contains("2:line2")
            .await
            .expect("the first read saw the original line 2");

        // The edit result is the exact success shape: refreshed snapshot header
        // + preview of the new line.
        let edit_output = output_text(
            &h.tool_result_output("builtin.edit")
                .await
                .expect("edit result"),
        );
        assert!(
            edit_output.starts_with("[/workspace/foo.txt#"),
            "edit output leads with the new snapshot header: {edit_output}"
        );
        assert!(
            edit_output.contains("2:CHANGED"),
            "edit preview shows the new line: {edit_output}"
        );

        // Read #2 sees the edited content (and only the edited content).
        let read2 = output_text(
            &h.tool_result_output("builtin.read")
                .await
                .expect("read result"),
        );
        assert!(
            read2.starts_with("[foo.txt#"),
            "read output leads with the hashline header: {read2}"
        );
        assert!(
            read2.contains("1:line1") && read2.contains("2:CHANGED") && read2.contains("3:line3"),
            "read #2 shows the edited file: {read2}"
        );
        assert!(
            !read2.contains("2:line2"),
            "read #2 must not show the stale line: {read2}"
        );

        // The edit really mutated the workspace file through RootFilesystem.
        h.assert_workspace_file_contains("foo.txt", changed)
            .await
            .expect("the edit persisted to the workspace file");
    });
}

/// The derived spelling of an overridden capability (`builtin__read`) still
/// resolves within the override seam — transcripts that call the derived
/// name keep working while the model is advertised the exact name.
#[test]
fn omp_derived_spelling_still_resolves() {
    run_async_test_with_stack("omp_derived_spelling_still_resolves", || async {
        let content = "alpha\nbeta\n";
        let h = RebornIntegrationHarness::test_default()
            .with_omp_coding_tools()
            .script([
                RebornScriptedReply::tool_call("builtin__read", json!({ "path": "foo.txt" })),
                RebornScriptedReply::text("read via derived spelling"),
            ])
            .build()
            .await
            .expect("harness builds");
        let path = h
            .capability_recorder
            .workspace_file_path("foo.txt")
            .expect("host-runtime harness exposes the workspace root");
        std::fs::write(&path, content).expect("seed workspace file");
        h.submit_turn("read the file by its encoded name")
            .await
            .expect("turn completes");

        let output = output_text(
            &h.tool_result_output("builtin.read")
                .await
                .expect("read result"),
        );
        assert!(
            output.starts_with("[foo.txt#")
                && output.contains("1:alpha")
                && output.contains("2:beta"),
            "the derived spelling builtin__read resolved to the omp engine: {output}"
        );
    });
}

/// A large omp result is persisted before the model sees its bounded preview,
/// and the same run can recover an exact line range through `read artifact://`.
#[test]
fn omp_large_read_spills_and_is_readable_by_artifact_selector() {
    run_async_test_with_stack(
        "omp_large_read_spills_and_is_readable_by_artifact_selector",
        || async {
            let content = (0..2_000)
                .map(|line| format!("payload-{line:04}-{}\n", "x".repeat(32)))
                .collect::<String>();
            let h = RebornIntegrationHarness::test_default()
                .with_omp_coding_tools()
                .script([
                    RebornScriptedReply::tool_call("read", json!({ "path": "large.txt" })),
                    RebornScriptedReply::tool_call("read", json!({ "path": "artifact://0:1-2" })),
                    RebornScriptedReply::text("artifact recovered"),
                ])
                .build()
                .await
                .expect("harness builds");
            let path = h
                .capability_recorder
                .workspace_file_path("large.txt")
                .expect("host-runtime harness exposes the workspace root");
            std::fs::write(&path, content).expect("seed large workspace file");

            h.submit_turn("read the large file, then recover its first two artifact lines")
                .await
                .expect("turn completes");
            let recovered = output_text(
                &h.tool_result_output("builtin.read")
                    .await
                    .expect("artifact read result"),
            );
            assert!(
                recovered.contains("1:[large.txt#") && recovered.contains("2:1:payload-0000-"),
                "artifact selector returns the first two exact spilled lines: {recovered}"
            );
        },
    );
}

/// The approval gate applies to the NEW capabilities: a scripted omp `write`
/// parks on a real `BlockedApproval` gate and only persists after approval.
#[test]
fn omp_gated_write_requires_approval() {
    run_async_test_with_stack("omp_gated_write_requires_approval", || async {
        let group = RebornIntegrationGroup::omp_coding_tools_with_approvals()
            .await
            .expect("omp approvals group builds");
        let h = group
            .thread("omp-gated-write")
            .script([
                RebornScriptedReply::tool_call(
                    "write",
                    json!({ "path": "/workspace/gated.txt", "content": "approved payload" }),
                ),
                RebornScriptedReply::text("file written"),
            ])
            .build()
            .await
            .expect("thread builds");

        let (run_id, gate_ref) = h
            .submit_turn_until_blocked("write the gated file")
            .await
            .expect("omp write raises a real approval gate");
        h.approve_gate(run_id, &gate_ref)
            .await
            .expect("gate approves");
        h.wait_for_status(run_id, ironclaw_turns::TurnStatus::Completed)
            .await
            .expect("run completes after resume");

        h.assert_workspace_file_contains("gated.txt", "approved payload")
            .await
            .expect("the approved omp write persisted to the workspace file");
    });
}

/// Runs the async test body on a dedicated 16 MiB-stack thread, mirroring
/// `tests/integration/process_port.rs`'s `run_with_larger_stack` and
/// `reborn_sandbox_shell_turn.rs`: the omp-selected harness builds through
/// the production-shaped composition (`build_production_shaped`), whose
/// debug async-state-machine chain alone consumes >2 MiB of stack — over the
/// default 2 MiB libtest thread stack (see the module doc's stack note).
fn run_async_test_with_stack<F, Fut>(name: &'static str, test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let handle = std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio test runtime")
                .block_on(test());
        })
        .expect("spawn stack-sized test thread");
    if let Err(panic) = handle.join() {
        std::panic::resume_unwind(panic);
    }
}
