//! The MCP tool surface, pinned against its frozen fixture.
//!
//! Two tool names shipped wrong before this suite existed. Both were inherited
//! from `provider-request-v1.json`, whose `operation` strings describe the
//! pre-MCP provider envelope rather than registered tool names, and neither was
//! asserted anywhere: the fault surfaces only as an `isError` from a live lane,
//! which no deterministic test reaches because every fake echoes back whatever
//! name it is handed.

use ironclaw_memory_mnesis::{
    MAX_CONTEXT_SNIPPETS, MAX_KNOWLEDGE_SEARCH_RESULTS, MAX_MEMORY_SEARCH_RESULTS, MnesisLane,
    MnesisTool,
};
use serde_json::Value;

const MANIFEST: &str = include_str!("../manifest.toml");

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/mcp-tools-v1.json"))
        .expect("the frozen tool fixture must be valid JSON")
}

fn tools() -> Vec<Value> {
    fixture()["tools"]
        .as_array()
        .expect("the fixture must declare a tool table")
        .clone()
}

fn entry_for(tool: MnesisTool) -> Value {
    let variant = format!("{tool:?}");
    tools()
        .into_iter()
        .find(|entry| entry["variant"].as_str() == Some(variant.as_str()))
        .unwrap_or_else(|| panic!("the frozen fixture does not describe {variant}"))
}

/// The declared lifecycle set, read from the manifest rather than restated.
fn declared_lifecycle_hooks() -> Vec<String> {
    let line = MANIFEST
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("lifecycle"))
        .expect("the manifest must declare a [memory] lifecycle");
    let (_, list) = line
        .split_once('=')
        .expect("lifecycle must be an assignment");
    list.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|hook| hook.trim().trim_matches('"').to_string())
        .filter(|hook| !hook.is_empty())
        .collect()
}

#[test]
fn every_tool_variant_is_described_by_the_frozen_fixture() {
    assert_eq!(
        tools().len(),
        MnesisTool::ALL.len(),
        "a tool was added or removed without moving the frozen fixture with it"
    );
    for tool in MnesisTool::ALL {
        entry_for(tool);
    }
}

#[test]
fn each_tool_sends_the_frozen_wire_name_on_its_frozen_lane() {
    for tool in MnesisTool::ALL {
        let entry = entry_for(tool);
        assert_eq!(
            tool.wire_name(),
            entry["wire_name"]
                .as_str()
                .expect("every entry must carry a wire name"),
            "{tool:?} no longer sends the tool name Mnesis registers"
        );
        let lane = match entry["lane"].as_str() {
            Some("memory") => MnesisLane::Memory,
            Some("knowledge") => MnesisLane::Knowledge,
            other => panic!("{tool:?} declares an unmodelled lane: {other:?}"),
        };
        assert_eq!(tool.lane(), lane, "{tool:?} moved lane");
        assert_eq!(
            tool.lifecycle_hook(),
            entry["lifecycle_hook"].as_str(),
            "{tool:?} changed which lifecycle hook it backs"
        );
    }
}

/// The guard the two shipped defects needed: a hook the manifest declares is a
/// hook the host calls every turn, so its tool must be one a live lane answered.
#[test]
fn no_lifecycle_hook_is_declared_against_an_unconfirmed_tool() {
    for hook in declared_lifecycle_hooks() {
        let Some(tool) = MnesisTool::ALL
            .into_iter()
            .find(|tool| tool.lifecycle_hook() == Some(hook.as_str()))
        else {
            panic!("the manifest declares {hook}, which no tool backs");
        };
        assert_eq!(
            entry_for(tool)["registration_confirmed"].as_bool(),
            Some(true),
            "{hook} is declared but {tool:?} has never been confirmed registered; \
             confirm it with a credentialed canary and record that in the fixture, \
             or withdraw the hook from the manifest"
        );
    }
}

#[test]
fn the_lane_result_ceilings_match_the_frozen_provider_boundaries() {
    let boundaries: Value = serde_json::from_str(include_str!("fixtures/provider-request-v1.json"))
        .expect("the frozen request fixture must be valid JSON");
    let declared = |key: &str| {
        boundaries["boundaries"][key]
            .as_u64()
            .unwrap_or_else(|| panic!("the frozen boundaries must declare {key}")) as usize
    };
    assert_eq!(
        MnesisLane::Memory.max_results(),
        declared("maximumMemorySearchResults")
    );
    assert_eq!(
        MnesisLane::Knowledge.max_results(),
        declared("maximumKnowledgeSearchResults")
    );
    assert_eq!(MAX_CONTEXT_SNIPPETS, declared("maximumContextSnippets"));
    assert_eq!(MAX_MEMORY_SEARCH_RESULTS, MnesisLane::Memory.max_results());
    assert_eq!(
        MAX_KNOWLEDGE_SEARCH_RESULTS,
        MnesisLane::Knowledge.max_results()
    );
}
