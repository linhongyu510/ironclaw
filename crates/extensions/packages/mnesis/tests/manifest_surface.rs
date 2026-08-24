use std::path::PathBuf;

const MANIFEST: &str = include_str!("../manifest.toml");

fn package_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn schema_refs() -> Vec<String> {
    MANIFEST
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (key, value) = line.split_once('=')?;
            if !key.trim().ends_with("schema_ref") {
                return None;
            }
            Some(value.trim().trim_matches('"').to_string())
        })
        .collect()
}

#[test]
fn every_schema_ref_resolves_to_a_file_in_the_package() {
    let refs = schema_refs();
    assert!(refs.len() >= 4, "expected input and output refs per tool");
    for reference in refs {
        let path = package_root().join(&reference);
        assert!(path.is_file(), "{reference} does not resolve to a file");
        let raw = std::fs::read_to_string(&path).expect("schema is readable");
        serde_json::from_str::<serde_json::Value>(&raw)
            .unwrap_or_else(|error| panic!("{reference} is not valid JSON: {error}"));
    }
}

/// Administrative capability may be declared, but never invoked unattended: the
/// model can see these tools and must still be granted each one.
#[test]
fn every_administrative_tool_is_gated() {
    let administrative = [
        "reindex",
        "consolidat",
        "promote",
        "decompile",
        "bootstrap",
        "export",
        "tenant_control",
        "attestation",
        "maintenance",
        "rotate",
    ];
    let mut checked = 0;
    for block in MANIFEST.split("[[tools]]").skip(1) {
        let id = block
            .lines()
            .find_map(|line| line.trim().strip_prefix("id = "))
            .map(|value| value.trim().trim_matches('"').to_ascii_lowercase())
            .expect("every tool block declares an id");
        if !administrative.iter().any(|term| id.contains(term)) {
            continue;
        }
        checked += 1;
        assert!(
            block.contains("loop_run = \"gated_unless_granted\""),
            "administrative tool {id} must be gated for loop_run"
        );
    }
    assert!(
        checked > 0,
        "the scan matched no administrative tool, so it proves nothing"
    );
}

#[test]
fn the_write_path_is_host_driven_and_never_model_visible() {
    let lowered = MANIFEST.to_ascii_lowercase();
    assert!(
        lowered.contains("lifecycle = [\"read_long_term\", \"record_interaction\"]"),
        "an undeclared hook is never called: the short-term lane stays undeclared until a \
         credentialed canary proves its tool round-trips, because a declared hook whose tool \
         the server does not register fails every threaded turn"
    );
    assert!(
        !lowered.contains("network"),
        "no declared tool may carry the network effect: the lanes are reached through the \
         provider's mediated transport, matching how the sibling REST provider declares itself"
    );
    // A model-visible write is allowed, but never ungated. The transcript write
    // stays a lifecycle hook; a tool that mutates memory must be a decision the
    // user can withhold.
    for block in MANIFEST.split("[[tools]]").skip(1) {
        if !block.contains("write_filesystem") {
            continue;
        }
        assert!(
            block.contains("loop_run = \"gated_unless_granted\""),
            "a tool carrying write_filesystem must be gated for loop_run: {block}"
        );
    }
    // `record_interaction` is a host-driven lifecycle hook, never a capability the
    // model can call: it must appear only under [memory], not as a tool id.
    for line in MANIFEST.lines() {
        if line.trim_start().starts_with("id = ") {
            assert!(
                !line.contains("record_interaction"),
                "recording must not be exposed as a model-callable tool: {line}"
            );
        }
    }
}

#[test]
fn the_two_lanes_stay_distinct_and_are_never_presented_as_one_surface() {
    assert!(
        MANIFEST.contains("ironclaw.memory.search"),
        "the memory lane keeps the stable IronClaw tool id"
    );
    assert!(
        MANIFEST.contains("mnesis.hosted.memory.knowledge.search"),
        "corpus retrieval is a distinct tool, not an ironclaw.memory.* id"
    );
    let memory_output =
        std::fs::read_to_string(package_root().join("schemas/memory/search.output.v1.json"))
            .expect("memory output schema");
    let knowledge_output =
        std::fs::read_to_string(package_root().join("schemas/knowledge/search.output.v1.json"))
            .expect("knowledge output schema");
    assert!(memory_output.contains("\"const\": \"memory\""));
    assert!(knowledge_output.contains("\"const\": \"rar\""));
    assert!(
        knowledge_output.contains("generation"),
        "corpus evidence must carry its index generation"
    );
}

#[test]
fn no_tool_description_invites_a_model_supplied_scope_override() {
    let lowered = MANIFEST.to_ascii_lowercase();
    for tempting in ["tenant_id", "user_id", "principal_id", "owner_scope"] {
        assert!(
            !lowered.contains(tempting),
            "a tool schema must not accept {tempting} from the model"
        );
    }
    assert!(
        lowered
            .matches("cannot be supplied or widened by the model")
            .count()
            >= 2,
        "each tool states that scope is trusted, not model supplied"
    );
}
