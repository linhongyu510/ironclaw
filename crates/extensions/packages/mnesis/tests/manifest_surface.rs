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

#[test]
fn the_tool_inventory_carries_no_administrative_capability() {
    let forbidden = [
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
        "generation_promote",
    ];
    let lowered = MANIFEST.to_ascii_lowercase();
    for term in forbidden {
        assert!(
            !lowered.contains(term),
            "the model-visible surface must not expose {term}"
        );
    }
}

#[test]
fn no_tool_declares_a_write_effect_while_the_write_path_is_undeclared() {
    let lowered = MANIFEST.to_ascii_lowercase();
    for effect in ["write_filesystem", "network", "record_interaction"] {
        assert!(
            !lowered.contains(effect),
            "the read-only provider must not declare {effect}"
        );
    }
    assert!(
        lowered.contains("lifecycle = [\"read_long_term\"]"),
        "only the long-term lane may be declared until the server proofs land"
    );
}

#[test]
fn the_two_lanes_stay_distinct_and_are_never_presented_as_one_surface() {
    assert!(
        MANIFEST.contains("ironclaw.memory.search"),
        "the memory lane keeps the stable IronClaw tool id"
    );
    assert!(
        MANIFEST.contains("mnesis.knowledge.search"),
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
