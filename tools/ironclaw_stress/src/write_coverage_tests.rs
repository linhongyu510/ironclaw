use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

const BUILTIN_POLICY: &str =
    include_str!("../../../crates/app/ironclaw_composition/src/builtin_capability_policy.toml");
const WRITE_COVERAGE: &str = include_str!("../fixtures/builtin_write_stress_coverage.toml");
const WRITE_EFFECTS: [&str; 4] = [
    "write_filesystem",
    "delete_filesystem",
    "external_write",
    "modify_approval",
];

#[derive(Deserialize)]
struct BuiltinPolicy {
    grants: Vec<Grant>,
}

#[derive(Deserialize)]
struct Grant {
    capability: String,
    effects: Vec<String>,
}

#[derive(Deserialize)]
struct CoverageInventory {
    schema_version: u32,
    entries: Vec<CoverageEntry>,
}

#[derive(Deserialize)]
struct CoverageEntry {
    capability: String,
    status: CoverageStatus,
    scenario: String,
    reason: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CoverageStatus {
    Nightly,
    Implemented,
    Backlog,
}

#[test]
fn every_builtin_write_effect_has_an_explicit_stress_classification() {
    let policy: BuiltinPolicy = toml::from_str(BUILTIN_POLICY).expect("builtin policy parses");
    let inventory: CoverageInventory =
        toml::from_str(WRITE_COVERAGE).expect("write stress inventory parses");
    assert_eq!(inventory.schema_version, 1, "unsupported inventory schema");

    let expected = policy
        .grants
        .into_iter()
        .filter(|grant| {
            grant
                .effects
                .iter()
                .any(|effect| WRITE_EFFECTS.contains(&effect.as_str()))
        })
        .map(|grant| grant.capability)
        .collect::<BTreeSet<_>>();

    let mut classified = BTreeMap::new();
    for entry in inventory.entries {
        assert!(
            !entry.scenario.trim().is_empty(),
            "{} has no workload family",
            entry.capability
        );
        assert!(
            !entry.reason.trim().is_empty(),
            "{} has no classification reason",
            entry.capability
        );
        if matches!(
            entry.status,
            CoverageStatus::Nightly | CoverageStatus::Implemented
        ) {
            assert!(
                !entry.scenario.contains(char::is_whitespace),
                "{} executable scenario names must not contain whitespace",
                entry.capability
            );
        }
        assert!(
            classified
                .insert(entry.capability.clone(), entry.status)
                .is_none(),
            "duplicate write stress classification for {}",
            entry.capability
        );
    }

    let actual = classified.into_keys().collect::<BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "the built-in write surface changed; classify every added or removed capability in \
         fixtures/builtin_write_stress_coverage.toml"
    );
}
