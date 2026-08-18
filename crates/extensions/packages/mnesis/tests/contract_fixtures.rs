//! The Rust half of the frozen provider wire contract suite.
//!
//! The fixtures under `tests/fixtures/provider-*-v1.json` are byte-identical
//! copies of the Mnesis-Core manifests of the same name, which its TypeScript
//! binding validates in `packages/provider-contracts/tests/contract-fixtures.test.ts`.
//! Both bindings decode the SAME frozen bytes, which is the point: an encoding
//! that round-trips inside one language proves nothing about the other, and the
//! attribution envelope is base64url of a positional tuple where a shifted field
//! or a different Unicode normalization silently changes meaning rather than
//! failing to parse.
//!
//! The files are versioned and frozen. A contract change is a `-v2` file, never
//! an edit to these, so the vendored copies cannot drift from their source
//! without a rename that is visible in review.

use ironclaw_memory_mnesis::{
    MAX_INTERACTION_BYTES, MAX_INTERACTION_MESSAGES, MAX_MESSAGE_BYTES, MAX_METADATA_ENTRIES,
    OwnerRecordClass, OwnerScope, PROVIDER_ATTRIBUTION_HEADER, ProviderAttribution,
};
use serde_json::Value;

fn attribution_fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/provider-attribution-v1.json"))
        .expect("the frozen attribution fixture must be valid JSON")
}

fn request_fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/provider-request-v1.json"))
        .expect("the frozen request fixture must be valid JSON")
}

fn error_fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/provider-error-v1.json"))
        .expect("the frozen error fixture must be valid JSON")
}

fn frozen_scope(scope: &Value) -> OwnerScope {
    let text = |key: &str| scope.get(key).and_then(Value::as_str).map(str::to_string);
    OwnerScope::narrowest(
        text("tenantId").expect("the frozen scope must carry a tenant"),
        text("principalId").expect("the frozen scope must carry a principal"),
        text("agentId"),
        text("projectId"),
        text("threadId"),
    )
}

#[test]
fn the_frozen_owner_scope_key_encodes_byte_for_byte() {
    let fixture = attribution_fixture();
    let scope = frozen_scope(&fixture["attribution"]["ownerScope"]);
    let expected = fixture["ownerScopeKey"]
        .as_str()
        .expect("the fixture must declare an owner scope key");
    assert_eq!(
        scope.key().expect("the frozen scope must encode"),
        expected,
        "the Rust owner scope key must match the frozen cross-language key"
    );
}

#[test]
fn the_frozen_scope_axes_select_the_declared_record_class() {
    let fixture = attribution_fixture();
    let declared = fixture["attribution"]["ownerScope"]["recordClass"]
        .as_str()
        .expect("the fixture must declare a record class");
    let scope = frozen_scope(&fixture["attribution"]["ownerScope"]);
    let expected = match declared {
        "principal-private" => OwnerRecordClass::PrincipalPrivate,
        "thread-private" => OwnerRecordClass::ThreadPrivate,
        other => panic!("the frozen fixture declares an unmodelled record class: {other}"),
    };
    assert_eq!(scope.record_class, expected);
}

#[test]
fn the_frozen_attribution_envelope_encodes_byte_for_byte() {
    let fixture = attribution_fixture();
    let declared = &fixture["attribution"];
    let attribution = ProviderAttribution {
        owner_scope: frozen_scope(&declared["ownerScope"]),
        mission_id: declared["missionId"].as_str().map(str::to_string),
        invocation_id: declared["invocationId"]
            .as_str()
            .expect("the fixture must carry an invocation id")
            .to_string(),
        correlation_id: declared["correlationId"]
            .as_str()
            .expect("the fixture must carry a correlation id")
            .to_string(),
        deadline_at_ms: declared["deadlineAt"]
            .as_i64()
            .expect("the fixture must carry a deadline"),
    };
    let expected = fixture["encoding"]
        .as_str()
        .expect("the fixture must declare an encoding");
    assert_eq!(
        attribution
            .encode()
            .expect("the frozen attribution must encode"),
        expected,
        "the Rust attribution envelope must match the frozen cross-language encoding"
    );
}

#[test]
fn the_frozen_header_name_matches_the_transport_header() {
    let fixture = attribution_fixture();
    let headers = fixture["headers"]
        .as_object()
        .expect("the fixture must declare headers");
    assert!(
        headers.contains_key(PROVIDER_ATTRIBUTION_HEADER),
        "the frozen header table must name {PROVIDER_ATTRIBUTION_HEADER}"
    );
    assert_eq!(
        headers[PROVIDER_ATTRIBUTION_HEADER]
            .as_str()
            .expect("the frozen header value must be a string"),
        fixture["encoding"].as_str().expect("encoding"),
        "the frozen header value must be the frozen attribution encoding"
    );
}

#[test]
fn frozen_interaction_boundaries_match_the_implemented_limits() {
    let fixture = request_fixture();
    let bounds = &fixture["boundaries"];
    let declared = |key: &str| {
        bounds
            .get(key)
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("the frozen boundaries must declare {key}")) as usize
    };
    assert_eq!(
        declared("maximumInteractionMessages"),
        MAX_INTERACTION_MESSAGES
    );
    assert_eq!(declared("maximumMessageBytes"), MAX_MESSAGE_BYTES);
    assert_eq!(declared("maximumInteractionBytes"), MAX_INTERACTION_BYTES);
    assert_eq!(declared("maximumMetadataEntries"), MAX_METADATA_ENTRIES);
}

/// The transport splits purely on 5xx: a 5xx lane is unavailable and degrades to
/// an empty result, anything else is an operation failure the caller sees. The
/// frozen table carries the server's finer vocabulary, and the Rust binding
/// deliberately does not reproduce all of it -- `MemoryServiceError` has no
/// deadline kind, so a 504 arrives as unavailable rather than as its own class.
/// What must hold across bindings is the SIDE of the split: every class the
/// server attributes to itself sits in 5xx, and every class it attributes to the
/// caller sits below 5xx. If that ever inverts, the transport would degrade a
/// caller fault to an empty lane and hide it.
#[test]
fn the_frozen_status_table_agrees_with_the_transport_fault_split() {
    let fixture = error_fixture();
    let table = fixture["statusToClass"]
        .as_array()
        .expect("the fixture must declare a status table");
    assert!(
        !table.is_empty(),
        "the frozen status table must not be empty"
    );
    for entry in table {
        let status = entry["status"]
            .as_u64()
            .expect("every status entry must carry a status");
        let class = entry["class"]
            .as_str()
            .expect("every status entry must carry a class");
        if matches!(class, "unavailable" | "deadline") {
            assert!(
                (500..600).contains(&status),
                "server-fault class {class} must sit in 5xx, got {status}"
            );
        }
        if matches!(
            class,
            "input" | "unauthenticated" | "policy_denied" | "rate_limited"
        ) {
            assert!(
                status < 500,
                "caller-fault class {class} must sit below 5xx, got {status}"
            );
        }
    }
}
