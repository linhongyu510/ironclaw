//! Credentialed live proof that a delegated owner scope round-trips and isolates.
//!
//! The deterministic suites drive fakes, so they cannot show that Mnesis honours
//! a principal that is not the bearer. This writes as one IronClaw user, reads it
//! back as that user, and confirms a second user does not see it.
//!
//! Run with the two lane bearers exported:
//!   MNESIS_LIVE_ENDPOINT, MNESIS_LIVE_KNOWLEDGE_BEARER, MNESIS_LIVE_MEMORY_BEARER

use ironclaw_memory_mnesis::{
    CatalogTool, EndpointProfile, MnesisConfig, MnesisHttpTransport, MnesisLane, MnesisLimits,
    MnesisRequest, MnesisTransport, OwnerAxes, OwnerScope, ProviderAttribution, catalog_tool,
};
use serde_json::{Value, json};

/// The typed memory lane keeps its own path, so it is not in the catalog table;
/// this drives the same wire name through the same transport.
/// Stable across runs: the engine deduplicates a repeated write, so recall must
/// not depend on this run having created a new fact.
const RECALL_QUERY: &str = "IronClaw delegated write proof";

const MEMORY_SEARCH: CatalogTool = CatalogTool {
    capability_id: "ironclaw.memory.search",
    wire_name: "memory_search",
    lane: MnesisLane::Memory,
    idempotent: true,
};

fn transport(endpoint: &str, knowledge: &str, memory: &str) -> MnesisHttpTransport {
    MnesisHttpTransport::new(
        &MnesisConfig {
            knowledge_endpoint: format!("{endpoint}/rar/mcp"),
            memory_endpoint: format!("{endpoint}/memory/mcp"),
            host_allowlist: Vec::new(),
            profile: EndpointProfile::Production,
            limits: MnesisLimits::default(),
        },
        knowledge,
        memory,
    )
    .expect("the live endpoint must pass validation")
}

/// Attribution for one IronClaw user, distinct from the bearer's own principal.
fn identity(tenant: &str, user: &str) -> (String, String) {
    let owner_scope = OwnerScope::narrowest(
        tenant,
        user,
        OwnerAxes {
            agent_id: Some("research-agent".to_string()),
            project_id: Some("ironclaw-mnesis".to_string()),
            thread_id: None,
        },
    );
    let session_key = owner_scope.key().expect("the owner scope keys");
    let deadline_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_millis() as i64
        + 30_000;
    let attribution = ProviderAttribution {
        owner_scope,
        mission_id: None,
        invocation_id: "11111111-2222-4333-8444-555555555555".to_string(),
        correlation_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_string(),
        deadline_at_ms,
    }
    .encode()
    .expect("the attribution encodes");
    (attribution, session_key)
}

async fn call(
    transport: &MnesisHttpTransport,
    tool: &CatalogTool,
    arguments: Value,
    identity: &(String, String),
) -> Value {
    let operation = tool.wire_name;
    let response = transport
        .execute(MnesisRequest {
            lane: tool.lane,
            operation,
            body: json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": operation, "arguments": arguments }
            }),
            idempotent: tool.idempotent,
            attribution: Some(identity.0.clone()),
            session_key: Some(identity.1.clone()),
        })
        .await
        .unwrap_or_else(|error| panic!("{operation} transport failed: {error}"));
    assert!(
        response.is_success(),
        "{operation} returned HTTP {}",
        response.status
    );
    assert_ne!(
        response
            .body
            .pointer("/result/isError")
            .and_then(Value::as_bool),
        Some(true),
        "{operation} was refused: {}",
        response.body
    );
    response.body
}

/// The decoded result rows. Asserting on these rather than on the serialized
/// payload matters: the engine echoes the query back in its `content` text, so a
/// substring check reports a leak whenever the marker is the query.
fn rows(body: &Value) -> Vec<Value> {
    body.pointer("/result/structuredContent/results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn rendered(body: &Value) -> String {
    body.pointer("/result/content")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

#[tokio::test]
#[ignore = "credentialed live proof; supplemental to the deterministic suite"]
async fn a_delegated_owner_scope_round_trips_and_stays_isolated() {
    let endpoint = std::env::var("MNESIS_LIVE_ENDPOINT").expect("set MNESIS_LIVE_ENDPOINT");
    let knowledge =
        std::env::var("MNESIS_LIVE_KNOWLEDGE_BEARER").expect("set MNESIS_LIVE_KNOWLEDGE_BEARER");
    let memory = std::env::var("MNESIS_LIVE_MEMORY_BEARER").expect("set MNESIS_LIVE_MEMORY_BEARER");
    let tenant = std::env::var("MNESIS_LIVE_TENANT").unwrap_or_else(|_| "ironclaw-lab".to_string());
    let marker = std::env::var("MNESIS_LIVE_MARKER").expect("set MNESIS_LIVE_MARKER to a nonce");

    let transport = transport(&endpoint, &knowledge, &memory);
    let author = identity(&tenant, "ironclaw-live-author");
    let stranger = identity(&tenant, "ironclaw-live-stranger");

    let write = call(
        &transport,
        catalog_tool("mnesis.hosted.memory.memory_add_fact")
            .expect("catalog declares memory_add_fact"),
        json!({
            "category": "ironclaw-live",
            "fact_key": format!("roundtrip-{marker}"),
            "fact": format!("IronClaw delegated write proof {marker}."),
            "source_session": "ironclaw-live-proof",
        }),
        &author,
    )
    .await;
    println!("  write: {}", rendered(&write).replace('\n', " | "));

    let recall = call(
        &transport,
        &MEMORY_SEARCH,
        json!({ "query": RECALL_QUERY, "limit": 10 }),
        &author,
    )
    .await;
    // A repeat run is deduplicated by the engine rather than stored twice, so the
    // invariant is that the author's scope is non-empty, not that this exact
    // marker landed.
    let mine = rows(&recall);
    println!("  author rows: {}", mine.len());
    assert!(
        !mine.is_empty(),
        "the author must recall its own scope: {recall}"
    );

    let foreign = call(
        &transport,
        &MEMORY_SEARCH,
        json!({ "query": RECALL_QUERY, "limit": 10 }),
        &stranger,
    )
    .await;
    let theirs = rows(&foreign);
    println!("  stranger rows: {}", theirs.len());
    assert!(
        theirs.is_empty(),
        "a different owner scope must see nothing of the author's: {foreign}"
    );
}
