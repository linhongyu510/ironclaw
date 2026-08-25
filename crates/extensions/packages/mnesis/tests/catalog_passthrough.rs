//! The catalog passthrough: tools the engines answer with their own shapes.
//!
//! The typed lanes map onto `MemoryService` types and are covered elsewhere.
//! What matters here is that a catalog call is forwarded intact and comes back
//! intact, while still carrying the attribution and session the typed lanes
//! carry — a passthrough that dropped either would answer under a scope that is
//! not the caller's.

use ironclaw_memory::{MemoryInvocation, MemoryServiceErrorKind};
use ironclaw_memory_mnesis::{
    CatalogTool, MnesisLane, MnesisMemoryService, MnesisResponse, MockMnesisTransport, catalog_tool,
};
use serde_json::{Value, json};

fn add_fact() -> &'static CatalogTool {
    catalog_tool("mnesis.hosted.memory.memory_add_fact")
        .expect("the catalog declares memory_add_fact")
}

fn invocation() -> MemoryInvocation {
    use ironclaw_host_api::ids::{
        AgentId, CorrelationId, InvocationId, ProjectId, TenantId, UserId,
    };
    MemoryInvocation {
        scope: ironclaw_host_api::resource::ResourceScope {
            tenant_id: TenantId::new("tenant-mnesis").unwrap(),
            user_id: UserId::new("user-mnesis").unwrap(),
            agent_id: Some(AgentId::new("agent-mnesis").unwrap()),
            project_id: Some(ProjectId::new("project-mnesis").unwrap()),
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        },
        correlation_id: CorrelationId::new(),
    }
}

fn fact_arguments() -> Value {
    json!({
        "category": "user-preferences",
        "fact_key": "commit-style",
        "fact": "Subject under seventy characters.",
        "source_session": "session-1"
    })
}

/// The engine answers this tool in `content` text, not `structuredContent`.
fn text_result() -> Value {
    json!({
        "result": {
            "content": [{ "type": "text", "text": "Added fact: fact-1 (version 1)" }]
        }
    })
}

#[tokio::test]
async fn a_catalog_call_reaches_its_tool_on_its_lane_with_the_arguments_intact() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(text_result()));

    service
        .call_tool(invocation(), add_fact(), fact_arguments())
        .await
        .expect("the catalog call succeeds");

    let recorded = service.transport().recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].operation, "memory_add_fact");
    assert_eq!(recorded[0].lane, MnesisLane::Memory);
    assert_eq!(recorded[0].body["params"]["name"], "memory_add_fact");
    assert_eq!(
        recorded[0].body["params"]["arguments"],
        fact_arguments(),
        "arguments must reach the engine exactly as the model authored them"
    );
}

#[tokio::test]
async fn a_catalog_call_carries_the_same_owner_scope_the_typed_lanes_carry() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(text_result()));

    service
        .call_tool(invocation(), add_fact(), fact_arguments())
        .await
        .unwrap();

    let recorded = service.transport().recorded();
    let attribution = recorded[0]
        .attribution
        .as_deref()
        .expect("a catalog call must be attributed");
    assert!(attribution.starts_with("mpa1."));
    let session = recorded[0]
        .session_key
        .as_deref()
        .expect("a catalog call must open its owner-scoped session");
    assert!(session.starts_with("mos1."));
}

#[tokio::test]
async fn the_engines_result_is_returned_without_interpretation() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(text_result()));

    let output = service
        .call_tool(invocation(), add_fact(), fact_arguments())
        .await
        .unwrap();

    assert_eq!(output, text_result()["result"]);
}

#[tokio::test]
async fn a_refused_tool_call_is_an_operation_failure_not_a_success() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({
        "result": {
            "isError": true,
            "content": [{ "type": "text", "text": "memory_add_fact failed" }]
        }
    })));

    let error = service
        .call_tool(invocation(), add_fact(), fact_arguments())
        .await
        .expect_err("an isError result must not read as success");
    assert_eq!(error.kind(), MemoryServiceErrorKind::Operation);
}

#[tokio::test]
async fn an_unavailable_lane_stays_unavailable_rather_than_degrading_to_empty() {
    let service = MnesisMemoryService::new(MockMnesisTransport::new(Box::new(|_request| {
        Some(MnesisResponse {
            status: 503,
            body: Value::Null,
        })
    })));

    let error = service
        .call_tool(invocation(), add_fact(), fact_arguments())
        .await
        .expect_err("a 5xx must surface");
    assert_eq!(error.kind(), MemoryServiceErrorKind::Unavailable);
}

/// A model-authored write carries no derived idempotency key, so the transport
/// must not replay it behind the model's back.
#[tokio::test]
async fn a_model_authored_write_is_sent_once() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(text_result()));

    service
        .call_tool(invocation(), add_fact(), fact_arguments())
        .await
        .unwrap();

    let recorded = service.transport().recorded();
    assert!(
        !recorded[0].idempotent,
        "a write the model authored must not be marked retryable"
    );
}

/// A JSON-RPC protocol error is transported at HTTP 200 with an `error` member
/// and no `result`. Reading the status alone hands that error body to the model
/// as though it were the tool's output.
#[tokio::test]
async fn a_json_rpc_protocol_error_is_a_failure_not_a_returned_result() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": { "code": -32601, "message": "Method not found" }
    })));

    let error = service
        .call_tool(invocation(), add_fact(), fact_arguments())
        .await
        .expect_err("a JSON-RPC error must not be returned as a tool result");
    assert_eq!(error.kind(), MemoryServiceErrorKind::Operation);
}

/// Arguments are model authored and reach the lane verbatim, so the passthrough
/// bounds them rather than forwarding an unbounded body to the engine.
#[tokio::test]
async fn oversized_arguments_are_refused_before_the_transport() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(text_result()));

    let error = service
        .call_tool(
            invocation(),
            add_fact(),
            json!({ "fact": "x".repeat(2 * 1024 * 1024) }),
        )
        .await
        .expect_err("an oversized argument body must be refused");
    assert_eq!(error.kind(), MemoryServiceErrorKind::Input);
    assert!(
        service.transport().recorded().is_empty(),
        "an oversized body must not reach the lane at all"
    );
}
