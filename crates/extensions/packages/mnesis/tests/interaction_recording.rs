use ironclaw_memory::{
    MemoryInteractionMessage, MemoryInteractionRole, MemoryInvocation, MemoryService,
    MemoryServiceRecordRequest,
};
use ironclaw_memory_mnesis::{MnesisLane, MnesisMemoryService, MockMnesisTransport};
use serde_json::{Value, json};

fn arguments(request: &ironclaw_memory_mnesis::MnesisRequest) -> &Value {
    &request.body["params"]["arguments"]
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

fn message(role: MemoryInteractionRole, content: &str) -> MemoryInteractionMessage {
    MemoryInteractionMessage {
        role,
        content: content.to_string(),
        name: None,
    }
}

fn record(messages: Vec<MemoryInteractionMessage>) -> MemoryServiceRecordRequest {
    MemoryServiceRecordRequest {
        messages,
        turn_run_id: Some("run-1".to_string()),
        metadata: json!({}),
    }
}

fn exchange() -> Vec<MemoryInteractionMessage> {
    vec![
        message(MemoryInteractionRole::User, "why did the build fail"),
        message(MemoryInteractionRole::Assistant, "the lockfile drifted"),
    ]
}

#[tokio::test]
async fn an_exchange_is_recorded_on_the_memory_lane_only() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({})));
    let response = service
        .record_interaction(invocation(), record(exchange()))
        .await
        .unwrap();

    assert!(response.recorded);
    let recorded = service.transport().recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].lane, MnesisLane::Memory);
    assert_eq!(recorded[0].operation, "memory_record_interaction");
}

#[tokio::test]
async fn an_empty_exchange_is_a_no_op_rather_than_an_error() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({})));
    let response = service
        .record_interaction(invocation(), record(Vec::new()))
        .await
        .unwrap();

    assert!(!response.recorded);
    assert!(
        service.transport().recorded().is_empty(),
        "an empty exchange must never reach the transport"
    );
}

#[tokio::test]
async fn every_message_reaches_the_wire_with_its_role_intact() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({})));
    let mut messages = exchange();
    messages.push(MemoryInteractionMessage {
        role: MemoryInteractionRole::Tool,
        content: "exit 1".to_string(),
        name: Some("bash".to_string()),
    });
    service
        .record_interaction(invocation(), record(messages))
        .await
        .unwrap();

    let recorded = service.transport().recorded();
    let sent = arguments(&recorded[0])["messages"].as_array().unwrap();
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[0]["role"], "user");
    assert_eq!(sent[1]["role"], "assistant");
    assert_eq!(sent[2]["role"], "tool");
    assert_eq!(sent[2]["name"], "bash");
    assert_eq!(sent[1]["content"], "the lockfile drifted");
}

#[tokio::test]
async fn the_write_carries_a_stable_operation_identity_and_the_turn_run() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({})));
    let held = invocation();
    service
        .record_interaction(held.clone(), record(exchange()))
        .await
        .unwrap();
    service
        .record_interaction(held, record(exchange()))
        .await
        .unwrap();

    let recorded = service.transport().recorded();
    let first = arguments(&recorded[0])["operation_id"].as_str().unwrap();
    let second = arguments(&recorded[1])["operation_id"].as_str().unwrap();
    assert_eq!(
        first, second,
        "one invocation must present one operation identity so a retry is idempotent"
    );
    assert_eq!(arguments(&recorded[0])["turn_run_id"], "run-1");
}

#[tokio::test]
async fn a_different_invocation_gets_a_different_operation_identity() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({})));
    service
        .record_interaction(invocation(), record(exchange()))
        .await
        .unwrap();
    service
        .record_interaction(invocation(), record(exchange()))
        .await
        .unwrap();

    let recorded = service.transport().recorded();
    assert_ne!(
        arguments(&recorded[0])["operation_id"],
        arguments(&recorded[1])["operation_id"],
        "two distinct turns must not collide onto one durable effect"
    );
}

#[tokio::test]
async fn an_oversized_exchange_is_refused_before_the_transport() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({})));
    let messages = vec![message(MemoryInteractionRole::User, &"x".repeat(9_000))];
    let outcome = service
        .record_interaction(invocation(), record(messages))
        .await;

    assert!(
        outcome.is_err(),
        "a message over the ceiling must be refused"
    );
    assert!(
        service.transport().recorded().is_empty(),
        "an out-of-bounds exchange must never reach the transport"
    );
}

#[tokio::test]
async fn every_recorded_write_carries_attribution_from_the_trusted_scope() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({})));
    service
        .record_interaction(invocation(), record(exchange()))
        .await
        .unwrap();

    let recorded = service.transport().recorded();
    let attribution = recorded[0]
        .attribution
        .as_ref()
        .expect("a write must carry owner scope");
    assert!(attribution.starts_with("mpa1."), "{attribution}");
}

#[tokio::test]
async fn scope_is_never_taken_from_the_recorded_payload() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({})));
    service
        .record_interaction(invocation(), record(exchange()))
        .await
        .unwrap();

    let recorded = service.transport().recorded();
    let sent = arguments(&recorded[0])
        .as_object()
        .expect("the wire arguments must be an object");
    for forbidden in [
        "tenant_id",
        "user_id",
        "principal_id",
        "owner_scope",
        "agent_id",
    ] {
        assert!(
            !sent.contains_key(forbidden),
            "identity must ride attribution, never the body: {forbidden}"
        );
    }
    assert_eq!(sent.get("metadata"), None::<&Value>);
}
