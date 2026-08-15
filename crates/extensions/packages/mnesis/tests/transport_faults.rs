use ironclaw_memory::{MemoryService, MemoryServiceErrorKind};
use ironclaw_memory_mnesis::{
    EndpointProfile, MnesisConfig, MnesisError, MnesisHttpTransport, MnesisLane, MnesisLimits,
    MnesisMemoryService, MnesisRequest, MnesisResponse, MnesisTransport, MockMnesisTransport,
    SecretHandle,
};
use serde_json::{Value, json};

fn config_for(endpoint: &str, profile: EndpointProfile) -> MnesisConfig {
    MnesisConfig {
        knowledge_endpoint: format!("{endpoint}/rar/mcp"),
        memory_endpoint: format!("{endpoint}/memory/mcp"),
        knowledge_credential: SecretHandle::new("services/rar-clients").unwrap(),
        memory_credential: SecretHandle::new("services/memory-clients").unwrap(),
        host_allowlist: Vec::new(),
        profile,
        limits: MnesisLimits::default(),
    }
}

fn build(config: &MnesisConfig, bearer: &str) -> Result<MnesisHttpTransport, MnesisError> {
    MnesisHttpTransport::new(config, bearer, bearer)
}

#[test]
fn ssrf_corpus_is_refused_across_address_encodings() {
    let blocked = [
        "https://169.254.169.254",
        "https://[::ffff:169.254.169.254]",
        "https://[fe80::1]",
        "https://169.254.1.1",
        "https://224.0.0.1",
        "https://[ff02::1]",
        "https://0.0.0.0",
        "https://[::]",
    ];
    for endpoint in blocked {
        assert!(
            build(&config_for(endpoint, EndpointProfile::Production), "t").is_err(),
            "{endpoint} must be refused"
        );
    }
}

#[test]
fn ssrf_corpus_refusal_is_an_invalid_endpoint_error() {
    for endpoint in [
        "https://169.254.169.254",
        "https://[fe80::1]",
        "https://0.0.0.0",
    ] {
        match build(&config_for(endpoint, EndpointProfile::Production), "t") {
            Err(MnesisError::InvalidEndpoint { .. }) => {}
            Err(other) => panic!("{endpoint}: wrong error {other:?}"),
            Ok(_) => panic!("{endpoint} must not build a client"),
        }
    }
}

#[test]
fn non_http_schemes_and_userinfo_are_refused() {
    for endpoint in [
        "file:///etc",
        "ftp://mnesis.example.com",
        "gopher://mnesis.example.com",
        "https://user:pass@mnesis.example.com",
    ] {
        build(&config_for(endpoint, EndpointProfile::Production), "t").expect_err(endpoint);
    }
}

#[test]
fn plain_http_is_refused_remotely_and_gated_locally() {
    build(
        &config_for("http://mnesis.example.com", EndpointProfile::Production),
        "t",
    )
    .unwrap_err();
    build(
        &config_for(
            "http://mnesis.example.com",
            EndpointProfile::LoopbackDevelopment,
        ),
        "t",
    )
    .unwrap_err();
    build(
        &config_for("http://127.0.0.1:3443", EndpointProfile::Production),
        "t",
    )
    .unwrap_err();
    build(
        &config_for(
            "http://127.0.0.1:3443",
            EndpointProfile::LoopbackDevelopment,
        ),
        "t",
    )
    .unwrap();
}

#[test]
fn an_allowlist_fails_closed_for_every_endpoint_it_does_not_name() {
    let mut config = config_for("https://mnesis.example.com", EndpointProfile::Production);
    config.host_allowlist = vec!["other.example.com".to_string()];
    build(&config, "t").unwrap_err();

    config.host_allowlist = vec!["mnesis.example.com".to_string()];
    build(&config, "t").unwrap();
}

#[test]
fn a_credential_that_cannot_be_a_header_is_refused_without_echoing_it() {
    let error = build(
        &config_for("https://mnesis.example.com", EndpointProfile::Production),
        "secret\nvalue",
    )
    .unwrap_err();
    assert!(matches!(error, MnesisError::Client { .. }));
    assert!(!error.to_string().contains("secret"), "{error}");
}

#[tokio::test]
async fn a_lane_denial_and_a_lane_outage_map_to_different_host_error_kinds() {
    for status in [401, 403, 429] {
        let service =
            MnesisMemoryService::new(MockMnesisTransport::new(Box::new(move |_request| {
                Some(MnesisResponse {
                    status,
                    body: Value::Null,
                })
            })));
        let error = service
            .read_long_term(invocation(), request("anything", 4))
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            MemoryServiceErrorKind::Operation,
            "status {status} is a policy failure and must stay visible"
        );
    }

    for status in [500, 503] {
        let service =
            MnesisMemoryService::new(MockMnesisTransport::new(Box::new(move |_request| {
                Some(MnesisResponse {
                    status,
                    body: Value::Null,
                })
            })));
        let snippets = service
            .read_long_term(invocation(), request("anything", 4))
            .await
            .unwrap_or_else(|error| panic!("status {status} must degrade, got {error}"));
        assert!(snippets.is_empty(), "status {status}");
    }
}

#[tokio::test]
async fn an_undecodable_body_yields_no_snippets_rather_than_garbage() {
    let service =
        MnesisMemoryService::new(MockMnesisTransport::always_ok(json!("not an envelope")));
    let snippets = service
        .read_long_term(invocation(), request("anything", 4))
        .await
        .unwrap();
    assert!(snippets.is_empty());
}

#[tokio::test]
async fn the_snippet_budget_is_never_exceeded_and_the_lifecycle_reads_memory_only() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({
        "results": (0..50)
            .map(|index| json!({
                "relativePath": format!("{index}.md"),
                "content": "x",
                "authorization": {
                    "kind": "owner-scope",
                    "ownerScope": {
                        "tenantId": "tenant-mnesis",
                        "principalId": "user-mnesis",
                        "agentId": "agent-mnesis",
                        "projectId": "project-mnesis"
                    }
                }
            }))
            .collect::<Vec<_>>()
    })));
    let snippets = service
        .read_long_term(invocation(), request("anything", 6))
        .await
        .unwrap();
    assert_eq!(snippets.len(), 6);

    let lanes = service_lanes(&service);
    assert!(lanes.contains(&MnesisLane::Memory));
    assert!(
        !lanes.contains(&MnesisLane::Knowledge),
        "corpus evidence has no stored owner scope, so it must not be forced through \
         the owner-scoped lifecycle snippet path; it reaches the model as a tool result"
    );
}

#[tokio::test]
async fn a_result_mnesis_did_not_owner_scope_is_dropped_rather_than_labelled() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({
        "results": [{"relativePath": "a.md", "content": "alpha"}]
    })));
    let snippets = service
        .read_long_term(invocation(), request("anything", 6))
        .await
        .unwrap();
    assert!(
        snippets.is_empty(),
        "an unscoped result must never be labelled with the caller's scope"
    );
}

#[tokio::test]
async fn an_oversized_query_is_an_input_error_not_a_silent_truncation() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(Value::Null));
    let error = service
        .read_long_term(invocation(), request(&"q".repeat(4_097), 4))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), MemoryServiceErrorKind::Input);
}

#[tokio::test]
async fn a_disabled_context_profile_never_reaches_the_transport() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(Value::Null));
    let mut context = request("anything", 4);
    context.context_profile_id =
        ironclaw_memory::MemoryContextProfileId::new("memory_disabled").unwrap();
    let snippets = service.read_long_term(invocation(), context).await.unwrap();
    assert!(snippets.is_empty());
    assert_eq!(service_lanes(&service).len(), 0);
}

#[tokio::test]
async fn every_read_carries_attribution_derived_from_the_trusted_scope() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(Value::Null));
    let _ = service
        .read_long_term(invocation(), request("anything", 4))
        .await;
    let recorded = service.transport().recorded();
    assert!(!recorded.is_empty());
    for entry in &recorded {
        let attribution = entry
            .attribution
            .as_ref()
            .expect("every read must carry owner scope");
        assert!(attribution.starts_with("mpa1."), "{attribution}");
    }
    assert!(
        recorded
            .iter()
            .all(|entry| entry.attribution == recorded[0].attribution),
        "one invocation must present one owner scope to every lane it touches"
    );
}

#[tokio::test]
async fn attribution_is_never_taken_from_the_request_body() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(Value::Null));
    let _ = service
        .read_long_term(invocation(), request("anything", 4))
        .await;
    for entry in service.transport().recorded() {
        let body = entry.body.as_object().expect("a JSON object body");
        for forbidden in ["ownerScope", "tenantId", "userId", "principalId", "scope"] {
            assert!(
                !body.contains_key(forbidden),
                "{forbidden} must ride attribution, not the body"
            );
        }
    }
}

#[tokio::test]
async fn every_read_is_marked_idempotent_so_retry_stays_safe() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(Value::Null));
    let _ = service
        .read_long_term(invocation(), request("anything", 4))
        .await;
    let recorded = service.transport().recorded();
    assert!(!recorded.is_empty());
    assert!(recorded.iter().all(|request| request.idempotent));
}

#[tokio::test]
#[ignore = "credentialed live canary; supplemental to the deterministic suite"]
async fn live_canary_reaches_both_published_lanes() {
    let endpoint = std::env::var("MNESIS_CANARY_ENDPOINT")
        .expect("set MNESIS_CANARY_ENDPOINT to run the canary");
    let bearer = std::env::var("MNESIS_CANARY_KNOWLEDGE_BEARER")
        .expect("set MNESIS_CANARY_KNOWLEDGE_BEARER to run the canary");
    let memory_bearer = std::env::var("MNESIS_CANARY_MEMORY_BEARER")
        .expect("set MNESIS_CANARY_MEMORY_BEARER to run the canary");

    let transport = MnesisHttpTransport::new(
        &config_for(&endpoint, EndpointProfile::Production),
        &bearer,
        &memory_bearer,
    )
    .expect("the canary endpoint must pass validation");

    for (lane, operation) in [
        (MnesisLane::Knowledge, "knowledge_search"),
        (MnesisLane::Memory, "memory_search"),
    ] {
        let response = transport
            .execute(MnesisRequest {
                lane,
                operation,
                body: json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "capabilities": {},
                        "clientInfo": {"name": "mnesis-live-canary", "version": "1.0.0"},
                        "protocolVersion": "2025-06-18"
                    }
                }),
                idempotent: true,
                attribution: Some(canary_attribution()),
            })
            .await
            .unwrap_or_else(|error| panic!("{operation} transport failed: {error}"));
        println!("  {operation}: status {}", response.status);
        assert!(
            response.status != 401 && response.status != 403,
            "{operation} was denied: check the bearer credential"
        );
    }
}

fn canary_attribution() -> String {
    use ironclaw_memory_mnesis::{OwnerScope, ProviderAttribution};
    let deadline_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_millis() as i64
        + 30_000;
    ProviderAttribution {
        owner_scope: OwnerScope::narrowest(
            std::env::var("MNESIS_CANARY_TENANT").unwrap_or_else(|_| "ironclaw-lab".to_string()),
            std::env::var("MNESIS_CANARY_PRINCIPAL")
                .unwrap_or_else(|_| "ironclaw-integration-reader".to_string()),
            None,
            None,
            None,
        ),
        mission_id: None,
        invocation_id: "11111111-2222-4333-8444-555555555555".to_string(),
        correlation_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_string(),
        deadline_at_ms,
    }
    .encode()
    .expect("the canary attribution encodes")
}

fn invocation() -> ironclaw_memory::MemoryInvocation {
    use ironclaw_host_api::ids::{
        AgentId, CorrelationId, InvocationId, ProjectId, TenantId, UserId,
    };
    ironclaw_memory::MemoryInvocation {
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

fn request(query: &str, max_snippets: usize) -> ironclaw_memory::MemoryServiceContextRequest {
    ironclaw_memory::MemoryServiceContextRequest {
        query: query.to_string(),
        max_snippets,
        context_profile_id: ironclaw_memory::MemoryContextProfileId::new("default").unwrap(),
    }
}

fn service_lanes(service: &MnesisMemoryService<MockMnesisTransport>) -> Vec<MnesisLane> {
    service
        .transport()
        .recorded()
        .iter()
        .map(|request| request.lane)
        .collect()
}
