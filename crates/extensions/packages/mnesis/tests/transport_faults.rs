use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use ironclaw_memory::{MemoryService, MemoryServiceErrorKind};
use ironclaw_memory_mnesis::{
    EndpointProfile, MnesisConfig, MnesisError, MnesisHttpTransport, MnesisLane, MnesisLimits,
    MnesisMemoryService, MnesisRequest, MnesisResponse, MnesisTransport, MockMnesisTransport,
    OwnerAxes, SecretHandle,
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
async fn a_refused_tool_call_is_an_error_even_though_the_lane_answered_200() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({
        "result": {
            "content": [{"type": "text", "text": "MCP error -32602: Tool nope not found"}],
            "isError": true
        }
    })));
    let error = service
        .read_long_term(invocation(), request("anything", 4))
        .await
        .expect_err("a refused tool call must not read as an empty lane");
    assert_eq!(error.kind(), MemoryServiceErrorKind::Operation);
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
async fn a_redirect_is_never_followed_and_the_credential_never_reaches_its_target() {
    let (relay_port, relayed) = redirect_target();
    let origin_port = redirecting_origin(relay_port);
    let config = config_for(
        &format!("http://127.0.0.1:{origin_port}"),
        EndpointProfile::LoopbackDevelopment,
    );
    let transport = build(&config, "redirect-canary-bearer").expect("loopback is permitted");

    let response = transport
        .execute(MnesisRequest {
            lane: MnesisLane::Memory,
            operation: "memory_search",
            body: json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            idempotent: false,
            attribution: None,
            session_key: None,
        })
        .await
        .expect("a redirect is a response, not a transport failure");

    assert!(
        relayed.recv_timeout(Duration::from_millis(500)).is_err(),
        "the redirect target was contacted, so the credential left its configured endpoint"
    );
    assert_eq!(
        response.status, 302,
        "the redirect must surface to the caller rather than being followed"
    );
    assert!(!response.is_success());
}

#[tokio::test]
async fn a_read_completes_against_a_lane_that_requires_an_mcp_session() {
    let port = session_required_origin();
    let config = config_for(
        &format!("http://127.0.0.1:{port}"),
        EndpointProfile::LoopbackDevelopment,
    );
    let service = MnesisMemoryService::new(
        build(&config, "lab-token").expect("the loopback endpoint builds"),
    );

    let snippets = service
        .read_long_term(invocation(), request("mnesis", 4))
        .await
        .expect("a session-requiring lane must still serve a read");

    assert_eq!(
        snippets.len(),
        1,
        "the lane yielded no snippet, which is exactly how an unestablished MCP session \
         presents to the caller: the server answers 'Server not initialized' and the \
         failure degrades to an empty lane"
    );
}

const SERVER_NOT_INITIALIZED: &str = r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request: Server not initialized"},"id":null}"#;

const JSON_RPC_PARSE_ERROR: &str = r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error: Invalid JSON-RPC message"},"id":null}"#;

const TOOL_CALL_RESULT: &str = r#"{"result":{"content":[{"type":"text","text":"1 memory"}],"structuredContent":{"schemaVersion":1,"engine":"memory","results":[{"text":"a stored lab memory","relativePath":"memory/lab.md","score":1.0,"authorization":{"kind":"owner-scope","ownerScope":{"recordClass":"thread-private","tenantId":"tenant-mnesis","principalId":"user-mnesis"}}}]}},"jsonrpc":"2.0","id":1}"#;

fn session_required_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the session origin binds");
    let port = listener
        .local_addr()
        .expect("the session origin reports its address")
        .port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let request = read_bounded(&mut stream);
            let response = if request.contains("\"initialize\"") {
                http_json(200, "{}", Some("session-1"))
            } else if !request.to_ascii_lowercase().contains("mcp-session-id:") {
                http_json(400, SERVER_NOT_INITIALIZED, None)
            } else if request.contains("\"tools/call\"") {
                http_sse(TOOL_CALL_RESULT)
            } else {
                http_json(400, JSON_RPC_PARSE_ERROR, None)
            };
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

fn http_json(status: u16, body: &str, session: Option<&str>) -> String {
    let reason = if status == 200 { "OK" } else { "Bad Request" };
    let session_header = session
        .map(|id| format!("Mcp-Session-Id: {id}\r\n"))
        .unwrap_or_default();
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         {session_header}\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

fn http_sse(payload: &str) -> String {
    let body = format!("event: message\ndata: {payload}\n\n");
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/event-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

fn redirect_target() -> (u16, std::sync::mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the redirect target binds");
    let port = listener
        .local_addr()
        .expect("the redirect target reports its address")
        .port();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let request = read_bounded(&mut stream);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            let _ = stream.flush();
            let _ = sender.send(request);
        }
    });
    (port, receiver)
}

fn redirecting_origin(target_port: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the redirecting origin binds");
    let port = listener
        .local_addr()
        .expect("the redirecting origin reports its address")
        .port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            read_bounded(&mut stream);
            let redirect = format!(
                "HTTP/1.1 302 Found\r\n\
                 Location: http://127.0.0.1:{target_port}/relayed\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\r\n"
            );
            let _ = stream.write_all(redirect.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

fn read_bounded(stream: &mut TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buffer = [0_u8; 4096];
    let read = stream.read(&mut buffer).unwrap_or(0);
    String::from_utf8_lossy(&buffer[..read]).into_owned()
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

    let (attribution, session_key) = canary_identity();
    for (lane, operation) in [
        (MnesisLane::Knowledge, "search_knowledge"),
        (MnesisLane::Memory, "memory_search"),
    ] {
        let response = transport
            .execute(MnesisRequest {
                lane,
                operation,
                body: json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": operation,
                        "arguments": {"query": "mnesis integration canary", "limit": 1}
                    }
                }),
                idempotent: true,
                attribution: Some(attribution.clone()),
                session_key: Some(session_key.clone()),
            })
            .await
            .unwrap_or_else(|error| panic!("{operation} transport failed: {error}"));
        println!("  {operation}: status {}", response.status);
        assert!(
            response.is_success(),
            "{operation} did not complete: status {}",
            response.status
        );
        assert!(
            response.body.pointer("/result/structuredContent").is_some(),
            "{operation} answered without the nested envelope the decoder reads"
        );
        if lane == MnesisLane::Knowledge {
            let hits = response
                .body
                .pointer("/result/structuredContent/results")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or_default();
            assert!(
                hits > 0,
                "the corpus lane returned no rows, so a 200 here would not \
                 distinguish a working read from an empty one"
            );
        }
    }
}

fn canary_identity() -> (String, String) {
    use ironclaw_memory_mnesis::{OwnerScope, ProviderAttribution};
    let deadline_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_millis() as i64
        + 30_000;
    let owner_scope = OwnerScope::narrowest(
        std::env::var("MNESIS_CANARY_TENANT").unwrap_or_else(|_| "ironclaw-lab".to_string()),
        std::env::var("MNESIS_CANARY_PRINCIPAL")
            .unwrap_or_else(|_| "ironclaw-integration-reader".to_string()),
        OwnerAxes::default(),
    );
    let session_key = owner_scope.key().expect("the canary owner scope keys");
    let attribution = ProviderAttribution {
        owner_scope,
        mission_id: None,
        invocation_id: "11111111-2222-4333-8444-555555555555".to_string(),
        correlation_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_string(),
        deadline_at_ms,
    }
    .encode()
    .expect("the canary attribution encodes");
    (attribution, session_key)
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

/// A server that sends response headers and then stalls forever. The client's
/// own deadline must end the call: a lane that trickles must not be able to pin
/// a run open, which is the client half of the slowloris defence.
fn stalling_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the stalling origin binds");
    let port = listener
        .local_addr()
        .expect("the stalling origin reports its address")
        .port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            read_bounded(&mut stream);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n",
            );
            let _ = stream.flush();
            std::thread::sleep(Duration::from_secs(30));
        }
    });
    port
}

#[tokio::test]
async fn a_stalled_lane_ends_on_the_client_deadline_rather_than_pinning_the_run() {
    let port = stalling_origin();
    let mut config = config_for(
        &format!("http://127.0.0.1:{port}"),
        EndpointProfile::LoopbackDevelopment,
    );
    config.limits.request_timeout_secs = 1;
    config.limits.total_deadline_secs = 3;
    config.limits.max_retries = 0;
    let transport = build(&config, "stall-canary-bearer").expect("loopback is permitted");

    let started = std::time::Instant::now();
    let error = transport
        .execute(MnesisRequest {
            lane: MnesisLane::Memory,
            operation: "memory_search",
            body: json!({"query": "anything", "limit": 4}),
            idempotent: false,
            attribution: None,
            session_key: None,
        })
        .await
        .expect_err("a stalled response must not resolve as success");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(15),
        "the client hung on a stalled lane for {elapsed:?} instead of honouring its deadline"
    );
    assert!(
        !error.to_string().contains("stall-canary-bearer"),
        "a timeout must not echo the credential"
    );
}

/// A plain-TCP listener addressed over `https://`. The handshake must fail
/// rather than degrade to cleartext: this is the control that also closes DNS
/// rebinding for a production endpoint, because an attacker-controlled address
/// cannot complete a TLS handshake for the configured hostname.
fn cleartext_listener_posing_as_tls() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the cleartext listener binds");
    let port = listener
        .local_addr()
        .expect("the cleartext listener reports its address")
        .port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            let _ = stream.flush();
        }
    });
    port
}

#[tokio::test]
async fn tls_is_required_and_never_degrades_to_cleartext() {
    let port = cleartext_listener_posing_as_tls();
    let config = config_for(
        &format!("https://127.0.0.1:{port}"),
        EndpointProfile::Production,
    );
    let transport = build(&config, "tls-canary-bearer").expect("loopback https is permitted");

    let error = transport
        .execute(MnesisRequest {
            lane: MnesisLane::Memory,
            operation: "memory_search",
            body: json!({"query": "anything", "limit": 4}),
            idempotent: false,
            attribution: None,
            session_key: None,
        })
        .await
        .expect_err("a server that cannot complete a TLS handshake must not be talked to");

    assert!(
        !error.to_string().contains("tls-canary-bearer"),
        "a handshake failure must not echo the credential"
    );
}
