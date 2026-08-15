use ironclaw_memory::MemoryService;
use ironclaw_memory_mnesis::{MnesisMemoryService, MockMnesisTransport};
use serde_json::{Value, json};

fn record(record_class: &str, thread: Option<&str>) -> Value {
    json!({
        "relativePath": "note.md",
        "content": "body",
        "authorization": {
            "kind": "owner-scope",
            "ownerScope": {
                "recordClass": record_class,
                "tenantId": "tenant-mnesis",
                "principalId": "user-mnesis",
                "agentId": "agent-mnesis",
                "projectId": "project-mnesis",
                "threadId": thread
            }
        }
    })
}

fn service_returning(results: Vec<Value>) -> MnesisMemoryService<MockMnesisTransport> {
    MnesisMemoryService::new(MockMnesisTransport::always_ok(
        json!({ "results": results }),
    ))
}

#[tokio::test]
async fn short_term_returns_nothing_without_a_trusted_thread() {
    let service = service_returning(vec![record("thread-private", Some("thread-a"))]);
    let snippets = service
        .read_short_term(invocation(None), request("anything", 4))
        .await
        .unwrap();
    assert!(
        snippets.is_empty(),
        "no thread axis means no short-term recall"
    );
    assert!(
        service.transport().recorded().is_empty(),
        "an absent thread must not even reach the transport"
    );
}

#[tokio::test]
async fn short_term_drops_any_record_that_is_not_thread_private() {
    let service = service_returning(vec![
        record("principal-private", None),
        record("project-private", None),
        record("agent-private", None),
        record("thread-private", Some("thread-a")),
    ]);
    let snippets = service
        .read_short_term(invocation(Some("thread-a")), request("anything", 10))
        .await
        .unwrap();
    assert_eq!(
        snippets.len(),
        1,
        "only a thread-private record belongs to the short-term lane"
    );
}

#[tokio::test]
async fn a_thread_private_record_never_enters_the_long_term_lane() {
    let service = service_returning(vec![record("thread-private", Some("thread-a"))]);
    let snippets = service
        .read_long_term(invocation(Some("thread-a")), request("anything", 10))
        .await
        .unwrap();
    for snippet in &snippets {
        assert!(
            !snippet.relative_path.is_empty(),
            "long-term snippets remain well formed"
        );
    }
    for entry in service.transport().recorded() {
        let attribution = entry.attribution.expect("attribution present");
        let owner = owner_tuple(&attribution);
        assert_eq!(
            owner[6],
            Value::Null,
            "the long-term request must not claim a thread axis"
        );
    }
}

#[tokio::test]
async fn short_term_requests_carry_the_thread_axis_and_the_thread_private_class() {
    let service = service_returning(vec![record("thread-private", Some("thread-a"))]);
    let _ = service
        .read_short_term(invocation(Some("thread-a")), request("anything", 4))
        .await;
    let recorded = service.transport().recorded();
    assert_eq!(recorded.len(), 1, "short term uses the memory lane only");
    let attribution = recorded[0]
        .attribution
        .clone()
        .expect("attribution present");
    let owner = owner_tuple(&attribution);
    assert_eq!(owner[1], "thread-private");
    assert_eq!(owner[6], "thread-a");
}

#[tokio::test]
async fn a_record_from_another_thread_is_still_labelled_with_its_own_thread() {
    let service = service_returning(vec![record("thread-private", Some("thread-b"))]);
    let snippets = service
        .read_short_term(invocation(Some("thread-a")), request("anything", 4))
        .await
        .unwrap();
    assert_eq!(snippets.len(), 1);
    assert_eq!(
        snippets[0].user_id, "user-mnesis",
        "the provider reports what Mnesis owner-scoped, never the caller's axes"
    );
}

#[tokio::test]
async fn an_unscoped_short_term_record_is_dropped() {
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(json!({
        "results": [{"relativePath": "a.md", "content": "alpha"}]
    })));
    let snippets = service
        .read_short_term(invocation(Some("thread-a")), request("anything", 4))
        .await
        .unwrap();
    assert!(snippets.is_empty());
}

fn owner_tuple(attribution: &str) -> Vec<Value> {
    use base64::Engine;
    let payload = attribution.strip_prefix("mpa1.").expect("prefix");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("canonical base64url");
    let tuple: Vec<Value> = serde_json::from_slice(&decoded).expect("tuple");
    let owner_key = tuple[1].as_str().expect("owner key");
    let owner_decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(owner_key.strip_prefix("mos1.").expect("prefix"))
        .expect("canonical base64url");
    serde_json::from_slice(&owner_decoded).expect("owner tuple")
}

fn invocation(thread: Option<&str>) -> ironclaw_memory::MemoryInvocation {
    use ironclaw_host_api::ids::{
        AgentId, CorrelationId, InvocationId, ProjectId, TenantId, ThreadId, UserId,
    };
    ironclaw_memory::MemoryInvocation {
        scope: ironclaw_host_api::resource::ResourceScope {
            tenant_id: TenantId::new("tenant-mnesis").unwrap(),
            user_id: UserId::new("user-mnesis").unwrap(),
            agent_id: Some(AgentId::new("agent-mnesis").unwrap()),
            project_id: Some(ProjectId::new("project-mnesis").unwrap()),
            mission_id: None,
            thread_id: thread.map(|id| ThreadId::new(id).unwrap()),
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
