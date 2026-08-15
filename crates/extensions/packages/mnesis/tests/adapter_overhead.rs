use ironclaw_memory::MemoryService;
use ironclaw_memory_mnesis::{MnesisMemoryService, MockMnesisTransport};
use serde_json::json;
use std::time::Instant;

const SAMPLES: usize = 2_000;

fn percentile(sorted: &[u128], fraction: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() as f64 - 1.0) * fraction).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

#[tokio::test(flavor = "multi_thread")]
async fn adapter_overhead_stays_inside_its_budget() {
    let body = json!({
        "results": (0..20)
            .map(|index| json!({
                "relativePath": format!("note-{index}.md"),
                "content": "the quick brown fox jumps over the lazy dog",
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
    });
    let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(body));

    for _ in 0..100 {
        let _ = service
            .read_long_term(invocation(), request("warm", 10))
            .await;
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let snippets = service
            .read_long_term(invocation(), request("benchmark query", 10))
            .await
            .expect("the mock always answers");
        samples.push(started.elapsed().as_micros());
        assert_eq!(snippets.len(), 10);
    }
    samples.sort_unstable();

    let p50 = percentile(&samples, 0.50);
    let p95 = percentile(&samples, 0.95);
    let p99 = percentile(&samples, 0.99);
    println!("  adapter overhead over {SAMPLES} samples (transport mocked)");
    println!("    p50 {p50}us  p95 {p95}us  p99 {p99}us");

    assert!(
        p95 < 2_000,
        "p95 adapter overhead {p95}us exceeds the 2000us budget"
    );
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
