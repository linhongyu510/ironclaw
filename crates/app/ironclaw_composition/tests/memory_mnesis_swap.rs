//! End-to-end provider-swap proof for the Mnesis memory provider.
//!
//! Drives the same build-time pipeline `memory_mem0_swap.rs` drives —
//! `[memory]` config → `resolve_memory_binding_policy` →
//! `resolve_memory_provider` → `register_memory_tool_handler` → registry-routed
//! dispatch — and shows that binding memory to the Mnesis extension id routes
//! the manifest-declared tools to the **Mnesis** transport rather than the
//! native filesystem store.
//!
//! Gated on `memory-mnesis`: the feature-off build carries no Mnesis code to
//! swap in.
#![cfg(feature = "memory-mnesis")]

use std::sync::Arc;

use ironclaw_composition::{
    Mem0ConnectionConfig, MemoryProviderDeps, MnesisConnectionConfig, RebornCompositionProfile,
    ResolvedMemoryProvider, resolve_memory_binding_policy, resolve_memory_provider,
};
use ironclaw_config::{MemoryAdminOverride, MemorySection};
use ironclaw_extension_contracts::memory::MemoryLifecycleHook;
use ironclaw_host_api::{
    ids::{CapabilityId, InvocationId, TenantId, UserId},
    mount::{MountGrant, MountPermissions, MountView},
    path::{MountAlias, VirtualPath},
    resource::ResourceScope,
};
use ironclaw_host_runtime::{
    FirstPartyCapabilityRegistry, FirstPartyCapabilityRequest, register_memory_tool_handler,
};
use ironclaw_memory::MEMORY_SEARCH_CAPABILITY_ID;
use ironclaw_memory_mnesis::{MNESIS_MEMORY_EXTENSION_ID, MnesisTransport, MockMnesisTransport};
use serde_json::{Value, json};

const KNOWLEDGE_SEARCH_CAPABILITY_ID: &str = "mnesis.hosted.memory.knowledge.search";

fn filesystem() -> Arc<ironclaw_filesystem::InMemoryBackend> {
    Arc::new(ironclaw_filesystem::InMemoryBackend::new())
}

fn memory_mount() -> MountView {
    MountView::new(vec![MountGrant::new(
        MountAlias::new("/memory").unwrap(),
        VirtualPath::new("/memory").unwrap(),
        MountPermissions::read_write_list_delete(),
    )])
    .unwrap()
}

fn tool_request(capability_id: &str, input: Value) -> FirstPartyCapabilityRequest {
    let mut request = FirstPartyCapabilityRequest::request_for_test(
        CapabilityId::new(capability_id).unwrap(),
        ResourceScope {
            tenant_id: TenantId::new("tenant-swap").unwrap(),
            user_id: UserId::new("user-swap").unwrap(),
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        },
        input,
        None,
    );
    request.mounts = Some(memory_mount());
    request
}

fn registry_for(resolved: &ResolvedMemoryProvider) -> FirstPartyCapabilityRegistry {
    let package = resolved
        .package
        .as_ref()
        .expect("bound provider must carry its package");
    let handler = resolved
        .tool_handler
        .as_ref()
        .expect("bound provider must carry its tool handler");
    let mut registry = FirstPartyCapabilityRegistry::new();
    register_memory_tool_handler(&mut registry, package, Arc::clone(handler));
    registry
}

async fn dispatch_tool(
    registry: &FirstPartyCapabilityRegistry,
    capability_id: &str,
    input: Value,
) -> Value {
    registry
        .get(&CapabilityId::new(capability_id).unwrap())
        .unwrap_or_else(|| panic!("bound manifest must register `{capability_id}`"))
        .dispatch(tool_request(capability_id, input))
        .await
        .unwrap_or_else(|error| panic!("`{capability_id}` dispatch failed: {error:?}"))
        .output
}

fn mnesis_section() -> MemorySection {
    MemorySection {
        provider: Some(MNESIS_MEMORY_EXTENSION_ID.to_string()),
        admin_overrides: vec![MemoryAdminOverride {
            extension_id: MNESIS_MEMORY_EXTENSION_ID.to_string(),
            deployment_profile: "production".to_string(),
        }],
        ..Default::default()
    }
}

fn deps_over_mock(transport: Arc<MockMnesisTransport>) -> MemoryProviderDeps {
    MemoryProviderDeps {
        filesystem: None,
        prompt_write_safety_sink: None,
        mem0: Mem0ConnectionConfig::default(),
        #[cfg(feature = "memory-mem0")]
        mem0_transport_override: None,
        mnesis: MnesisConnectionConfig::default(),
        mnesis_transport_override: Some(transport as Arc<dyn MnesisTransport>),
    }
}

fn hit(text: &str, path: &str) -> Value {
    json!({ "results": [ { "content": text, "relativePath": path } ] })
}

#[tokio::test]
async fn config_binding_swaps_the_memory_provider_to_mnesis_through_the_factory() {
    let transport = Arc::new(MockMnesisTransport::always_ok(hit(
        "swapped hit",
        "notes/a.md",
    )));

    let policy = resolve_memory_binding_policy(
        Some(&mnesis_section()),
        RebornCompositionProfile::Production,
    )
    .expect("mnesis binding resolves with the production override");
    let resolved = resolve_memory_provider(Some(policy), &deps_over_mock(Arc::clone(&transport)))
        .expect("the bound mnesis provider resolves");

    let package = resolved
        .package
        .as_ref()
        .expect("binding mnesis must register mnesis's package");
    assert_eq!(package.manifest.id.as_str(), MNESIS_MEMORY_EXTENSION_ID);

    assert!(
        resolved
            .lifecycle
            .declares(MemoryLifecycleHook::ReadLongTerm)
    );
    assert!(
        resolved
            .lifecycle
            .declares(MemoryLifecycleHook::RecordInteraction)
    );
    assert!(
        resolved
            .lifecycle
            .declares(MemoryLifecycleHook::ReadShortTerm)
    );
    assert!(
        !resolved
            .lifecycle
            .declares(MemoryLifecycleHook::ProfileRead)
    );

    assert!(
        resolved
            .resolver
            .resolve_provider(filesystem(), None)
            .is_some(),
        "memory binding must resolve to the mnesis provider for the lifecycle lanes"
    );

    let registry = registry_for(&resolved);

    let search = dispatch_tool(
        &registry,
        MEMORY_SEARCH_CAPABILITY_ID,
        json!({"query": "swapped", "limit": 5}),
    )
    .await;
    assert_eq!(search["result_count"], 1);
    assert_eq!(search["results"][0]["content"], "swapped hit");

    let knowledge = dispatch_tool(
        &registry,
        KNOWLEDGE_SEARCH_CAPABILITY_ID,
        json!({"query": "swapped", "limit": 5}),
    )
    .await;
    assert_eq!(knowledge["result_count"], 1);

    assert_eq!(
        transport.count_operation("memory_search"),
        1,
        "the memory tool must reach the Mnesis memory lane"
    );
    assert_eq!(
        transport.count_operation("search_knowledge"),
        1,
        "the knowledge tool must reach the Mnesis knowledge lane"
    );
}

#[tokio::test]
async fn mnesis_binding_without_an_endpoint_fails_closed() {
    let policy = resolve_memory_binding_policy(
        Some(&mnesis_section()),
        RebornCompositionProfile::Production,
    )
    .expect("policy resolves");
    let resolved = resolve_memory_provider(
        Some(policy),
        &MemoryProviderDeps::for_third_party(Mem0ConnectionConfig::default()),
    )
    .expect("an unbuildable binding still resolves (to nothing)");

    assert!(
        resolved
            .resolver
            .resolve_provider(filesystem(), None)
            .is_none()
    );
    assert!(resolved.package.is_none());
    assert!(resolved.tool_handler.is_none());
    assert!(resolved.lifecycle.lifecycle.is_empty());
}

#[tokio::test]
async fn mnesis_binding_without_a_credential_fails_closed() {
    let policy = resolve_memory_binding_policy(
        Some(&mnesis_section()),
        RebornCompositionProfile::Production,
    )
    .expect("policy resolves");
    let deps = MemoryProviderDeps::for_third_party(Mem0ConnectionConfig::default()).with_mnesis(
        MnesisConnectionConfig {
            knowledge_endpoint: Some("https://mnesis.example.com/rar/mcp".to_string()),
            memory_endpoint: Some("https://mnesis.example.com/memory/mcp".to_string()),
            ..Default::default()
        },
    );
    let resolved = resolve_memory_provider(Some(policy), &deps).expect("binding resolves");

    assert!(
        resolved
            .resolver
            .resolve_provider(filesystem(), None)
            .is_none(),
        "an endpoint without a lane credential must not build a provider"
    );
    assert!(resolved.package.is_none());
}

#[test]
fn mnesis_binding_in_production_requires_an_admin_override() {
    let section = MemorySection {
        provider: Some(MNESIS_MEMORY_EXTENSION_ID.to_string()),
        admin_overrides: Vec::new(),
        ..Default::default()
    };
    let resolved =
        resolve_memory_binding_policy(Some(&section), RebornCompositionProfile::Production);
    assert!(
        resolved.is_err(),
        "production must reject an unverified third-party binding without an override"
    );
}

#[tokio::test]
async fn a_binding_under_another_extension_id_never_reaches_mnesis() {
    let section = MemorySection {
        provider: Some("someone.elses.memory".to_string()),
        admin_overrides: vec![MemoryAdminOverride {
            extension_id: "someone.elses.memory".to_string(),
            deployment_profile: "production".to_string(),
        }],
        ..Default::default()
    };
    let policy =
        resolve_memory_binding_policy(Some(&section), RebornCompositionProfile::Production)
            .expect("policy resolves for an unknown third-party id");
    let transport = Arc::new(MockMnesisTransport::always_ok(hit("nope", "notes/a.md")));
    let resolved = resolve_memory_provider(Some(policy), &deps_over_mock(Arc::clone(&transport)))
        .expect("an unknown id still resolves (to nothing)");

    assert!(
        resolved
            .resolver
            .resolve_provider(filesystem(), None)
            .is_none(),
        "an unknown extension id must not be satisfied by the Mnesis provider"
    );
    assert_eq!(
        transport.recorded().len(),
        0,
        "an unknown binding must never reach the Mnesis transport"
    );
}

#[tokio::test]
async fn disabled_memory_never_reaches_mnesis() {
    let section = MemorySection {
        provider: Some("memory.disabled".to_string()),
        admin_overrides: Vec::new(),
        ..Default::default()
    };
    let policy =
        resolve_memory_binding_policy(Some(&section), RebornCompositionProfile::Standalone)
            .expect("a disabled section resolves outside production");
    let transport = Arc::new(MockMnesisTransport::always_ok(hit("nope", "notes/a.md")));
    let resolved = resolve_memory_provider(Some(policy), &deps_over_mock(Arc::clone(&transport)))
        .expect("a disabled binding resolves to nothing");

    assert!(
        resolved
            .resolver
            .resolve_provider(filesystem(), None)
            .is_none()
    );
    assert!(resolved.package.is_none());
    assert_eq!(
        transport.recorded().len(),
        0,
        "disabled memory must never reach the Mnesis transport"
    );
}

#[tokio::test]
async fn standalone_swaps_to_mnesis_without_an_override() {
    let section = MemorySection {
        provider: Some(MNESIS_MEMORY_EXTENSION_ID.to_string()),
        admin_overrides: Vec::new(),
        ..Default::default()
    };
    let policy =
        resolve_memory_binding_policy(Some(&section), RebornCompositionProfile::Standalone)
            .expect("standalone allows the third-party binding without an override");
    let transport = Arc::new(MockMnesisTransport::always_ok(hit(
        "dev swap",
        "notes/b.md",
    )));
    let resolved = resolve_memory_provider(Some(policy), &deps_over_mock(Arc::clone(&transport)))
        .expect("local-dev mnesis binding resolves");

    assert!(
        resolved
            .resolver
            .resolve_provider(filesystem(), None)
            .is_some()
    );
    assert!(
        resolved.package.is_some(),
        "standalone binding registers the Mnesis package"
    );
    assert_eq!(transport.count_operation("memory_search"), 0);
}
