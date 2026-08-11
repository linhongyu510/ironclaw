//! Provider-level contract suites for [`MemoryService`](crate::MemoryService)
//! implementations and the optional conventional memory document tools.
//!
//! Same scaffolding pattern as `ironclaw_memory_native::contract_tests`
//! (factory closures, one `#[tokio::test]` per contract per impl via a wiring
//! macro): an invariant is defined ONCE here, and each applicable provider
//! wires the suite over a real (or stateful-fake) backing so the contract is
//! proven per impl, not per mock.
//!
//! The lifecycle contracts every applicable provider wires:
//! - **Scope isolation** across tenant/user/agent/project: content written in
//!   one scope is invisible to retrieval in any scope differing on any axis.
//! - **Lane disjointness** (F4 regression) for providers declaring BOTH
//!   retrieval lanes: a short-term (active-thread) result never appears in
//!   the long-term lane and vice versa, so the host's concatenation can never
//!   double-spend its byte budget on duplicates.
//! - **`record_interaction` round-trip visibility** (F5 regression) for
//!   providers declaring the hook: a recorded exchange reports
//!   `recorded: true` and is retrievable from the short-term lane.
//!
//! The optional conventional document-tool contract:
//! - **Target-alias resolution** (#7505): a provider declaring the conventional
//!   `ironclaw.memory.write` + `.read` tools with the shared prompt/schema must
//!   return a fact written with `target: "memory"` at canonical `MEMORY.md`,
//!   never store/read it only under the alias.
//!
//! F6 note (owner decision, 2026-07-27): there is deliberately NO profile-CAS
//! contract — profile-write atomicity is per-provider (native CASes; mem0
//! read-merge-writes), accepted variance behind the shared tool id.
//!
//! Tool surfaces are provider-owned (registry-routed handlers). The
//! `memory_service_contract_*` macros therefore take a SEED closure only for
//! arranging lifecycle-test content; they do NOT require a provider to expose
//! document tools. A provider that opts into the conventional
//! `ironclaw.memory.write` + `.read` surface separately wires
//! [`memory_document_tool_contract!`] with WRITE and READ closures through its
//! own inherent tool operations.
//!
//! Lifecycle wiring:
//! - [`memory_service_contract_full!`] `(label, factory, seed)` for both lanes
//!   plus recording (the native shape).
//! - [`memory_service_contract_retrieval_only!`] `(label, factory, seed)` for a
//!   long-term-only provider (the mem0 shape).
//!
//! Optional document-tool wiring:
//! - [`memory_document_tool_contract!`] `(label, factory, write, read)`.

use ironclaw_host_api::{
    ids::{AgentId, CorrelationId, InvocationId, ProjectId, TenantId, ThreadId, UserId},
    resource::ResourceScope,
};

use crate::{
    MEMORY_DOCUMENT_PATH, MEMORY_DOCUMENT_TARGET, MemoryContextProfileId, MemoryInteractionMessage,
    MemoryInteractionRole, MemoryInvocation, MemoryService, MemoryServiceContextRequest,
    MemoryServiceContextSnippet, MemoryServiceError, MemoryServiceReadRequest,
    MemoryServiceReadResponse, MemoryServiceRecordRequest, MemoryServiceWriteRequest,
};

/// Base scope every contract writes under: the full four-axis tuple, so each
/// probe scope can differ on exactly one axis.
fn base_scope() -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new("tenant-contract").expect("tenant id"),
        user_id: UserId::new("user-contract").expect("user id"),
        agent_id: Some(AgentId::new("agent-contract").expect("agent id")),
        project_id: Some(ProjectId::new("project-contract").expect("project id")),
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

fn invocation(scope: ResourceScope) -> MemoryInvocation {
    MemoryInvocation {
        scope,
        correlation_id: CorrelationId::new(),
    }
}

fn with_thread(mut scope: ResourceScope, thread: &str) -> ResourceScope {
    scope.thread_id = Some(ThreadId::new(thread).expect("thread id"));
    scope
}

fn context_request(query: &str) -> MemoryServiceContextRequest {
    MemoryServiceContextRequest {
        query: query.to_string(),
        max_snippets: 10,
        context_profile_id: MemoryContextProfileId::new("default").expect("profile id"),
    }
}

fn write_request(target: &str, content: &str) -> MemoryServiceWriteRequest {
    MemoryServiceWriteRequest {
        target: target.to_string(),
        content: content.to_string(),
        append: true,
        old_string: None,
        new_string: None,
        replace_all: false,
        metadata: None,
        timezone: None,
    }
}

fn texts(snippets: &[MemoryServiceContextSnippet]) -> Vec<&str> {
    snippets
        .iter()
        .map(|snippet| snippet.text.as_str())
        .collect()
}

/// Contract: content written in the base scope is retrievable there and
/// invisible to every scope differing on exactly one of
/// tenant/user/agent/project.
///
/// The thread axis is deliberately NOT an isolation axis for durable memory
/// (#7294): general memory written while one conversation is active is
/// user-scoped, so the same user's other conversations — and thread-less
/// (e.g. trigger-fired) invocations — retrieve it BY DESIGN. Recall across
/// conversations is not a leak; how recalled memory is framed to the model
/// is the host's prompt-assembly concern, not a provider scoping concern.
pub async fn scope_isolation_across_tenant_user_agent_project<S, F, Seed>(factory: F, seed: Seed)
where
    S: MemoryService,
    F: Fn() -> S,
    Seed: AsyncFn(&S, MemoryInvocation, MemoryServiceWriteRequest),
{
    let service = factory();
    let base = base_scope();
    // Seed while a conversation is ACTIVE: the durable write must not be
    // silently keyed to the active thread.
    seed(
        &service,
        invocation(with_thread(base.clone(), "thread-isolation-writer")),
        write_request("notes/isolation.md", "contract isolation marker kestrel"),
    )
    .await;

    let own = service
        .read_long_term(invocation(base.clone()), context_request("kestrel"))
        .await
        .expect("base-scope retrieval must succeed");
    assert!(
        own.iter().any(|snippet| snippet.text.contains("kestrel")),
        "the writing scope must retrieve its own content (got {:?})",
        texts(&own)
    );

    // Same four-axis scope, DIFFERENT conversation: durable memory crosses
    // threads by design — a "fix" that thread-scopes the long-term lane would
    // silently amnesia every new conversation (#7294 by-design half).
    let other_thread = service
        .read_long_term(
            invocation(with_thread(base.clone(), "thread-isolation-reader")),
            context_request("kestrel"),
        )
        .await
        .expect("cross-thread retrieval must succeed");
    assert!(
        other_thread
            .iter()
            .any(|snippet| snippet.text.contains("kestrel")),
        "durable memory is user-scoped, not thread-scoped: another conversation \
         of the same scope must still retrieve it (got {:?})",
        texts(&other_thread)
    );

    let mut other_tenant = base.clone();
    other_tenant.tenant_id = TenantId::new("tenant-other").expect("tenant id");
    let mut other_user = base.clone();
    other_user.user_id = UserId::new("user-other").expect("user id");
    let mut other_agent = base.clone();
    other_agent.agent_id = Some(AgentId::new("agent-other").expect("agent id"));
    let mut other_project = base.clone();
    other_project.project_id = Some(ProjectId::new("project-other").expect("project id"));

    for (axis, probe) in [
        ("tenant", other_tenant),
        ("user", other_user),
        ("agent", other_agent),
        ("project", other_project),
    ] {
        let cross = service
            .read_long_term(invocation(probe), context_request("kestrel"))
            .await
            .expect("cross-scope retrieval must succeed (empty, not error)");
        assert!(
            cross
                .iter()
                .all(|snippet| !snippet.text.contains("kestrel")),
            "a scope differing on the {axis} axis must not see the base scope's \
             content (got {:?})",
            texts(&cross)
        );
    }
}

/// Contract (F4): for a provider declaring BOTH retrieval lanes, the lanes
/// stay disjoint under the SAME thread-carrying invocation — a short-term
/// (active-thread) result never appears in the long-term lane, and the
/// short-term lane never surfaces general memory.
pub async fn retrieval_lanes_are_disjoint<S, F, Seed>(factory: F, seed: Seed)
where
    S: MemoryService,
    F: Fn() -> S,
    Seed: AsyncFn(&S, MemoryInvocation, MemoryServiceWriteRequest),
{
    let service = factory();
    let scoped = with_thread(base_scope(), "thread-disjoint");

    seed(
        &service,
        invocation(scoped.clone()),
        write_request("notes/general.md", "osprey durable general fact"),
    )
    .await;
    let recorded = service
        .record_interaction(
            invocation(scoped.clone()),
            MemoryServiceRecordRequest {
                messages: vec![MemoryInteractionMessage {
                    role: MemoryInteractionRole::User,
                    content: "osprey scratch note for this thread".to_string(),
                    name: Some("user-contract".to_string()),
                }],
                turn_run_id: Some("run-disjoint-1".to_string()),
                metadata: serde_json::json!({}),
            },
        )
        .await
        .expect("record_interaction must succeed");
    assert!(recorded.recorded, "the thread exchange must be recorded");

    let long = service
        .read_long_term(invocation(scoped.clone()), context_request("osprey"))
        .await
        .expect("long-term lane must succeed");
    let short = service
        .read_short_term(invocation(scoped), context_request("osprey"))
        .await
        .expect("short-term lane must succeed");

    assert!(
        long.iter().any(|snippet| snippet.text.contains("durable")),
        "long-term lane must surface the general doc (got {:?})",
        texts(&long)
    );
    assert!(
        short.iter().any(|snippet| snippet.text.contains("scratch")),
        "short-term lane must surface the recorded thread doc (got {:?})",
        texts(&short)
    );
    // Disjointness both ways: no snippet path may appear in both lanes, the
    // long-term lane carries no thread scratch, and the short-term lane
    // carries no general memory.
    for snippet in &long {
        assert!(
            !short
                .iter()
                .any(|other| other.relative_path == snippet.relative_path),
            "lanes must be disjoint; {} appeared in both (F4)",
            snippet.relative_path
        );
        assert!(
            !snippet.text.contains("scratch"),
            "long-term lane leaked thread scratch: {:?}",
            snippet.text
        );
    }
    for snippet in &short {
        assert!(
            !snippet.text.contains("durable"),
            "short-term lane leaked general memory: {:?}",
            snippet.text
        );
    }
}

/// Contract (F5): a provider declaring `record_interaction` really records —
/// the response reports `recorded: true` and the exchange is retrievable
/// from the short-term lane of the SAME thread (and only that thread).
///
/// Cross-conversation containment (#7294 leak hypothesis): a recorded
/// conversation transcript is per-thread scratch, so it must be invisible to
/// EVERY retrieval lane of any other invocation — another thread's short-term
/// lane, another thread's long-term lane, and a thread-less (e.g.
/// trigger-fired) invocation's long-term lane. Only the durable memory the
/// model explicitly writes may cross conversations; raw transcripts never do.
pub async fn record_interaction_round_trips_into_retrieval<S, F>(factory: F)
where
    S: MemoryService,
    F: Fn() -> S,
{
    let service = factory();
    let scoped = with_thread(base_scope(), "thread-record");

    let recorded = service
        .record_interaction(
            invocation(scoped.clone()),
            MemoryServiceRecordRequest {
                messages: vec![
                    MemoryInteractionMessage {
                        role: MemoryInteractionRole::User,
                        content: "remember the merlin launch window".to_string(),
                        name: Some("user-contract".to_string()),
                    },
                    MemoryInteractionMessage {
                        role: MemoryInteractionRole::Assistant,
                        content: "noted: merlin launch window".to_string(),
                        name: Some("agent-contract".to_string()),
                    },
                ],
                turn_run_id: Some("run-record-1".to_string()),
                metadata: serde_json::json!({}),
            },
        )
        .await
        .expect("record_interaction must succeed");
    assert!(
        recorded.recorded,
        "a declared recorder must report recorded: true (F5 — a silent no-op \
         behind a declared hook is exactly the defect this pins)"
    );

    let same_thread = service
        .read_short_term(invocation(scoped.clone()), context_request("merlin"))
        .await
        .expect("short-term retrieval must succeed");
    assert!(
        same_thread
            .iter()
            .any(|snippet| snippet.text.contains("merlin")),
        "the recorded exchange must be retrievable from its thread's \
         short-term lane (got {:?})",
        texts(&same_thread)
    );

    let other_thread = service
        .read_short_term(
            invocation(with_thread(base_scope(), "thread-unrelated")),
            context_request("merlin"),
        )
        .await
        .expect("other-thread retrieval must succeed");
    assert!(
        other_thread
            .iter()
            .all(|snippet| !snippet.text.contains("merlin")),
        "another thread's short-term lane must not see the recording (got {:?})",
        texts(&other_thread)
    );

    // #7294: the transcript must not resurface through the DURABLE lane of a
    // different conversation either — the long-term lane is the one that
    // crosses threads by design, so an unexcluded transcript there is exactly
    // the "agent remembers another conversation's routine" leak.
    let other_thread_long_term = service
        .read_long_term(
            invocation(with_thread(base_scope(), "thread-unrelated")),
            context_request("merlin"),
        )
        .await
        .expect("other-thread long-term retrieval must succeed");
    assert!(
        other_thread_long_term
            .iter()
            .all(|snippet| !snippet.text.contains("merlin")),
        "another thread's long-term lane must not surface a recorded \
         conversation transcript (got {:?})",
        texts(&other_thread_long_term)
    );

    // Thread-less invocation (the trigger-fired / no-active-conversation
    // shape): the durable lane still must not surface any thread's transcript.
    let thread_less_long_term = service
        .read_long_term(invocation(base_scope()), context_request("merlin"))
        .await
        .expect("thread-less long-term retrieval must succeed");
    assert!(
        thread_less_long_term
            .iter()
            .all(|snippet| !snippet.text.contains("merlin")),
        "a thread-less invocation's long-term lane must not surface a recorded \
         conversation transcript (got {:?})",
        texts(&thread_less_long_term)
    );
}

/// Optional conventional document-tool contract (#7505): a provider that
/// declares `ironclaw.memory.write` + `.read` with the shared prompt/schema
/// resolves their target aliases identically. A fact written with
/// `target: "memory"` (the alias the shared write prompt teaches) must be
/// returned by a read of canonical `MEMORY.md` — the path the host's
/// always-on prompt lane reads. A provider that stores the alias unresolved
/// (or skips compatibility matching on its read path) fails this contract.
pub async fn target_aliases_resolve_to_canonical_documents<S, F, Write, Read>(
    factory: F,
    write: Write,
    read: Read,
) where
    S: MemoryService,
    F: Fn() -> S,
    Write: AsyncFn(&S, MemoryInvocation, MemoryServiceWriteRequest),
    Read: AsyncFn(
        &S,
        MemoryInvocation,
        MemoryServiceReadRequest,
    ) -> Result<MemoryServiceReadResponse, MemoryServiceError>,
{
    let service = factory();
    let inv = invocation(base_scope());
    write(
        &service,
        inv.clone(),
        write_request(MEMORY_DOCUMENT_TARGET, "alias contract marker ibis"),
    )
    .await;

    let canonical = read(
        &service,
        inv,
        MemoryServiceReadRequest {
            path: MEMORY_DOCUMENT_PATH.to_string(),
        },
    )
    .await
    .expect("reading the canonical document must succeed (not fail or report absent)");
    assert!(
        canonical.content.contains("alias contract marker ibis"),
        "a fact written with `target: \"memory\"` must be readable at `MEMORY.md` — \
         a provider that stores the alias unresolved fails the optional conventional \
         document-tool contract (#7505); read back: {:?}",
        canonical.content
    );
}

/// Wire the FULL provider lifecycle contract suite (both retrieval lanes +
/// interaction recording — the native shape). `$factory` must return a fresh
/// service over a fresh backing per call. `$seed` arranges test content
/// through a provider-specific seam; it does not imply a model-facing write
/// tool.
#[macro_export]
macro_rules! memory_service_contract_full {
    ($label:ident, $factory:expr, $seed:expr) => {
        mod $label {
            use super::*;

            #[tokio::test]
            async fn scope_isolation_across_tenant_user_agent_project() {
                $crate::test_support::scope_isolation_across_tenant_user_agent_project(
                    $factory, $seed,
                )
                .await;
            }

            #[tokio::test]
            async fn retrieval_lanes_are_disjoint() {
                $crate::test_support::retrieval_lanes_are_disjoint($factory, $seed).await;
            }

            #[tokio::test]
            async fn record_interaction_round_trips_into_retrieval() {
                $crate::test_support::record_interaction_round_trips_into_retrieval($factory).await;
            }
        }
    };
}

/// Wire the provider lifecycle contract suite for a provider declaring ONLY
/// the long-term retrieval lane (the mem0 shape): scope isolation applies;
/// lane and recording contracts do not (those hooks are undeclared, so the
/// host never calls them). `$seed` need not be a model-facing tool.
#[macro_export]
macro_rules! memory_service_contract_retrieval_only {
    ($label:ident, $factory:expr, $seed:expr) => {
        mod $label {
            use super::*;

            #[tokio::test]
            async fn scope_isolation_across_tenant_user_agent_project() {
                $crate::test_support::scope_isolation_across_tenant_user_agent_project(
                    $factory, $seed,
                )
                .await;
            }
        }
    };
}

/// Wire the OPTIONAL conventional document-tool contract for a provider
/// whose manifest declares `ironclaw.memory.write` + `.read` with the shared
/// prompt/schema vocabulary. Providers exposing different tools do not wire
/// this suite.
#[macro_export]
macro_rules! memory_document_tool_contract {
    ($label:ident, $factory:expr, $write:expr, $read:expr) => {
        mod $label {
            use super::*;

            #[tokio::test]
            async fn target_aliases_resolve_to_canonical_documents() {
                $crate::test_support::target_aliases_resolve_to_canonical_documents(
                    $factory, $write, $read,
                )
                .await;
            }
        }
    };
}
