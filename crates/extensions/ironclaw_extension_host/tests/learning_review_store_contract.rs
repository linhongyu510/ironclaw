use std::sync::Arc;

use ironclaw_extension_host::learning_review::FilesystemLearningCandidateStore;
use ironclaw_filesystem::{InMemoryBackend, ScopedFilesystem};
use ironclaw_host_api::{
    ids::{AgentId, InvocationId, ProjectId, TenantId, UserId},
    mount::{MountGrant, MountPermissions, MountView},
    path::{MountAlias, VirtualPath},
    resource::ResourceScope,
    turn::TurnRunId,
};
use ironclaw_memory::{
    LearningCandidateInsert, LearningCandidateStore, LearningDecision, LearningExplicitness,
    LearningReview, LearningReviewRecord, LearningScope, MemoryLearningProposal,
    MemoryLearningProposalKind,
};

fn resource_scope() -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new("tenant-a").expect("tenant"),
        user_id: UserId::new("user-a").expect("user"),
        agent_id: None,
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
    .tenant_shared_managed_scope()
}

fn learning_scope() -> LearningScope {
    LearningScope::new(
        TenantId::new("tenant-a").expect("tenant"),
        UserId::new("user-a").expect("user"),
        AgentId::new("agent-a").expect("agent"),
        Some(ProjectId::new("project-a").expect("project")),
    )
}

fn record(run_id: TurnRunId) -> LearningReviewRecord {
    LearningReviewRecord::new(
        run_id,
        learning_scope(),
        LearningReview {
            memory: vec![MemoryLearningProposal {
                kind: MemoryLearningProposalKind::Preference,
                content: "Use short status reports".to_string(),
                source_message_indices: vec![0],
                confidence_basis_points: 9_000,
                explicitness: LearningExplicitness::Explicit,
                tainted: false,
            }],
            skill: LearningDecision::skip(),
        },
    )
    .expect("record")
}

#[tokio::test]
async fn candidate_store_is_idempotent_by_run() {
    let backend = Arc::new(InMemoryBackend::new());
    let filesystem = ScopedFilesystem::new(backend, |scope| {
        MountView::new(vec![MountGrant::new(
            MountAlias::new("/tenant-shared")?,
            VirtualPath::new(format!("/tenants/{}/shared", scope.tenant_id.as_str()))?,
            MountPermissions::read_write(),
        )])
    });
    let store = FilesystemLearningCandidateStore::new(Arc::new(filesystem), resource_scope());
    let record = record(TurnRunId::new());

    assert_eq!(
        store.insert_if_absent(&record).await.expect("first insert"),
        LearningCandidateInsert::Created
    );
    assert_eq!(
        store
            .insert_if_absent(&record)
            .await
            .expect("replay insert"),
        LearningCandidateInsert::AlreadyExists
    );
    assert_eq!(
        store
            .get(&learning_scope(), record.run_id)
            .await
            .expect("get candidate"),
        Some(record.clone())
    );
    assert_eq!(
        store
            .list_unresolved(&learning_scope())
            .await
            .expect("list unresolved"),
        vec![record]
    );
}
