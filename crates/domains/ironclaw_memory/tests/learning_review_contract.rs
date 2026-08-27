use ironclaw_host_api::ids::{AgentId, ProjectId, TenantId, UserId};
use ironclaw_host_api::turn::TurnRunId;
use ironclaw_memory::{
    LearningAction, LearningCandidateStatus, LearningDecision, LearningExplicitness,
    LearningReview, LearningReviewRecord, LearningScope, MAX_LEARNING_MEMORY_PROPOSALS,
    MAX_LEARNING_PROPOSAL_BYTES, MemoryLearningProposal, MemoryLearningProposalKind,
};

fn scope() -> LearningScope {
    LearningScope::new(
        TenantId::new("tenant-a").expect("tenant"),
        UserId::new("user-a").expect("user"),
        AgentId::new("agent-a").expect("agent"),
        Some(ProjectId::new("project-a").expect("project")),
    )
}

fn proposal(content: &str) -> MemoryLearningProposal {
    MemoryLearningProposal {
        kind: MemoryLearningProposalKind::Preference,
        content: content.to_string(),
        source_message_indices: vec![1],
        confidence_basis_points: 9_000,
        explicitness: LearningExplicitness::Explicit,
        tainted: false,
    }
}

#[test]
fn learning_review_rejects_too_many_or_oversized_memory_proposals() {
    let too_many = LearningReview {
        memory: vec![proposal("bounded"); MAX_LEARNING_MEMORY_PROPOSALS + 1],
        skill: LearningDecision::skip(),
    };
    assert!(too_many.validate().is_err());

    let oversized = LearningReview {
        memory: vec![proposal(&"x".repeat(MAX_LEARNING_PROPOSAL_BYTES + 1))],
        skill: LearningDecision::skip(),
    };
    assert!(oversized.validate().is_err());
}

#[test]
fn learning_review_rejects_unknown_output_fields() {
    let json = r#"{
        "memory": [],
        "skill": {"action": "skip", "reason": null, "source_message_indices": []},
        "unexpected": true
    }"#;
    assert!(serde_json::from_str::<LearningReview>(json).is_err());
}

#[test]
fn learning_review_rejects_invalid_confidence_and_source_references() {
    let invalid_confidence = LearningReview {
        memory: vec![MemoryLearningProposal {
            confidence_basis_points: 10_001,
            ..proposal("bounded")
        }],
        skill: LearningDecision::skip(),
    };
    assert!(invalid_confidence.validate().is_err());

    let missing_source = LearningReview {
        memory: vec![MemoryLearningProposal {
            source_message_indices: Vec::new(),
            ..proposal("bounded")
        }],
        skill: LearningDecision::skip(),
    };
    assert!(missing_source.validate().is_err());
}

#[test]
fn record_seals_scope_run_and_candidate_status() {
    let run_id = TurnRunId::new();
    let review = LearningReview {
        memory: vec![proposal("Use concise status reports")],
        skill: LearningDecision {
            action: LearningAction::Distill,
            reason: Some("The run contains a reusable procedure".to_string()),
            source_message_indices: vec![1],
        },
    };

    let record = LearningReviewRecord::new(run_id, scope(), review).expect("valid record");
    assert_eq!(record.run_id, run_id);
    assert_eq!(record.status, LearningCandidateStatus::Candidate);
    assert_eq!(
        record.idempotency_key.as_str(),
        format!("learning-review:{run_id}")
    );
    assert_eq!(record.scope.user_id().as_str(), "user-a");
}
