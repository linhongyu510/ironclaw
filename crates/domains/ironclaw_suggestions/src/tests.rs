use std::sync::Arc;

use chrono::{Duration, Utc};
use ironclaw_filesystem::InMemoryBackend;
use ironclaw_host_api::ids::{TenantId, ThreadId, UserId};
use ironclaw_host_api::turn::TurnRunId;
use uuid::Uuid;

use super::*;

fn tenant() -> TenantId {
    TenantId::new("suggestions-tenant").expect("tenant id")
}

fn user() -> UserId {
    UserId::new("suggestions-user").expect("user id")
}

fn card(title: &str) -> SuggestionCard {
    SuggestionCard {
        id: Uuid::new_v4(),
        title: title.to_string(),
        description: "do the thing".to_string(),
        extension_id: Some("gmail".to_string()),
        requires_connection: true,
        suggested_prompt: "go do the thing".to_string(),
        category: "email".to_string(),
    }
}

// --- derive_suggestions_view precedence (spec §4) --------------------------

#[test]
fn empty_doc_derives_none_with_no_cards() {
    let view = derive_suggestions_view(&SuggestionsDoc::empty(), None);
    assert_eq!(view.generation.state, GenerationState::None);
    assert!(view.cards.is_empty());
    assert_eq!(view.schema_version, SUGGESTIONS_SCHEMA_VERSION);
}

#[test]
fn active_job_with_live_run_derives_running() {
    let mut doc = SuggestionsDoc::empty();
    let job_id = Uuid::new_v4();
    doc.active_job = Some(ActiveJob {
        job_id,
        thread_id: ThreadId::new("t1").expect("thread id"),
        run_id: TurnRunId::new(),
        started_at: Utc::now(),
    });

    let view = derive_suggestions_view(&doc, Some(RunLiveness::Live));

    assert_eq!(view.generation.state, GenerationState::Running);
    assert_eq!(view.generation.job_id, Some(job_id));
}

#[test]
fn active_job_with_dead_run_derives_failed_without_a_janitor() {
    // Crash-recovery path (spec §5): a dead run's active_job was never
    // cleared, but the read alone must still derive `failed` — no repair
    // process required.
    let mut doc = SuggestionsDoc::empty();
    doc.active_job = Some(ActiveJob {
        job_id: Uuid::new_v4(),
        thread_id: ThreadId::new("t1").expect("thread id"),
        run_id: TurnRunId::new(),
        started_at: Utc::now(),
    });

    for liveness in [RunLiveness::Terminal, RunLiveness::Missing] {
        let view = derive_suggestions_view(&doc, Some(liveness));
        assert_eq!(view.generation.state, GenerationState::Failed);
        assert!(view.generation.error.is_some());
    }
}

#[test]
fn missing_liveness_answer_fails_toward_failed_not_stuck_running() {
    let mut doc = SuggestionsDoc::empty();
    doc.active_job = Some(ActiveJob {
        job_id: Uuid::new_v4(),
        thread_id: ThreadId::new("t1").expect("thread id"),
        run_id: TurnRunId::new(),
        started_at: Utc::now(),
    });

    let view = derive_suggestions_view(&doc, None);

    assert_eq!(view.generation.state, GenerationState::Failed);
}

#[test]
fn last_error_newer_than_last_result_derives_failed_with_stale_cards() {
    let now = Utc::now();
    let doc = SuggestionsDoc {
        schema_version: SUGGESTIONS_SCHEMA_VERSION,
        active_job: None,
        last_result: Some(LastResult {
            cards: vec![card("old suggestion")],
            completed_at: now - Duration::hours(1),
        }),
        last_error: Some(LastError {
            message: "model never called render_suggestions".to_string(),
            failed_at: now,
        }),
    };

    let view = derive_suggestions_view(&doc, None);

    assert_eq!(view.generation.state, GenerationState::Failed);
    assert_eq!(
        view.generation.error.as_deref(),
        Some("model never called render_suggestions")
    );
    // Stale cards still render alongside the retry banner (spec §4).
    assert_eq!(view.cards.len(), 1);
}

#[test]
fn last_result_newer_than_last_error_derives_ready() {
    let now = Utc::now();
    let doc = SuggestionsDoc {
        schema_version: SUGGESTIONS_SCHEMA_VERSION,
        active_job: None,
        last_result: Some(LastResult {
            cards: vec![card("fresh suggestion")],
            completed_at: now,
        }),
        last_error: Some(LastError {
            message: "an earlier attempt failed".to_string(),
            failed_at: now - Duration::hours(1),
        }),
    };

    let view = derive_suggestions_view(&doc, None);

    assert_eq!(view.generation.state, GenerationState::Ready);
    assert_eq!(view.generation.error, None);
    assert_eq!(view.cards.len(), 1);
}

// --- schema tolerance (item 8) ---------------------------------------------

#[test]
fn unknown_fields_are_ignored_on_deserialize() {
    let json = serde_json::json!({
        "schema_version": SUGGESTIONS_SCHEMA_VERSION,
        "active_job": null,
        "last_result": null,
        "last_error": null,
        "some_future_field": {"nested": true},
    });

    let doc: SuggestionsDoc =
        serde_json::from_value(json).expect("unknown fields must not fail deserialization");

    assert_eq!(doc.schema_version, SUGGESTIONS_SCHEMA_VERSION);
    assert!(doc.active_job.is_none());
}

#[test]
fn card_extension_id_is_optional_on_the_wire() {
    let json = serde_json::json!({
        "id": Uuid::new_v4(),
        "title": "Triage inbox",
        "description": "Summarize unread mail",
        "requires_connection": false,
        "suggested_prompt": "go triage my inbox",
        "category": "email",
    });

    let card: SuggestionCard = serde_json::from_value(json).expect("extension_id must be optional");

    assert_eq!(card.extension_id, None);
}

// --- SuggestionsStore CAS semantics -----------------------------------------

fn store() -> SuggestionsStore {
    SuggestionsStore::new(Arc::new(InMemoryBackend::default()))
}

#[tokio::test]
async fn read_doc_on_absent_path_returns_none() {
    let store = store();
    let doc = store
        .read_doc(&tenant(), &user())
        .await
        .expect("read succeeds");
    assert!(doc.is_none());
}

#[tokio::test]
async fn wrong_schema_version_reads_as_absent() {
    use ironclaw_filesystem::{CasExpectation, Entry, RootFilesystem};

    let path = ironclaw_host_api::path::VirtualPath::new(format!(
        "/tenants/{}/users/{}/suggestions/doc.json",
        tenant().as_str(),
        user().as_str()
    ))
    .expect("path");
    let body = serde_json::json!({
        "schema_version": SUGGESTIONS_SCHEMA_VERSION + 1,
        "active_job": null,
        "last_result": null,
        "last_error": null,
    });
    let raw = Arc::new(InMemoryBackend::default());
    raw.put(
        &path,
        Entry::bytes(serde_json::to_vec(&body).expect("serialize")),
        CasExpectation::Any,
    )
    .await
    .expect("write raw doc directly, bypassing the store's own schema version");

    let store_over_raw = SuggestionsStore::new(raw);
    let doc = store_over_raw
        .read_doc(&tenant(), &user())
        .await
        .expect("read succeeds");
    assert!(doc.is_none());
}

// `claim_active_job_succeeds_when_absent`,
// `second_claim_while_first_is_active_dedupes_to_same_job_id`, and
// `record_result_clears_active_job_and_sets_last_result` are intentionally
// NOT here: the §8 integration suite
// (`tests/integration/suggestion_cards.rs`) drives the same claim/dedupe/
// record-result behavior through the real `RebornSuggestionsProductService`
// and (for the happy path) the real `render_suggestions` tool — a strictly
// stronger proof than exercising this store directly, so keeping both would
// be pure duplication. What stays here is what the integration tier
// genuinely cannot reach: the wrong-schema-version-reads-as-absent edge case
// and the superseded-job no-op race below (deterministic at this tier;
// timing-dependent to force through a full production run).

#[tokio::test]
async fn record_result_for_superseded_job_is_a_noop() {
    let store = store();
    let ClaimOutcome::Claimed { job_id: stale_job } = store
        .claim_active_job(
            &tenant(),
            &user(),
            ThreadId::new("t1").expect("thread id"),
            TurnRunId::new(),
        )
        .await
        .expect("claim")
    else {
        panic!("expected claim");
    };
    store
        .record_failure(&tenant(), &user(), stale_job, "stale".to_string())
        .await
        .expect("clear stale claim");
    let ClaimOutcome::Claimed { job_id: fresh_job } = store
        .claim_active_job(
            &tenant(),
            &user(),
            ThreadId::new("t2").expect("thread id"),
            TurnRunId::new(),
        )
        .await
        .expect("fresh claim")
    else {
        panic!("expected fresh claim")
    };
    assert_ne!(stale_job, fresh_job);

    // A late outcome for the stale job must not clobber the fresh claim.
    store
        .record_result(&tenant(), &user(), stale_job, vec![card("stale cards")])
        .await
        .expect("stale outcome is a no-op, not an error");

    let doc = store
        .read_doc(&tenant(), &user())
        .await
        .expect("read")
        .expect("doc present");
    assert_eq!(
        doc.active_job.expect("fresh claim still active").job_id,
        fresh_job
    );
    assert!(doc.last_result.is_none());
}

// `record_failure_sets_last_error_and_clears_active_job` is likewise not
// here — `dead_run_derives_failed_and_a_fresh_generate_claims_cleanly` in
// the integration suite drives `record_failure` through the real product
// service.
