//! Rollout-evidence projection contract (#7166 §5).
//!
//! Progressive tool disclosure shipped default-on with nothing durable behind
//! it. These tests pin the read path an operator actually uses: durable
//! per-model-call events in, and totals grouped by model, run profile, and
//! catalog-size bucket out.

use std::sync::Arc;

use ironclaw_event_log::{
    DurableEventLog, InMemoryDurableEventLog, ModelCallMetrics, ModelCallOutcome, RuntimeEvent,
    ToolDisclosureMetrics,
};
use ironclaw_event_projections::{
    EventProjectionService, ProjectionRequest, ProjectionScope, ReplayEventProjectionService,
};
use ironclaw_host_api::{
    ids::{AgentId, CapabilityId, InvocationId, ProjectId, TenantId, ThreadId, UserId},
    resource::ResourceScope,
};

const MODEL_CAPABILITY_ID: &str = "loop.model";

fn scope_for_run(invocation_id: InvocationId) -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new("tenant-metrics").unwrap(),
        user_id: UserId::new("user-metrics").unwrap(),
        agent_id: Some(AgentId::new("agent-metrics").unwrap()),
        project_id: Some(ProjectId::new("project-metrics").unwrap()),
        mission_id: None,
        thread_id: Some(ThreadId::new("thread-metrics").unwrap()),
        invocation_id,
    }
}

fn model_capability_id() -> CapabilityId {
    CapabilityId::new(MODEL_CAPABILITY_ID).unwrap()
}

fn disclosure(
    full_tool_count: u32,
    advertised_tool_count: u32,
    bucket: &str,
    tool_search_count: u32,
    empty_search_count: u32,
    promotions: u32,
) -> ToolDisclosureMetrics {
    ToolDisclosureMetrics {
        deferred: true,
        full_tool_count,
        advertised_tool_count,
        full_schema_tokens: 12_000,
        advertised_schema_tokens: 1_956,
        catalog_size_bucket: bucket.to_string(),
        tool_search_count,
        empty_search_count,
        selected_result_rank: Some(1),
        promotions,
        recoveries: 0,
        outside_surface_attempts: 0,
    }
}

fn metrics(
    requested_model: &str,
    effective_model: &str,
    prompt_tokens: u64,
    cached_prompt_tokens: u64,
    duration_ms: u64,
    disclosure: Option<ToolDisclosureMetrics>,
) -> ModelCallMetrics {
    ModelCallMetrics {
        iteration: 0,
        requested_model: requested_model.to_string(),
        effective_model: Some(effective_model.to_string()),
        fallback_index: 0,
        outcome: ModelCallOutcome::Succeeded,
        failure_kind: None,
        duration_ms,
        prompt_tokens,
        cached_prompt_tokens,
        cache_creation_tokens: 0,
        output_tokens: 100,
        disclosure,
    }
}

/// The three query dimensions the issue names — model, run profile, and
/// catalog-size bucket — must actually separate the totals. Two runs on
/// different models with different catalog cohorts must never collapse into one
/// row, or the rollout comparison the epic is gated on cannot be made.
#[tokio::test]
async fn totals_are_grouped_by_model_run_profile_and_catalog_bucket() {
    let log = Arc::new(InMemoryDurableEventLog::new());
    let service = ReplayEventProjectionService::new(Arc::clone(&log));
    let wide_run = InvocationId::new();
    let small_run = InvocationId::new();

    log.append(RuntimeEvent::model_call_metrics_recorded(
        scope_for_run(wide_run),
        model_capability_id(),
        metrics(
            "balanced",
            "provider/model-x",
            1_000,
            800,
            1_200,
            Some(disclosure(48, 4, "wide", 2, 1, 1)),
        ),
    ))
    .await
    .unwrap();
    log.append(RuntimeEvent::model_call_metrics_recorded(
        scope_for_run(small_run),
        model_capability_id(),
        metrics(
            "fast",
            "provider/model-y",
            500,
            0,
            300,
            Some(disclosure(12, 12, "at_or_below_caps", 0, 0, 0)),
        ),
    ))
    .await
    .unwrap();

    let page = service
        .model_call_metrics(ProjectionRequest {
            scope: ProjectionScope::from_resource_scope(&scope_for_run(wide_run)),
            after: None,
            limit: 32,
        })
        .await
        .expect("metrics page reads");
    assert_eq!(page.entries.len(), 2);

    let aggregates = page.aggregate();
    assert_eq!(
        aggregates.len(),
        2,
        "two distinct (profile, model, bucket) cohorts must stay two rows"
    );

    let wide = aggregates
        .iter()
        .find(|aggregate| aggregate.key.catalog_size_bucket.as_deref() == Some("wide"))
        .expect("wide cohort is queryable by its bucket");
    assert_eq!(wide.key.requested_model, "balanced");
    assert_eq!(
        wide.key.effective_model.as_deref(),
        Some("provider/model-x")
    );
    assert_eq!(wide.model_calls, 1);
    assert_eq!(wide.total_prompt_tokens, 1_000);
    assert_eq!(wide.total_cached_prompt_tokens, 800);
    assert_eq!(wide.total_duration_ms, 1_200);
    assert_eq!(wide.tool_searches, 2);
    assert_eq!(wide.empty_tool_searches, 1);
    assert_eq!(wide.promotions, 1);
    assert_eq!(wide.max_full_tool_count, 48);
    assert_eq!(wide.max_advertised_tool_count, 4);

    let small = aggregates
        .iter()
        .find(|aggregate| aggregate.key.catalog_size_bucket.as_deref() == Some("at_or_below_caps"))
        .expect("below-caps cohort is queryable by its bucket");
    assert_eq!(small.tool_searches, 0);
    assert_eq!(
        small.max_full_tool_count, 12,
        "the below-caps cohort must keep its own catalog size, not the wide run's"
    );
}

/// Disclosure counters are cumulative over a run, so the aggregate must take
/// the per-run high-water mark. Summing them per call would report one search
/// as three the moment the run makes three model calls — the kind of inflation
/// that makes an operator distrust the whole dashboard.
#[tokio::test]
async fn cumulative_counters_are_not_multiplied_across_a_run() {
    let log = Arc::new(InMemoryDurableEventLog::new());
    let service = ReplayEventProjectionService::new(Arc::clone(&log));
    let run = InvocationId::new();

    for search_count in [1_u32, 1, 1] {
        log.append(RuntimeEvent::model_call_metrics_recorded(
            scope_for_run(run),
            model_capability_id(),
            metrics(
                "balanced",
                "provider/model-x",
                100,
                0,
                10,
                Some(disclosure(48, 4, "wide", search_count, 0, 1)),
            ),
        ))
        .await
        .unwrap();
    }

    let page = service
        .model_call_metrics(ProjectionRequest {
            scope: ProjectionScope::from_resource_scope(&scope_for_run(run)),
            after: None,
            limit: 32,
        })
        .await
        .expect("metrics page reads");
    let aggregates = page.aggregate();
    let aggregate = aggregates.first().expect("one cohort");

    assert_eq!(aggregate.model_calls, 3, "every model call is counted");
    assert_eq!(
        aggregate.tool_searches, 1,
        "one search observed three times is still one search"
    );
    assert_eq!(aggregate.runs, 1);
}

/// "Model calls per completed task" needs a completed task. A run still in
/// flight must leave the ratio unanswered rather than divide by an empty
/// denominator or, worse, silently count an unfinished run as finished.
#[tokio::test]
async fn model_calls_per_completed_run_requires_a_completed_run() {
    let log = Arc::new(InMemoryDurableEventLog::new());
    let service = ReplayEventProjectionService::new(Arc::clone(&log));
    let run = InvocationId::new();

    for _ in 0..4 {
        log.append(RuntimeEvent::model_call_metrics_recorded(
            scope_for_run(run),
            model_capability_id(),
            metrics("balanced", "provider/model-x", 100, 0, 10, None),
        ))
        .await
        .unwrap();
    }

    let request = || ProjectionRequest {
        scope: ProjectionScope::from_resource_scope(&scope_for_run(run)),
        after: None,
        limit: 32,
    };
    let in_flight = service
        .model_call_metrics(request())
        .await
        .expect("metrics page reads");
    assert!(
        in_flight.completed_run_ids.is_empty(),
        "no LoopCompleted has been recorded yet"
    );
    assert_eq!(
        in_flight.aggregate()[0].model_calls_per_completed_run(),
        None,
        "an unfinished run must report the ratio as unanswerable"
    );

    log.append(RuntimeEvent::loop_completed(
        scope_for_run(run),
        CapabilityId::new("loop.run").unwrap(),
    ))
    .await
    .unwrap();

    let completed = service
        .model_call_metrics(request())
        .await
        .expect("metrics page reads");
    let aggregate = &completed.aggregate()[0];
    assert_eq!(aggregate.completed_runs, 1);
    assert_eq!(
        aggregate.model_calls_per_completed_run(),
        Some(4.0),
        "four model calls finished one task"
    );
}

/// A metrics-kind event whose payload is missing is a producer bug. It must be
/// skipped, not folded in as a zero-token, zero-latency call that silently
/// drags every average down.
#[tokio::test]
async fn metrics_events_without_a_payload_are_skipped_not_counted_as_zero() {
    let log = Arc::new(InMemoryDurableEventLog::new());
    let service = ReplayEventProjectionService::new(Arc::clone(&log));
    let run = InvocationId::new();

    let mut malformed = RuntimeEvent::model_call_metrics_recorded(
        scope_for_run(run),
        model_capability_id(),
        metrics("balanced", "provider/model-x", 100, 0, 10, None),
    );
    malformed.model_call_metrics = None;
    log.append(malformed).await.unwrap();

    let page = service
        .model_call_metrics(ProjectionRequest {
            scope: ProjectionScope::from_resource_scope(&scope_for_run(run)),
            after: None,
            limit: 32,
        })
        .await
        .expect("metrics page reads");

    assert!(page.entries.is_empty());
    assert!(page.aggregate().is_empty());
}
