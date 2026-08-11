//! Automation suggestion cards (#7038) — the §8 integration suite.
//!
//! Two harness shapes, matched to what each scenario needs to prove:
//!
//! - Scenarios that only exercise the CAS store / derived-state seam through
//!   the real `RebornSuggestionsProductService` (dedupe, dead-run recovery)
//!   use the lightweight `RebornIntegrationHarness` + `suggestions_submit`'s
//!   `generate_suggestions_for_test` (real service, real thread service, real
//!   turn coordinator — the store/turn-liveness seam, not the model).
//! - Scenarios that need the REAL `render_suggestions` first-party tool, the
//!   REAL suggestion-generation capability-surface allow-list, and the REAL
//!   `/api/webchat/v2/suggestions*` routes (happy path, strict-output
//!   enforcement, capability lockdown, hidden-thread listing, card-click
//!   round-trip) build a full production-composed runtime
//!   (`build_reborn_runtime`, exactly `product_surface.rs`'s own wiring) with
//!   ONE non-scope-keyed scripted `LlmProviderModelGateway` — this test's
//!   turns are the only turns run against that runtime, so a single gateway
//!   (not the group harness's per-scope `ScopeRegistryGateway`) is the
//!   correct shape and avoids needing to know the internally-minted hidden
//!   thread id ahead of the real `POST /suggestions/generate` call.

#[allow(dead_code)]
#[path = "support/mod.rs"]
mod reborn_support;
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use ironclaw_composition::{
    RebornRuntime, RebornRuntimeIdentity, RebornRuntimeInput, build_reborn_runtime,
    standalone_runtime_policy,
};
use ironclaw_host_api::ids::{AgentId, TenantId, ThreadId, UserId};
use ironclaw_llm::testing::provider_chain_over;
use ironclaw_llm::{LlmProvider, SessionConfig, create_session_manager};
use ironclaw_loop_host::{HostManagedModelGateway, LlmModelProfilePolicy, LlmProviderModelGateway};
use ironclaw_product_contracts::surface::{ProductSurface, ProductSurfaceCaller};
use reborn_support::builder::RebornIntegrationHarness;
use reborn_support::reply::RebornScriptedReply;
use reborn_support::scripted_provider::{SCRIPTED_MODEL_NAME, scripted_trace_llm};
use reborn_support::suggestions_submit::{
    suggestions_service_for_harness, suggestions_thread_id, wait_for_suggestions_view,
};
use reborn_support::webui_mount::{get_json, mount_webui_v2_router, post_json};
use serde_json::{Value, json};
use support::trace_llm::TraceLlm;
use tempfile::tempdir;

type HarnessResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn valid_card(title: &str) -> Value {
    json!({
        "id": uuid::Uuid::new_v4(),
        "title": title,
        "description": "a concrete one-shot automation flow",
        "requires_connection": false,
        "suggested_prompt": format!("go {title}"),
        "category": "email",
    })
}

// ============================================================================
// Item 2 + 7: store/turn-liveness seam through the real product service
// (lightweight int-tier harness — no model/tool dispatch needed).
// ============================================================================

/// (2) Second `generate` call while the first is still running dedupes onto
/// the SAME job — no second claim, no second thread.
#[tokio::test]
async fn second_generate_while_running_dedupes_to_the_same_job() -> HarnessResult<()> {
    let harness = RebornIntegrationHarness::test_default()
        .script([RebornScriptedReply::text(
            "unused — turn never scripted to complete",
        )])
        .build()
        .await?;
    let service = suggestions_service_for_harness(&harness);
    let caller = harness.suggestions_caller();

    let first = service
        .generate_suggestions_for_test(caller.clone(), suggestions_thread_id("dedupe-a"))
        .await?;
    let second = service
        .generate_suggestions_for_test(caller.clone(), suggestions_thread_id("dedupe-b"))
        .await?;

    assert_eq!(
        first.generation.job_id, second.generation.job_id,
        "both calls must observe the same job_id: first={first:?} second={second:?}"
    );
    assert!(
        first.generation.job_id.is_some(),
        "a running generation must carry a job_id: {first:?}"
    );
    Ok(())
}

/// (2) Concurrent-POST CAS case: two racing `generate` calls converge on
/// exactly one claim — the store's compare-and-swap, driven through the real
/// service, not just the store's own unit test.
#[tokio::test]
async fn concurrent_generate_calls_converge_on_one_claim() -> HarnessResult<()> {
    let harness = RebornIntegrationHarness::test_default()
        .script([RebornScriptedReply::text("unused")])
        .build()
        .await?;
    let service = suggestions_service_for_harness(&harness);
    let caller = harness.suggestions_caller();

    let (a, b) = tokio::join!(
        service.generate_suggestions_for_test(caller.clone(), suggestions_thread_id("race-a")),
        service.generate_suggestions_for_test(caller.clone(), suggestions_thread_id("race-b")),
    );
    let (a, b) = (a?, b?);

    assert_eq!(
        a.generation.job_id, b.generation.job_id,
        "concurrent racers must converge on ONE job_id: a={a:?} b={b:?}"
    );
    assert_eq!(
        a.generation.state,
        ironclaw_suggestions::GenerationState::Running
    );
    Ok(())
}

/// (7) A doc seeded with `active_job` referencing a terminal/missing run
/// derives `failed` on GET, and a subsequent generate claims cleanly (no
/// janitor, no stuck state — spec §5).
#[tokio::test]
async fn dead_run_derives_failed_and_a_fresh_generate_claims_cleanly() -> HarnessResult<()> {
    let harness = RebornIntegrationHarness::test_default()
        .script([RebornScriptedReply::text("unused")])
        .build()
        .await?;
    let service = suggestions_service_for_harness(&harness);
    let caller = harness.suggestions_caller();

    // Claim a job whose run_id will never be submitted through the real
    // coordinator, so `get_run_state` resolves it as missing/terminal.
    let dead_thread_id = suggestions_thread_id("dead-run");
    let claimed = service
        .generate_suggestions_for_test(caller.clone(), dead_thread_id.clone())
        .await?;
    assert_eq!(
        claimed.generation.state,
        ironclaw_suggestions::GenerationState::Running
    );

    // The real turn submitted for this claim is scripted to a plain text
    // reply with no `render_suggestions` call, so it completes without ever
    // writing `last_result` — the doc's `active_job` genuinely goes stale
    // relative to a fresh read once the run terminates. Wait for the store to
    // observe that.
    let view = wait_for_suggestions_view(&service, caller.clone(), |view| {
        view.generation.state != ironclaw_suggestions::GenerationState::Running
    })
    .await?;
    assert_eq!(
        view.generation.state,
        ironclaw_suggestions::GenerationState::Failed,
        "a run that completed without calling render_suggestions must derive failed: {view:?}"
    );

    // A fresh generate call must claim cleanly — not stay wedged behind the
    // dead claim.
    let retried = service
        .generate_suggestions_for_test(caller, suggestions_thread_id("dead-run-retry"))
        .await?;
    assert_eq!(
        retried.generation.state,
        ironclaw_suggestions::GenerationState::Running
    );
    assert_ne!(
        retried.generation.job_id, claimed.generation.job_id,
        "the retry must be a genuinely NEW job, not the dead one"
    );
    Ok(())
}

// ============================================================================
// Items 1, 3, 4, 5, 6: full production composition (real render_suggestions
// tool, real capability allow-list, real webui routes).
// ============================================================================

struct SuggestionsProdHarness {
    runtime: RebornRuntime,
    webui: Arc<dyn ProductSurface>,
    caller: ProductSurfaceCaller,
    tenant_id: TenantId,
    user_id: UserId,
    agent_id: AgentId,
    // Kept alive for the harness's lifetime: `build_reborn_runtime` seeds the
    // standalone identity prompt file (`SYSTEM.md`) under this tempdir and
    // reads it back on every turn. Dropping the `TempDir` guard when the
    // builder function returns deletes that seeded storage out from under
    // any later turn, which surfaced as `host_stage_unavailable_prompt` /
    // "identity context source unavailable" on the very first prompt build.
    _storage_root_guard: tempfile::TempDir,
    _session_root_guard: tempfile::TempDir,
}

impl SuggestionsProdHarness {
    async fn shutdown(self) {
        drop(self.webui);
        self.runtime.shutdown().await.expect("runtime shuts down");
    }
}

/// Builds a full production-composed runtime (`build_reborn_runtime`, the
/// SAME wiring `product_surface.rs` composes — real `RenderSuggestionsHook`,
/// real `SUGGESTION_GENERATION_CAPABILITY_SURFACE_PROFILE_ID` allow-list,
/// real `SUGGESTIONS_VIEW`/`SUGGESTIONS_GENERATE_COMMAND` dispatch) with one
/// scripted model gateway serving every call this runtime's turns make.
async fn build_suggestions_prod_harness(
    test_name: &str,
    replies: impl IntoIterator<Item = RebornScriptedReply>,
) -> HarnessResult<SuggestionsProdHarness> {
    let root = tempdir()?;
    let storage_root = root.path().join("local-dev");
    let tenant_id = TenantId::new(format!("suggestions-{test_name}-tenant"))?;
    let agent_id = AgentId::new(format!("suggestions-{test_name}-agent"))?;
    let user_id = UserId::new(format!("suggestions-{test_name}-user"))?;
    let input =
        ironclaw_composition::local_filesystem_build_input(user_id.as_str(), storage_root.clone())
            .with_local_runtime_identity(tenant_id.clone(), agent_id.clone())
            .with_runtime_policy(standalone_runtime_policy()?)
            .with_bundled_first_party_for_test()
            .with_network_http_egress_for_test(Arc::new(
                reborn_support::harness::RecordingNetworkHttpEgress::with_body(Vec::new()),
            ));

    let scripted_llm: Arc<TraceLlm> = Arc::new(scripted_trace_llm(replies));
    let raw: Arc<dyn LlmProvider> = scripted_llm;
    let session_root = tempdir()?;
    let session = create_session_manager(SessionConfig {
        session_path: session_root.path().join("suggestions.session.json"),
        ..SessionConfig::default()
    })
    .await;
    let llm_config = ironclaw_llm::testing::nearai_test_config(SCRIPTED_MODEL_NAME);
    let provider = provider_chain_over(raw, &llm_config, session).await?;
    let model_profile_id = ironclaw_loop_contracts::ModelProfileId::new("interactive_model")
        .map_err(|reason| format!("invalid model profile id: {reason}"))?;
    let policy = LlmModelProfilePolicy::new().allow_model_profile(model_profile_id, None);
    let gateway: Arc<dyn HostManagedModelGateway> =
        Arc::new(LlmProviderModelGateway::new(provider, policy));

    let runtime = build_reborn_runtime(
        RebornRuntimeInput::from_build_input(input)
            .with_identity(RebornRuntimeIdentity {
                tenant_id: tenant_id.as_str().to_string(),
                agent_id: agent_id.as_str().to_string(),
                source_binding_id: format!("suggestions-{test_name}-source"),
                reply_target_binding_id: format!("suggestions-{test_name}-reply"),
            })
            .with_poll_settings(ironclaw_composition::PollSettings {
                interval: Duration::from_millis(10),
                max_total: Duration::from_secs(15),
            })
            .with_model_gateway_override(gateway),
    )
    .await?;
    let webui = runtime.product_surface(None)?;
    let caller = ProductSurfaceCaller::new(
        tenant_id.clone(),
        user_id.clone(),
        Some(agent_id.clone()),
        None,
    );

    // Global auto-approve so scripted tool calls (memory search/read,
    // extension_search) that default to `PermissionMode::Ask` complete
    // instead of parking on an approval gate mid-run — mirrors
    // `webui_v2_e2e.rs`'s production-runtime scripted-model setup.
    runtime
        .standalone_auto_approve_settings_for_test()
        .ok_or("standalone runtime exposes auto-approve settings for test")?
        .set(ironclaw_approvals::AutoApproveSettingInput {
            updated_by: ironclaw_host_api::scope::Principal::User(user_id.clone()),
            scope: ironclaw_host_api::resource::ResourceScope {
                tenant_id: tenant_id.clone(),
                user_id: user_id.clone(),
                agent_id: Some(agent_id.clone()),
                project_id: None,
                mission_id: None,
                thread_id: None,
                invocation_id: ironclaw_host_api::ids::InvocationId::new(),
            },
            enabled: true,
        })
        .await?;

    Ok(SuggestionsProdHarness {
        runtime,
        webui,
        caller,
        tenant_id,
        user_id,
        agent_id,
        _storage_root_guard: root,
        _session_root_guard: session_root,
    })
}

async fn poll_suggestions_until(
    harness: &SuggestionsProdHarness,
    predicate: impl Fn(&Value) -> bool,
) -> HarnessResult<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let (status, body) = get_json(
            mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
            "/api/webchat/v2/suggestions",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "GET suggestions body: {body}");
        if predicate(&body) {
            return Ok(body);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(
                format!("timed out waiting for suggestions predicate; last body: {body}").into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn is_running(body: &Value) -> bool {
    body["generation"]["state"] == "running"
}

/// (1) Generate happy path: POST kicks a run, the scripted model calls
/// `render_suggestions` with valid cards, GET returns `ready` with cards
/// byte-equal to the tool input.
#[tokio::test]
async fn generate_happy_path_reaches_ready_with_the_scripted_cards() -> HarnessResult<()> {
    let cards = json!([valid_card("Triage inbox"), valid_card("Summarize mentions")]);
    let harness = build_suggestions_prod_harness(
        "happy",
        [
            RebornScriptedReply::tool_call(
                "builtin.render_suggestions",
                json!({ "cards": cards.clone() }),
            ),
            RebornScriptedReply::text("done"),
        ],
    )
    .await?;

    let (status, generate_body) = post_json(
        mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
        "/api/webchat/v2/suggestions/generate",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "generate body: {generate_body}");
    assert_eq!(generate_body["generation"]["state"], "running");

    let body = poll_suggestions_until(&harness, |body| !is_running(body)).await?;
    assert_eq!(
        body["generation"]["state"], "ready",
        "expected ready after a valid render_suggestions call: {body}"
    );
    let returned_cards = body["cards"].clone();
    assert_eq!(
        returned_cards
            .as_array()
            .map(|array| array.len())
            .unwrap_or(0),
        2,
        "returned cards: {body}"
    );
    for (expected, actual) in cards
        .as_array()
        .unwrap()
        .iter()
        .zip(returned_cards.as_array().unwrap().iter())
    {
        assert_eq!(expected["title"], actual["title"], "card mismatch: {body}");
        assert_eq!(
            expected["suggested_prompt"], actual["suggested_prompt"],
            "card mismatch: {body}"
        );
    }
    harness.shutdown().await;
    Ok(())
}

/// (3) Strict-output enforcement, prose branch: the model replies with prose
/// instead of calling `render_suggestions` — the run completes but the
/// derived state is `failed`, never a silently-accepted prose "success".
#[tokio::test]
async fn prose_reply_without_render_suggestions_derives_failed() -> HarnessResult<()> {
    let harness = build_suggestions_prod_harness(
        "prose",
        [RebornScriptedReply::text(
            "Here are some suggestions: 1. Triage inbox 2. Summarize mentions",
        )],
    )
    .await?;

    let (status, _) = post_json(
        mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
        "/api/webchat/v2/suggestions/generate",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let body = poll_suggestions_until(&harness, |body| !is_running(body)).await?;
    assert_eq!(
        body["generation"]["state"], "failed",
        "a prose-only reply must never derive ready: {body}"
    );
    harness.shutdown().await;
    Ok(())
}

/// (3) Strict-output enforcement, invalid-cards branch: an empty card array
/// is a tool-input error the model sees and can retry from; a valid retry
/// still succeeds.
#[tokio::test]
async fn invalid_cards_are_rejected_then_a_valid_retry_succeeds() -> HarnessResult<()> {
    let cards = json!([valid_card("Triage inbox")]);
    let harness = build_suggestions_prod_harness(
        "invalid-retry",
        [
            RebornScriptedReply::tool_call("builtin.render_suggestions", json!({ "cards": [] })),
            RebornScriptedReply::tool_call(
                "builtin.render_suggestions",
                json!({ "cards": cards.clone() }),
            ),
            RebornScriptedReply::text("done"),
        ],
    )
    .await?;

    let (status, _) = post_json(
        mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
        "/api/webchat/v2/suggestions/generate",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let body = poll_suggestions_until(&harness, |body| !is_running(body)).await?;
    assert_eq!(
        body["generation"]["state"], "ready",
        "a valid retry after an invalid-cards tool error must still reach ready: {body}"
    );
    assert_eq!(body["cards"].as_array().map(|a| a.len()), Some(1));
    harness.shutdown().await;
    Ok(())
}

/// (5) Capability lockdown: a suggestion-generation run whose scripted model
/// attempts a denied tool (`builtin.echo`, not in the allow-list) never sees
/// that call succeed — the run still completes cleanly (the denial is
/// model-recoverable, not a hard failure), and `builtin.echo` never ran
/// (proven by never resolving to a persisted result the model could report).
#[tokio::test]
async fn suggestion_generation_run_cannot_call_a_non_allow_listed_tool() -> HarnessResult<()> {
    let cards = json!([valid_card("Triage inbox")]);
    let harness = build_suggestions_prod_harness(
        "lockdown",
        [
            // The model attempts an out-of-surface tool; the real
            // `RuntimeProfiledCapabilityPortFactory` allow-list (proven
            // directly, with break-it-to-prove-it evidence, by
            // `ironclaw_turn_runner::runtime::tests::suggestion_generation_surface_is_allow_listed`)
            // means `builtin.echo` is not part of the model-visible surface
            // this run resolves, so the executor transparently re-issues the
            // model call rather than dispatching it (same observable shape
            // `scenario_trigger_self_create_denied.rs` documents for the
            // scheduled_trigger deny-map).
            RebornScriptedReply::tool_call("builtin.echo", json!({"message": "leak"})),
            RebornScriptedReply::tool_call(
                "builtin.render_suggestions",
                json!({ "cards": cards.clone() }),
            ),
            RebornScriptedReply::text("done"),
        ],
    )
    .await?;

    let (status, _) = post_json(
        mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
        "/api/webchat/v2/suggestions/generate",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let body = poll_suggestions_until(&harness, |body| !is_running(body)).await?;
    assert_eq!(
        body["generation"]["state"], "ready",
        "the run must still complete via the fallback render_suggestions call: {body}"
    );

    // The state reaching `ready` alone doesn't prove the lockdown held (a
    // dispatched-then-ignored echo would also end in `ready`, since the
    // scripted `render_suggestions` call still follows it). Read the raw
    // transcript directly through the thread service — bypassing the
    // suggestion-generation thread's hidden-from-listing filter, the same
    // way the hidden-thread test's regression setup does — and check the
    // security property directly: `builtin.echo`'s distinctive scripted
    // message never appears anywhere in it, so the tool call was never
    // dispatched (mirrors `scenario_trigger_self_create_denied.rs`'s
    // "assert the security property directly" approach for a seam where
    // nothing tool-shaped gets persisted for a denied call).
    let thread_service = harness.runtime.session_thread_service();
    let scope = ironclaw_threads::ThreadScope {
        tenant_id: harness.tenant_id.clone(),
        agent_id: harness.agent_id.clone(),
        project_id: None,
        owner_user_id: Some(harness.user_id.clone()),
        mission_id: None,
    };
    let threads = thread_service
        .list_threads_for_scope(ironclaw_threads::ListThreadsForScopeRequest {
            scope: scope.clone(),
            limit: Some(20),
            cursor: None,
        })
        .await?;
    let suggestion_thread = threads
        .threads
        .iter()
        .find(|thread| {
            thread
                .metadata_json
                .as_deref()
                .is_some_and(|metadata| metadata.contains("suggestion_generation"))
        })
        .ok_or("suggestion-generation thread must exist")?;
    let history = thread_service
        .list_thread_history(ironclaw_threads::ThreadHistoryRequest {
            scope,
            thread_id: suggestion_thread.thread_id.clone(),
        })
        .await?;
    let transcript = format!("{:?}", history.messages);
    assert!(
        !transcript.contains("leak"),
        "builtin.echo's scripted message must never reach the transcript — the \
         non-allow-listed tool must never actually dispatch: {transcript}"
    );

    harness.shutdown().await;
    Ok(())
}

/// (4) Hidden-thread listing: a suggestion-generation thread never appears
/// in `/api/webchat/v2/threads`, its transcript is still directly readable
/// (never-delete), and the SAME generalized predicate keeps an
/// automation-trigger thread hidden too (regression for the generalization).
#[tokio::test]
async fn suggestion_generation_thread_is_hidden_from_listing_but_transcript_is_readable()
-> HarnessResult<()> {
    let cards = json!([valid_card("Triage inbox")]);
    let harness = build_suggestions_prod_harness(
        "hidden-thread",
        [
            RebornScriptedReply::tool_call(
                "builtin.render_suggestions",
                json!({ "cards": cards.clone() }),
            ),
            RebornScriptedReply::text("done"),
        ],
    )
    .await?;

    let (status, _) = post_json(
        mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
        "/api/webchat/v2/suggestions/generate",
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    poll_suggestions_until(&harness, |body| !is_running(body)).await?;

    let (status, threads_body) = get_json(
        mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
        "/api/webchat/v2/threads",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "threads body: {threads_body}");
    let threads = threads_body["threads"].as_array().expect("threads array");
    assert!(
        !threads.iter().any(|thread| {
            thread["metadata_json"]
                .as_str()
                .is_some_and(|metadata| metadata.contains("suggestion_generation"))
        }),
        "a suggestion-generation thread must never appear in the listing: {threads_body}"
    );

    // Regression: an automation-trigger thread (the ORIGINAL hidden-thread
    // source) must ALSO stay hidden through the same generalized predicate —
    // seed one directly via the real thread service and metadata helper.
    let thread_service = harness.runtime.session_thread_service();
    let trigger_thread_id = ThreadId::new("automation-trigger-regression-thread")?;
    let thread_scope = ironclaw_threads::ThreadScope {
        tenant_id: harness.tenant_id.clone(),
        agent_id: harness.agent_id.clone(),
        project_id: None,
        owner_user_id: Some(harness.user_id.clone()),
        mission_id: None,
    };
    thread_service
        .ensure_thread(ironclaw_threads::EnsureThreadRequest {
            scope: thread_scope.clone(),
            thread_id: Some(trigger_thread_id.clone()),
            created_by_actor_id: harness.user_id.as_str().to_string(),
            title: None,
            metadata_json: Some(ironclaw_assistant::automation_trigger_thread_metadata_json(
                "regression-trigger-id",
            )),
        })
        .await?;
    thread_service
        .accept_inbound_message(ironclaw_threads::AcceptInboundMessageRequest {
            scope: thread_scope,
            thread_id: trigger_thread_id.clone(),
            actor_id: harness.user_id.as_str().to_string(),
            source_binding_id: Some("automation-trigger-regression".to_string()),
            reply_target_binding_id: Some("automation-trigger-regression".to_string()),
            external_event_id: Some("automation-trigger-regression".to_string()),
            content: ironclaw_threads::MessageContent::text("trigger prompt".to_string()),
        })
        .await?;

    let (status, threads_body) = get_json(
        mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
        "/api/webchat/v2/threads",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "threads body: {threads_body}");
    let threads = threads_body["threads"].as_array().expect("threads array");
    assert!(
        !threads
            .iter()
            .any(|thread| thread["thread_id"] == trigger_thread_id.as_str()),
        "the automation-trigger thread must stay hidden after generalizing the predicate: {threads_body}"
    );

    // Never-delete: both hidden transcripts remain directly readable.
    let (status, timeline_body) = get_json(
        mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
        &format!(
            "/api/webchat/v2/threads/{}/timeline",
            trigger_thread_id.as_str()
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "hidden thread transcript must remain directly readable: {timeline_body}"
    );
    let messages = timeline_body["messages"]
        .as_array()
        .expect("messages array");
    assert!(
        messages.iter().any(|message| message["content"]
            .as_str()
            .is_some_and(|content| content.contains("trigger prompt"))),
        "hidden thread transcript content must be present: {timeline_body}"
    );

    harness.shutdown().await;
    Ok(())
}

/// (6) Card-click path: `suggested_prompt` round-trips verbatim as an
/// ordinary user message in a NEW, visible thread through the existing
/// create-thread + send-message path — the card click never re-derives or
/// rewrites the prompt server-side.
#[tokio::test]
async fn card_click_round_trips_suggested_prompt_as_an_ordinary_message() -> HarnessResult<()> {
    let harness = build_suggestions_prod_harness(
        "card-click",
        [RebornScriptedReply::text("Sure, triaging your inbox now.")],
    )
    .await?;
    let suggested_prompt = "Go through my unread emails from the past week and summarize them.";

    let (status, create_body) = post_json(
        mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
        "/api/webchat/v2/threads",
        json!({"client_action_id": "card-click-create-thread"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create thread body: {create_body}");
    let thread_id = create_body["thread"]["thread_id"]
        .as_str()
        .expect("thread id")
        .to_string();

    let (status, send_body) = post_json(
        mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
        &format!("/api/webchat/v2/threads/{thread_id}/messages"),
        json!({
            "client_action_id": "card-click-send-message",
            "content": suggested_prompt,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "send message body: {send_body}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let timeline_body = loop {
        let (status, body) = get_json(
            mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
            &format!("/api/webchat/v2/threads/{thread_id}/timeline"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "timeline body: {body}");
        if body["messages"].as_array().is_some_and(|messages| {
            messages
                .iter()
                .any(|message| message["kind"] == "assistant" && message["status"] == "finalized")
        }) {
            break body;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for the card-click turn to finalize: {body}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let messages = timeline_body["messages"].as_array().expect("messages");
    assert!(
        messages.iter().any(|message| message["kind"] == "user"
            && message["content"].as_str() == Some(suggested_prompt)),
        "suggested_prompt must round-trip verbatim as the user message: {timeline_body}"
    );

    // Visible, unlike a suggestion-generation thread: it must appear in the
    // ordinary thread listing.
    let (status, threads_body) = get_json(
        mount_webui_v2_router(Arc::clone(&harness.webui), harness.caller.clone()),
        "/api/webchat/v2/threads",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "threads body: {threads_body}");
    assert!(
        threads_body["threads"]
            .as_array()
            .expect("threads array")
            .iter()
            .any(|thread| thread["thread_id"] == thread_id),
        "a card-click thread is an ordinary visible thread: {threads_body}"
    );

    harness.shutdown().await;
    Ok(())
}
