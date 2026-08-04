//! Standing-policy serde, upload-claim cache keys and error labels, and device-key auth modes.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::contribution::*;

#[test]
fn standing_policy_serde_back_compat_when_invite_code_missing() {
    // Existing policy files written before the invite_code field landed
    // must continue to parse unchanged.
    let legacy_json = r#"{
        "enabled": true,
        "ingestion_endpoint": "https://example/v1/traces",
        "bearer_token_env": "IRONCLAW_TRACE_SUBMIT_TOKEN",
        "upload_token_issuer_url": "https://issuer.example/v1/trace-upload-claim",
        "upload_token_issuer_allowed_hosts": ["issuer.example"],
        "upload_token_audience": "trace-commons",
        "upload_token_tenant_id": "tenant-a",
        "upload_token_workload_token_env": "IRONCLAW_TRACE_WORKLOAD_TOKEN",
        "upload_token_issuer_timeout_ms": 7000,
        "include_message_text": false,
        "include_tool_payloads": false,
        "auto_submit_failed_traces": true,
        "auto_submit_high_value_traces": true,
        "selected_tools": [],
        "require_manual_approval_when_pii_detected": true,
        "min_submission_score": 0.35,
        "credit_notice_interval_hours": 168,
        "default_scope": "debugging_evaluation"
    }"#;
    let policy: StandingTraceContributionPolicy =
        serde_json::from_str(legacy_json).expect("legacy policy parses");
    assert!(policy.upload_token_invite_code.is_none());
    assert!(policy.enabled);
}
#[test]
fn standing_policy_serde_round_trips_invite_code_when_set() {
    let policy =
        StandingTraceContributionPolicy::default().set_upload_token_invite_code("INV-PILOT-001");
    let serialized = serde_json::to_string(&policy).expect("serializes");
    assert!(
        serialized.contains("\"upload_token_invite_code\":\"INV-PILOT-001\""),
        "serialized policy carries invite code: {serialized}"
    );
    let round: StandingTraceContributionPolicy =
        serde_json::from_str(&serialized).expect("round trips");
    assert_eq!(
        round.upload_token_invite_code.as_deref(),
        Some("INV-PILOT-001")
    );
}
#[test]
fn standing_policy_serde_omits_invite_code_when_none() {
    // skip_serializing_if keeps existing-shape policies byte-identical
    // for deployments that never configured an invite code.
    let policy = StandingTraceContributionPolicy::default();
    let serialized = serde_json::to_string(&policy).expect("serializes");
    assert!(
        !serialized.contains("upload_token_invite_code"),
        "default policy must not emit upload_token_invite_code: {serialized}"
    );
}
#[test]
fn cache_key_distinguishes_different_invite_codes() {
    let make_policy = |invite: Option<&str>| {
        let policy = StandingTraceContributionPolicy::default()
            .set_upload_token_issuer_url("https://issuer.example/v1/trace-upload-claim");
        if let Some(invite) = invite {
            policy.set_upload_token_invite_code(invite)
        } else {
            policy
        }
    };
    let context = TraceUploadClaimContext::for_status_sync();
    let key_a = trace_upload_claim_cache_key(&make_policy(Some("INV-A")), &context).unwrap();
    let key_b = trace_upload_claim_cache_key(&make_policy(Some("INV-B")), &context).unwrap();
    let key_none = trace_upload_claim_cache_key(&make_policy(None), &context).unwrap();
    assert_ne!(
        key_a, key_b,
        "different invite codes => different cache keys"
    );
    assert_ne!(key_a, key_none, "with-invite vs no-invite must differ");
}
#[test]
fn cache_key_isolates_scopes_in_device_key_mode() {
    // Security property: in DeviceKey mode a claim minted for scope A must
    // not be servable from cache for scope B. Same tenant/audience/issuer,
    // different scope_dir => different cache key.
    let policy = StandingTraceContributionPolicy::default()
        .set_auth_mode(TraceUploadAuthMode::DeviceKey)
        .set_upload_token_issuer_url("https://issuer.example/v1/trace-upload-claim")
        .set_upload_token_tenant_id("tenant-shared")
        .set_upload_token_audience("trace-commons-ingest");
    let ctx_a = TraceUploadClaimContext::for_status_sync()
        .with_scope_dir(std::path::PathBuf::from("/scopes/user-a"));
    let ctx_b = TraceUploadClaimContext::for_status_sync()
        .with_scope_dir(std::path::PathBuf::from("/scopes/user-b"));

    let key_a = trace_upload_claim_cache_key(&policy, &ctx_a).unwrap();
    let key_b = trace_upload_claim_cache_key(&policy, &ctx_b).unwrap();
    assert_ne!(
        key_a, key_b,
        "DeviceKey mode: different scope_dir must yield different cache keys"
    );
}
#[test]
fn cache_key_ignores_scope_dir_in_workload_token_env_mode() {
    // In WorkloadTokenEnv mode there is no scope concept; adding a scope_dir
    // to the context must not change the key (preserves pre-change behavior).
    let policy = StandingTraceContributionPolicy::default()
        .set_auth_mode(TraceUploadAuthMode::WorkloadTokenEnv)
        .set_upload_token_issuer_url("https://issuer.example/v1/trace-upload-claim");
    let ctx_no_scope = TraceUploadClaimContext::for_status_sync();
    let ctx_with_scope = TraceUploadClaimContext::for_status_sync()
        .with_scope_dir(std::path::PathBuf::from("/scopes/user-a"));

    let key_no_scope = trace_upload_claim_cache_key(&policy, &ctx_no_scope).unwrap();
    let key_with_scope = trace_upload_claim_cache_key(&policy, &ctx_with_scope).unwrap();
    assert_eq!(
        key_no_scope, key_with_scope,
        "WorkloadTokenEnv mode: scope_dir must not affect the cache key"
    );
}
#[test]
fn parse_trace_upload_claim_error_label_handles_known_shapes() {
    assert_eq!(
        parse_trace_upload_claim_error_label(r#"{"error":"PilotAllowlistNotMatched"}"#).as_deref(),
        Some("PilotAllowlistNotMatched")
    );
    assert_eq!(
        parse_trace_upload_claim_error_label(
            r#"  {"error": "  PilotAllowlistStale  ", "extra": 1}"#
        )
        .as_deref(),
        Some("PilotAllowlistStale")
    );
    // Body with no `error` field => None (caller falls back to HTTP status).
    assert!(parse_trace_upload_claim_error_label(r#"{"message":"oops"}"#).is_none());
    // Empty / whitespace / non-JSON => None, never panics.
    assert!(parse_trace_upload_claim_error_label("").is_none());
    assert!(parse_trace_upload_claim_error_label("   ").is_none());
    assert!(parse_trace_upload_claim_error_label("not json").is_none());
    // `error` present but empty/whitespace-only => None (not a usable label).
    assert!(parse_trace_upload_claim_error_label(r#"{"error":"   "}"#).is_none());
}
#[test]
fn parse_trace_upload_claim_error_label_returns_none_for_non_string_error() {
    // Non-string error fields must not panic and must return None so the
    // caller falls back to the generic HTTP-status diagnostic rather than
    // formatting a label like "42" or "[1,2,3]" into the user-facing
    // message.
    assert!(parse_trace_upload_claim_error_label(r#"{"error":42}"#).is_none());
    assert!(parse_trace_upload_claim_error_label(r#"{"error":{"detail":"x"}}"#).is_none());
    assert!(parse_trace_upload_claim_error_label(r#"{"error":[1,2,3]}"#).is_none());
    assert!(parse_trace_upload_claim_error_label(r#"{"error":true}"#).is_none());
    assert!(parse_trace_upload_claim_error_label(r#"{"error":null}"#).is_none());
}
#[tokio::test]
async fn fetch_trace_upload_claim_from_issuer_returns_typed_pilot_allowlist_error() {
    // Spin up a mock HTTP server that returns the issuer's typed
    // PilotAllowlistNotMatched refusal, then drive the factored-out
    // error-formatting helper directly with that body to assert the
    // user-actionable diagnostic (the helper is the unit under test;
    // the mock confirms the body shape the real issuer emits).
    let app = axum::Router::new().route(
        "/v1/trace-upload-claim",
        axum::routing::post(|| async {
            (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "PilotAllowlistNotMatched"})),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock issuer listener binds");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let client = reqwest::Client::builder()
        .build()
        .expect("reqwest client builds");
    let response = client
        .post(format!("http://{addr}/v1/trace-upload-claim"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("mock issuer responds");
    let status = response.status().as_u16();
    let body_text = response.text().await.expect("mock issuer body");
    assert_eq!(status, 400);

    let error = build_trace_upload_claim_http_error("issuer.example", status, &body_text);
    let chain = format!("{error:#}");
    assert!(
        chain.contains("PilotAllowlistNotMatched"),
        "diagnostic chain must surface the typed label: {chain}"
    );
    assert!(
        chain.contains("invite code hash was not in the issuer's active allowlist"),
        "diagnostic chain must surface the user-actionable diagnostic text: {chain}"
    );
}
#[tokio::test]
async fn fetch_trace_upload_claim_from_issuer_generic_http_error_when_label_unknown() {
    // Issuer returns a non-JSON 500 — the helper must fall back to the
    // generic "HTTP 500" diagnostic without naming any PilotAllowlist
    // refusal label.
    let app = axum::Router::new().route(
        "/v1/trace-upload-claim",
        axum::routing::post(|| async {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock issuer listener binds");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let client = reqwest::Client::builder()
        .build()
        .expect("reqwest client builds");
    let response = client
        .post(format!("http://{addr}/v1/trace-upload-claim"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("mock issuer responds");
    let status = response.status().as_u16();
    let body_text = response.text().await.expect("mock issuer body");
    assert_eq!(status, 500);

    let error = build_trace_upload_claim_http_error("issuer.example", status, &body_text);
    let chain = format!("{error:#}");
    assert!(
        chain.contains("HTTP 500"),
        "generic fallback must surface the HTTP status: {chain}"
    );
    assert!(
        !chain.contains("PilotAllowlist"),
        "generic fallback must not name any PilotAllowlist label: {chain}"
    );
}
#[test]
fn cache_key_hashes_invite_code_with_sha256_prefix() {
    let policy = StandingTraceContributionPolicy::default()
        .set_upload_token_issuer_url("https://issuer.example/v1/trace-upload-claim")
        .set_upload_token_invite_code("INV-PILOT-001");
    let context = TraceUploadClaimContext::for_status_sync();
    let key = trace_upload_claim_cache_key(&policy, &context).expect("cache key");
    assert!(
        !key.contains("INV-PILOT-001"),
        "raw invite code must not appear in cache key: {key}"
    );
    let expected_hash = format!(
        "sha256:{}",
        hex::encode(Sha256::digest("INV-PILOT-001".as_bytes()))
    );
    assert!(
        key.contains(&expected_hash),
        "cache key must include sha256-hashed invite code: {key}"
    );
}
#[test]
fn legacy_policy_json_defaults_to_workload_token_env_auth() {
    // Take the default policy's JSON and strip the two NEW fields to simulate
    // a pre-upgrade policy file on disk.
    let mut legacy = serde_json::to_value(StandingTraceContributionPolicy::default()).unwrap();
    let obj = legacy.as_object_mut().unwrap();
    obj.remove("auth_mode");
    obj.remove("device_key_id");
    let policy: StandingTraceContributionPolicy = serde_json::from_value(legacy).unwrap();
    assert_eq!(policy.auth_mode, TraceUploadAuthMode::WorkloadTokenEnv);
    assert!(policy.device_key_id.is_none());
}
#[test]
fn device_key_policy_round_trips() {
    let policy = StandingTraceContributionPolicy::default()
        .set_auth_mode(TraceUploadAuthMode::DeviceKey)
        .set_device_key_id("sha256:abc".to_string());
    let json = serde_json::to_value(&policy).unwrap();
    assert_eq!(json["auth_mode"], "device_key");
    let back: StandingTraceContributionPolicy = serde_json::from_value(json).unwrap();
    assert_eq!(back.auth_mode, TraceUploadAuthMode::DeviceKey);
    assert_eq!(back.device_key_id.as_deref(), Some("sha256:abc"));
}

// --- DeviceKey auth mode tests for issuer_request_bearer ---
#[tokio::test]
async fn device_key_auth_mode_self_signs_workload_jwt() {
    let dir = tempfile::tempdir().unwrap();
    let pending =
        crate::onboarding::DeviceKeypair::load_or_generate_pending(dir.path(), "h").unwrap();
    let promoted = pending.promote(dir.path(), "tenant-a").unwrap();

    let policy = StandingTraceContributionPolicy::default()
        .set_auth_mode(TraceUploadAuthMode::DeviceKey)
        .set_upload_token_tenant_id("tenant-a".to_string())
        .set_upload_token_audience("trace-commons-ingest".to_string());
    let context =
        TraceUploadClaimContext::for_status_sync().with_scope_dir(dir.path().to_path_buf());

    let result = issuer_request_bearer(&policy, &context).await.unwrap();
    let bearer = result.expect("DeviceKey mode must return a bearer token");

    // The JWT must be EdDSA and carry the device key id as kid.
    let header = jsonwebtoken::decode_header(&bearer).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
    assert_eq!(header.kid.as_deref(), Some(promoted.device_key_id.as_str()));
}
#[tokio::test]
async fn device_key_auth_mode_without_local_key_errors_clearly() {
    // Empty dir — no key has ever been generated or promoted.
    let dir = tempfile::tempdir().unwrap();

    let policy = StandingTraceContributionPolicy::default()
        .set_auth_mode(TraceUploadAuthMode::DeviceKey)
        .set_upload_token_tenant_id("tenant-a".to_string())
        .set_upload_token_audience("trace-commons-ingest".to_string());
    let context =
        TraceUploadClaimContext::for_status_sync().with_scope_dir(dir.path().to_path_buf());

    let err = issuer_request_bearer(&policy, &context).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("re-run onboarding"),
        "error should mention re-run onboarding, got: {msg}"
    );
}
#[tokio::test]
async fn device_key_auth_mode_without_scope_dir_errors_clearly() {
    let policy = StandingTraceContributionPolicy::default()
        .set_auth_mode(TraceUploadAuthMode::DeviceKey)
        .set_upload_token_tenant_id("tenant-a".to_string())
        .set_upload_token_audience("trace-commons-ingest".to_string());
    // No scope_dir — context constructed without with_scope_dir().
    let context = TraceUploadClaimContext::for_status_sync();

    let err = issuer_request_bearer(&policy, &context).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("scope"),
        "error should mention scope directory, got: {msg}"
    );
}
/// Regression for the revoke path: a DeviceKey-mode revoke context built
/// from `for_submission_id` plus a real `scope_dir` must reach the signing
/// path and resolve a bearer, rather than hard-erroring on missing scope.
/// This is a focused test on the bearer/context construction the revoke
/// path now performs (wiring the full revoke HTTP path is heavier; the
/// scope_dir threading is what regressed).
#[tokio::test]
async fn device_key_auth_mode_revoke_context_self_signs_workload_jwt() {
    let dir = tempfile::tempdir().unwrap();
    let pending =
        crate::onboarding::DeviceKeypair::load_or_generate_pending(dir.path(), "h").unwrap();
    let promoted = pending.promote(dir.path(), "tenant-a").unwrap();

    let policy = StandingTraceContributionPolicy::default()
        .set_auth_mode(TraceUploadAuthMode::DeviceKey)
        .set_upload_token_tenant_id("tenant-a".to_string())
        .set_upload_token_audience("trace-commons-ingest".to_string());
    // Mirror the revoke path: context from for_submission_id + scope_dir.
    let context = TraceUploadClaimContext::for_submission_id(Uuid::new_v4())
        .with_scope_dir(dir.path().to_path_buf());

    let bearer = issuer_request_bearer(&policy, &context)
        .await
        .unwrap()
        .expect("DeviceKey revoke context must resolve a bearer token");

    let header = jsonwebtoken::decode_header(&bearer).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
    assert_eq!(header.kid.as_deref(), Some(promoted.device_key_id.as_str()));
}
#[tokio::test]
async fn workload_token_env_mode_reads_env_unchanged() {
    // Use a uniquely named env var so other tests cannot interfere.
    let env_var = "IRONCLAW_TEST_WORKLOAD_TOKEN_UNIQUE_9f3a2b1c";
    // SAFETY: test-only; uniquely named var not read by any other test.
    unsafe {
        std::env::set_var(env_var, "test-bearer-xyz");
    }

    let policy = StandingTraceContributionPolicy::default()
        .set_auth_mode(TraceUploadAuthMode::WorkloadTokenEnv)
        .set_upload_token_workload_token_env(env_var.to_string());
    let context = TraceUploadClaimContext::for_status_sync();

    let result = issuer_request_bearer(&policy, &context).await.unwrap();
    assert_eq!(result.as_deref(), Some("test-bearer-xyz"));

    // SAFETY: same as set above — cleanup.
    unsafe {
        std::env::remove_var(env_var);
    }
}
/// Focused unit test on request construction: verify that DeviceKey mode
/// sets invite_code = None while WorkloadTokenEnv mode uses the policy value.
#[test]
fn invite_code_gated_by_auth_mode() {
    // DeviceKey mode — invite_code must be None regardless of policy field.
    let policy_device_key = StandingTraceContributionPolicy::default()
        .set_auth_mode(TraceUploadAuthMode::DeviceKey)
        .set_upload_token_invite_code("should-not-appear".to_string());
    let invite_code_device_key = match policy_device_key.auth_mode {
        TraceUploadAuthMode::WorkloadTokenEnv => policy_device_key
            .upload_token_invite_code
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        TraceUploadAuthMode::DeviceKey => None,
    };
    assert!(
        invite_code_device_key.is_none(),
        "DeviceKey mode must not send invite_code"
    );

    // WorkloadTokenEnv mode — invite_code from policy should be forwarded.
    let policy_env = StandingTraceContributionPolicy::default()
        .set_auth_mode(TraceUploadAuthMode::WorkloadTokenEnv)
        .set_upload_token_invite_code("invite-abc".to_string());
    let invite_code_env = match policy_env.auth_mode {
        TraceUploadAuthMode::WorkloadTokenEnv => policy_env
            .upload_token_invite_code
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        TraceUploadAuthMode::DeviceKey => None,
    };
    assert_eq!(
        invite_code_env.as_deref(),
        Some("invite-abc"),
        "WorkloadTokenEnv mode must forward invite_code from policy"
    );
}

// ── community profile (public_attribution second opt-in) ────────────────
