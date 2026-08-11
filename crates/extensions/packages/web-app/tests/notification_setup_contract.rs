//! The web-app adapter's own notification-setup error arms (§7b).
//!
//! The generic service tests (`ironclaw_assistant`'s
//! `outbound_delivery_contract`) drive a scripted adapter, so they prove
//! dispatch plumbing rather than this adapter's parse → validate → store
//! path; the production round-trip integration test covers the happy path
//! and the undeclared-host rejection. What is left — and what this file
//! pins — is what the adapter does with input its own client would never
//! send: malformed enrollment documents, key material that is not valid
//! base64url, and an endpoint that no declared push service could serve.
//!
//! The rule under test is uniform: every one of these is a *caller-visible
//! parse/validation rejection*, never a panic and never a silent success
//! that would leave the browser believing it is enrolled with no server
//! record behind it.

use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_extension_contracts::channel_adapter::NotificationSetupScope;
use ironclaw_extension_contracts::channel_adapter::{ChannelAdapter, ChannelContext, ChannelError};
use ironclaw_host_api::ids::{TenantId, UserId};
use ironclaw_host_api::resource::ResourceScope;
use ironclaw_web_app::{
    PushEndpoint, PushSubscriptionRecord, PushSubscriptionUpsertOutcome, WebAppError,
    WebAppRuntime, WebAppRuntimeSlot, WebAppSubscriptionStore,
};
use ironclaw_web_app_extension::WebAppChannelAdapter;

/// Records every write it is asked to perform, so a test can prove a
/// rejected payload never reached storage.
#[derive(Default)]
struct RecordingStore {
    upserts: std::sync::Mutex<Vec<String>>,
    removals: std::sync::Mutex<Vec<String>>,
}

impl RecordingStore {
    fn upsert_count(&self) -> usize {
        self.upserts.lock().expect("upserts").len()
    }
}

#[async_trait]
impl WebAppSubscriptionStore for RecordingStore {
    async fn upsert_subscription(
        &self,
        _scope: &ResourceScope,
        record: PushSubscriptionRecord,
    ) -> Result<PushSubscriptionUpsertOutcome, WebAppError> {
        self.upserts
            .lock()
            .expect("upserts")
            .push(record.endpoint.as_str().to_string());
        Ok(PushSubscriptionUpsertOutcome::Enrolled)
    }

    async fn remove_subscription(
        &self,
        _scope: &ResourceScope,
        endpoint: &PushEndpoint,
    ) -> Result<bool, WebAppError> {
        self.removals
            .lock()
            .expect("removals")
            .push(endpoint.as_str().to_string());
        Ok(true)
    }

    async fn list_subscriptions(
        &self,
        _scope: &ResourceScope,
    ) -> Result<Vec<PushSubscriptionRecord>, WebAppError> {
        Ok(Vec::new())
    }
}

fn adapter_with(store: Arc<RecordingStore>) -> WebAppChannelAdapter {
    let slot = WebAppRuntimeSlot::new();
    slot.install(Arc::new(WebAppRuntime {
        subscriptions: store as Arc<dyn WebAppSubscriptionStore>,
        vapid_public_key: "BPublicKeyPlaceholder".to_string(),
        allowed_push_hosts: vec!["push.example".to_string()],
    }))
    .expect("slot installs once");
    WebAppChannelAdapter::new(slot)
}

fn setup_scope() -> NotificationSetupScope {
    NotificationSetupScope {
        tenant_id: TenantId::new("tenant-a").expect("tenant"),
        user_id: UserId::new("user-a").expect("user"),
    }
}

fn context() -> ChannelContext<'static> {
    ChannelContext {
        extension_id: "web-app",
        installation_id: "install-1",
        config: &[],
    }
}

/// A structurally valid enrollment document for the declared push host —
/// the shape every rejection case below deviates from by exactly one field.
fn valid_payload() -> String {
    serde_json::json!({
        "endpoint": "https://push.example/send/abc",
        "keys": {
            "p256dh": "BAcbFqLBpVaCLGId1nAJJZR6WKR7Zr9WOZ0Zx7SFmR4bC5ZBBQGkG7t1XEHqRLZzP8Rm2Fh1kQ0YfWzMPqDaBnE",
            "auth": "c2VjcmV0LWF1dGgtdmFs"
        },
        "user_agent": "TestBrowser/1.0"
    })
    .to_string()
}

#[tokio::test]
async fn enable_rejects_a_payload_that_is_not_json_without_touching_the_store() {
    let store = Arc::new(RecordingStore::default());
    let adapter = adapter_with(Arc::clone(&store));

    let error = adapter
        .enable_notifications(&context(), &setup_scope(), "this is not json")
        .await
        .expect_err("a non-JSON enrollment document must be rejected");

    assert!(
        matches!(error, ChannelError::Parse { .. }),
        "a malformed document is a caller-correctable parse rejection, got {error:?}"
    );
    assert_eq!(
        store.upsert_count(),
        0,
        "a rejected payload must never reach the subscription store"
    );
}

#[tokio::test]
async fn enable_rejects_a_structurally_valid_document_missing_key_material() {
    let store = Arc::new(RecordingStore::default());
    let adapter = adapter_with(Arc::clone(&store));
    // Valid JSON, valid endpoint, but no `keys` — the browser always sends
    // them, so this is exactly the shape a hand-crafted request has.
    let payload = serde_json::json!({ "endpoint": "https://push.example/send/abc" }).to_string();

    let error = adapter
        .enable_notifications(&context(), &setup_scope(), &payload)
        .await
        .expect_err("enrollment without key material must be rejected");

    assert!(
        matches!(error, ChannelError::Parse { .. }),
        "missing key material is a parse rejection, got {error:?}"
    );
    assert_eq!(store.upsert_count(), 0);
}

#[tokio::test]
async fn enable_rejects_key_material_that_is_not_base64url() {
    let store = Arc::new(RecordingStore::default());
    let adapter = adapter_with(Arc::clone(&store));
    let payload = serde_json::json!({
        "endpoint": "https://push.example/send/abc",
        "keys": { "p256dh": "not valid base64!!", "auth": "also not valid!!" }
    })
    .to_string();

    let error = adapter
        .enable_notifications(&context(), &setup_scope(), &payload)
        .await
        .expect_err("undecodable key material must be rejected");

    assert!(
        matches!(error, ChannelError::Parse { .. }),
        "undecodable key material is a parse rejection, got {error:?}"
    );
    assert_eq!(
        store.upsert_count(),
        0,
        "key material is validated before anything persists"
    );
}

#[tokio::test]
async fn enable_rejects_an_endpoint_on_an_undeclared_push_host() {
    let store = Arc::new(RecordingStore::default());
    let adapter = adapter_with(Arc::clone(&store));
    let payload = valid_payload().replace("push.example", "evil.example");

    let error = adapter
        .enable_notifications(&context(), &setup_scope(), &payload)
        .await
        .expect_err("an endpoint outside the manifest's egress hosts must be rejected");

    assert!(
        matches!(error, ChannelError::Parse { .. }),
        "an undeclared push host is a caller-correctable rejection, got {error:?}"
    );
    assert_eq!(
        store.upsert_count(),
        0,
        "the host allowlist is enforced before persistence"
    );
}

#[tokio::test]
async fn disable_rejects_a_malformed_unenrollment_document() {
    let store = Arc::new(RecordingStore::default());
    let adapter = adapter_with(Arc::clone(&store));

    let error = adapter
        .disable_notifications(&context(), &setup_scope(), "{\"not_an_endpoint\": 1}")
        .await
        .expect_err("an unenrollment document without an endpoint must be rejected");

    assert!(
        matches!(error, ChannelError::Parse { .. }),
        "a malformed unenrollment document is a parse rejection, got {error:?}"
    );
    assert!(
        store.removals.lock().expect("removals").is_empty(),
        "a rejected removal must never reach the store"
    );
}

/// Without an installed runtime the adapter has no store and no advertised
/// key: every setup operation must fail closed rather than report an empty
/// but successful enrollment state.
#[tokio::test]
async fn setup_operations_fail_closed_when_no_runtime_is_installed() {
    let adapter = WebAppChannelAdapter::new(WebAppRuntimeSlot::new());

    let status = adapter
        .notification_setup_status(&context(), &setup_scope())
        .await;
    assert!(
        status.is_err(),
        "status must fail closed without an installed runtime"
    );

    let enable = adapter
        .enable_notifications(&context(), &setup_scope(), &valid_payload())
        .await;
    assert!(
        enable.is_err(),
        "enable must fail closed without an installed runtime"
    );
}
