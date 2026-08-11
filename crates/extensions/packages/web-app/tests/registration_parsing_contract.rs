//! What survived enrollment moving host-side (design §8), re-aimed at where
//! the behavior now lives.
//!
//! The six tests this file replaced drove `enable_notifications` /
//! `disable_notifications` on the adapter. Those methods are gone, and their
//! assertions split cleanly in two:
//!
//! - **Endpoint admission and storage bounds** — that a submitted endpoint
//!   must target a declared egress host, that the per-user cap and the
//!   document bound fail closed before anything is written — became generic,
//!   host-side, and are pinned in `ironclaw_auth::delivery_registrations`.
//!   They are not this package's to test any more, and duplicating them here
//!   would be the second copy that drifts.
//! - **Interpreting the opaque document** — the channel-specific half — is
//!   still this package's, and now happens at delivery, which is the only
//!   place it happens at all. That is what this file covers.
//!
//! The rule under test: a registration this half cannot use fails **that
//! registration**, never the delivery and never its siblings, and is reported
//! for pruning on the same path an expired endpoint takes.

use std::sync::Mutex;

use async_trait::async_trait;
use ironclaw_extension_contracts::channel_adapter::{
    ChannelDelivery, DeliveryRegistration, OutboundEnvelope, OutboundPart, OutboundTarget,
    PartDeliveryOutcome,
};
use ironclaw_extension_contracts::external::ExternalConversationRef;
use ironclaw_extension_contracts::tool_adapter::{
    RestrictedEgress, RestrictedEgressError, RestrictedEgressRequest, RestrictedEgressResponse,
};
use ironclaw_web_app_extension::WebAppChannelAdapter;

#[derive(Default)]
struct RecordingEgress {
    requests: Mutex<Vec<RestrictedEgressRequest>>,
    /// Status returned for each request, in order; the last repeats.
    statuses: Mutex<Vec<u16>>,
}

impl RecordingEgress {
    fn with_statuses(statuses: Vec<u16>) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            statuses: Mutex::new(statuses),
        }
    }

    fn urls(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("requests lock")
            .iter()
            .map(|request| request.url.clone())
            .collect()
    }
}

#[async_trait]
impl RestrictedEgress for RecordingEgress {
    async fn send(
        &self,
        request: RestrictedEgressRequest,
    ) -> Result<RestrictedEgressResponse, RestrictedEgressError> {
        let index = self.requests.lock().expect("requests lock").len();
        self.requests.lock().expect("requests lock").push(request);
        let statuses = self.statuses.lock().expect("statuses lock");
        let status = statuses
            .get(index)
            .copied()
            .or_else(|| statuses.last().copied())
            .unwrap_or(201);
        Ok(RestrictedEgressResponse {
            status,
            body: Vec::new(),
        })
    }
}

fn registration(id: &str, token: &str, document: &str) -> DeliveryRegistration {
    DeliveryRegistration {
        registration_id: id.to_string(),
        endpoint: format!("https://push.example/send/{token}"),
        document: document.to_string(),
        created_at: "2026-08-11T00:00:00Z".to_string(),
    }
}

/// A well-formed browser enrollment document: base64url key material of the
/// exact lengths RFC 8291 requires.
fn valid_document() -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut point = vec![0x04u8];
    point.extend_from_slice(&[7u8; 64]);
    serde_json::json!({
        "keys": {
            "p256dh": URL_SAFE_NO_PAD.encode(point),
            "auth": URL_SAFE_NO_PAD.encode([9u8; 16]),
        },
        "user_agent": "Test Browser",
    })
    .to_string()
}

fn envelope(registrations: Vec<DeliveryRegistration>) -> OutboundEnvelope {
    OutboundEnvelope {
        extension_id: "web-app".to_string(),
        installation_id: "web-app".to_string(),
        delivery_attempt_id: "attempt-1".to_string(),
        target: OutboundTarget {
            conversation: ExternalConversationRef::new(None, "web-push", None, None)
                .expect("conversation"),
            thread_anchor: None,
        },
        parts: vec![OutboundPart::Text("a notice".to_string())],
        reply_context: None,
        registrations,
    }
}

/// Each malformed shape is one the old `enable_notifications` arms rejected
/// before storage. The host still bounds size and admits the endpoint host;
/// what it deliberately cannot check is the opaque document, so these fail
/// here — per registration, and reported for pruning.
#[tokio::test]
async fn an_unusable_registration_document_is_pruned_and_never_sent_to() {
    for document in [
        "this is not json",
        r#"{"user_agent":"no keys at all"}"#,
        r#"{"keys":{"p256dh":"not base64url!!","auth":"also bad"}}"#,
        r#"{"keys":{"p256dh":"c2hvcnQ","auth":"c2hvcnQ"}}"#,
    ] {
        let egress = RecordingEgress::default();
        let report = WebAppChannelAdapter::new()
            .deliver(
                envelope(vec![registration("reg-1", "a", document)]),
                &egress,
            )
            .await
            .expect("an unusable registration is not a delivery error");

        assert_eq!(
            report.prune_registrations,
            vec!["reg-1".to_string()],
            "an unusable registration must be reported for pruning: {document}"
        );
        assert!(
            egress.urls().is_empty(),
            "nothing may be sent for a registration that could not be parsed: {document}"
        );
        assert!(
            matches!(
                report.parts.as_slice(),
                [PartDeliveryOutcome::Permanent { .. }]
            ),
            "with no usable registration the part is permanently undeliverable: {document}"
        );
    }
}

/// The isolation rule, stated as a test: one bad record must not cost a good
/// one its notification. Before §8 this was unreachable — the adapter read
/// its own store and a decode failure failed the whole list.
#[tokio::test]
async fn one_unusable_registration_does_not_block_its_siblings() {
    let egress = RecordingEgress::default();
    let report = WebAppChannelAdapter::new()
        .deliver(
            envelope(vec![
                registration("reg-bad", "a", "{}"),
                registration("reg-good", "b", &valid_document()),
            ]),
            &egress,
        )
        .await
        .expect("deliver");

    assert_eq!(report.prune_registrations, vec!["reg-bad".to_string()]);
    assert_eq!(
        egress.urls(),
        vec!["https://push.example/send/b".to_string()],
        "the good registration is still delivered to, and the bad one is not"
    );
    assert!(
        matches!(report.parts.as_slice(), [PartDeliveryOutcome::Sent { .. }]),
        "one accepted send is a Sent part: {:?}",
        report.parts
    );
}

/// 404/410 is the push service saying the registration is gone. It takes the
/// same path an unparseable one does — reported, never written, because this
/// half holds no store.
#[tokio::test]
async fn an_expired_endpoint_is_reported_for_pruning_not_removed_locally() {
    let egress = RecordingEgress::with_statuses(vec![410]);
    let report = WebAppChannelAdapter::new()
        .deliver(
            envelope(vec![registration("reg-gone", "a", &valid_document())]),
            &egress,
        )
        .await
        .expect("deliver");

    assert_eq!(report.prune_registrations, vec!["reg-gone".to_string()]);
    assert_eq!(egress.urls().len(), 1, "the send is attempted, then pruned");
}

/// The coordinator resolves zero registrations to a "no target" outcome
/// before this half is called, so reaching it with an empty list means the
/// channel declared no enrollment requirement. Say so; do not pretend a send
/// was attempted.
#[tokio::test]
async fn no_registrations_is_a_permanent_outcome_with_no_egress() {
    let egress = RecordingEgress::default();
    let report = WebAppChannelAdapter::new()
        .deliver(envelope(Vec::new()), &egress)
        .await
        .expect("deliver");

    assert!(report.prune_registrations.is_empty());
    assert!(egress.urls().is_empty());
    assert!(matches!(
        report.parts.as_slice(),
        [PartDeliveryOutcome::Permanent { .. }]
    ));
}

/// Parts this transport cannot carry stay individually accounted for, so a
/// mixed envelope reports per part rather than failing wholesale.
#[tokio::test]
async fn unsupported_parts_are_reported_individually() {
    let egress = RecordingEgress::default();
    let mut envelope = envelope(vec![registration("reg-1", "a", &valid_document())]);
    envelope.parts.push(OutboundPart::React {
        vendor_message_ref: "m-1".to_string(),
        reaction: ironclaw_extension_contracts::channel_adapter::RunReaction::Working,
        action: ironclaw_extension_contracts::channel_adapter::ReactionAction::Add,
    });

    let report = WebAppChannelAdapter::new()
        .deliver(envelope, &egress)
        .await
        .expect("deliver");

    assert!(matches!(report.parts[0], PartDeliveryOutcome::Sent { .. }));
    assert!(matches!(
        report.parts[1],
        PartDeliveryOutcome::Permanent { .. }
    ));
}
