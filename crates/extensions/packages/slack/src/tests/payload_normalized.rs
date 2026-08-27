use super::*;
use proptest::prelude::*;

fn installation_id() -> AdapterInstallationId {
    AdapterInstallationId::new("install-alpha").expect("installation")
}

fn normalize(value: serde_json::Value) -> SlackInboundEvent {
    normalize_slack_event(
        &serde_json::to_vec(&value).expect("payload"),
        &installation_id(),
    )
    .expect("normalizes")
}

fn message(value: serde_json::Value) -> Box<ParsedSlackInboundMessage> {
    match normalize(value) {
        SlackInboundEvent::Message(message) => message,
        other => panic!("expected message, got {other:?}"),
    }
}

#[test]
fn url_verification_is_an_immediate_channel_outcome() {
    assert!(matches!(
        normalize(serde_json::json!({
            "type": "url_verification",
            "challenge": "challenge-token"
        })),
        SlackInboundEvent::UrlVerification { challenge }
            if challenge == "challenge-token"
    ));
}

#[test]
fn dm_and_thread_messages_normalize_to_the_same_contract() {
    let dm = message(serde_json::json!({
        "type": "event_callback",
        "team_id": "T123",
        "event_id": "EvDm",
        "event": {
            "type": "message",
            "channel_type": "im",
            "user": "U123",
            "channel": "D123",
            "text": "hello from dm",
            "ts": "1710000000.000001"
        }
    }));
    assert_eq!(dm.actor.id(), "U123");
    assert_eq!(dm.conversation.conversation_id(), "D123");
    assert_eq!(dm.text, "hello from dm");
    assert_eq!(dm.trigger, ProductTriggerReason::DirectChat);

    let thread = message(serde_json::json!({
        "type": "event_callback",
        "team_id": "T123",
        "event_id": "EvThread",
        "event": {
            "type": "message",
            "user": "U456",
            "channel": "C123",
            "text": "continue",
            "thread_ts": "1710000000.000010",
            "ts": "1710000000.000011"
        }
    }));
    assert_eq!(thread.conversation.topic_id(), Some("1710000000.000010"));
    assert_eq!(thread.trigger, ProductTriggerReason::ReplyToBot);
}

#[test]
fn app_mention_strips_only_the_provider_mention_and_self_roots_a_thread() {
    let message = message(serde_json::json!({
        "type": "event_callback",
        "team_id": "T123",
        "event_id": "EvMention",
        "event": {
            "type": "app_mention",
            "user": "U123",
            "channel": "C123",
            "text": "<@UBOT> please help",
            "ts": "1710000000.000002"
        }
    }));
    assert_eq!(message.text, "please help");
    assert_eq!(message.trigger, ProductTriggerReason::BotMention);
    assert_eq!(message.conversation.topic_id(), Some("1710000000.000002"));
}

/// Slack stamps `subtype` on two unrelated things: events that are not one
/// person's message, and ordinary human messages that render specially. Only
/// the first family may be dropped — dropping the second silences a real
/// person behind a bare 200.
#[test]
fn the_subtype_gate_admits_human_messages_and_drops_only_non_messages() {
    for (label, event, admitted) in [
        // A reply sent with "Also send to channel" carries `thread_broadcast`
        // on BOTH the app_mention and the message.channels event. The
        // app_mention is the one that matters: a `ReplyToBot` thread reply is
        // a NoOp at the product surface, so a mention that loses its
        // app_mention never runs at all.
        (
            "thread_broadcast mention",
            serde_json::json!({
                "type": "app_mention", "user": "U1", "channel": "C1",
                "text": "<@UBOT> broadcast question", "subtype": "thread_broadcast",
                "thread_ts": "1710000000.000010", "ts": "1710000000.000011"
            }),
            true,
        ),
        (
            "thread_broadcast channel message",
            serde_json::json!({
                "type": "message", "user": "U1", "channel": "C1",
                "text": "broadcast reply", "subtype": "thread_broadcast",
                "thread_ts": "1710000000.000010", "ts": "1710000000.000011"
            }),
            true,
        ),
        (
            "reply_broadcast, thread_broadcast's deprecated predecessor",
            serde_json::json!({
                "type": "message", "user": "U1", "channel": "C1",
                "text": "older broadcast", "subtype": "reply_broadcast",
                "thread_ts": "1710000000.000010", "ts": "1710000000.000012"
            }),
            true,
        ),
        (
            "me_message",
            serde_json::json!({
                "type": "message", "user": "U1", "channel": "D1", "channel_type": "im",
                "text": "shrugs", "subtype": "me_message", "ts": "1710000000.000013"
            }),
            true,
        ),
        (
            "file_share",
            serde_json::json!({
                "type": "message", "user": "U1", "channel": "D1", "channel_type": "im",
                "text": "here it is", "subtype": "file_share", "ts": "1710000000.000014"
            }),
            true,
        ),
        // Not one user-authored message.
        (
            "bot echo",
            serde_json::json!({
                "type": "message", "user": "U1", "channel": "D1", "text": "loop",
                "ts": "1.0", "bot_id": "B1"
            }),
            false,
        ),
        (
            "bot_message carrying no bot_id",
            serde_json::json!({
                "type": "message", "user": "U1", "channel": "D1", "channel_type": "im",
                "text": "loop", "ts": "1.0", "subtype": "bot_message"
            }),
            false,
        ),
        // Real edit/delete events carry no top-level author at all, so the
        // author guard already rejects them; these synthesize one so the
        // subtype denial itself is what stays pinned.
        (
            "message_changed",
            serde_json::json!({
                "type": "message", "user": "U1", "channel": "D1", "channel_type": "im",
                "text": "changed", "ts": "1.0", "subtype": "message_changed"
            }),
            false,
        ),
        (
            "message_deleted",
            serde_json::json!({
                "type": "message", "user": "U1", "channel": "D1", "channel_type": "im",
                "text": "deleted", "ts": "1.0", "subtype": "message_deleted"
            }),
            false,
        ),
        (
            "message_replied",
            serde_json::json!({
                "type": "message", "user": "U1", "channel": "C1",
                "text": "replied", "subtype": "message_replied",
                "thread_ts": "1710000000.000010", "ts": "1710000000.000015"
            }),
            false,
        ),
        (
            "assistant_app_thread",
            serde_json::json!({
                "type": "message", "user": "U1", "channel": "D1", "channel_type": "im",
                "text": "assistant thread", "subtype": "assistant_app_thread",
                "ts": "1710000000.000016"
            }),
            false,
        ),
        (
            "ambient channel chatter",
            serde_json::json!({
                "type": "message", "user": "U1", "channel": "C1", "text": "ambient",
                "ts": "1.0"
            }),
            false,
        ),
    ] {
        let outcome = normalize(serde_json::json!({
            "type": "event_callback", "team_id": "T123",
            "event_id": "EvSubtype", "event": event
        }));
        assert_eq!(
            matches!(outcome, SlackInboundEvent::Message(_)),
            admitted,
            "{label} normalized to {outcome:?}"
        );
    }
}

/// The incident shape: an @mention written as a threaded reply with "Also send
/// to channel" must reach the host as a `BotMention` still anchored to the
/// thread it was written in.
#[test]
fn a_broadcast_mention_keeps_its_thread_anchor_and_bot_mention_trigger() {
    let broadcast = message(serde_json::json!({
        "type": "event_callback",
        "team_id": "T123",
        "event_id": "EvBroadcast",
        "event": {
            "type": "app_mention",
            "user": "U091135TNG6",
            "channel": "C088U5W0CCA",
            "subtype": "thread_broadcast",
            "text": "<@UBOT> what do you think about OpenAI Jalapeno?",
            "thread_ts": "1787687594.022139",
            "ts": "1787756973.320549"
        }
    }));
    assert_eq!(broadcast.text, "what do you think about OpenAI Jalapeno?");
    assert_eq!(broadcast.trigger, ProductTriggerReason::BotMention);
    assert_eq!(broadcast.conversation.topic_id(), Some("1787687594.022139"));
    assert_eq!(broadcast.conversation.conversation_id(), "C088U5W0CCA");
}

#[test]
fn attachment_handles_remain_provider_local_until_the_adapter_fetches_them() {
    let message = message(serde_json::json!({
        "type": "event_callback",
        "team_id": "T123",
        "event_id": "EvFile",
        "event": {
            "type": "message",
            "channel_type": "im",
            "user": "U123",
            "channel": "D123",
            "text": "see file",
            "ts": "1710000000.000003",
            "files": [{
                "id": "F123", "mimetype": "text/plain", "name": "notes.txt", "size": 12
            }]
        }
    }));
    assert!(message.attachments.is_empty());
    assert_eq!(message.pending_attachments.len(), 1);
    assert_eq!(message.pending_attachments[0].vendor_ref, "F123");
    assert_eq!(
        message.pending_attachments[0]
            .descriptor
            .filename
            .as_deref(),
        Some("notes.txt")
    );
}

#[test]
fn slash_command_forms_normalize_without_a_second_product_parser() {
    let headers = vec![(
        "content-type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    )];
    let event = normalize_slack_inbound(
        b"channel_id=D123&channel_name=directmessage&user_id=U123&command=%2Fironclaw&text=hello&trigger_id=trigger-1&team_id=T123",
        &headers,
        &installation_id(),
    )
    .expect("slash form");
    let SlackInboundEvent::Message(message) = event else {
        panic!("slash command must become a message");
    };
    assert_eq!(message.text, "/hello");
    assert_eq!(message.trigger, ProductTriggerReason::DirectChat);
}

#[test]
fn oversized_payload_and_missing_event_id_fail_closed() {
    let oversized = vec![b'x'; MAX_SLACK_PAYLOAD_BYTES + 1];
    assert!(normalize_slack_event(&oversized, &installation_id()).is_err());
    assert!(matches!(
        normalize_slack_event(
            br#"{"type":"event_callback","event":{"type":"message"}}"#,
            &installation_id()
        ),
        Err(SlackPayloadParseError::InvalidExternalRef {
            kind: "external_event_id",
            ..
        })
    ));
}

proptest! {
    #[test]
    fn arbitrary_untrusted_bytes_never_panic(raw in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = normalize_slack_event(&raw, &installation_id());
    }
}
