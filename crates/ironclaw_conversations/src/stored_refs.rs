//! Durable spelling of the channel-owned external refs this crate persists.
//!
//! [`ExternalActorRef`] and [`ExternalConversationRef`] are owned by
//! `ironclaw_extension_contracts`, but the *records* that embed them belong to
//! this crate, and a record grammar outlives the type that shaped it. Released
//! builds wrote `{kind,id}` for the actor and `{space_id,conversation_id,
//! thread_id,message_id}` for the conversation; the canonical type spells the
//! last two `topic_id` / `reply_target_message_id` and adds `display_name`.
//!
//! These adapters write the canonical spelling and read either. Without them a
//! durable binding written before the unification would load with
//! `topic_id: None` — serde fills a missing `Option` field silently — and every
//! threaded reply route would collapse to its conversation root without a
//! single error. The compatibility lives here, in the crate that owns the
//! records, rather than in the contracts crate that owns the type.
//!
//! # Rollback boundary
//!
//! **The compatibility is one-way, by decision. Downgrading a deployment to a
//! binary from before this commit is not supported once it has written
//! conversation-binding or reply-target records.** Compatibility runs
//! upgrade-only: this build reads either spelling and writes only the canonical
//! one, so a record written here and read by a pre-rename binary hits the exact
//! failure this module exists to prevent, in the other direction —
//! `thread_id`/`message_id` are absent, serde fills the `Option`s with `None`
//! without an error, and every threaded route silently collapses to its
//! conversation root. Binding identity is durable, so nothing ages out of it;
//! the 48-hour `DELIVERED_GATE_ROUTE_TTL` heals the *fingerprint* format change
//! recorded on the same CHECKLIST row, not this.
//!
//! Dual-writing both spellings for a transition window was considered and
//! refused: it is exactly the compatibility shim the type-placement rule
//! forbids (see the WS5 CHECKLIST row), it would have to survive in both
//! adapters plus `ExternalConversationIdentity`, and `#[serde(alias)]` makes it
//! self-defeating — a reader that accepts both spellings rejects a record
//! carrying both as a duplicate field. If a downgrade is ever needed, the
//! recovery is to re-pair the affected routes, not to read the old spelling
//! back.

use ironclaw_extension_contracts::external::{ExternalActorRef, ExternalConversationRef};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serde adapter for a persisted [`ExternalConversationRef`] field.
pub(crate) mod conversation_ref {
    use super::*;

    pub(crate) fn serialize<S>(
        value: &ExternalConversationRef,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<ExternalConversationRef, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Stored {
            space_id: Option<String>,
            conversation_id: String,
            #[serde(alias = "thread_id")]
            topic_id: Option<String>,
            #[serde(alias = "message_id")]
            reply_target_message_id: Option<String>,
        }

        let stored = Stored::deserialize(deserializer)?;
        ExternalConversationRef::new(
            stored.space_id.as_deref(),
            stored.conversation_id,
            stored.topic_id.as_deref(),
            stored.reply_target_message_id.as_deref(),
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Serde adapter for a persisted [`ExternalActorRef`] field.
pub(crate) mod actor_ref {
    use super::*;

    pub(crate) fn serialize<S>(value: &ExternalActorRef, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<ExternalActorRef, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Stored {
            kind: String,
            id: String,
            /// Absent in records written before the unification. Actor identity
            /// is `(kind, id)` — `PartialEq`/`Hash` on the canonical type
            /// exclude the display name — so a missing one never re-keys a
            /// pairing.
            #[serde(default)]
            display_name: Option<String>,
        }

        let stored = Stored::deserialize(deserializer)?;
        ExternalActorRef::new(stored.kind, stored.id, stored.display_name)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct StoredConversation {
        #[serde(with = "conversation_ref")]
        external_conversation_ref: ExternalConversationRef,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct StoredActor {
        #[serde(with = "actor_ref")]
        external_actor_ref: ExternalActorRef,
    }

    #[test]
    fn legacy_conversation_record_keeps_its_topic_and_reply_target() {
        let legacy: StoredConversation = serde_json::from_str(
            r#"{"external_conversation_ref":{"space_id":"T1","conversation_id":"C1",
                "thread_id":"1700.1","message_id":"1800.2"}}"#,
        )
        .expect("a record written before the unification must still load");
        let route = &legacy.external_conversation_ref;
        assert_eq!(route.topic_id(), Some("1700.1"));
        assert_eq!(route.reply_target_message_id(), Some("1800.2"));
    }

    #[test]
    fn current_conversation_record_round_trips_and_is_written_in_the_new_spelling() {
        let record = StoredConversation {
            external_conversation_ref: ExternalConversationRef::new(
                Some("T1"),
                "C1",
                Some("1700.1"),
                Some("1800.2"),
            )
            .expect("valid"),
        };
        let json = serde_json::to_string(&record).expect("serialize");
        assert!(json.contains("topic_id"), "writes the canonical spelling");
        assert!(
            !json.contains("\"thread_id\""),
            "never writes the legacy spelling back: {json}"
        );
        let parsed: StoredConversation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, parsed);
    }

    #[test]
    fn stored_conversation_ref_revalidates_on_load() {
        let result: Result<StoredConversation, _> = serde_json::from_str(
            r#"{"external_conversation_ref":{"space_id":null,"conversation_id":"",
                "topic_id":null,"reply_target_message_id":null}}"#,
        );
        assert!(result.is_err(), "an empty conversation id must not load");
    }

    #[test]
    fn legacy_actor_record_loads_without_a_display_name_and_keeps_its_identity() {
        let legacy: StoredActor =
            serde_json::from_str(r#"{"external_actor_ref":{"kind":"slack","id":"U1"}}"#)
                .expect("a record written before the unification must still load");
        assert_eq!(legacy.external_actor_ref.kind(), "slack");
        assert_eq!(legacy.external_actor_ref.id(), "U1");
        assert_eq!(legacy.external_actor_ref.display_name(), None);

        let named = StoredActor {
            external_actor_ref: ExternalActorRef::new("slack", "U1", Some("Alice")).expect("valid"),
        };
        assert_eq!(
            legacy.external_actor_ref, named.external_actor_ref,
            "pairing lookups key on (kind, id), so a display name must not re-key them"
        );
    }

    #[test]
    fn stored_actor_ref_revalidates_on_load() {
        let result: Result<StoredActor, _> =
            serde_json::from_str(r#"{"external_actor_ref":{"kind":"slack","id":""}}"#);
        assert!(result.is_err(), "an empty actor id must not load");
    }
}
