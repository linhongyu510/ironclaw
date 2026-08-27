//! Slack Events API payload normalization.
// arch-exempt: large_file, split into Events-API vs slash-form parsing vs shared normalization modules, plan #6894
//!
//! Inputs are raw, host-verified Slack webhook bytes. Outputs are the
//! provider-neutral channel contract: a normalized complete-message precursor,
//! an immediate verification response, or an authenticated ignore decision.

use ironclaw_extension_contracts::channel_adapter::{
    ChannelAttachmentRef, NormalizedInboundMessage, ProductTriggerReason,
};
use ironclaw_extension_contracts::external::{
    ExternalActorRef, ExternalConversationRef, ExternalEventId, ProductAttachmentDescriptor,
    ProductAttachmentKind,
};
use ironclaw_host_api::product_adapter::AdapterInstallationId;
use serde::Deserialize;
use thiserror::Error;

pub const SLACK_API_HOST: &str = "slack.com";
pub const SLACK_USER_ACTOR_KIND: &str = "slack_user";
/// Manifest admin-configuration handle carrying the bot's own member id.
/// Declared `required = true`, so a configured installation always has it.
const SLACK_BOT_USER_ID_HANDLE: &str = "slack_bot_user_id";
/// Slack `subtype` values that are not one person's message.
///
/// The gate here used to be the inverse — an allowlist of "human" subtypes,
/// holding only `None` and `file_share`. That is a standing bet that Slack
/// will never add another way for a person to post, and this adapter already
/// lost it: `thread_broadcast` (a threaded reply sent with "Also send to
/// channel") was discarded as if it were a channel-join announcement, so a
/// mention written that way silently never ran.
///
/// Inverting it means an unrecognized subtype is admitted, not dropped. That
/// is safe because this list only has to name what the guards below cannot
/// see for themselves. Slack's system subtypes (`channel_join`,
/// `channel_topic`, `pinned_item`, …) are channel-scoped announcements with
/// no thread anchor, so the ambient-chatter rule in [`normalize_slack_event`]
/// already drops them; message mutations carry their author under a nested
/// `message` object, so the author guard already drops them. What is named
/// here is what would otherwise slip past both: bot-authored posts, because a
/// mention loop between two apps does not terminate on its own, and mutations
/// that do arrive with a thread anchor.
const NON_USER_MESSAGE_SUBTYPES: &[&str] = &[
    "bot_message",
    "message_changed",
    "message_deleted",
    "message_replied",
    "assistant_app_thread",
];

/// Maximum accepted byte length for any Slack inbound webhook payload.
const MAX_SLACK_PAYLOAD_BYTES: usize = 1024 * 1024; // 1 MB

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SlackPayloadParseError {
    #[error("invalid Slack event JSON: {reason}")]
    InvalidJson { reason: String },
    #[error("invalid Slack slash-command form: {reason}")]
    InvalidForm { reason: String },
    #[error("invalid external reference: {kind}: {reason}")]
    InvalidExternalRef { kind: &'static str, reason: String },
}

// ── Channel-normalized parsing (generic ingress router, extension-runtime P4) ──

/// One host-verified Slack inbound request, normalized for the generic
/// channel-adapter contract: a URL-verification challenge, an ignored event,
/// or one plain user message. Gate-resolution classification (`approve` /
/// `deny gate:<ref>` / `auth deny <ref>`) is deliberately NOT applied here —
/// the shared host sink applies the channel-neutral interaction grammar.
#[derive(Debug)]
pub enum SlackInboundEvent {
    UrlVerification {
        challenge: String,
    },
    /// Slack's one-time endpoint-verification probe for a native slash
    /// command (distinct from the Events API's `UrlVerification` challenge).
    /// Any 200 response satisfies it; the body is ignored.
    SslCheck,
    Ignore {
        reason: SlackIgnoreReason,
    },
    Message(Box<ParsedSlackInboundMessage>),
}

/// Why a verified Slack event produced no message.
///
/// Carried rather than discarded so the adapter can log one line per drop.
/// Every rejection on this path ends in [`SlackInboundEvent::Ignore`], the
/// router maps that to a bare `200`, and Slack's retry machinery is satisfied
/// — so a human message dropped by mistake leaves no trace anywhere unless
/// the reason travels with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackIgnoreReason {
    /// Envelope is not `event_callback` (`app_rate_limited`, …).
    NotAnEventCallback,
    /// `event_callback` with no `event` object.
    MissingEventPayload,
    /// An event type this channel does not act on.
    UnsupportedEventType,
    /// A channel message that neither mentions the bot nor replies in a
    /// thread — bystander chatter.
    AmbientChannelMessage,
    /// Authored by an integration, including this bot's own echo.
    BotAuthored,
    /// A `subtype` in [`NON_USER_MESSAGE_SUBTYPES`].
    NonUserMessageSubtype(String),
    /// A field the normalized contract cannot be built without (`user` on a
    /// message mutation, `channel`, `ts`).
    MissingField(&'static str),
}

/// Pure payload-normalization result retained inside the Slack package until
/// [`crate::channel::SlackChannelAdapter`] finishes vendor reads.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedSlackInboundMessage {
    pub message: NormalizedInboundMessage,
    pub pending_attachments: Vec<ChannelAttachmentRef>,
}

impl std::ops::Deref for ParsedSlackInboundMessage {
    type Target = NormalizedInboundMessage;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

/// Parse one host-verified Slack Events API request into its normalized
/// channel form. Pure protocol work — no I/O, no secrets; the host executed
/// the signature recipe before calling this.
pub fn normalize_slack_event(
    raw_payload: &[u8],
    installation_id: &AdapterInstallationId,
    bot_user_id: Option<&str>,
) -> Result<SlackInboundEvent, SlackPayloadParseError> {
    if raw_payload.len() > MAX_SLACK_PAYLOAD_BYTES {
        return Err(SlackPayloadParseError::InvalidJson {
            reason: "payload exceeds size limit".into(),
        });
    }
    let url_wrapper: SlackUrlVerificationWrapper =
        serde_json::from_slice(raw_payload).map_err(|err| SlackPayloadParseError::InvalidJson {
            reason: err.to_string(),
        })?;
    if url_wrapper.event_type == "url_verification" {
        let challenge =
            url_wrapper
                .challenge
                .ok_or_else(|| SlackPayloadParseError::InvalidExternalRef {
                    kind: "slack_url_verification_challenge",
                    reason: "missing challenge".to_string(),
                })?;
        return Ok(SlackInboundEvent::UrlVerification { challenge });
    }

    let wrapper: SlackEventWrapper =
        serde_json::from_slice(raw_payload).map_err(|err| SlackPayloadParseError::InvalidJson {
            reason: err.to_string(),
        })?;
    require_well_formed_envelope(wrapper.event_id.as_deref(), &wrapper.event_type)?;
    if wrapper.event_type != "event_callback" {
        return Ok(SlackInboundEvent::Ignore {
            reason: SlackIgnoreReason::NotAnEventCallback,
        });
    }
    let Some(event) = wrapper.event.as_ref() else {
        return Ok(SlackInboundEvent::Ignore {
            reason: SlackIgnoreReason::MissingEventPayload,
        });
    };
    let team_id = wrapper.team_id.as_deref();
    let kind = if is_dm_channel(
        event.channel.as_deref().unwrap_or_default(),
        event.channel_type.as_deref(),
    ) {
        // A DM is a direct chat whichever of the two events announced it.
        // Deciding that here, rather than letting whichever event happens to
        // arrive first choose, is what keeps the collapsed pair deterministic.
        SlackMessageKind::Dm
    } else {
        match event.event_type.as_str() {
            "app_mention" => SlackMessageKind::Mention,
            "message" => {
                if mentions_bot(event.text.as_deref().unwrap_or_default(), bot_user_id) {
                    // Recognizing the mention in the text makes the two events
                    // redundant rather than making one of them load-bearing.
                    // `BotMention` is the only channel trigger that starts a
                    // run, so depending solely on `app_mention` arriving is one
                    // vendor quirk away from silence — which is exactly how a
                    // `thread_broadcast` mention went unanswered.
                    SlackMessageKind::Mention
                } else if event.thread_ts.is_some() {
                    SlackMessageKind::ThreadReply
                } else {
                    return Ok(SlackInboundEvent::Ignore {
                        reason: SlackIgnoreReason::AmbientChannelMessage,
                    });
                }
            }
            _ => {
                return Ok(SlackInboundEvent::Ignore {
                    reason: SlackIgnoreReason::UnsupportedEventType,
                });
            }
        }
    };
    normalize_user_message(installation_id, team_id, event, kind)
}

/// Slack renders a mention as `<@U…>` (or `<@U…|handle>`), so an explicit
/// mention is detectable from the message text alone, without the
/// `app_mention` event.
fn mentions_bot(text: &str, bot_user_id: Option<&str>) -> bool {
    let Some(bot) = bot_user_id.filter(|id| !id.is_empty()) else {
        return false;
    };
    text.contains(&format!("<@{bot}>")) || text.contains(&format!("<@{bot}|"))
}

/// The bot's own member id from host-resolved, manifest-declared non-secret
/// configuration. Absent only on an installation configured before the handle
/// existed; mention detection then degrades to `app_mention` alone, which is
/// the behavior that shipped before this.
pub fn slack_bot_user_id(config: &[(String, String)]) -> Option<&str> {
    config
        .iter()
        .find(|(handle, _)| handle == SLACK_BOT_USER_ID_HANDLE)
        .map(|(_, value)| value.as_str())
}

/// Parse one host-verified Slack inbound request that may be EITHER the
/// Events API's JSON envelope or a native slash-command form POST — Slack
/// registers both against the identical Request URL (one ingress route per
/// extension), distinguished only by the (host-forwarded, verification-
/// exempt) Content-Type header. The JSON branch delegates verbatim to
/// [`normalize_slack_event`] so the two entry points share exactly one JSON
/// parsing implementation; this function adds no new behavior to that path.
pub(crate) fn normalize_slack_inbound(
    raw_payload: &[u8],
    headers: &[(String, String)],
    installation_id: &AdapterInstallationId,
    bot_user_id: Option<&str>,
) -> Result<SlackInboundEvent, SlackPayloadParseError> {
    if is_form_urlencoded_content_type(headers) {
        return normalize_slack_slash_command(raw_payload, installation_id);
    }
    normalize_slack_event(raw_payload, installation_id, bot_user_id)
}

/// Case-insensitive Content-Type match for Slack's slash-command / ssl_check
/// form encoding. Absent or non-matching headers fall through to the JSON
/// path — the pre-existing default behavior.
fn is_form_urlencoded_content_type(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && value
                .to_ascii_lowercase()
                .contains("application/x-www-form-urlencoded")
    })
}

/// Parse one native Slack slash-command form POST (`ssl_check` handshake or
/// a real `/ironclaw ...` invocation) into its normalized channel form.
fn normalize_slack_slash_command(
    raw_payload: &[u8],
    installation_id: &AdapterInstallationId,
) -> Result<SlackInboundEvent, SlackPayloadParseError> {
    if raw_payload.len() > MAX_SLACK_PAYLOAD_BYTES {
        return Err(SlackPayloadParseError::InvalidForm {
            reason: "payload exceeds size limit".into(),
        });
    }

    // Slack's ssl_check verification probe carries ONLY `ssl_check` +
    // `token` — never the slash command's mandatory fields. Check for it
    // via a minimal, all-Option probe BEFORE parsing the full form (which
    // requires channel_id/user_id/command/trigger_id), or the probe would
    // always fail mandatory-field validation.
    let probe: SlackSlashCommandProbe =
        serde_urlencoded::from_bytes(raw_payload).map_err(|err| {
            SlackPayloadParseError::InvalidForm {
                reason: err.to_string(),
            }
        })?;
    if probe.ssl_check.is_some() {
        return Ok(SlackInboundEvent::SslCheck);
    }

    let form: SlackSlashCommandForm = serde_urlencoded::from_bytes(raw_payload).map_err(|err| {
        SlackPayloadParseError::InvalidForm {
            reason: err.to_string(),
        }
    })?;

    let event_id = build_slash_event_id(installation_id, &form.trigger_id)?;
    let actor = build_actor_ref(&form.user_id)?;
    let conversation =
        build_conversation_ref(form.team_id.as_deref(), &form.channel_id, None, None)?;
    let is_dm = form.channel_name.as_deref() == Some("directmessage")
        || is_dm_channel(&form.channel_id, None);
    let trigger = if is_dm {
        ProductTriggerReason::DirectChat
    } else {
        ProductTriggerReason::BotCommand
    };
    let text = slash_command_dispatch_text(&form.command, form.text.as_deref());

    Ok(SlackInboundEvent::Message(Box::new(
        ParsedSlackInboundMessage {
            message: NormalizedInboundMessage {
                actor,
                conversation,
                event_id,
                text,
                trigger,
                attachments: Vec::new(),
                conversation_context: None,
                reply_context: None,
            },
            pending_attachments: Vec::new(),
        },
    )))
}

/// Map a slash command's `command` + `text` fields to the dispatcher's
/// invocation text. `/ironclaw` is this extension's own registered command:
/// empty or `help` text becomes `/help`; otherwise the text becomes the
/// dispatched command, defensively stripped of a leading `/` first so a
/// user typing `/ironclaw /status` does not double it to `//status`. A
/// DIFFERENT registered command name (an app-config mistake pointing a
/// second slash command at this same URL) is passed through verbatim as
/// `"{command} {text}"` — the generic classifier/admission layer rejects it
/// as undeclared, with help, rather than this adapter guessing intent.
fn slash_command_dispatch_text(command: &str, text: Option<&str>) -> String {
    let text = text.unwrap_or_default().trim();
    if command != "/ironclaw" {
        return format!("{command} {text}").trim().to_string();
    }
    if text.is_empty() || text.eq_ignore_ascii_case("help") {
        return "/help".to_string();
    }
    let stripped = text.strip_prefix('/').unwrap_or(text);
    format!("/{stripped}")
}

fn build_slash_event_id(
    installation_id: &AdapterInstallationId,
    trigger_id: &str,
) -> Result<ExternalEventId, SlackPayloadParseError> {
    // Namespaced separately from the Events API's `event_callback` id space
    // (same defensive rationale as build_event_id's own `-noop-` namespace):
    // a slash invocation and an Events API callback must never collide on
    // dedup key even if some future id happened to coincide.
    ExternalEventId::new(format!(
        "slack-{}-slash-{trigger_id}",
        installation_id.as_str()
    ))
    .map_err(|err| SlackPayloadParseError::InvalidExternalRef {
        kind: "external_event_id",
        reason: err.to_string(),
    })
}

/// Fixed user-message routing strategies in this first slice.
/// `AppMention`: public channel, strip leading `@mention`, thread fallback to `ts`.
/// `Dm`: direct-message channel required, keep text verbatim, no thread fallback.
/// `ThreadReply`: channel thread reply, strip an optional leading `@mention`,
/// require `thread_ts`.
#[derive(Debug, Clone, Copy)]
enum SlackMessageKind {
    /// The bot was named explicitly — via the `app_mention` event, or via its
    /// member id in a channel message's text.
    Mention,
    Dm,
    ThreadReply,
}

fn normalize_user_message(
    installation_id: &AdapterInstallationId,
    team_id: Option<&str>,
    event: &SlackEvent,
    kind: SlackMessageKind,
) -> Result<SlackInboundEvent, SlackPayloadParseError> {
    if event.bot_id.is_some() {
        return Ok(SlackInboundEvent::Ignore {
            reason: SlackIgnoreReason::BotAuthored,
        });
    }
    if let Some(subtype) = event.subtype.as_deref()
        && NON_USER_MESSAGE_SUBTYPES.contains(&subtype)
    {
        return Ok(SlackInboundEvent::Ignore {
            reason: SlackIgnoreReason::NonUserMessageSubtype(subtype.to_string()),
        });
    }
    // A message mutation (`message_changed`, `message_deleted`) keeps its
    // author and text under a nested `message` object, so a missing top-level
    // author is the structural half of the subtype rule above, not a
    // redundant check.
    let Some(user) = event.user.as_deref() else {
        return Ok(SlackInboundEvent::Ignore {
            reason: SlackIgnoreReason::MissingField("user"),
        });
    };
    let Some(channel) = event.channel.as_deref() else {
        return Ok(SlackInboundEvent::Ignore {
            reason: SlackIgnoreReason::MissingField("channel"),
        });
    };
    // `kind` was derived from `channel_type` and `thread_ts` in
    // `normalize_slack_event`, this function's only caller, so re-checking
    // them here can only ever agree.
    let Some(ts) = event.ts.as_deref() else {
        return Ok(SlackInboundEvent::Ignore {
            reason: SlackIgnoreReason::MissingField("ts"),
        });
    };

    let event_id = build_message_event_id(installation_id, team_id, channel, ts)?;

    let raw_text = event.text.as_deref().unwrap_or_default();
    let (text, thread_ts, trigger) = match kind {
        SlackMessageKind::Mention => (
            strip_leading_bot_mention(raw_text),
            event.thread_ts.as_deref().or(Some(ts)),
            ProductTriggerReason::BotMention,
        ),
        SlackMessageKind::Dm => (
            raw_text.to_string(),
            event.thread_ts.as_deref(),
            ProductTriggerReason::DirectChat,
        ),
        SlackMessageKind::ThreadReply => (
            strip_leading_bot_mention(raw_text),
            event.thread_ts.as_deref(),
            ProductTriggerReason::ReplyToBot,
        ),
    };

    let actor = build_actor_ref(user)?;
    let conversation = build_conversation_ref(team_id, channel, thread_ts, Some(ts))?;
    let pending_attachments = collect_attachments(&event.files)?
        .into_iter()
        .map(|descriptor| ChannelAttachmentRef {
            vendor_ref: descriptor.external_file_id.clone(),
            descriptor,
        })
        .collect();
    Ok(SlackInboundEvent::Message(Box::new(
        ParsedSlackInboundMessage {
            message: NormalizedInboundMessage {
                actor,
                conversation,
                event_id,
                text,
                trigger,
                attachments: Vec::new(),
                conversation_context: None,
                reply_context: None,
            },
            pending_attachments,
        },
    )))
}

/// A signed `event_callback` without an `event_id` is malformed, and refusing
/// it stays fail-closed. The value is no longer the dedupe key — see
/// [`build_message_event_id`] — but a well-formed envelope is still required.
fn require_well_formed_envelope(
    event_id: Option<&str>,
    wrapper_event_type: &str,
) -> Result<(), SlackPayloadParseError> {
    if wrapper_event_type == "event_callback" && event_id.is_none() {
        return Err(SlackPayloadParseError::InvalidExternalRef {
            kind: "external_event_id",
            reason: "event_callback must carry event_id".to_string(),
        });
    }
    Ok(())
}

/// Identity of the MESSAGE, not of the delivery.
///
/// Slack announces one person's message as up to two events — `app_mention`
/// and the matching `message.*` — each carrying its own `event_id`. The
/// durable admission dedupe keys on [`ExternalEventId`], so keying on
/// `event_id` makes the pair look like two messages: before mention detection
/// existed only one of them could start a run, which hid this; now that either
/// can, per-delivery identity would run one mention twice. `(team, channel,
/// ts)` names the message itself, so whichever events describe it collapse to
/// one admission and the first to arrive wins.
fn build_message_event_id(
    installation_id: &AdapterInstallationId,
    team_id: Option<&str>,
    channel: &str,
    ts: &str,
) -> Result<ExternalEventId, SlackPayloadParseError> {
    ExternalEventId::new(format!(
        "slack-{}-msg-{}-{channel}-{ts}",
        installation_id.as_str(),
        team_id.unwrap_or("noteam"),
    ))
    .map_err(|err| SlackPayloadParseError::InvalidExternalRef {
        kind: "external_event_id",
        reason: err.to_string(),
    })
}

fn build_actor_ref(user: &str) -> Result<ExternalActorRef, SlackPayloadParseError> {
    ExternalActorRef::new(SLACK_USER_ACTOR_KIND, user, None::<&str>).map_err(|err| {
        SlackPayloadParseError::InvalidExternalRef {
            kind: "external_actor_ref",
            reason: err.to_string(),
        }
    })
}

fn build_conversation_ref(
    team_id: Option<&str>,
    channel: &str,
    thread_ts: Option<&str>,
    message_ts: Option<&str>,
) -> Result<ExternalConversationRef, SlackPayloadParseError> {
    ExternalConversationRef::new(team_id, channel, thread_ts, message_ts).map_err(|err| {
        SlackPayloadParseError::InvalidExternalRef {
            kind: "external_conversation_ref",
            reason: err.to_string(),
        }
    })
}

fn collect_attachments(
    files: &Option<Vec<SlackFile>>,
) -> Result<Vec<ProductAttachmentDescriptor>, SlackPayloadParseError> {
    files
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|file| {
            let mime_type = file
                .mimetype
                .as_deref()
                .unwrap_or("application/octet-stream")
                .to_ascii_lowercase();
            ProductAttachmentDescriptor::new(
                file.id.clone(),
                mime_type.clone(),
                file.name.clone(),
                file.size,
                attachment_kind_for_mime(&mime_type),
            )
            .map_err(|err| SlackPayloadParseError::InvalidExternalRef {
                kind: "attachment_descriptor",
                reason: err.to_string(),
            })
        })
        .collect()
}

fn attachment_kind_for_mime(mime_type: &str) -> ProductAttachmentKind {
    match mime_type.split('/').next().unwrap_or_default() {
        "image" => ProductAttachmentKind::Image,
        "audio" => ProductAttachmentKind::Audio,
        "video" => ProductAttachmentKind::Video,
        _ => ProductAttachmentKind::Document,
    }
}

fn strip_leading_bot_mention(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.starts_with("<@")
        && let Some(end) = trimmed.find('>')
    {
        return trimmed[end + 1..].trim_start().to_string();
    }
    trimmed.to_string()
}

fn is_dm_channel(channel: &str, channel_type: Option<&str>) -> bool {
    match channel_type {
        Some("im") => true,
        Some(_) => false,
        None => channel.starts_with('D'),
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SlackUrlVerificationWrapper {
    #[serde(rename = "type")]
    event_type: String,
    challenge: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SlackEventWrapper {
    #[serde(rename = "type")]
    event_type: String,
    event: Option<SlackEvent>,
    team_id: Option<String>,
    event_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SlackEvent {
    #[serde(rename = "type")]
    event_type: String,
    user: Option<String>,
    channel: Option<String>,
    text: Option<String>,
    thread_ts: Option<String>,
    ts: Option<String>,
    bot_id: Option<String>,
    subtype: Option<String>,
    channel_type: Option<String>,
    #[serde(default)]
    files: Option<Vec<SlackFile>>,
}

#[derive(Debug, Clone, Deserialize)]
struct SlackFile {
    id: String,
    mimetype: Option<String>,
    name: Option<String>,
    size: Option<u64>,
}

/// Minimal probe for Slack's `ssl_check` endpoint-verification POST, which
/// carries only `ssl_check` + `token` — never a slash command's mandatory
/// fields. Parsed before [`SlackSlashCommandForm`] so the probe never trips
/// that struct's required-field validation.
#[derive(Debug, Clone, Deserialize)]
struct SlackSlashCommandProbe {
    ssl_check: Option<String>,
}

/// One native Slack slash-command form POST
/// (`application/x-www-form-urlencoded`). Liberal on purpose — Slack adds
/// fields across API versions and this is a public untrusted-ingress
/// boundary — so only the fields the dispatcher mapping cannot proceed
/// without are mandatory; everything else is `Option`. There is no
/// `deny_unknown_fields`, so fields this crate does not yet consume
/// (`response_url` — future out-of-DM delivery; `ssl_check` — already
/// resolved by [`SlackSlashCommandProbe`] before this struct is parsed;
/// `token` — Slack's legacy verification field, superseded here by HMAC
/// signing) arrive and are silently dropped rather than declared dead.
#[derive(Debug, Clone, Deserialize)]
struct SlackSlashCommandForm {
    channel_id: String,
    user_id: String,
    command: String,
    trigger_id: String,
    text: Option<String>,
    channel_name: Option<String>,
    team_id: Option<String>,
}

#[cfg(test)]
#[path = "tests/payload_normalized.rs"]
mod tests;
