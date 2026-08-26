//! Scenario 5: a model call to a bundled extension capability whose extension
//! is NOT installed is rejected fail-closed at the model gateway
//! (the capability has no registry descriptor, so it is never advertised nor
//! resolvable) — the call never reaches the capability port and the run
//! recovers via a model retry instead of wedging. After a real
//! `extension_install` on a sibling thread over the
//! SAME shared runtime, the identical call on the SAME conversation
//! dispatches. Grants alone must never make an unpublished extension
//! capability callable; only install-time registry publication may.
//!
//! Uses "gmail" (untouched by scenarios 1-4). Install's credential gate
//! and turn 2's dispatch-time staging pass via the google account this
//! scenario seeds under the capability dispatch scope.
//!
//! Turn 2 also carries the WS12 row-5 leg-3 JOIN (security audit F3): the
//! dispatched `gmail.list_messages` must put the seeded google access token on
//! the outbound wire — production dispatch → first-party gsuite handler →
//! staged credential obligation → host egress chokepoint
//! (`apply_credential_injection`) → recorded network transport — through the
//! gmail manifest's declared recipe
//! (`injection = { type = "header", name = "authorization", prefix = "Bearer " }`
//! toward `gmail.googleapis.com`). Before this assertion the two halves were
//! each tested but never joined: handler→staging at crate tier, and
//! staging→wire only for GitHub/Slack.
//!
//! Runs on its OWN freshly built group with a Google OAuth backend
//! configured, rather than the shared `g` every other scenario in this
//! binary runs on: `g` is deliberately built WITHOUT a Google OAuth backend so
//! Scenario 4.5's readiness-map chokepoint has something to fire on, and
//! that chokepoint gates the "google" PROVIDER build-time-wide — not just
//! the specific package — so a "gmail" install on `g` would now hit the
//! same early-fail Scenario 4.5 pins, never reaching the seeded credential
//! account this scenario actually wants to exercise. This scenario shares no
//! cross-thread state with `g` (its own doc always called out "gmail,
//! untouched by scenarios 1-4"), so an isolated
//! `extension_lifecycle_google_oauth_configured()` group — the same
//! constructor Scenario 4.5's Phase 2 uses — is the honest fix rather than a
//! readiness-map carve-out.

use super::reborn_support::group::{HarnessResult, RebornIntegrationGroup};
use super::reborn_support::reply::RebornScriptedReply;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ironclaw_auth::{
    GOOGLE_GMAIL_MODIFY_SCOPE, GOOGLE_GMAIL_READONLY_SCOPE, GOOGLE_GMAIL_SEND_SCOPE,
};
use serde_json::json;

pub async fn run() -> HarnessResult<()> {
    let g = RebornIntegrationGroup::extension_lifecycle_google_oauth_configured().await?;
    let g = &g;
    // One conversation, two turns. Turn 1's rejected tool call consumes script
    // entry 1; the recovery retry consumes entry 2 as the reply. Turn 2's
    // dispatched call consumes entries 3+4 normally.
    let caller = g
        .thread("ext-uninstalled-gmail-caller")
        .script([
            RebornScriptedReply::tool_call("gmail.list_messages", json!({})),
            RebornScriptedReply::text("gmail unavailable"),
            RebornScriptedReply::tool_call("gmail.list_messages", json!({})),
            RebornScriptedReply::text("gmail dispatched"),
            RebornScriptedReply::tool_call(
                "gmail.get_message",
                json!({"message_id": "msg-semantic-preview"}),
            ),
            RebornScriptedReply::text("gmail message read"),
        ])
        .build()
        .await?;

    // ── Turn 1: gmail not installed → gateway rejects the call, run recovers ─
    caller.submit_turn("check my mail").await?;
    if caller
        .assert_tool_invoked("gmail.list_messages")
        .await
        .is_ok()
    {
        return Err("uninstalled extension capability must never reach the capability port".into());
    }
    // The reply is script entry 2 — proof the rejection triggered a recovery
    // model retry (a second model call in the same turn) rather than wedging
    // the run or silently dispatching entry 1's call.
    caller.assert_reply_contains("gmail unavailable").await?;

    // ── Sibling thread: real lifecycle verbs over the SAME shared runtime ───
    let lifecycle = g
        .thread("ext-uninstalled-gmail-lifecycle")
        .script([
            RebornScriptedReply::tool_call(
                "builtin.extension_install",
                json!({"extension_id": "gmail"}),
            ),
            RebornScriptedReply::text("gmail ready"),
        ])
        .build()
        .await?;
    // gmail's install credential gate and turn 2's dispatch-time credential
    // staging both select a google account under the CAPABILITY dispatch scope
    // — seed one with real material through the production manual-token flow.
    lifecycle
        .seed_capability_credential_account(
            "google",
            "itest google",
            &[
                GOOGLE_GMAIL_MODIFY_SCOPE,
                GOOGLE_GMAIL_READONLY_SCOPE,
                GOOGLE_GMAIL_SEND_SCOPE,
            ],
        )
        .await?;
    lifecycle.submit_turn("install gmail").await?;
    lifecycle
        .assert_tool_result_contains("\"installed\":true")
        .await?;
    lifecycle
        .assert_tool_result_contains("\"phase\":\"active\"")
        .await?;
    lifecycle
        .assert_model_message_content_contains(r#"\"installed\":true"#)
        .await?;
    lifecycle
        .assert_model_message_content_contains(r#"\"phase\":\"active\""#)
        .await?;

    // ── Turn 2 (same conversation): the identical call now dispatches ───────
    caller.submit_turn("check my mail again").await?;
    caller.assert_tool_invoked("gmail.list_messages").await?;
    caller.assert_reply_contains("gmail dispatched").await?;

    // The JOIN (WS12 row 5 leg 3, audit F3): the seeded google credential
    // must land on the dispatched call's outbound HTTPS request, injected at
    // the host egress chokepoint per the gmail manifest's declared recipe —
    // header `authorization`, prefix `Bearer `, audience
    // `gmail.googleapis.com`. The exact value is pinned:
    // `seed_capability_credential_account` stores `itest-google-token`, so a
    // pass proves the STORED material traversed store → dispatch-time staging
    // → `apply_credential_injection` → wire, not merely that some
    // bearer-shaped header existed.
    caller
        .assert_network_egress_header_contains(
            "gmail.googleapis.com",
            "authorization",
            "Bearer itest-google-token",
        )
        .await?;

    // Drive the semantic producer through the same installed extension,
    // first-party runtime adapter, obligations, loop capability port, and
    // durable staged-I/O writer used in production. The model sees selected
    // readable content while the canonical stored result retains the complete
    // provider response.
    let readable_body = format!(
        "Production chain semantic preview. 😀\n{}",
        "plain-body-line ".repeat(900)
    );
    let encoded_plain_body = URL_SAFE_NO_PAD.encode(readable_body.as_bytes());
    let html_marker = "HTML-ONLY-CONTENT";
    let encoded_html_body =
        URL_SAFE_NO_PAD.encode(format!("<html><body>{html_marker}</body></html>").as_bytes());
    let encoded_attachment = URL_SAFE_NO_PAD.encode(b"attachment-transport-bytes");
    let provider_message = json!({
        "id": "msg-semantic-preview",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "From", "value": "Ada <ada@example.com>"},
                {"name": "To", "value": "Grace <grace@example.com>"},
                {"name": "Subject", "value": "Production preview"},
                {"name": "Date", "value": "Tue, 25 Aug 2026 12:34:56 +0000"},
                {"name": "X-Transport-Debug", "value": "transport-only-metadata"}
            ],
            "parts": [
                {
                    "mimeType": "text/html",
                    "body": {"data": encoded_html_body}
                },
                {
                    "mimeType": "multipart/alternative",
                    "parts": [
                        {
                            "mimeType": "text/plain",
                            "body": {"data": encoded_plain_body}
                        },
                        {
                            "mimeType": "text/calendar",
                            "body": {"data": URL_SAFE_NO_PAD.encode(b"calendar-transport-part")}
                        }
                    ]
                },
                {
                    "mimeType": "application/octet-stream",
                    "filename": "transport.bin",
                    "body": {"data": encoded_attachment}
                }
            ]
        }
    });
    g.install_network_response_script(200, serde_json::to_vec(&provider_message)?)?;

    caller.submit_turn("read the message").await?;
    caller.assert_tool_invoked("gmail.get_message").await?;
    let envelopes = caller.persisted_tool_result_envelopes().await?;
    let observation = envelopes
        .last()
        .and_then(|envelope| envelope.model_observation.as_ref())
        .ok_or("Gmail result did not persist a model observation")?;
    let preview = observation["detail"]["preview"]
        .as_str()
        .ok_or_else(|| format!("Gmail result persisted no preview: {observation}"))?;
    if preview.len() > 4 * 1024 {
        return Err(format!(
            "Gmail semantic preview exceeded the automatic 4KiB budget: {} bytes",
            preview.len()
        )
        .into());
    }
    let preview: serde_json::Value = serde_json::from_str(preview)?;
    let preview_headers = preview
        .get("headers")
        .and_then(serde_json::Value::as_object)
        .ok_or("Gmail semantic preview omitted parsed headers")?;
    for (name, expected) in [
        ("from", "Ada <ada@example.com>"),
        ("to", "Grace <grace@example.com>"),
        ("subject", "Production preview"),
        ("date", "Tue, 25 Aug 2026 12:34:56 +0000"),
    ] {
        if preview_headers
            .get(name)
            .and_then(serde_json::Value::as_str)
            != Some(expected)
        {
            return Err(format!(
                "Gmail semantic preview header {name:?} was not preserved: {preview}"
            )
            .into());
        }
    }
    let preview_body = preview
        .get("body")
        .and_then(serde_json::Value::as_str)
        .ok_or("Gmail semantic preview omitted the decoded plain-text body")?;
    if !preview_body.starts_with("Production chain semantic preview. 😀\nplain-body-line ")
        || preview_body.len() >= readable_body.len()
        || preview["body_truncated"] != json!(true)
    {
        return Err(format!(
            "Gmail semantic preview did not carry a decoded, truncated body: {preview}"
        )
        .into());
    }
    let preview_text = preview.to_string();
    for forbidden in [
        html_marker,
        "transport-only-metadata",
        "calendar-transport-part",
        "attachment-transport-bytes",
        encoded_plain_body.as_str(),
        encoded_html_body.as_str(),
        encoded_attachment.as_str(),
    ] {
        if preview_text.contains(forbidden) {
            return Err(format!(
                "Gmail semantic preview leaked forbidden transport content {forbidden:?}"
            )
            .into());
        }
    }
    caller
        .assert_model_message_content_contains("Ada <ada@example.com>")
        .await?;
    if caller
        .assert_model_message_content_contains("transport-only-metadata")
        .await
        .is_ok()
    {
        return Err("transport-only Gmail fields leaked into the semantic preview".into());
    }
    let envelope = envelopes
        .last()
        .ok_or("Gmail result did not persist a tool-result envelope")?;
    let expected_output = caller.tool_result_output("gmail.get_message").await?;
    if expected_output["body"] != provider_message {
        return Err("normalized Gmail output did not retain the complete provider response".into());
    }
    let expected_bytes = serde_json::to_vec(&expected_output)?;
    if expected_bytes.len() <= 512 {
        return Err("Gmail fixture must exceed one durable record page".into());
    }
    let durable_bytes = caller
        .read_durable_tool_result_record_pages(&envelope.result_ref, 512)
        .await?;
    if durable_bytes != expected_bytes {
        return Err(format!(
            "durable Gmail result bytes differed from the complete provider output: \
             expected {} bytes, read {} bytes",
            expected_bytes.len(),
            durable_bytes.len()
        )
        .into());
    }
    Ok(())
}
