# Generic progressive channel previews

**Status:** Implemented on `codex/slack-ai-streaming`.

## Decision

Streaming is a disposable preview, not a delivery mode.

```text
preview start
  -> best-effort cumulative updates
  -> preview stop or native expiry
  -> ordinary complete final message
```

The ordinary `OutboundPart::Text` final-reply path remains the only
authoritative delivery. Preview failure never changes final delivery, creates
recovery logic, or requires durable stream state.

## Generic contract

Channels opt in through typed manifest presentation metadata:

```toml
[channel.presentation.progressive_preview]
scope = "all" # or "direct_only"
max_chars = 12000
```

The coordinator exposes three channel-neutral operations:

```rust
enum ProgressivePreviewPart {
    Start,
    Update {
        vendor_message_ref: String,
        accepted_text: String,
        current_text: String,
    },
    Stop {
        vendor_message_ref: String,
    },
}
```

Updates carry cumulative text plus the last accepted text. This keeps delta
calculation and vendor mechanics inside the adapter without introducing a
generic append ledger. A channel that cannot safely derive an update rejects
it; the generic forwarder then stops sending previews for that run.

## Policy and lifecycle

- `Start` is a source-routed working-notice operation. If it fails, the
  existing plain `Ironclaw is thinking...` indicator is used.
- `Update` uses the normal outbound-policy pipeline as a `ProgressUpdate`.
  Preview text is model output and receives the same target revalidation as
  other policy-class run notifications.
- Updates are coalesced to at most one attempt per second.
- A changed prefix, provider rejection, policy rejection, or character-limit
  breach disables further preview updates. There is no retry.
- `Stop` is best-effort cleanup. It runs before a final reply or gate prompt,
  and on timeout/error exits through the observer safety net.
- The finalized assistant message is always posted afterward through the
  existing final-reply path, even if cleanup fails.

## Slack implementation

- `Start` maps to `chat.startStream`.
- `Update` verifies `current_text.starts_with(accepted_text)` and sends only
  the suffix through `chat.appendStream`.
- `Stop` calls `chat.stopStream` with non-answer placeholder text, then
  `chat.delete`.
- Slack declares `scope = "all"` and `max_chars = 12000`.

## Telegram implementation

- `Start` maps to `sendMessageDraft` with an empty text, which renders
  Telegram's native thinking state.
- The adapter derives a stable nonzero `draft_id` from the delivery attempt and
  returns it as the vendor message reference.
- `Update` validates the accepted prefix and sends cumulative plain text with
  the same `draft_id` through `sendMessageDraft`.
- Telegram has no explicit draft-stop method. `Stop` validates the reference
  without vendor I/O; the normal final message clears the draft, and Telegram
  expires abandoned drafts after 30 seconds.
- Telegram declares `scope = "direct_only"` and `max_chars = 4096`. Groups
  retain the ordinary working indicator rather than emulating streaming with
  durable message edits.

## Verification

Coverage pins:

- manifest parsing, optionality, scope, and positive character limit;
- Slack start routing and recipient/thread requirements;
- cumulative update suffix calculation and prefix mismatch rejection;
- stop followed by delete;
- complete final post after preview success, update failure, or cleanup
  failure;
- preview cleanup on blocked, failed, and timeout paths;
- plain-indicator fallback when preview start fails;
- Telegram native draft start/update behavior, stable draft identity,
  private-chat enforcement, native expiry cleanup, and durable final delivery.
