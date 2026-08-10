# Unified channel model — target architecture

**Status:** Target design (approved direction, 2026-08-10). Not yet built.
**Audience:** Any agent touching channel inbound, outbound/reply, notifications,
or the web-app/web-push surface. **Read this first** — the code is mid-migration
toward it and the old shape (below) is a known smell being removed, not a
pattern to copy.

Owning families: `crates/extensions/` (adapters + host), `crates/contracts/ironclaw_extension_contracts`
(the `ChannelAdapter` + descriptor vocabulary), `crates/product/` (the shared
inbound/reply core). Cross-ref: `docs/reborn/target-architecture/families/extensions.md`,
`.claude/rules/gateway-events.md`, `.claude/rules/safety-and-sandbox.md`.

---

## 1. The one-sentence goal

**Every channel — web-app, Slack, Telegram — is a `ChannelAdapter` that implements
inbound, outbound/reply, and notifications the same way. The only thing that
varies per channel is (a) the *entrypoint* it declares (how a request arrives)
and (b) the *delivery capabilities* it declares (streaming vs batched, max
message size, markdown, …). Everything between the entrypoint and delivery is
one abstract, channel-agnostic core.**

The core never knows whether it is talking to a browser or Slack. Channels never
reimplement binding, idempotency, turn submission, or notification routing —
they implement only their own protocol (parse bytes in, render/deliver bytes
out).

## 2. Why (the smell being removed)

Today there are **two** post-ingress cores in `ironclaw_assistant`, plus a split
reply model:

- **Webhook channels** (Slack/Telegram) enter `ChannelInboundProductSurface::admit_channel_inbound`
  (`crates/contracts/ironclaw_product_contracts/src/surface.rs:76`) →
  `DefaultProductSurface::submit_inbound_inner` (`crates/product/ironclaw_assistant/src/workflow.rs:344`):
  resolve-or-create binding from an external ref, durable `IdempotencyLedger`,
  T2 verified-inbound evidence.
- **Browser + OpenAI-compat** enter `ProductSurface::invoke(SUBMIT_TURN_COMMAND)`
  → `RebornServices::submit_turn` (`crates/product/ironclaw_assistant/src/reborn_services.rs:3693`):
  bind an existing caller-owned thread, thread-service idempotency, T1 session
  caller.

Both do the *same* three steps — **idempotency → bind → `TurnCoordinator::submit_turn`**
(`crates/kernel/ironclaw_turns/src/coordinator.rs:130`) — against different
ports. That is a parallel pipeline: a change to binding/idempotency/admission
must land in two places and one always lags
(`.claude/rules/architecture.md` §4). Replies are split the same way: Slack/
Telegram replies go through the `DeliveryCoordinator`/outbound path (batched
final send), while the web-app streams through the durable-event → projection →
`EventStreamManager` pipeline (`.claude/rules/gateway-events.md`). The web-app
is special-cased on **both** the inbound and the reply side. It should just be a
channel.

## 3. The `ChannelAdapter` — one contract, three responsibilities

`ChannelAdapter` (`crates/contracts/ironclaw_extension_contracts/src/channel_adapter.rs`)
is the *only* channel-specific code. Every channel (web-app included) implements
it. Its three responsibilities:

1. **Inbound** — parse the raw protocol payload into a `NormalizedInboundMessage`.
   Pure, panic-isolated, no host authority (it cannot forge trust — see §6).
2. **Outbound / reply** — consume the core's abstract reply-event stream and
   deliver it per the channel's declared reply mode (§5).
3. **Notifications** — deliver a blocked-automation notice (approval/auth gate,
   run-failure) through the channel, gated on the `notifications` capability
   (PR1). Same adapter, same egress.

Auth has **no** adapter (the manifest recipe engine runs it); only channels get
an adapter. The host runs verification, credential injection, binding,
idempotency, and turn submission generically — the adapter only ever sees
already-verified inbound and already-authorized egress.

## 4. Entrypoints are declared, thin, and pluggable

An entrypoint is *how a request arrives*. It is declared by the channel's
`[channel.ingress]` and does exactly two jobs, then hands off to the one core:
**establish the trust class** and **normalize** (via `adapter.inbound`).

Entrypoint kinds, expressed by `IngressVerificationRecipe`
(`crates/contracts/ironclaw_extension_contracts/src/recipe.rs`):

| Entrypoint | Recipe kind | Trust class | Mount |
| --- | --- | --- | --- |
| Webhook | `hmac_sha256` / `shared_secret_header` / `none` | T2 verified-inbound (host verifies signature) | `/webhooks/extensions/{id}/{route_suffix}` |
| Authenticated session (POST + bearer) | `authenticated_session` | T1 (host transport already verified the session) | no webhook route — the host transport is the door |
| API key | `authenticated_session` (API-key projection of the caller) | T1 | host transport |

The `route_suffix` is present only for webhook entrypoints and **forbidden** for
`authenticated_session` (a session channel mounts no webhook route). This pairing
is already enforced fail-closed in `ChannelDescriptor::validate`
(`crates/contracts/ironclaw_extension_contracts/src/channel.rs`) and the webhook
verifier rejects a session recipe. **A browser request can never reach the
webhook mount** — structurally, not by convention.

## 5. The abstract core (inbound) and the reply model (outbound)

### Inbound core (channel-agnostic)
After the entrypoint establishes `(trust class, normalized message, binding
inputs)`, one core runs for every channel:

```
  normalized message + trust class + binding inputs
    → idempotency        (durable ledger, one mechanism for all channels)
    → bind               (enum: OwnedThread{thread_id}   — session owns its thread
                                | ExternalRef{...}         — webhook resolves-or-creates)
    → TurnCoordinator::submit_turn
```

`bind` is the one place the channels legitimately differ, expressed as an enum,
not two implementations: a session channel binds a thread the caller already
owns; a webhook resolve-or-creates from an external conversation ref. Trust is
likewise an enum arm (`SessionCaller` (T1) | `VerifiedInbound` (T2 + installation
tenant + external-actor pairing)). **The webhook trust/pairing machinery must
never run for a session channel and vice versa** — the enum gates it; the
plumbing below `submit_turn` is shared unchanged.

### Reply model (symmetric — abstract events, channel-declared delivery)
Turn execution emits **abstract reply events** — `thinking`, partial/token,
tool-activity, `final`. These are **durable** (written through the event log →
projections, per `.claude/rules/gateway-events.md`); durability, replay, and
reconnect are preserved. The channel declares a **reply mode**, and the adapter's
**reply sink** consumes the (live + replayed) event stream per that mode:

| Channel | Reply mode | Adapter reply sink behavior |
| --- | --- | --- |
| web-app | `streaming` | forward the live/replayed event stream to the frontend (the existing SSE/WebSocket path becomes this sink) |
| Slack | `batched` | on first event, post a generic "IronClaw is thinking…"; on `final`, send the reply, split to `max_message_chars`; a duplicate says "your request is processing" |
| Telegram | `batched` | same shape, Telegram rendering + its own `max_message_chars` |

**Load-bearing layering rule:** the reply sink sits *on top of* the durable
event/projection pipeline — it is a **consumer** of durable reply events, not a
replacement. The core always writes durable events; the sink chooses how to
surface them. This is what keeps the web-app's replay/reconnect guarantees while
unifying delivery with Slack/Telegram's batched send. The `DeliveryCoordinator`
becomes the batched reply sink's delivery mechanism, not a separate reply path.

## 6. Channel-declared capabilities (the manifest surface)

A channel declares its behavior; the core reads it and adapts. All optional
except where noted:

- **`inbound` / `outbound` / `notifications`** (bool) — which responsibilities
  this channel fulfils. (`notifications` is PR1's capability.)
- **`ingress`** — the entrypoint (recipe kind + optional `route_suffix`, §4).
  Required iff `inbound`.
- **`egress`** — declared vendor hosts + host-side credential injection for
  outbound/notification delivery (never in the adapter).
- **reply mode** — `streaming` | `batched` (new). Drives the reply sink.
- **`max_message_chars`** — **optional** (evolve `ChannelPresentation.max_message_chars`
  from required-with-default to optional). **Undeclared = unlimited → never
  batch/split** (web-app). Declared (Slack ~1000, Telegram ~2000) → the batched
  reply sink splits long replies to fit. Streaming mode ignores it (or uses it
  only as a chunking hint).
- **`supports_markdown` / `supports_threads`** — existing presentation flags the
  renderer honors.
- **`conversation_model`** — `continuous` (protocol supplies conversation
  identity) | `isolated` (client creates/switches). For `authenticated_session`
  the browser owns native threads (`OwnedThread` binding), so this field is inert
  on that path but still declared.

## 7. Trust and security invariants (non-negotiable)

- **Trust is established at the entrypoint, once, and carried as a typed class.**
  Adapters never mint trust — verified-inbound evidence is sealed
  (`reborn_sealed_evidence_mint_ratchet.rs`); session evidence is minted only by
  the host transport (`ironclaw_webui` auth middleware).
- **A session channel has no webhook mount** (validation + verifier fail-closed).
  Browser traffic never traverses the T2 webhook path.
- **Tenant/actor come from trusted config, never the payload** — webhook tenant
  from installation config + external-actor pairing; session tenant/actor from
  the authenticated caller.
- **Durable-first replies** — reply events are durable before delivery; the reply
  sink never invents un-replayable state (`.claude/rules/gateway-events.md`).
- **Egress credentials are host-injected at the chokepoint**, never seen by the
  adapter (`.claude/rules/safety-and-sandbox.md`).

## 8. What is NOT a channel concern (stays on `ProductSurface`)

The web-app is *also* a rich client: thread list/management, settings, gate
resolution, file browsing, extension management, projections. Those are
`ProductSurface` query/command operations and stay there — Slack/Telegram do not
have them. **Only the message-in / reply-out path of the web-app becomes the
unified channel model.** Slack/Telegram are channel-only.

## 9. The web-app extension (concrete)

One extension, one channel (today's `web-push` package, evolved in place; the
string rename `web-push` → `web-app` across ids/crates/routes/frontend is pure
churn, deferred as a separate follow-up). Its single channel:

```toml
id = "web-push"                 # rename to "web-app" deferred
name = "Web app"

[channel]
id = "web-app"
display_name = "Web app"
inbound = true                  # browser chat (session entrypoint)
outbound = true                 # replies (streaming) + push
notifications = true            # blocked-automation notices
conversation_model = "isolated" # browser owns native threads
reply_mode = "streaming"        # NEW — the reply sink streams to the frontend
# max_message_chars: UNDECLARED → unlimited, never batch

[channel.ingress]               # NEW — session entrypoint, no webhook, no route
method = "post"
[channel.ingress.verification]
kind = "authenticated_session"

[[channel.egress]]              # UNCHANGED — outbound push (VAPID, host-signed)
host = "fcm.googleapis.com"     # (+ mozilla, apple)
injection = { type = "vapid_authorization" }
```

Slack/Telegram manifests gain `reply_mode = "batched"` and their existing
`max_message_chars` becomes the (declared) split bound.

## 10. Migration from today (concrete deltas)

1. **Generalize the inbound entry DTO** (`ChannelInboundSurfaceRequest` /
   `ProductInboundEnvelope`): `evidence` becomes a trust-class enum
   (`VerifiedInbound` | `SessionCaller`); binding inputs become an enum
   (`ExternalRef` | `OwnedThread`). (`workflow.rs:282` `build_channel_envelope`,
   `conversation_binding.rs:430` `resolve_binding`.)
2. **Route browser + OpenAI-compat through the one core**: re-plumb
   `RebornServices::submit_turn` (`reborn_services.rs:3693`) to build the neutral
   request and call `admit_channel_inbound` / `submit_inbound_inner`
   (`workflow.rs:344`). Collapse the two idempotency mechanisms onto the durable
   ledger (browser `client_action_id` → `ActionFingerprintKey` with the existing
   `webui_source_binding_id`).
3. **Delete the duplicate tail**: `RebornServices::submit_turn`'s bespoke
   binding/idempotency/submit body and its `runs`-owner helpers
   (`AcceptedWebUiMessage`, `mark_message_submitted_or_replay`,
   `replay_webui_send_message`, …). `SUBMIT_TURN_COMMAND` (the command constant)
   stays; only its implementation re-routes. **No HTTP route is removed.**
4. **Give the web-app a `ChannelAdapter`**: inbound normalization for the browser
   POST; a `streaming` reply sink that *is* the current SSE/projection forward;
   the existing web-push egress for outbound push + notifications.
5. **Unify the reply side**: introduce the reply-mode + reply-sink abstraction;
   the web-app sink = streaming (existing SSE), Slack/Telegram sink = batched
   (via `DeliveryCoordinator`, split by `max_message_chars`, with a thinking
   indicator). Reply events stay durable.
6. **Make `max_message_chars` optional** and load-bearing for the batched sink.

Order: (1)+(2)+(3) is the inbound unification (highest-traffic path — drive
test-first against the existing `send_message`/inbound contract tests, preserve
caller-owns-thread + `client_action_id` replay + no thread auto-creation).
(4)+(5)+(6) is the reply/outbound unification.

## 11. Non-goals / open questions

- **String rename** `web-push` → `web-app` (ids, `ironclaw_web_push*` crates,
  `/web-push/*` routes, frontend `WEB_PUSH_*`): deferred, pure churn, its own PR.
- **`/web-push/{subscribe,unsubscribe,status}` enrollment routes**: device
  subscription management, a separate concern from inbound conversation — they
  stay unless a later decision folds them into a generic extension-config flow.
- **Reply-mode taxonomy**: `streaming | batched` is the initial set; a channel
  that wants thinking-indicator-but-batched, or edit-in-place, is expressed as
  additional declared reply capabilities, not new pipelines.
- **Exact reply-event vocabulary** the sink consumes (thinking/partial/tool/
  final): to be pinned against the existing `WebChatV2EventFrame` projection so
  the streaming sink is a no-behavior-change wrapper on day one.
