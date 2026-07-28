# Agent Activity & Streaming — webui_v2 Design Brief

**Workstream:** `design/agent-activity-streaming` (split out from `design/oobe-chat-automations`).
**Status:** design complete, implementation not started.
**Interactive mockup (Artifact):** https://claude.ai/code/artifact/92974a1f-d2b7-46d9-8927-bc882adcc495

> File/symbol references below are a point-in-time trace (2026-07-28). Verify against
> live code before relying on them — prefer the codebase knowledge graph / `openwiki/`.

## Goal

Bring the webui_v2 chat's agent-activity + streaming experience up to (and past) Claude
Desktop **Cowork**: replace raw `Activity — N tools` + JSON disclosures with **narrated
activity**, a **live verb + elapsed** status, and a persistent **Plan / Context** rail —
then extend with **IronClaw-native** surfaces Cowork has no equivalent for.

The insight from the audit: webui_v2 already ships richer *per-component* pieces than
Cowork. The gap is **composition + a few small backend payloads**, not a rebuild.

## Where this lives

SPA: `crates/ironclaw_webui/frontend/src` (React 19 + Tailwind v4; tokens in
`styles/app.css`). Backend edge: `crates/ironclaw_webui/src/webui_v2/{schema.rs,handlers.rs}`.
Producer/mapping: `crates/ironclaw_reborn_composition/src/projection/live_progress.rs`.

Chat stream components (`pages/chat/`): `chat.tsx`, `components/message-list.tsx`,
`message-bubble.tsx` (incl. `ThinkingDisclosure`), `tool-activity.tsx`, `activity-run.tsx`,
`typing-indicator.tsx`, `plan-card.tsx`, `approval-card.tsx`, `auth-oauth-card.tsx` /
`auth-token-card.tsx` / `auth-generic-card.tsx`, `onboarding-pairing-card.tsx`.
SSE consume: `hooks/useSSE.ts`, `lib/useChatEvents.ts`, `lib/history-messages.ts`,
`lib/tool-activity-state.ts`, `lib/gates.ts`.
Live component harness (real components + mock data): `pages/design-preview/design-preview-page.tsx`.
Right-rail precedent (none in chat yet): `pages/projects/components/project-inspector-rail.tsx`.

**Event pipeline (5 layers):**
`LoopHostMilestoneKind` (`ironclaw_turns`) → `LiveProgressMilestoneSink`
(`ironclaw_reborn_composition`) → `ThreadLiveProjectionItem` (`ironclaw_event_streams`) →
`ProductProjectionItem` (`ironclaw_product_adapters`) → `WebChatV2Event` (`ironclaw_webui`)
→ `useSSE.ts` → `useChatEvents.ts`.

## Design principles

- **Narrate, don't dump.** Lead each step with a plain-English line; keep raw tool name +
  params one disclosure away.
- **Live status = verb + elapsed** (animated glyph). Verb is derivable from
  `ProgressUpdateView.kind` (Typing/ToolRunning/Reflecting) + `WorkSummary` phase.
- **Task telemetry rail:** a persistent Plan (pending/active/done) + Context (tools & files
  touched). No right-rail exists in chat today.
- **Respect the near-static motion policy.** Only `v2-typing-bounce`, `v2-spin`, `v2-breathe`
  are whitelisted in `styles/app.css`; everything else is `animation:none`. Match that restraint.
- **Both themes** off the real `--v2-*` tokens (light is the default).

## Ledger — shipped vs. needs-a-payload

**Already in the webui_v2 stream (bind today):**
- Thinking narration — `ProductProjectionItem::Thinking` (`ModelReasoningDelta`).
- Grouped tool run w/ expandable params — `WebChatV2Event::CapabilityActivity`
  (`CapabilityActivityView`) + `CapabilityDisplayPreview`; rendered by `activity-run.tsx`.
- **Safety-approval gate** — `WebChatV2Event::Gate` / `ProductProjectionItem::Gate` +
  `approval-card.tsx`. *Cowork has no equivalent — IronClaw already leads here.*
- Connector / auth card — `WebChatV2Event::AuthRequired` (`AuthPromptView`, challenge kinds
  `oauth_url` / `manual_token` / `pairing`). Honors `credential_name` vs `extension_name`
  (wire carries `provider` + `connection.channel`, never a raw `CredentialName`).
- Text streaming / final — `ModelTextDelta` → `Text` / `final_reply`.
- Run status — `ProductProjectionItem::RunStatus`; skill activation — `SkillActivation`.

**Needs a new payload (the buildable core):**
1. **Per-tool duration.** UI already renders `{toolDurationMs}ms` but `toolCardFromActivity` /
   `toolCardFromPreview` hardcode `toolDurationMs: null`. Add `started_at`/`completed_at` (or
   `duration_ms`) to `CapabilityActivityView` and the `CapabilityCompleted` milestone. *Smallest — do first.*
2. **Live Plan / todo tracker.** No plan/todo event exists anywhere. `plan-card.tsx` is fed by
   `useAutomationTasks` → `lib/automation-tasks-api.ts`, an explicit client-side **mock**. Add a
   projection item (e.g. `PlanUpdate { steps: [{id,title,status}] }`) + a producing milestone,
   and surface it as the right-rail tracker.
3. **Elapsed timer.** Only point timestamps stream (`updated_at`/`generated_at`). Emit a run/step
   start timestamp; UI computes elapsed.
4. **Background-job progress on the turn stream.** Jobs are REST-polled today
   (`ProcessStatus { Running, Completed, Failed, Killed }` — no `Pending`/`InProgress`); not on
   chat SSE. Bridge job status into the projection (or enrich the enum) to show inline job chips.

Plus **multi-channel handoff** (Telegram/Slack "continue / deliver via") — new UI + action, no
event today.

## IronClaw-native surfaces (past Cowork)

Inline safety-approval gate (shipped — make first-class) · background-job state chip ·
multi-channel handoff · stateful connector cards on the `credential_name`/`extension_name` split.

## Suggested build order

1. Per-tool durations (UI slot exists). 2. Elapsed + verb live-status. 3. Right-rail scaffold +
Context panel. 4. `PlanUpdate` event + Plan rail. 5. Background-job → projection bridge + chip.
6. Multi-channel handoff. Iterate against `design-preview-page.tsx` with mock data before wiring live.

## Dev loop

`.claude/launch.json` → `preview_start {name:"webui-v2-dev"}` runs the Vite dev server
(`crates/ironclaw_webui/frontend`, port 5173). The SPA proxies `/api`, `/auth`, `/vendor` to the
Rust gateway on `:3000`; run that + a token (`ironclaw status`) to get past the console sign-in.
