# Tenant BI Telemetry V0 — Shape Research

**Date:** 2026-08-26
**Status:** Revised shape selected; trusted `RootFilesystem` store approved 2026-08-27
**Scope:** Planning only. No production behavior is changed by this document.

> **Revision note (2026-08-27):** The initial direct-SQL selection below was
> rejected after review against the live universal filesystem contract. The
> current decision is Shape B, refined as a trusted host store over the existing
> `Arc<dyn RootFilesystem>`, with terminal-trigger production wiring and a real
> libSQL `tests/integration` proof in the foundation PR. Historical Shape A
> analysis remains as the record of the rejected alternative.

## Briefing

IronClaw can add tenant-scoped BI telemetry without putting a database write on
every run, tool call, or inference. The closest existing mechanism is the
event-store coalescing sink: callers make a synchronous, non-blocking
`try_send`, one lifecycle-owned task drains a bounded queue, and that task
writes batches. Telemetry should extend that mechanism, but not reuse the
durable event log: telemetry is explicitly best-effort and lossy, while the
event log claims durable, replayable state.

The selected durable shape is a dedicated `ironclaw_telemetry` domain whose
typed repository writes through the existing universal `RootFilesystem`.
Composition passes the already-assembled root handle; telemetry names no SQL
driver and creates no database, pool, URL, runtime, migration, or parallel
connection plane. The trusted background repository writes only beneath the
typed tenant telemetry namespace.

Only hourly additive facts become durable. Per-call/per-run observations live
in the queue and disappear after aggregation. This keeps write volume bounded
while still supporting arbitrary admin-selected daily, weekly, monthly, and
cohort windows by summing hourly rows. Lifecycle transitions are a separate,
low-volume event table because collapsing them to hours would prevent state
reconstruction.

The current code does not have an authoritative `event` or `webhook` trigger
kind. Scheduled triggers expose `Cron` and `Once`; trigger executions expose
`Schedule` and `Manual`. V0 must not manufacture a richer taxonomy. It can
export `cron`, `once`, and `manual` automation facts and identify the missing
event/webhook attribution as a follow-up requiring an upstream origin contract.

## Structural map

```text
canonical producers
  model gateway completion ───────────────┐
  committed terminal turn result ────────┤
  trigger lifecycle/settlement ──────────┤  try_record(observation)
  identity/setup lifecycle ──────────────┘
                                           │ non-blocking try_send
                                           ▼
                             bounded in-memory MPSC queue
                                           │ one consumer
                                           ▼
                          hourly accumulator + batch worker
                                           │ bounded CAS updates
                                           ▼
                             existing RootFilesystem
                              (libSQL/PostgreSQL/in-memory)
                                           │
                                           ▼
                          typed tenant-scoped export reader
                                           │ authorized ProductSurface call
                                           ▼
                       streamed ZIP: CSV tables + manifest.json
```

### Existing extension points

| Concern | Existing seam to extend | Evidence |
|---|---|---|
| Non-blocking bounded batching | `CoalescingEventSink` and its single drain loop | `crates/events/ironclaw_event_store/src/coalescing_sink.rs:19`, `:125`, `:211` |
| Model-call facts | model completion after the physical provider/effective model and token usage are known | `crates/loop/ironclaw_loop_host/src/lib.rs:1803`, `:1914`; `crates/loop/ironclaw_loop_host/src/model_gateway.rs:1392`, `:2094` |
| Provider-neutral usage shape | `LoopModelUsage` | `crates/contracts/ironclaw_loop_contracts/src/host/model.rs:314` |
| Run terminal fact | executor after terminal state has been committed | `crates/loop/ironclaw_turn_runner/src/turn_run_executor.rs:572` |
| Terminal vocabulary | `TurnStatus::is_terminal` and its closed variants | `crates/contracts/ironclaw_host_api/src/turn.rs:877` |
| Automation records | `TriggerRecord`, repository, and settlement path | `crates/domains/ironclaw_triggers/src/lib.rs:349`, `:1136`, `:1282` |
| Actual automation taxonomy | `TriggerSchedule::{Cron, Once}` and `TriggerExecutionSource::{Schedule, Manual}` | `crates/domains/ironclaw_triggers/src/lib.rs:445`, `:681` |
| Tenant-admin authorization | `RebornServices::authorize_admin` and current active Admin/Owner lookup | `crates/product/ironclaw_assistant/src/reborn_services/product_commands.rs:26`; `crates/product/ironclaw_assistant/src/reborn_services.rs:3735` |
| Literal SQL domain precedent | typed trigger repository plus libSQL/PostgreSQL implementations | `crates/domains/ironclaw_triggers/src/lib.rs:1136`; `src/libsql.rs:77`; `src/postgres.rs:1704` |
| Backend parity | shared trigger repository conformance suite | `crates/domains/ironclaw_triggers/tests/repository_contract.rs:72`, `:1343`, `:1548` |
| Existing database admission | 8-reader/1-writer libSQL runtime and composition-owned backend handles | `crates/substrates/ironclaw_libsql_runtime/src/lib.rs:183`, `:332`; `crates/app/ironclaw_composition/src/filesystem_assembly.rs:68` |

### Constraints that shape the feature

- A new domain normally persists through `ScopedFilesystem`; hand-written SQL
  requires its own ADR. `crates/domains/AGENTS.md:57` and
  `.claude/rules/database.md` make this explicit.
- Contracts crates contain neutral vocabulary and ports only; they cannot own
  persistence or execution. `crates/contracts/AGENTS.md:1`.
- Product transports cannot derive tenant scope from request data or mutate a
  domain repository directly. Authorization and orchestration stay behind
  `ProductSurface`.
- The event log is for durable replayable truth. Best-effort BI telemetry must
  remain visibly distinct from it. `.claude/rules/events.md`.
- LLM content is never deleted. Telemetry must never capture prompts,
  responses, reasoning, tool arguments/results, or raw errors in the first
  place; a future telemetry retention policy therefore cannot affect canonical
  LLM records.
- There is no existing production CSV/ZIP export or bounded response-body
  abstraction to extend. The streaming archive path is new behavior and needs
  its own limits, escaping tests, and rate-limit descriptor.

## Candidate shapes

### Shape A — Typed SQL telemetry domain (rejected after review)

Create `ironclaw_telemetry_contracts` for the neutral observation/recorder port
and `ironclaw_telemetry` for aggregation, SQL repositories, and export reads.
Wire canonical producers to an injected `Arc<dyn TelemetryRecorder>`. The
implementation owns one bounded queue and one worker. Add an ADR authorizing
literal SQL, reuse existing composition-owned handles, and add shared libSQL/
PostgreSQL conformance tests.

**Extend:** coalescing-sink mechanics, trigger repository/backend parity,
existing model gateway and terminal-run seams, admin authorization, and
ProductSurface routing.
**Fork:** persistence policy, via a narrow documented exception.
**Delete:** nothing.
**Leave untouched:** canonical event log, RootFilesystem semantics, transcripts,
diagnostic logging, model-provider contracts, and operational run records.
**Cost to undo:** moderate. Producers depend only on the neutral recorder, so
the SQL repository can later be replaced; schema/data migration would still be
required for already-collected telemetry.

This shape was initially selected, then rejected because the current
`RootFilesystem` already owns structured records, ordered indexes, CAS, and
backend parity. Adding another driver-linked domain path would fork the
canonical persistence plane.

### Shape B — Trusted RootFilesystem hourly records (selected)

Store typed hourly records beneath `/tenants/{tenant}/telemetry/v0`, use the
shared bounded CAS helper for increments, and use tenant-leading ordered
indexes for bounded reads. The one trusted multi-tenant worker receives the
existing `Arc<dyn RootFilesystem>`; producers and future admin handlers do not.

**Extend:** the default persistence contract and mount catalog.
**Fork:** none.
**Delete:** telemetry SQL adapters, driver dependencies, ADR 0005, and their
architecture allowlists.
**Leave untouched:** canonical event-log durability and physical filesystem
backend implementations.
**Cost to undo:** low.

This is selected because telemetry's best-effort contract tolerates a partially
applied multi-record drain, while the existing filesystem supplies the required
typed entries, tenant-leading indexes, keyset queries, and backend parity.

### Shape C — Durable event-log observations plus projections

Append every run/model/tool observation to the canonical event log and build
hourly projections for export.

**Extend:** durable event ingestion, projections, replay, and cursor handling.
**Fork:** the product meaning of the event log by adding intentionally lossy BI
facts to a durable stream.
**Delete:** nothing initially; substantially more durable detail accumulates.
**Leave untouched:** very little of the event pipeline.
**Cost to undo:** high because durable history and replay contracts outlive the
projection.

This shape is rejected. It conflicts with the accepted best-effort loss model,
persists the high-frequency detail V0 is intended to avoid, and creates more
write load than batching hourly aggregates directly.

## Selected boundary signatures

The exact fields are fixed in the design spec; these signatures show ownership
and dependency direction:

```rust
pub trait TelemetryRecorder: Send + Sync {
    fn try_record(&self, observation: TelemetryObservation) -> RecordOutcome;
}

pub enum RecordOutcome {
    Accepted,
    DroppedQueueFull,
    DroppedClosed,
    DroppedInvalid,
}

#[async_trait]
pub trait TelemetryRepository: Send + Sync {
    async fn upsert_batch(&self, batch: TelemetryBatch) -> Result<(), TelemetryStoreError>;
    async fn scan_export(
        &self,
        request: TenantTelemetryExportQuery,
    ) -> Result<TelemetryExportCursor, TelemetryStoreError>;
}
```

`try_record` is deliberately synchronous and non-failing from the producer's
perspective. Repository errors are counted by the worker and never fail a user
run. `scan_export` is tenant-scoped by construction and yields bounded pages;
the WebUI never receives a repository handle.

## Human gate

Shape B was explicitly approved on 2026-08-27 after reviewing the initially
opened PR. The foundation PR must also wire terminal trigger settlement and
prove a real trigger execution persists through a real embedded libSQL-backed
`RootFilesystem` in `tests/integration`; only the authenticated admin export
surface remains deferred.

## Historical direct-SQL PR1 recon (superseded)

### Map

- The neutral synchronous observer pattern is `BudgetEventSink`
  (`crates/kernel/ironclaw_resources/src/event.rs:79`); the bounded batching
  mechanics are `CoalescingEventSink`
  (`crates/events/ironclaw_event_store/src/coalescing_sink.rs:99`, `:125`,
  `:211`). PR1 copies the injection and drain shapes, not event-log durability.
- The dual-backend SQL precedent is `ironclaw_triggers`: libSQL receives the
  shared `Arc<LibSqlRuntime>` (`crates/domains/ironclaw_triggers/src/libsql.rs:77`)
  and PostgreSQL receives an already-open pool in its private adapter
  (`crates/domains/ironclaw_triggers/src/postgres.rs:47`). Telemetry may not
  parse a URL, create a runtime, or open a pool.
- Adding the two crates requires more than their directories: the root
  workspace manifest, PROPOSAL target tree, family inventories, crate-test
  buckets, canonical-package discovery, driver allowlists, same-layer edge
  inventory, and dependency-boundary rules are all exact gates.
- The contracts crate owns observation vocabulary and the synchronous
  `TelemetryRecorder` only. The domain crate owns record validation,
  aggregation, repository contracts, literal adapters, the queue, and the
  worker. No producer, composition, ProductSurface, or WebUI files belong in
  PR1.

### Briefing

PR1 builds a dormant but fully tested telemetry foundation. Callers will
eventually see one small injected recorder, while all queueing and database
behavior stays behind the domain boundary. The worker writes the current UTC
hour incrementally—at one second or 512 observations—so an hour is a database
grouping key, not an hour-long memory buffer. The only expected crash or
deployment loss is the small unflushed queue tail, with a five-second graceful
drain available to later composition wiring.

The SQL exception is deliberately narrow. Telemetry owns literal relational
tables because additive grouped upserts and tenant/time scans are the product
requirement, but it receives existing admission handles and cannot become a
second database configuration or connection plane. Driver types stay private
to backend adapters and every new dependency is pinned by an ADR-backed
architecture inventory.

### PR1 rulings

- PR1 means plan Tasks 1–4: structural charter, typed contracts/aggregation,
  dual-backend repository parity, and the bounded worker.
- `RecordOutcome::DroppedInvalid` is distinct from queue-full and queue-closed
  loss, matching the collector coverage schema.
- PostgreSQL follows the trigger repository precedent: the private adapter may
  name the explicitly allowlisted driver and accepts an already-created pool.
- `ironclaw_telemetry -> ironclaw_libsql_runtime` and any contracts-family edge
  are explicit same-layer inventory rows, not layer-matrix exceptions.
