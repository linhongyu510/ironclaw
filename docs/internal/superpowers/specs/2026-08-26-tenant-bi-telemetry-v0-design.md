# Tenant BI Telemetry V0 Design

**Status:** Accepted for implementation; revised 2026-08-27 after persistence review
**Date:** 2026-08-26
**Shape research:** [Tenant BI Telemetry V0 — Shape Research](../../plans/2026-08-26-tenant-bi-telemetry-v0-research.md)

## Purpose

Give a tenant administrator a bounded download of privacy-safe, tenant-local BI
facts. Frequent observations are recorded asynchronously and aggregated into
one-hour UTC buckets before they become durable. The administrator receives the
lowest durable grain and performs daily, weekly, monthly, cohort, and retention
calculations outside IronClaw.

V0 is tenant-local collection and export infrastructure, not a BI dashboard or
a centrally hosted analytics service.

## Accepted product decisions

- Scope and authorization are tenant-level. An active tenant Admin or Owner can
  export only that tenant; an instance operator retains the existing explicit
  operator bypass.
- Cross-tenant/global analytics and a cloud analytics database are not in V0.
- Capture is fully asynchronous, bounded, best-effort, and may lose data.
- Producers receive an injected shared recorder. There is no process-global
  static singleton.
- Producers never wait for persistence and never acquire storage handles.
- One lifecycle-owned worker drains the queue and writes aggregates.
- Durable usage grain is one UTC hour. V0 has no hourly-to-daily compaction.
- Individual runs, model calls, and tool calls are not durable telemetry rows.
- Heartbeats, prompts, responses, reasoning, tool arguments/results, raw error
  messages, emails, display names, and estimated cost are never captured.
- Activation, retention, churn, win-back, and revenue remain analyst-defined
  calculations, not product-owned metric endpoints.
- There is no telemetry purge/TTL in V0. A retention policy requires a separate
  deletion contract and must never delete canonical LLM or product records.

## Delivery slices

The replacement foundation PR is independently useful and testable. It includes:

1. typed observations and the non-blocking recorder;
2. hourly aggregation and a typed `RootFilesystem` repository;
3. lifecycle-owned composition over the existing mounted root filesystem;
4. one authoritative producer for terminal trigger executions; and
5. an in-process integration test that drives the real trigger path into a
   real embedded libSQL-backed `RootFilesystem` and reads the durable result.

The authenticated admin query/download surface, the remaining run/model/setup
producers, and the full metric-proof fixture are follow-up PRs. Deferring the
HTTP surface does not defer backend-neutral bounded repository reads: the
integration test and later admin service use the same typed read contract.

## Ownership

### Neutral producer contract

`crates/contracts/ironclaw_telemetry_contracts` owns only bounded,
provider-neutral observation types and this injection port:

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
```

Observation construction validates maximum identifier lengths and admits no
open metadata map. The contract crate contains no filesystem, SQL, runtime,
queue, or product dependencies.

### Durable telemetry domain

`crates/domains/ironclaw_telemetry` owns:

- UTC-hour bucketing and checked additive aggregation;
- the bounded recorder queue and one worker;
- typed durable record grammar and path/index construction;
- a `FilesystemTelemetryRepository` over `Arc<dyn RootFilesystem>`;
- bounded tenant/time reads with keyset cursors; and
- repository conformance, batching, loss-accounting, and metric-proof tests.

The domain does not depend on `libsql`, `ironclaw_libsql_runtime`,
`deadpool-postgres`, or `tokio-postgres`. It contains no SQL, DDL, migrations,
pool construction, backend selection, or storage URL/path parsing. Backend
selection and physical database lifecycle remain entirely in composition and
`ironclaw_filesystem`.

### Trusted root authority

The collector is a trusted host-owned background service that batches
observations from multiple tenants. Its repository therefore receives the
existing composition-owned `Arc<dyn RootFilesystem>` rather than constructing
or caching one `ScopedFilesystem` per tenant.

Every public repository operation requires a typed `TenantId`, and every path
is rooted beneath:

```text
/tenants/{tenant_id}/telemetry/v0/
```

The repository accepts no caller-supplied virtual path. Producers receive only
`Arc<dyn TelemetryRecorder>` and cannot access the root filesystem. Future
admin reads derive `TenantId` from authorized product context before calling
the typed repository; no untrusted caller receives root authority.

## Observation contract

```rust
pub enum TelemetryObservation {
    RunSettled(RunSettledObservation),
    ModelCallCompleted(ModelCallCompletedObservation),
    AutomationSettled(AutomationSettledObservation),
    LifecycleTransition(LifecycleTransitionObservation),
}
```

All usage observations include typed `tenant_id`, attributable `user_id`, and
`occurred_at`. Observations without tenant/user attribution are rejected and
counted as invalid; they never enter an instance-global bucket.

`RunSettledObservation` contains terminal outcome, typed origin, duration,
optional evidence-backed reported tool-call count, and a bounded sanitized
failure category. `ModelCallCompletedObservation` contains provider, effective
model, inference count, and provider-reported token counters. These types stay
in the foundation even though their production producers land later.

`AutomationSettledObservation` contains the attributable user, stable
automation identity, `automation_kind` (`cron`, `once`, or `manual`), and
terminal outcome. The foundation PR emits this observation from the trigger
poller's authoritative terminal active-run settlement path—not when a poller
tick merely discovers or submits work.

The trigger terminal-settlement event must carry typed tenant, creator user,
trigger identity, fire slot, run identity, automation kind, and terminal
outcome. The callback runs only after trigger history and active-fire state are
durably settled. Its implementation calls `try_record` exactly once, performs
no filesystem I/O, and ignores the best-effort outcome except for bounded
diagnostics. Successful and failed terminal trigger runs use the same closed
settlement event; pre-submit failures are not reported as completed
automations.

`LifecycleTransitionObservation` contains a stable event ID, closed event kind,
closed subject kind, subject ID, optional attributable user, and timestamp.
V0 event kinds remain `member_added`, `member_removed`, `routine_created`,
`routine_enabled`, `routine_disabled`, and `routine_deleted`; their production
producers are follow-ups.

## Queue and worker contract

| Setting | V0 default |
|---|---:|
| queue capacity | 8,192 observations |
| maximum drained batch | 512 observations |
| maximum wait before draining a non-empty queue | 1 second |
| graceful shutdown flush budget | 5 seconds |

`try_record` validates and calls `try_send` exactly once. A full or closed
queue increments bounded in-memory diagnostics and returns immediately. It
never logs observation fields. One consumer task guarantees drains do not
overlap.

For each drain, the worker:

1. buckets observations by `floor_utc_hour(occurred_at)`;
2. combines identical durable keys with checked arithmetic;
3. retains lifecycle events as individually deduplicated records;
4. calls one repository batch operation; and
5. releases the drain before receiving the next batch.

The filesystem repository applies each aggregate record with the shared
bounded `cas_update` helper. A batch may commit a prefix before a later record
fails; this is acceptable for explicitly best-effort analytics and is reported
through collector coverage. The worker does not replay an ambiguous aggregate
write, because additive replay could double-count. Telemetry failures never
fail or delay the originating product action.

On shutdown, composition closes intake and waits at most five seconds. Timeout
aborts the worker and records the remaining count in operational diagnostics.
Deployments therefore normally flush their sub-second queue tail without
holding shutdown indefinitely.

## Durable record layout

Each aggregate is a typed JSON `Entry` with a versioned `RecordKind` and
explicit indexed projections. The body is the typed record; queryable tenant,
time, user, family, and dimensions are duplicated only in `Entry::indexed`.
Unknown record kinds, schema versions, or enum values fail closed.

Canonical paths are deterministic and include every primary-key dimension:

```text
/tenants/{tenant}/telemetry/v0/hourly/activity/{hour}/{user}/{origin}.json
/tenants/{tenant}/telemetry/v0/hourly/model/{hour}/{user}/{provider}/{model}.json
/tenants/{tenant}/telemetry/v0/hourly/failure/{hour}/{user}/{category}.json
/tenants/{tenant}/telemetry/v0/hourly/automation/{hour}/{user}/{kind}.json
/tenants/{tenant}/telemetry/v0/lifecycle/{event_id}.json
/tenants/{tenant}/telemetry/v0/coverage/{hour}/{collector_instance_id}.json
```

Path components are encoded by one reversible, bounded domain helper; callers
never concatenate raw identifiers. Tenant equality is present in both the
trusted virtual root and indexed projection.

The repository declares ordered indexes whose leading keys are:

```text
[tenant_id, record_family, window_start, tie_breaker]
[tenant_id, user_id, record_family, window_start, tie_breaker]
[tenant_id, record_family, provider_id, effective_model_id, window_start, tie_breaker]
[tenant_id, subject_kind, subject_id, occurred_at, event_id]
```

Reads use `query_ordered` with a bounded page size and opaque keyset cursor.
There is no offset pagination, directory scan, full-result sort, or body parse
for filtering. Index creation is idempotent and happens during telemetry
repository initialization after the root filesystem has been assembled.

### Hourly user activity

Key: `(tenant, hour, user, origin)`. Values are run count, reported-tool
denominators/totals, terminal outcome counts, total latency, observed span, and
schema version.

### Hourly model usage

Key: `(tenant, hour, user, provider, effective model)`. Values are inference
count, usage-reported count, input/output/cache token totals, observed span,
and schema version. No cost fields exist.

### Hourly run failures

Key: `(tenant, hour, user, sanitized failure category)`. Value is failure
count plus observed span and schema version. No error text is stored.

### Hourly automation usage

Key: `(tenant, hour, user, automation kind)`. Values are run and terminal
outcome counts plus observed span and schema version. Stable automation IDs are
accepted at observation time for attribution/deduplication diagnostics but are
not an unbounded per-run durable row.

### Lifecycle events

Key: `(tenant, event_id)`. Records are idempotent and contain only the closed
event/subject vocabulary and timestamp. No arbitrary JSON payload exists.

### Collector coverage

Key: `(tenant, hour, collector_instance_id)`. Values are accepted, queue-full,
closed, invalid, and write-failed counts plus observed span. A UUID identifies
one process incarnation. Coverage exposes best-effort gaps; it does not claim
losslessness.

## Composition and real-libSQL proof

Production composition creates one telemetry repository over the exact
`CompositeRootFilesystem` already used by the runtime, initializes indexes,
then starts one recorder/worker. It injects only the neutral recorder into the
trigger terminal-settlement observer. No new database handle, pool, runtime,
path setting, feature flag, or backend selector is added.

The foundation PR adds an in-process integration scenario under
`tests/integration/` that:

1. builds the production-profile runtime over a temporary real embedded
   libSQL database and the real `LibSqlRootFilesystem`;
2. creates and fires a due trigger through the production trigger poller;
3. drives the resulting run to a successful terminal state;
4. waits through an explicit telemetry drain/shutdown synchronization seam;
5. constructs a fresh typed telemetry repository over a reopened
   libSQL-backed root filesystem;
6. reads the tenant/hour automation aggregate and asserts the exact tenant,
   creator user, automation kind, completed count, and schema version; and
7. queries the same range for another tenant and asserts zero rows.

The test never queries telemetry SQL, calls a private adapter, invokes the
recorder directly, or relies only on `TurnStatus::Completed`. It proves the
real trigger producer, composition wiring, asynchronous worker, filesystem
dispatch, libSQL durability, typed readback, and tenant isolation.

## Follow-up admin export contract

The next PR adds the authenticated tenant-admin `ProductView` and streamed
archive. It derives `tenant_id` from authorized caller context and uses the
repository's bounded keyset reads. The intended route remains:

```text
GET /api/webchat/v2/admin/telemetry/export
    ?from=<RFC3339 UTC inclusive>
    &to=<RFC3339 UTC exclusive>
    &include_partial=false
    &provider_id=<optional exact filter>
    &effective_model_id=<optional exact filter>
```

The current open hour is excluded unless `include_partial=true`. Range and
archive size limits, CSV formula escaping, audit records, and ZIP framing land
with that surface rather than in the foundation PR.

## Privacy and security

- User IDs are stable opaque identifiers. Emails, names, roles, prompts,
  content, raw errors, run/thread IDs, and tool details are absent.
- Provider/model IDs and every path component are validated bounded types.
- The repository exposes tenant-scoped typed methods, never arbitrary paths.
- Root filesystem authority remains inside trusted composition and the domain
  repository; producers and future HTTP handlers cannot obtain it.
- Operational logs contain counts and stable failure classes only.

## Compatibility, rollback, and failure semantics

The change is additive to product behavior and uses the existing universal
storage plane. Existing actions never depend on telemetry success. Rollback
removes composition wiring and the telemetry consumer mount records remain
unread but harmless; deletion is not part of rollback.

There is no dedicated telemetry SQL schema to migrate or drop. PostgreSQL,
libSQL, and in-memory parity comes from their existing `RootFilesystem`
implementations plus shared telemetry repository conformance tests. No metric
is represented as exact when its inputs are best-effort, and later downloads
include collector coverage so analysts can judge fitness for use.
