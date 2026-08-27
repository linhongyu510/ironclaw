# Tenant BI Telemetry V0 Design

**Status:** Proposed; requirements decisions accepted in discussion, pending code review at implementation time
**Date:** 2026-08-26
**Shape research:** [Tenant BI Telemetry V0 — Shape Research](../../plans/2026-08-26-tenant-bi-telemetry-v0-research.md)

## Purpose

Give a tenant administrator a bounded download of privacy-safe, tenant-local BI
facts. Frequent observations are recorded asynchronously and aggregated into
one-hour UTC buckets before they become durable. The administrator receives
the lowest durable grain and performs daily, weekly, monthly, cohort, and
retention calculations outside IronClaw.

V0 is collection and export infrastructure, not a BI dashboard and not a
centrally hosted analytics service.

## Accepted product decisions

- Scope and authorization are tenant-level. An active tenant Admin or Owner can
  export only that tenant; an instance operator retains the existing explicit
  operator bypass.
- Cross-tenant/global analytics and a cloud analytics database are not in V0.
- Capture is fully asynchronous, bounded, best-effort, and may lose data.
- Producers receive an injected shared recorder. There is no process-global
  static singleton.
- Producers never wait for the database and never acquire connections.
- A single lifecycle-owned worker drains the queue and writes batches.
- Durable usage grain is one UTC hour. V0 has no hourly-to-daily compaction.
- Individual runs, model calls, and tool calls are not durable telemetry rows.
- Heartbeats, prompts, responses, reasoning, tool arguments/results, raw error
  messages, emails, display names, and estimated cost are never captured.
- The current, still-open hour is excluded from export unless the admin sets
  `include_partial=true`.
- Activation, retention, churn, win-back, and revenue are analyst-defined
  calculations, not product-owned metric endpoints in V0.
- There is no telemetry purge/TTL in V0. A retention policy requires a separate
  deletion contract; it must never delete canonical LLM or product records.

## Ownership

### Neutral producer contract

Add `crates/contracts/ironclaw_telemetry_contracts`. It owns only bounded,
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

The two consumers that justify the contracts crate are the loop/trigger/
identity producers and the domain-owned buffered implementation. Observation
construction validates maximum identifier lengths and admits no open metadata
map. `DroppedInvalid` remains distinct from queue pressure and a closed worker
so collector coverage can report why an observation was lost.

### Durable domain

Add `crates/domains/ironclaw_telemetry`. It owns:

- UTC hour bucketing and additive aggregation;
- the bounded queue implementation and worker;
- typed durable record grammar;
- libSQL and PostgreSQL repositories;
- tenant-scoped, paged export reads;
- shared backend conformance and metric-proof tests.

The crate receives composition-owned database handles. It cannot parse a
database URL/path/environment variable, create a runtime or pool, or choose a
backend. ADR 0005 records and limits this exception.

### Product and transport

`ironclaw_assistant` registers a paginated telemetry `ProductView`, authorizes
the caller, and issues a tenant-bound export read through the existing frozen
`ProductSurface::query` conduit. `ironclaw_webui` validates range/filter syntax
and streams archive framing. Neither imports a SQL driver or domain repository.

## Observation contract

```rust
pub enum TelemetryObservation {
    RunSettled(RunSettledObservation),
    ModelCallCompleted(ModelCallCompletedObservation),
    AutomationSettled(AutomationSettledObservation),
    LifecycleTransition(LifecycleTransitionObservation),
}
```

All observations include `tenant_id`, attributable `user_id`, and `occurred_at`
as typed values. Observations without a tenant or user are rejected locally and
counted as invalid; they are not placed into an instance-global bucket.

`RunSettledObservation` includes only terminal outcome, typed origin, duration
milliseconds, optional evidence-backed reported tool-call count, whether at
least one tool was called when that count is known, and the existing bounded
`SanitizedFailure` category when the run failed. A composition-owned
`ProcessJournalCommitObserver` emits it from the committed terminal process
snapshot, so executor errors and supervisor-caught panics are covered too. The
origin is a closed enum derived from canonical typed run context: `human`,
`parent_agent`, `system`, `automation`, or `other`; no transport string is
reinterpreted. Before recording, the observer asks a threads-owned
`RunToolUsageEvidenceReader` for the count of durable, finalized, run-scoped
tool-call evidence. That narrow read contract is implemented over the existing
`SessionThreadService`; it does not widen the kernel-only
`LoopExitEvidencePort`, and canonical loop-exit claims and run snapshots remain
unchanged. If evidence cannot supply a count, the observation retains `None`
instead of claiming zero; exports therefore label these fields as reported
rather than exact execution totals.

`ModelCallCompletedObservation` is emitted at the physical model gateway after
the provider, effective model, and provider-reported usage are known. It
contains `provider_id`, `effective_model_id`, one inference, and the four token
counters. Missing provider-reported usage records the inference with zero token
counters; this means inference counts remain useful without pretending token
usage was reported.

`AutomationSettledObservation` contains the attributable user, stable
automation identity, `automation_kind` (`cron`, `once`, or `manual`), and
settlement outcome. `event` and `webhook` are deliberately absent because the
current trigger contract does not establish either origin.

`LifecycleTransitionObservation` contains a stable event ID, closed event kind,
closed subject kind, subject ID, optional attributable user, and timestamp.
V0 event kinds are `member_added`, `member_removed`, `routine_created`,
`routine_enabled`, `routine_disabled`, and `routine_deleted`. Channel and skill
lifecycle were listed as nice-to-have inputs, but their current owners do not
offer a tenant-and-user-attributed committed observer suitable for this
collector; V0 reports them as unsupported rather than editing unrelated paths
or inferring transitions from a read snapshot. A producer is added only where
a committed authoritative transition exists.

## Queue and worker contract

Defaults are fixed and configurable only through typed `DeploymentConfig`:

| Setting | V0 default |
|---|---:|
| queue capacity | 8,192 observations |
| maximum drained batch | 512 observations |
| maximum wait before draining a non-empty queue | 1 second |
| graceful shutdown flush budget | 5 seconds |

`try_record` uses `try_send` exactly once. A full or closed queue increments an
in-memory loss counter and returns immediately. It never logs a field from the
observation. There is exactly one consumer task, so flushes cannot overlap.

For each drain, the worker:

1. buckets usage observations by `floor_utc_hour(occurred_at)`;
2. combines identical durable keys using checked `u64` accumulation;
3. retains lifecycle events as individually deduplicated rows;
4. acquires one admitted writer/client;
5. performs all upserts/inserts in one transaction;
6. commits and releases the handle before draining again.

The open hour is upserted incrementally; the worker does not retain an hour of
observations in memory. A crash can lose the queue tail but cannot produce a
partially committed batch. On an acquisition, statement, or commit error, the
worker drops that drain, increments its in-memory write-loss counters, and
continues. It does not retry an ambiguously committed additive upsert, which
would risk double-counting. A later successful coverage write reports the loss.
Telemetry failures never fail or delay the originating product action.

At shutdown, composition closes senders and gives the worker up to five
seconds to drain. Expiry aborts the worker and reports the remaining count as
lost through operational diagnostics.

## Literal durable tables

All timestamps are UTC. `window_start` is an exact hour and every usage table
has tenant-leading primary/index keys. `schema_version` is `0` in V0.
PostgreSQL uses `TIMESTAMPTZ`; libSQL stores canonical RFC3339 text while the
typed repository enforces identical ordering and precision.

### `telemetry_hourly_user_activity_v0`

Primary key:

```text
(tenant_id, window_start, user_id, origin_kind)
```

Additive values:

```text
run_count
runs_with_reported_tool_calls_count
tool_count_reported_run_count
reported_tool_call_count
completed_count
failed_count
cancelled_count
recovery_required_count
total_run_latency_ms
```

Metadata: `first_observed_at`, `last_observed_at`, `schema_version`,
`updated_at`. The sum of the four terminal counts equals `run_count` by typed
construction. `tool_count_reported_run_count` exposes runs for which durable
evidence could not report a count; averages over reported tool calls use that
denominator. Timeout is not a terminal status in the current turn
contract; V0 cannot separately query it.

### `telemetry_hourly_model_usage_v0`

Primary key, matching the accepted requirement:

```text
(tenant_id, user_id, window_start, provider_id, effective_model_id)
```

Additive values:

```text
inference_count
usage_reported_count
input_tokens
output_tokens
cache_read_input_tokens
cache_creation_input_tokens
```

`usage_reported_count` makes zero-token calls distinguishable from calls whose
provider omitted usage. Metadata matches the activity table. No cost columns
exist.

### `telemetry_hourly_run_failures_v0`

Primary key:

```text
(tenant_id, window_start, user_id, failure_category)
```

The additive value is `failure_count`; metadata matches the activity table.
`failure_category` is copied only from the bounded, sanitized category already
stored on the terminal run. No error message or provider payload is admitted.

### `telemetry_hourly_automation_usage_v0`

Primary key:

```text
(tenant_id, window_start, user_id, automation_kind)
```

Additive values are `run_count`, `completed_count`, `failed_count`,
`cancelled_count`, and `recovery_required_count`; metadata matches the other
hourly tables. `automation_kind` is a checked value among `cron`, `once`, and
`manual`.

### `telemetry_lifecycle_events_v0`

Primary key `(tenant_id, event_id)`, with scan index
`(tenant_id, occurred_at, event_id)` and reconstruction index
`(tenant_id, subject_kind, subject_id, occurred_at, event_id)`.

Columns are `event_id`, `tenant_id`, `user_id` nullable only for a tenant-level
transition, `event_kind`, `subject_kind`, `subject_id`, `occurred_at`, and
`schema_version`. No arbitrary JSON payload exists. Conflict on the stable
event ID is a no-op, making producer replay idempotent.

### `telemetry_collector_hourly_v0`

Primary key `(tenant_id, window_start, collector_instance_id)`. Values are
`accepted_observation_count`, `queue_full_drop_count`, `closed_drop_count`,
`invalid_drop_count`, `write_failed_observation_count`, `first_observed_at`,
and `last_observed_at`.

`collector_instance_id` identifies one process incarnation, not a second
worker within a process. A restart or rolling deployment can legitimately
produce two instances in the same hour; keeping them separate makes their
non-overlapping observed spans visible instead of merging them into false
full-hour coverage. The manifest conservatively marks every hour with anything
other than exactly one full-span, loss-free incarnation as partial; V0 never
tries to prove that two incarnation spans are contiguous. This table exposes
coverage limitations; it does not make the data lossless.
If the database remains unavailable, the latest losses cannot themselves be
persisted. The export manifest therefore labels counts as last successfully
reported and marks a bucket partial whenever its observed span does not cover
the full hour or any reported loss is non-zero.

### Physical partitioning and retention

V0 uses tenant-leading primary keys and time scan indexes, not native database
partitions. Hourly rows already bound cardinality and native partitioning would
need materially different libSQL/PostgreSQL lifecycle machinery. Table-size
and export-size observability is included; partitioning, daily compaction, and
purge are follow-ups based on measured volume.

## Export contract

The route is:

```text
GET /api/webchat/v2/admin/telemetry/export
    ?from=<RFC3339 UTC inclusive>
    &to=<RFC3339 UTC exclusive>
    &include_partial=false
    &provider_id=<optional exact filter>
    &effective_model_id=<optional exact filter>
```

`from` and `to` are required, `from < to`, and the range is at most 366 days.
Provider and model filters affect only `hourly_model_usage.csv`; the manifest
echoes normalized filters. The product service derives `tenant_id` from the
authorized caller and never accepts it in query parameters.

Unless `include_partial=true`, `to` is capped at the current UTC hour boundary
and rows whose `window_start` is the current hour are excluded. Lifecycle
events use the same half-open `[from, to)` timestamps. Admins can export longer
history in adjacent chunks without a single unbounded request.

The response is a streamed ZIP with:

```text
manifest.json
hourly_user_activity.csv
hourly_model_usage.csv
hourly_run_failures.csv
hourly_automation_usage.csv
lifecycle_events.csv
collector_coverage.csv
```

Every CSV has a versioned, fixed column order. Cells that begin with `=`, `+`,
`-`, `@`, tab, or carriage return are prefixed with a single quote after CSV
escaping to prevent spreadsheet formula injection. IDs are bounded before
capture. The archive writer reads repository pages of at most 2,000 rows and
applies a 1,000,000-row and 256 MiB uncompressed limit; exceeding either
returns a typed `range_too_large` error before a successful archive is claimed.
The route has a dedicated low-rate admission descriptor and disconnect
cancellation releases the read cursor promptly.

`manifest.json` includes schema version, tenant ID, requested and effective
ranges, generation time, filters, partial-hour policy, per-file row counts,
collector coverage/loss summaries, supported lifecycle kinds, and these known
gaps: no channel/skill lifecycle, event/webhook origin, timeout classification,
latency percentiles, cost/revenue, global analytics, or guaranteed-complete
signup/setup history.

## Privacy and security

- Tenant scope is derived from `ProductSurfaceCaller` after a fresh admin
  authorization check for every request.
- User IDs are stable opaque identifiers. Emails, names, roles, prompts,
  content, raw errors, run/thread IDs, and tool details are absent.
- Provider/model IDs are validated bounded identifiers; they are not free-form
  metadata bags.
- Export is audited using the existing sanitized product-admin audit path; the
  audit record contains tenant, caller, time range, filters, and result status,
  never archive contents.
- The worker's operational logs contain counts and typed error classes only.

## Compatibility, rollback, and failure semantics

The feature is additive. Existing actions do not depend on successful
telemetry capture. Rollback disables composition wiring and the export route;
tables may remain unread but harmless. Dropping tables is a separate destructive
migration and is not part of rollback. Schema names include `_v0`, export files
carry versioned headers, and unknown persisted enum values fail closed as a
sanitized storage error rather than being silently remapped.

No V0 metric is represented as exact when its inputs are best-effort. Downloads
are accompanied by collector coverage so analysts can decide whether a range
is fit for a particular calculation.
