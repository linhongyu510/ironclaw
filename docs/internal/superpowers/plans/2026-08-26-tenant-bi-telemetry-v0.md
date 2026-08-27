# Tenant BI Telemetry V0 Implementation Plan

> **For implementers:** Execute this plan task by task. Every task is labeled
> **Structural** or **Behavioral**; do not mix the two kinds in one commit.

**Goal:** Collect privacy-safe tenant BI facts through a non-blocking injected
recorder, durably aggregate frequent facts by UTC hour in dedicated libSQL and
PostgreSQL tables, and let an authorized tenant admin download bounded CSV data
with explicit coverage metadata.

**Architecture:** Canonical producers synchronously `try_send` typed
observations to one bounded queue. A single lifecycle-owned worker combines a
drain into additive hourly rows and writes it in one admitted database
transaction. A typed domain reader pages tenant-scoped rows through a
registered `ProductView` on the existing authorized `ProductSurface::query`
conduit; WebUI streams a ZIP of fixed-schema CSV files and a manifest. The
event log, transcript, operational diagnostics, and canonical run/model
records remain unchanged.

**Tech stack:** Rust, Tokio bounded MPSC, chrono, existing
`ironclaw_libsql_runtime`, existing PostgreSQL pool, typed ProductSurface,
Axum WebUI, ZIP/CSV libraries selected as bounded streaming dependencies.

**Design spec:** [Tenant BI Telemetry V0 Design](../specs/2026-08-26-tenant-bi-telemetry-v0-design.md)
**Shape research:** [Tenant BI Telemetry V0 — Shape Research](../../plans/2026-08-26-tenant-bi-telemetry-v0-research.md)

## Definition of done

- Producers make no awaited telemetry calls and acquire no database handles.
- Queue-full, queue-closed, invalid-observation, and database-write loss are
  observable without failing the product action.
- One batch uses one admitted handle and one transaction; flushes cannot run in
  parallel.
- No individual run, inference, or tool call is a durable telemetry row.
- libSQL and PostgreSQL pass the same repository, migration, aggregation,
  isolation, and export-order conformance suite.
- Tenant scope is derived from an authorized caller, never a query parameter.
- Default export excludes the open UTC hour and all exports use half-open
  `[from, to)` ranges.
- Admins can calculate every metric marked **Available** or **Derivable** in
  the coverage matrix below from the CSVs, using the pseudo queries in this
  plan.
- Every metric marked **Unavailable** is named in `manifest.json`; no endpoint,
  documentation, or column implies otherwise.
- No prompt, response, reasoning, tool argument/result, raw error, email,
  display name, run/thread ID, or cost estimate enters telemetry.
- The SQL exception is accepted in ADR 0005 and mechanically limited by the
  architecture tests.

## Durable schema contract

The following PostgreSQL-like DDL is the semantic contract. The libSQL adapter
uses canonical RFC3339 UTC text for timestamps and equivalent constraints and
indexes. Migration statements remain adapter-local because the two drivers
have different syntax; shared tests prove behavioral parity.

```sql
CREATE TABLE telemetry_hourly_user_activity_v0 (
  tenant_id TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  user_id TEXT NOT NULL,
  origin_kind TEXT NOT NULL CHECK
    (origin_kind IN ('human','parent_agent','system','automation','other')),
  run_count BIGINT NOT NULL CHECK (run_count >= 0),
  runs_with_reported_tool_calls_count BIGINT NOT NULL CHECK (runs_with_reported_tool_calls_count >= 0),
  tool_count_reported_run_count BIGINT NOT NULL CHECK (tool_count_reported_run_count >= 0),
  reported_tool_call_count BIGINT NOT NULL CHECK (reported_tool_call_count >= 0),
  completed_count BIGINT NOT NULL CHECK (completed_count >= 0),
  failed_count BIGINT NOT NULL CHECK (failed_count >= 0),
  cancelled_count BIGINT NOT NULL CHECK (cancelled_count >= 0),
  recovery_required_count BIGINT NOT NULL CHECK (recovery_required_count >= 0),
  total_run_latency_ms BIGINT NOT NULL CHECK (total_run_latency_ms >= 0),
  first_observed_at TIMESTAMPTZ NOT NULL,
  last_observed_at TIMESTAMPTZ NOT NULL,
  schema_version SMALLINT NOT NULL CHECK (schema_version = 0),
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, window_start, user_id, origin_kind),
  CHECK (completed_count + failed_count + cancelled_count +
         recovery_required_count = run_count),
  CHECK (runs_with_reported_tool_calls_count <= tool_count_reported_run_count),
  CHECK (tool_count_reported_run_count <= run_count)
);
CREATE INDEX telemetry_activity_tenant_user_time_v0
  ON telemetry_hourly_user_activity_v0 (tenant_id, user_id, window_start);

CREATE TABLE telemetry_hourly_model_usage_v0 (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  provider_id TEXT NOT NULL,
  effective_model_id TEXT NOT NULL,
  inference_count BIGINT NOT NULL CHECK (inference_count >= 0),
  usage_reported_count BIGINT NOT NULL CHECK (usage_reported_count >= 0),
  input_tokens BIGINT NOT NULL CHECK (input_tokens >= 0),
  output_tokens BIGINT NOT NULL CHECK (output_tokens >= 0),
  cache_read_input_tokens BIGINT NOT NULL CHECK (cache_read_input_tokens >= 0),
  cache_creation_input_tokens BIGINT NOT NULL CHECK (cache_creation_input_tokens >= 0),
  first_observed_at TIMESTAMPTZ NOT NULL,
  last_observed_at TIMESTAMPTZ NOT NULL,
  schema_version SMALLINT NOT NULL CHECK (schema_version = 0),
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY
    (tenant_id, user_id, window_start, provider_id, effective_model_id),
  CHECK (usage_reported_count <= inference_count)
);
CREATE INDEX telemetry_model_tenant_time_model_v0
  ON telemetry_hourly_model_usage_v0
    (tenant_id, window_start, provider_id, effective_model_id);

CREATE TABLE telemetry_hourly_run_failures_v0 (
  tenant_id TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  user_id TEXT NOT NULL,
  failure_category TEXT NOT NULL,
  failure_count BIGINT NOT NULL CHECK (failure_count >= 0),
  first_observed_at TIMESTAMPTZ NOT NULL,
  last_observed_at TIMESTAMPTZ NOT NULL,
  schema_version SMALLINT NOT NULL CHECK (schema_version = 0),
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, window_start, user_id, failure_category)
);

CREATE TABLE telemetry_hourly_automation_usage_v0 (
  tenant_id TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  user_id TEXT NOT NULL,
  automation_kind TEXT NOT NULL CHECK
    (automation_kind IN ('cron','once','manual')),
  run_count BIGINT NOT NULL CHECK (run_count >= 0),
  completed_count BIGINT NOT NULL CHECK (completed_count >= 0),
  failed_count BIGINT NOT NULL CHECK (failed_count >= 0),
  cancelled_count BIGINT NOT NULL CHECK (cancelled_count >= 0),
  recovery_required_count BIGINT NOT NULL CHECK (recovery_required_count >= 0),
  first_observed_at TIMESTAMPTZ NOT NULL,
  last_observed_at TIMESTAMPTZ NOT NULL,
  schema_version SMALLINT NOT NULL CHECK (schema_version = 0),
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, window_start, user_id, automation_kind),
  CHECK (completed_count + failed_count + cancelled_count +
         recovery_required_count = run_count)
);

CREATE TABLE telemetry_lifecycle_events_v0 (
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  user_id TEXT NULL,
  event_kind TEXT NOT NULL,
  subject_kind TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL,
  schema_version SMALLINT NOT NULL CHECK (schema_version = 0),
  PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX telemetry_lifecycle_tenant_time_v0
  ON telemetry_lifecycle_events_v0 (tenant_id, occurred_at, event_id);
CREATE INDEX telemetry_lifecycle_subject_history_v0
  ON telemetry_lifecycle_events_v0
    (tenant_id, subject_kind, subject_id, occurred_at, event_id);

CREATE TABLE telemetry_collector_hourly_v0 (
  tenant_id TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  collector_instance_id TEXT NOT NULL,
  accepted_observation_count BIGINT NOT NULL CHECK (accepted_observation_count >= 0),
  queue_full_drop_count BIGINT NOT NULL CHECK (queue_full_drop_count >= 0),
  closed_drop_count BIGINT NOT NULL CHECK (closed_drop_count >= 0),
  invalid_drop_count BIGINT NOT NULL CHECK (invalid_drop_count >= 0),
  write_failed_observation_count BIGINT NOT NULL CHECK (write_failed_observation_count >= 0),
  first_observed_at TIMESTAMPTZ NOT NULL,
  last_observed_at TIMESTAMPTZ NOT NULL,
  schema_version SMALLINT NOT NULL CHECK (schema_version = 0),
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, window_start, collector_instance_id)
);
```

`collector_instance_id` is a process-incarnation ID. V0 still has exactly one
worker per process, but a restart or rolling deployment can create multiple
process incarnations in the same hour. Separate coverage rows preserve each
observed span and expose partial deployment hours; merging them would falsely
suggest continuous collection. The metric fixture must exercise two
incarnations in one hour.

## Why literal SQL is justified here

`RootFilesystem` is the default and remains the right choice for typed record
documents and bounded CAS mutation. It is not selected here because V0's
explicit product requirement is literal tenant/time/dimension tables that an
admin can export through ordered grouped scans. Implementing additive counters
as CAS documents would repeatedly rewrite hot `(tenant,user,hour,dimension)`
records and would still lack backend-native grouped indexes; it would satisfy a
different storage requirement.

The durable event pipeline is also not selected. Its entries are replayable
product evidence and therefore deliberately durable. Telemetry observations
are explicitly best-effort, high-frequency, privacy-reduced, and noncanonical.
Appending each observation to the event log would retain exactly the per-call
detail and write volume the hourly aggregation is meant to avoid and would
misrepresent lossy BI input as replayable truth. The new SQL exception is
therefore narrow: only telemetry-owned aggregate/lifecycle tables, existing
composition-owned handles, no database selection in the domain, and shared
backend conformance. ADR 0005 ratifies this already-stated comparison; it does
not defer the decision evidence.

All additive upserts use checked Rust accumulation before binding and the
database equivalent of `existing + excluded`. If adding would exceed signed
64-bit storage, the whole batch rolls back with `CounterOverflow`; values are
never saturated silently in durable storage.

## Metric coverage verification

Status meanings:

- **Available:** direct aggregate over exported facts.
- **Derivable:** requires a documented analyst-selected window/cohort rule; V0
  does not publish it as an official metric.
- **Diagnostic only:** useful but best-effort lifecycle loss prevents an exact
  population assertion.
- **Unavailable:** the source contract or approved V0 scope does not contain
  the fact.

| Requirement metric | V0 status | Export proof / limitation |
|---|---|---|
| Signups: first `(tenant,user)` membership | Diagnostic only | first `member_added` per user from lifecycle CSV; best-effort loss means not an authoritative signup ledger |
| Users provisioned / membership population | Diagnostic only | reconstruct latest member event; roles are intentionally not captured, and missed events can skew state |
| Activation within one week | Diagnostic only | cohort from best-effort first member add to first completed human or automation run; lifecycle loss prevents an exact denominator and product does not bless which completion is the core event |
| Added → routine → first OK funnel | Diagnostic only | membership/routine lifecycle events plus first completed run; best-effort loss applies |
| Channel-connected funnel stage | Unavailable | current V0 has no tenant-and-user-attributed committed channel lifecycle observer; channel events remain a nice-to-have follow-up |
| Tenant active in a period | Available | any activity or automation row in the period |
| Users per tenant | Diagnostic only | latest member lifecycle state; no cross-tenant query exists |
| DAU / WAU / MAU | Available | distinct user IDs with runs in daily/7-day/month windows |
| WAU/MAU stickiness | Available | quotient of the two distinct-user queries |
| Reported activity events per WAU | Available | human-origin `runs_with_reported_tool_calls_count` divided by human WAU; the manifest exposes the reported-count denominator |
| Inferences per WAU | Available | model `inference_count` divided by active distinct users |
| User retention / churn | Derivable | weekly active sets and set intersection/difference |
| Tenant retention / churn | Derivable for this tenant only | whether this one tenant has activity in consecutive periods; comparing companies requires central cross-tenant analytics |
| Win-back after 1..K quiet weeks | Derivable | weekly active sets and anti-joins |
| Runs / inference | Available | run counts divided by inference counts over the same range |
| Average latency / run | Available | summed latency divided by run count |
| P50/P95/P99 latency | Unavailable | hourly sums do not retain a histogram or individual latencies |
| Reported tool calls / run with reported count | Available | summed evidence-backed reported tool calls divided by `tool_count_reported_run_count`; compare that denominator with total runs to expose missing evidence |
| Run failure rate | Available | failed count divided by run count |
| Error-kind mix | Available | bounded sanitized failure-category table |
| Provider/model adoption | Available | exact provider/model dimensions and distinct users |
| Token usage | Available | input/output/cache token sums; `usage_reported_count` exposes missing provider usage |
| Estimated cost / revenue | Unavailable | explicitly excluded; no cost columns |
| Users with configured automations | Diagnostic only | reconstruct latest routine lifecycle state; exact only when coverage shows no loss and all producer kinds are supported |
| Users whose automations ran / succeeded | Available | distinct users and outcome sums in automation usage CSV |
| Cron vs once vs manual mix | Available | `automation_kind` dimension |
| Event/webhook automation mix | Unavailable | no authoritative current trigger taxonomy for these origins |
| Setup depth: routines | Diagnostic only | lifecycle event reconstruction, subject to best-effort loss |
| Setup depth: channels/skills | Unavailable | no V0 producer with the required committed tenant/user attribution |
| Total number of companies | Unavailable | tenant export cannot enumerate other tenants |
| Global users/events/revenue | Unavailable | cross-tenant global analytics is excluded from V0 |
| Timeout rate | Unavailable | `TurnStatus` has no terminal timeout variant |

This matrix is the scope check: every original requested metric is either
backed by a durable field and a query below, or explicitly declared unavailable
with the missing source fact identified.

## Pseudo-query proof

These queries use the durable table names so they can be run in backend
conformance fixtures. The same logic works on downloaded CSVs in DuckDB,
SQLite, pandas, or a spreadsheet pivot. Every query binds `:tenant_id`,
`:from`, and `:to`; ranges are inclusive/exclusive. Queries should normally
use a closed-hour `:to`.

### Q1 — direct activity totals and quality

```sql
SELECT
  SUM(run_count) AS runs,
  SUM(runs_with_reported_tool_calls_count) AS reported_activity_events,
  SUM(tool_count_reported_run_count) AS runs_with_reported_tool_count,
  SUM(reported_tool_call_count) AS reported_tool_calls,
  SUM(completed_count) AS completed,
  SUM(failed_count) AS failed,
  1.0 * SUM(failed_count) / NULLIF(SUM(run_count), 0) AS failure_rate,
  1.0 * SUM(total_run_latency_ms) / NULLIF(SUM(run_count), 0)
    AS average_latency_ms,
  1.0 * SUM(reported_tool_call_count)
    / NULLIF(SUM(tool_count_reported_run_count), 0)
    AS reported_tool_calls_per_reported_run
FROM telemetry_hourly_user_activity_v0
WHERE tenant_id = :tenant_id
  AND window_start >= :from AND window_start < :to;
```

### Q2 — DAU, WAU, MAU, and stickiness

```sql
WITH daily AS (
  SELECT DATE(window_start) AS day, COUNT(DISTINCT user_id) AS dau
  FROM telemetry_hourly_user_activity_v0
  WHERE tenant_id = :tenant_id
    AND window_start >= :from AND window_start < :to
  GROUP BY DATE(window_start)
), weekly AS (
  SELECT DATE_TRUNC('week', window_start) AS week,
         COUNT(DISTINCT user_id) AS wau
  FROM telemetry_hourly_user_activity_v0
  WHERE tenant_id = :tenant_id
    AND window_start >= :from AND window_start < :to
  GROUP BY DATE_TRUNC('week', window_start)
), monthly AS (
  SELECT DATE_TRUNC('month', window_start) AS month,
         COUNT(DISTINCT user_id) AS mau
  FROM telemetry_hourly_user_activity_v0
  WHERE tenant_id = :tenant_id
    AND window_start >= :from AND window_start < :to
  GROUP BY DATE_TRUNC('month', window_start)
)
SELECT * FROM daily; -- export each CTE or join by the analyst's calendar rule
```

For a particular week/month pair, stickiness is
`wau / NULLIF(mau, 0)`. PostgreSQL `DATE_TRUNC` is pseudo syntax here; exported
CSV consumers choose an explicit UTC calendar implementation.

### Q3 — reported activity events and inference per WAU

```sql
WITH active AS (
  SELECT COUNT(DISTINCT user_id) AS wau
  FROM telemetry_hourly_user_activity_v0
  WHERE tenant_id = :tenant_id
    AND window_start >= :week_start AND window_start < :week_end
), activity AS (
  SELECT SUM(runs_with_reported_tool_calls_count) AS reported_activity_events
  FROM telemetry_hourly_user_activity_v0
  WHERE tenant_id = :tenant_id AND origin_kind = 'human'
    AND window_start >= :week_start AND window_start < :week_end
), inference AS (
  SELECT SUM(inference_count) AS inferences
  FROM telemetry_hourly_model_usage_v0
  WHERE tenant_id = :tenant_id
    AND window_start >= :week_start AND window_start < :week_end
)
SELECT reported_activity_events / NULLIF(1.0 * wau, 0)
         AS reported_activity_events_per_wau,
       inferences / NULLIF(1.0 * wau, 0) AS inferences_per_wau
FROM active CROSS JOIN activity CROSS JOIN inference;
```

### Q4 — model/provider usage and adoption

```sql
SELECT provider_id, effective_model_id,
       COUNT(DISTINCT user_id) AS users,
       SUM(inference_count) AS inferences,
       SUM(usage_reported_count) AS calls_with_reported_usage,
       SUM(input_tokens) AS input_tokens,
       SUM(output_tokens) AS output_tokens,
       SUM(cache_read_input_tokens) AS cache_read_input_tokens,
       SUM(cache_creation_input_tokens) AS cache_creation_input_tokens
FROM telemetry_hourly_model_usage_v0
WHERE tenant_id = :tenant_id
  AND window_start >= :from AND window_start < :to
  AND (:provider_id IS NULL OR provider_id = :provider_id)
  AND (:effective_model_id IS NULL OR effective_model_id = :effective_model_id)
GROUP BY provider_id, effective_model_id
ORDER BY inferences DESC;
```

### Q5 — inferences per run

```sql
WITH r AS (
  SELECT SUM(run_count) AS runs
  FROM telemetry_hourly_user_activity_v0
  WHERE tenant_id = :tenant_id
    AND window_start >= :from AND window_start < :to
), i AS (
  SELECT SUM(inference_count) AS inferences
  FROM telemetry_hourly_model_usage_v0
  WHERE tenant_id = :tenant_id
    AND window_start >= :from AND window_start < :to
)
SELECT 1.0 * inferences / NULLIF(runs, 0) AS inferences_per_run
FROM r CROSS JOIN i;
```

### Q6 — sanitized failure-category mix

```sql
SELECT failure_category, SUM(failure_count) AS failures,
       1.0 * SUM(failure_count)
         / NULLIF(SUM(SUM(failure_count)) OVER (), 0) AS share
FROM telemetry_hourly_run_failures_v0
WHERE tenant_id = :tenant_id
  AND window_start >= :from AND window_start < :to
GROUP BY failure_category
ORDER BY failures DESC;
```

### Q7 — automation users, success, and type mix

```sql
SELECT automation_kind,
       COUNT(DISTINCT user_id) AS users_who_ran_automation,
       SUM(run_count) AS runs,
       SUM(completed_count) AS completed,
       1.0 * SUM(completed_count) / NULLIF(SUM(run_count), 0) AS success_rate
FROM telemetry_hourly_automation_usage_v0
WHERE tenant_id = :tenant_id
  AND window_start >= :from AND window_start < :to
GROUP BY automation_kind
ORDER BY automation_kind;
```

This answers cron/once/manual only. Adding an `event` or `webhook` label without
an authoritative producer is forbidden.

### Q8 — first observed signup and weekly signup cohorts

```sql
WITH first_add AS (
  SELECT user_id, MIN(occurred_at) AS signed_up_at
  FROM telemetry_lifecycle_events_v0
  WHERE tenant_id = :tenant_id AND event_kind = 'member_added'
    AND occurred_at >= :from AND occurred_at < :to
  GROUP BY user_id
)
SELECT DATE_TRUNC('week', signed_up_at) AS signup_week, COUNT(*) AS signups
FROM first_add
GROUP BY DATE_TRUNC('week', signed_up_at)
ORDER BY signup_week;
```

This is diagnostic, not an authoritative population ledger: a dropped first
`member_added` cannot be reconstructed from telemetry.

### Q9 — current membership from lifecycle history

```sql
WITH latest AS (
  SELECT user_id, event_kind, occurred_at,
         ROW_NUMBER() OVER (
           PARTITION BY user_id ORDER BY occurred_at DESC, event_id DESC
         ) AS rank
  FROM telemetry_lifecycle_events_v0
  WHERE tenant_id = :tenant_id
    AND event_kind IN ('member_added','member_removed')
    AND occurred_at < :to
)
SELECT COUNT(*) AS observed_current_members
FROM latest
WHERE rank = 1 AND event_kind = 'member_added';
```

### Q10 — configured-automation users from lifecycle history

```sql
WITH latest_routine AS (
  SELECT subject_id AS routine_id, user_id, event_kind,
         ROW_NUMBER() OVER (
           PARTITION BY subject_id ORDER BY occurred_at DESC, event_id DESC
         ) AS rank
  FROM telemetry_lifecycle_events_v0
  WHERE tenant_id = :tenant_id AND subject_kind = 'routine'
    AND occurred_at < :to
)
SELECT COUNT(DISTINCT user_id) AS users_with_enabled_routines
FROM latest_routine
WHERE rank = 1 AND event_kind IN ('routine_created','routine_enabled');
```

This is diagnostic because lifecycle observations are best-effort.

### Q11 — supported setup funnel

```sql
WITH member AS (
  SELECT user_id, MIN(occurred_at) AS added_at
  FROM telemetry_lifecycle_events_v0
  WHERE tenant_id = :tenant_id AND event_kind = 'member_added'
  GROUP BY user_id
), routine AS (
  SELECT user_id, MIN(occurred_at) AS routine_at
  FROM telemetry_lifecycle_events_v0
  WHERE tenant_id = :tenant_id AND event_kind = 'routine_created'
  GROUP BY user_id
), first_ok AS (
  SELECT user_id, MIN(window_start) AS first_completed_hour
  FROM telemetry_hourly_user_activity_v0
  WHERE tenant_id = :tenant_id AND completed_count > 0
  GROUP BY user_id
)
SELECT COUNT(*) AS added,
       COUNT(routine.routine_at) AS routine_created,
       COUNT(first_ok.first_completed_hour) AS reached_completed_run
FROM member
LEFT JOIN routine USING (user_id)
LEFT JOIN first_ok USING (user_id)
WHERE member.added_at >= :from AND member.added_at < :to;
```

### Q12 — one-week activation under an analyst-selected definition

```sql
WITH arrival AS (
  SELECT user_id, MIN(occurred_at) AS added_at
  FROM telemetry_lifecycle_events_v0
  WHERE tenant_id = :tenant_id AND event_kind = 'member_added'
  GROUP BY user_id
), first_ok AS (
  SELECT user_id, MIN(window_start) AS first_ok_hour
  FROM telemetry_hourly_user_activity_v0
  WHERE tenant_id = :tenant_id AND completed_count > 0
  GROUP BY user_id
)
SELECT AVG(CASE WHEN first_ok_hour >= added_at
                     AND first_ok_hour < added_at + INTERVAL '7 days'
                THEN 1.0 ELSE 0.0 END) AS activated_within_7_days
FROM arrival LEFT JOIN first_ok USING (user_id)
WHERE added_at >= :from AND added_at < :to;
```

Hourly aggregation makes activation time accurate to an hour, not an exact
turn timestamp. V0 labels this diagnostic and analyst-defined because the
membership cohort is best-effort and “core event” is not a product-owned
criterion in scope.

### Q13 — weekly user retention and churn

```sql
WITH active AS (
  SELECT DISTINCT DATE_TRUNC('week', window_start) AS week, user_id
  FROM telemetry_hourly_user_activity_v0
  WHERE tenant_id = :tenant_id
    AND window_start >= :from AND window_start < :to
), weeks AS (
  SELECT prior.week AS prior_week,
         COUNT(*) AS prior_users,
         COUNT(current.user_id) AS retained_users
  FROM active prior
  LEFT JOIN active current
    ON current.user_id = prior.user_id
   AND current.week = prior.week + INTERVAL '7 days'
  GROUP BY prior.week
)
SELECT prior_week, retained_users,
       prior_users - retained_users AS churned_users,
       1.0 * retained_users / NULLIF(prior_users, 0) AS retention_rate
FROM weeks ORDER BY prior_week;
```

### Q14 — win-back after 1..K quiet weeks

```sql
WITH active AS (
  SELECT DISTINCT DATE_TRUNC('week', window_start) AS week, user_id
  FROM telemetry_hourly_user_activity_v0
  WHERE tenant_id = :tenant_id
    AND window_start >= :from AND window_start < :to
), returned AS (
  SELECT now.week, now.user_id, MAX(previous.week) AS previous_active_week
  FROM active now
  JOIN active previous
    ON previous.user_id = now.user_id AND previous.week < now.week
  GROUP BY now.week, now.user_id
)
SELECT week, COUNT(*) AS won_back_users
FROM returned
WHERE previous_active_week <= week - (:quiet_weeks * INTERVAL '7 days')
GROUP BY week ORDER BY week;
```

The denominator for a win-back rate is the analyst's chosen lapsed pool. V0
exports enough weekly activity to construct it but does not fix `K`.

### Q15 — tenant-active periods

```sql
SELECT DATE_TRUNC('week', window_start) AS week,
       CASE WHEN SUM(run_count) > 0 THEN 1 ELSE 0 END AS tenant_active
FROM telemetry_hourly_user_activity_v0
WHERE tenant_id = :tenant_id
  AND window_start >= :from AND window_start < :to
GROUP BY DATE_TRUNC('week', window_start)
ORDER BY week;
```

This supports retention/churn for the exported tenant itself. It cannot count
or compare companies across deployments.

### Q16 — coverage and partial-hour safety

```sql
SELECT window_start,
       MIN(first_observed_at) AS first_observed_at,
       MAX(last_observed_at) AS last_observed_at,
       SUM(accepted_observation_count) AS accepted,
       SUM(queue_full_drop_count + closed_drop_count + invalid_drop_count +
           write_failed_observation_count) AS reported_lost,
       CASE WHEN COUNT(*) <> 1
                  OR MIN(first_observed_at) > window_start
                  OR MAX(last_observed_at) < window_start + INTERVAL '1 hour'
                  OR SUM(queue_full_drop_count + closed_drop_count +
                         invalid_drop_count + write_failed_observation_count) > 0
            THEN 1 ELSE 0 END AS partial_or_lossy
FROM telemetry_collector_hourly_v0
WHERE tenant_id = :tenant_id
  AND window_start >= :from AND window_start < :to
GROUP BY window_start ORDER BY window_start;
```

Coverage is evidence of known gaps, not proof of completeness: a database
outage can prevent its own final loss report from being persisted. More than
one process incarnation makes the hour partial even when the earliest start
and latest end touch the hour boundaries; V0 does not merge separate spans or
claim that a restart/rolling-deployment gap was continuously observed.

## Implementation tasks

### Task 1 — [Structural] Charter the persistence exception and crate placement

**Files:**

- Create: `docs/internal/adr/0005-telemetry-keeps-dedicated-sql-tables.md`
- Modify: `Cargo.toml`
- Modify: `AGENTS.md`
- Modify: `.claude/rules/database.md`
- Modify: `crates/AGENTS.md`
- Modify: `crates/README.md`
- Create: `crates/contracts/ironclaw_telemetry_contracts/Cargo.toml`
- Create: `crates/contracts/ironclaw_telemetry_contracts/README.md`
- Create: `crates/contracts/ironclaw_telemetry_contracts/src/lib.rs`
- Create: `crates/domains/ironclaw_telemetry/Cargo.toml`
- Create: `crates/domains/ironclaw_telemetry/README.md`
- Create: `crates/domains/ironclaw_telemetry/src/lib.rs`
- Modify: `crates/contracts/AGENTS.md`
- Modify: `crates/domains/AGENTS.md`
- Modify: `docs/internal/reborn/target-architecture/PROPOSAL.md`
- Modify: `docs/internal/reborn/target-architecture/families/contracts.md`
- Modify: `docs/internal/reborn/target-architecture/families/domains.md`
- Modify: `crates/app/ironclaw_architecture_tests/tests/reborn_persistence_driver_boundary.rs`
- Modify: `crates/app/ironclaw_architecture_tests/tests/reborn_same_layer_edge_inventory.rs`
- Modify: `crates/app/ironclaw_architecture_tests/tests/reborn_dependency_boundaries.rs`
- Modify: `scripts/ci/reborn-crate-test-buckets.sh`
- Modify: `scripts/ci/test-reborn-crate-test-buckets.sh`
- Modify: `scripts/ci/discover-reborn-package-crates.sh`
- Modify the closest discovery/planner tests covering canonical packages.

**Steps:**

- [ ] Write the architecture tests first so they fail on an unchartered new SQL
  crate and pass only when ADR 0005, the precise driver allowlist, layer
  metadata, and allowed dependencies agree.
- [ ] In ADR 0005, document why literal grouped tables and tenant/time indexes
  were selected over RootFilesystem CAS documents, why the exception takes
  existing admission only, and why event-log persistence was rejected.
- [ ] Update the canonical root and database guidance so the default remains
  RootFilesystem while naming the existing ADR-or-converge exception process
  and the exact telemetry ADR. Avoid an unconditional rule that contradicts
  the architecture allowlist.
- [ ] Add empty, documented crate shells. The contracts crate may depend only
  on foundational contract crates needed for typed tenant/user IDs. The domain
  crate may depend downward on the contracts crate and the two admitted DB
  substrates; no upward dependency is permitted.
- [ ] Add workspace membership, target-tree/family inventories, canonical CI
  package discovery, family charter rows, and test-bucket ownership. Do not add
  behavior, queue logic, migrations, or SQL in this commit.
- [ ] Run:

```bash
python3 scripts/ci/check-target-tree.py
cargo test -p ironclaw_architecture_tests
python3 scripts/ci/docs_publication_boundary.py
```

- [ ] Commit: `chore(telemetry): charter tenant telemetry persistence boundary`

### Task 2 — [Behavioral] Define typed observations, buckets, and invariants

**Files:**

- Create: `crates/contracts/ironclaw_telemetry_contracts/src/observation.rs`
- Create: `crates/contracts/ironclaw_telemetry_contracts/src/recorder.rs`
- Modify: `crates/contracts/ironclaw_telemetry_contracts/src/lib.rs`
- Create: `crates/contracts/ironclaw_telemetry_contracts/tests/observation_contract.rs`
- Create: `crates/domains/ironclaw_telemetry/src/aggregate.rs`
- Create: `crates/domains/ironclaw_telemetry/src/records.rs`
- Create: `crates/domains/ironclaw_telemetry/tests/hour_bucket_contract.rs`

**Steps:**

- [ ] First write tests for exact UTC floor behavior at hour/day/month/year and
  DST boundaries, identifier byte limits, closed enums, terminal-count
  equality, missing model usage, stable lifecycle deduplication IDs, checked
  overflow, and rejection of absent tenant/user attribution.
- [ ] Define `TelemetryRecorder`, `RecordOutcome` (`Accepted`,
  `DroppedQueueFull`, `DroppedClosed`, `DroppedInvalid`),
  `TelemetryObservation`, and the four typed observation structs. Do not
  include `HashMap`, JSON metadata, raw error strings, or content-bearing IDs.
- [ ] Define `HourlyUserActivity`, `HourlyModelUsage`, `HourlyRunFailure`,
  `HourlyAutomationUsage`, `LifecycleEvent`, `CollectorCoverage`, and
  `TelemetryBatch` with private fields and validating constructors.
- [ ] Implement pure `floor_utc_hour` and `aggregate_batch`. Aggregation must be
  order-independent, deduplicate lifecycle event IDs, and return a typed error
  on overflow.
- [ ] Run:

```bash
cargo test -p ironclaw_telemetry_contracts
cargo test -p ironclaw_telemetry --test hour_bucket_contract
```

- [ ] Commit: `feat(telemetry): define bounded tenant observation contract`

### Task 3 — [Behavioral] Implement literal schemas and shared repository contract

**Files:**

- Create: `crates/domains/ironclaw_telemetry/src/repository.rs`
- Create: `crates/domains/ironclaw_telemetry/src/libsql.rs`
- Create: `crates/domains/ironclaw_telemetry/src/postgres.rs`
- Create: `crates/domains/ironclaw_telemetry/src/error.rs`
- Create: `crates/domains/ironclaw_telemetry/tests/repository_contract.rs`
- Modify: `crates/domains/ironclaw_telemetry/src/lib.rs`

**Steps:**

- [ ] Write one shared conformance harness over a `TelemetryRepository` factory.
  Run it against in-memory libSQL and a required testcontainer PostgreSQL leg.
- [ ] Before implementation, make tests fail for: migration replay; all six
  table/index shapes; additive same-key upsert; different tenant/user/hour/
  provider/model/origin/kind isolation; lifecycle idempotency; whole-batch
  rollback; overflow rollback; timestamp ordering; half-open export ranges;
  current-hour exclusion flag; provider/model filters; deterministic
  `(window_start, key...)` pagination; and unknown enum failure.
- [ ] Implement `TelemetryRepository::{migrate, upsert_batch,
  scan_activity_page, scan_model_page, scan_failure_page,
  scan_automation_page, scan_lifecycle_page, scan_coverage_page}`.
- [ ] Each `upsert_batch` call acquires one handle, starts one transaction,
  executes all table writes, commits, and releases. Add a test double around
  admission proving exactly one acquisition and no nested/parallel acquire.
- [ ] Preserve server-side causes in internal errors and sanitize product
  projections. Do not use `.unwrap()` or `.expect()` in production.
- [ ] Run both deployment shapes; the PostgreSQL command must fail rather than
  silently skip when Docker is unavailable:

```bash
cargo test -p ironclaw_telemetry --test repository_contract
IRONCLAW_REQUIRE_POSTGRES=1 cargo test -p ironclaw_telemetry --test repository_contract
```

- [ ] Commit: `feat(telemetry): persist hourly facts with backend parity`

### Task 4 — [Behavioral] Add the bounded recorder and single batch worker

**Files:**

- Create: `crates/domains/ironclaw_telemetry/src/buffered_recorder.rs`
- Create: `crates/domains/ironclaw_telemetry/src/worker.rs`
- Create: `crates/domains/ironclaw_telemetry/tests/buffered_recorder_contract.rs`
- Modify: `crates/domains/ironclaw_telemetry/src/lib.rs`

**Steps:**

- [ ] Extend the coalescing-sink test pattern with a fake repository. First
  prove `try_record` never awaits, full/closed queues return the correct
  outcome, 512 items or one second triggers a drain, drains never overlap,
  one repository failure drops only that drain, later drains continue,
  coverage counters carry forward, and shutdown respects five seconds.
- [ ] Implement `BufferedTelemetryRecorder::spawn(config, repository, clock)`
  returning `Arc<dyn TelemetryRecorder>` plus a lifecycle handle. Use exactly
  one bounded Tokio MPSC channel and one consumer task.
- [ ] Use a fake clock in tests; do not add real sleeps. Keep database calls out
  of `try_record` and do not hold a mutex across repository I/O.
- [ ] Add count-only operational diagnostics for queue pressure, batch size,
  flush latency, and typed failure class.
- [ ] Run:

```bash
cargo test -p ironclaw_telemetry --test buffered_recorder_contract
```

- [ ] Commit: `feat(telemetry): batch best-effort observations asynchronously`

### Task 5 — [Behavioral] Capture physical model-call usage

**Files:**

- Modify: `crates/loop/ironclaw_loop_host/src/model_gateway.rs`
- Modify: `crates/loop/ironclaw_loop_host/src/lib.rs`
- Modify the existing closest model-gateway tests in those modules; do not add
  a parallel test file if the seam is already covered.

**Steps:**

- [ ] First extend the gateway test double to capture every telemetry argument.
  Prove one completed physical provider call emits one observation with tenant,
  user, physical provider, effective model, and exact reported token fields;
  provider failover attributes the successful call to the actual provider;
  missing usage increments inference but not `usage_reported_count`; recorder
  rejection does not alter the model result.
- [ ] Inject `Arc<dyn TelemetryRecorder>` into the existing loop-host/model
  gateway assembly. Add a no-op implementation for tests/compositions that do
  not enable telemetry; do not use a global static.
- [ ] Emit only after the physical call outcome establishes the effective
  provider/model. Do not derive per-model facts from terminal cumulative usage,
  because that loses failover attribution.
- [ ] Run the narrow loop-host tests and compile every constructor/decorator
  found with the structural impact query.
- [ ] Commit: `feat(telemetry): observe provider-attributed model usage`

### Task 6 — [Behavioral] Derive reported tool totals and observe committed terminal runs

**Files:**

- Modify: `crates/domains/ironclaw_threads/src/service.rs`
- Modify the closest `ironclaw_threads` service test module identified by the
  required `SessionThreadService` impact query.
- Create: `crates/app/ironclaw_composition/src/telemetry/process_commit_observer.rs`
- Modify: `crates/app/ironclaw_composition/src/telemetry/mod.rs`
- Extend the closest loop-exit validation, process-journal observer, and
  production composition tests.

**Steps:**

- [ ] First drive the process journal path and prove exactly one observation
  occurs after each committed `Completed`, `Failed`, `Cancelled`, or
  `RecoveryRequired` terminal result, including executor error and
  supervisor-caught panic settlement; no observation occurs for parked,
  intermediate, or failed-to-commit transitions.
- [ ] Compute latency from canonical run `received_at` to the committed journal
  transition `occurred_at`; do not reuse an optional diagnostics timer.
- [ ] Add a narrow threads-owned `RunToolUsageEvidenceReader` and typed request
  that count durable finalized tool-call evidence for an authorized
  `(TurnScope, TurnRunId)`. Implement it over the existing
  `SessionThreadService` history/read model, reusing the threads domain's
  run-scope and finalized-result semantics. Do not widen the kernel-only
  `LoopExitEvidencePort`, and do not add a field to `LoopExit`,
  `TurnRunRecord`, or another canonical per-run record.
- [ ] Implement a composition-owned `ProcessJournalCommitObserver` that filters
  committed terminal agent-turn snapshots, asks the threads-owned reader for
  the optional reported tool-call count, calls `try_record`, and always
  returns success so best-effort queue or evidence-query loss advances its
  durable observer cursor rather than replaying and double-counting. Classify
  origin only from typed run context/provenance and copy only
  `SanitizedFailure.category`. A missing evidence count is `None`, never zero.
- [ ] Prove recorder queue loss does not alter the terminal run result, observer
  replay does not double-count, missing tool count increments no reported
  denominator, and no run/thread/message/tool identity is included.
- [ ] Commit: `feat(telemetry): observe committed runs and reported tool usage`

### Task 7 — [Behavioral] Capture automation usage and supported lifecycle facts

**Files:**

- Modify: `crates/domains/ironclaw_triggers/src/worker/ports.rs`
- Modify: `crates/domains/ironclaw_triggers/src/worker/active_cleanup.rs`
- Modify: `crates/domains/ironclaw_triggers/src/worker/tests.rs`
- Modify: `crates/app/ironclaw_composition/src/automation/trigger_poller.rs`
- Modify: `crates/product/ironclaw_assistant/src/automation_product_service.rs`
- Modify: `crates/product/ironclaw_assistant/src/automation_product_service/tests/mutation_tests.rs`
- Modify: `crates/domains/ironclaw_identity/src/identity_store/directory.rs`
- Modify: `crates/domains/ironclaw_identity/src/user_directory.rs`
- Modify: `crates/domains/ironclaw_identity/src/identity_store/tests.rs`

**Steps:**

- [ ] Extend the existing owner-defined `TriggerFireSettlementObserver`; do not
  add instrumentation beside its callers. Add a terminal settlement callback
  carrying creator user, source/schedule kind, fire slot, and bounded terminal
  outcome from `active_cleanup`. Derive `cron`/`once` from the owned
  `TriggerSchedule` and `manual` from `TriggerSourceKind::Manual` before the
  record leaves the trigger owner.
- [ ] First test cron, once, and manual automation attribution and every
  terminal outcome. Prove no observation is emitted before repository
  settlement, `Ok` and failure cleanup both notify exactly once, and duplicate
  canonical settlement uses a stable observation ID.
- [ ] For lifecycle, test committed-success emits once, rejected/rolled-back
  actions emit none, replayed stable event IDs deduplicate, and recorder loss
  never changes the domain result.
- [ ] Add an identity-owned `RebornUserDirectoryLifecycleObserver` port beside
  `RebornUserDirectory`, invoke it only after `RebornIdentityStore`
  create/delete commits, and implement it in composition with a non-blocking
  telemetry adapter. `ironclaw_identity` must not depend on
  `ironclaw_telemetry_contracts` or widen its armed dependency allowlist.
- [ ] Emit routine facts only after `AutomationProductService` mutation commits;
  the product owner already depends on neutral telemetry contracts and calls
  remain non-blocking through `TelemetryRecorder`.
- [ ] Channel and skill lifecycle have no V0 producer. Assert their absence in
  the supported-kind manifest and keep their metrics `Unavailable`; do not
  infer them from snapshots or add speculative observer layers.
- [ ] Do not add `event`, `webhook`, or `heartbeat` variants. A future trigger
  origin expansion starts in the owning trigger/ingress contract, then extends
  telemetry.
- [ ] Commit: `feat(telemetry): observe supported automation and setup facts`

### Task 8 — [Structural] Register the telemetry ProductView boundary

**Files:**

- Create: `crates/contracts/ironclaw_product_contracts/src/telemetry.rs`
- Modify: `crates/contracts/ironclaw_product_contracts/src/lib.rs`
- Modify: `crates/product/ironclaw_assistant/src/reborn_services.rs`
- Modify the product-view ownership/descriptor architecture tests; preserve
  the frozen `ProductSurface::{invoke, query, stream_events}` method set.
- Add module shells in `ironclaw_assistant` and `ironclaw_webui` only where
  required by their local charters.

**Steps:**

- [ ] Write architecture tests first for one registered paginated
  `TENANT_TELEMETRY_EXPORT_VIEW`, neutral range/filter/page DTOs, no
  SQL/ZIP/Axum types in contracts, no WebUI-to-domain edge, and no new
  ProductSurface method.
- [ ] Add `TenantTelemetryExportRequest`, typed page/cursor DTOs, and the
  neutral view payload contracts. Define the concrete
  `TENANT_TELEMETRY_EXPORT_VIEW` descriptor constant in `ironclaw_assistant`,
  where the repository keeps its product view inventory, and handle it through
  the existing `ProductSurface::query`. The request contains no tenant field;
  the contracts crate must not acquire a concrete view ID.
- [ ] Add module declarations and constructor fields only. Do not implement
  authorization, reads, CSV, ZIP, or HTTP in this commit.
- [ ] Run `cargo test -p ironclaw_architecture_tests`.
- [ ] Commit: `chore(telemetry): establish tenant export product boundary`

### Task 9 — [Behavioral] Implement the authorized paged view query

**Files:**

- Create: `crates/product/ironclaw_assistant/src/reborn_services/telemetry.rs`
- Modify: `crates/product/ironclaw_assistant/src/reborn_services.rs`
- Modify: `crates/product/ironclaw_assistant/src/lib.rs`
- Extend the existing RebornServices admin authorization tests.

**Steps:**

- [ ] First test active Admin and Owner access, removed/demoted/non-admin
  rejection, operator bypass, tenant derivation from caller, no cross-tenant
  request field, half-open UTC validation, 366-day cap, provider/model filters,
  open-hour default exclusion, explicit partial inclusion, and deterministic
  page cursors.
- [ ] Reuse `RebornServices::authorize_admin`; perform it once per request
  before opening a repository cursor. Do not cache a prior role decision.
- [ ] Dispatch the registered descriptor in the existing query handler and
  return typed row pages plus a manifest seed. Keep archive/CSV concerns out of
  assistant and do not add a feature-specific surface method.
- [ ] Add sanitized admin-audit evidence for requested/effective range,
  normalized filters, caller, row-limit outcome, and completion/cancellation.
- [ ] Commit: `feat(telemetry): authorize tenant-scoped export reads`

### Task 10 — [Behavioral] Stream the bounded CSV/ZIP download

**Files:**

- Create: `crates/product/ironclaw_webui/src/webui_v2/handlers/telemetry.rs`
- Modify: `crates/product/ironclaw_webui/src/webui_v2/handlers.rs`
- Modify: `crates/product/ironclaw_webui/src/webui_v2/router.rs`
- Modify: `crates/product/ironclaw_webui/src/webui_v2/descriptors.rs`
- Modify: `crates/product/ironclaw_webui/Cargo.toml`
- Add/extend handler integration tests under `crates/product/ironclaw_webui/src/webui_v2/`.

**Steps:**

- [ ] Before selecting libraries, verify they support async/chunked output
  without buffering the complete archive. Add only the narrow dependency
  features needed; do not introduce a Cargo feature flag.
- [ ] First test query parsing, no tenant parameter, authorization errors,
  headers, exact fixed CSV header order, RFC4180 escaping, formula-injection
  defense for all six dangerous prefixes, UTF-8/bounded IDs, 2,000-row paging,
  one-million-row and 256-MiB limits, client disconnect cancellation, and ZIP
  manifest/file consistency.
- [ ] Register a dedicated low-rate route descriptor for
  `/api/webchat/v2/admin/telemetry/export`. Route exclusively through the
  telemetry view on `ProductSurface::query`.
- [ ] Stream these files in fixed order: manifest seed/final manifest mechanism
  chosen so row counts are truthful, activity, model, failures, automation,
  lifecycle, coverage. If the ZIP format requires the final manifest last,
  name it `manifest.json` and document ordering rather than buffering it.
- [ ] Return `Content-Disposition: attachment` with a sanitized deterministic
  filename. Do not log archive cells.
- [ ] Commit: `feat(telemetry): stream bounded tenant CSV archive`

### Task 11 — [Behavioral] Wire one recorder, one worker, and graceful shutdown

**Files:**

- Modify: `crates/app/ironclaw_composition/src/filesystem_assembly.rs`
- Modify: `crates/app/ironclaw_composition/src/backend_store_assembly.rs`
- Modify: `crates/app/ironclaw_composition/src/factory/production_backend_assembly.rs`
- Modify: `crates/app/ironclaw_composition/src/input.rs`
- Modify: `crates/app/ironclaw_composition/src/runtime_input.rs`
- Modify: `crates/app/ironclaw_composition/src/factory/production_build_assembly.rs`
- Extend production assembly tests.

**Steps:**

- [ ] First test that libSQL composition passes the same `Arc<LibSqlRuntime>`
  used by RootFilesystem, PostgreSQL composition clones the existing pool,
  neither path opens a new handle source, and exactly one recorder/worker is
  shared by every producer and the export reader.
- [ ] Add typed deployment settings with the exact V0 defaults. Preserve all
  existing deployment defaults when telemetry is absent; no cargo feature.
- [ ] Start the worker after repository migration succeeds. On telemetry
  migration/start failure, fail startup with a cause-preserving configuration
  error rather than running an export surface against missing tables.
- [ ] On normal shutdown, close senders, wait up to five seconds, then continue
  shutdown. A flush timeout is diagnostic and cannot hang the process.
- [ ] Run both production assembly profiles and architecture tests.
- [ ] Commit: `feat(telemetry): wire lifecycle-owned tenant collector`

### Task 12 — [Behavioral] Prove the end-to-end product path

**Files:**

- Create: `tests/integration/reborn_integration_tenant_telemetry_export.rs`
- Modify: `tests/AGENTS.md`
- Create: `crates/domains/ironclaw_telemetry/tests/metric_coverage_contract.rs`

**Steps:**

- [ ] Build one deterministic fixture spanning two tenants, three users, two
  closed hours plus the current open hour, human/automation runs, tool calls,
  failures, two providers/models, missing reported usage, setup events, two
  collector process incarnations in one hour, and known collector loss.
- [ ] Execute Q1, Q3–Q7, Q9–Q10, and Q16 semantically against both durable
  backends and assert exact expected values. Execute Q8 and Q11–Q14 with the
  fixture while asserting they are labeled diagnostic/analyst-defined.
- [ ] Through the production-wired HTTP/ProductSurface path, authenticate a
  tenant admin, request a closed range, stream/unzip the archive, assert exact
  rows and manifest gaps, and prove tenant B never appears.
- [ ] Assert the current open-hour row is absent by default and present only
  with `include_partial=true`.
- [ ] Saturate the queue during an otherwise successful run and prove the run
  completes, a loss outcome is counted, and no per-run telemetry row exists.
- [ ] Use an integration seam assertion, not merely a completed status.
- [ ] Run:

```bash
cargo test -p ironclaw_telemetry metric_coverage_contract
IRONCLAW_REQUIRE_POSTGRES=1 cargo test -p ironclaw_telemetry metric_coverage_contract
cargo test -p ironclaw_integration_tests --test reborn_integration_tenant_telemetry_export
```

- [ ] Commit: `test(telemetry): prove tenant metrics and export isolation`

### Task 13 — [Structural] Finalize owned guidance and operator documentation

**Files:**

- Modify: `crates/contracts/ironclaw_telemetry_contracts/README.md`
- Modify: `crates/domains/ironclaw_telemetry/README.md`
- Modify: `crates/contracts/AGENTS.md`
- Modify: `crates/domains/AGENTS.md`
- Modify: `.env.example` only if the final typed deployment settings are
  environment-exposed through the existing documented config bridge.
- Create: `docs/internal/operations/tenant-telemetry.md`

**Steps:**

- [ ] Document producer ownership, table grammar, loss semantics, coverage
  interpretation, export bounds, supported/gap taxonomy, rollback, and the rule
  forbidding content/PII/arbitrary metadata.
- [ ] Document that native partitioning, compaction, purge, event/webhook origin,
  percentiles, costs, official metric criteria, and cross-tenant analytics are
  follow-ups—not hidden V0 behavior.
- [ ] Search moved/added names across guidance, contracts, tests, scripts, and
  manifests and update every owning reference.
- [ ] Run docs and architecture gates.
- [ ] Commit: `docs(telemetry): publish collection and export contracts`

## Final verification gate

Before claiming implementation complete:

```bash
cargo fmt --check
cargo clippy --all --benches --tests --examples --all-features -- -D warnings
cargo test -p ironclaw_telemetry_contracts
cargo test -p ironclaw_telemetry
IRONCLAW_REQUIRE_POSTGRES=1 cargo test -p ironclaw_telemetry
cargo test -p ironclaw_webui
cargo test -p ironclaw_assistant
cargo test -p ironclaw_architecture_tests
cargo test -p ironclaw_integration_tests --test reborn_integration_tenant_telemetry_export
python3 scripts/ci/check-target-tree.py
python3 scripts/ci/docs_publication_boundary.py
git diff --check
```

Then inspect changed production files for `.unwrap()`/`.expect()`, raw error
loss, unconstrained strings/maps, SQL handles outside admitted adapters,
process-local mutexes held across I/O, content/PII fields, direct WebUI store
access, and any new event/webhook/timeout/cost claims.

## Compatibility and rollback checklist

- Existing product actions are independent of telemetry acceptance and writes.
- SQL migrations are additive and replay-safe on both backends.
- Disabling composition wiring stops new collection and removes the export
  route; it does not require dropping tables.
- Table removal is deliberately not part of rollback.
- No second pool, database URL, libSQL runtime, or backend selector is added.
- Export schemas are fixed at V0 and include `schema_version=0`.
- A future schema changes table/file version or adds backward-compatible
  columns under an explicit export contract; it does not silently reinterpret
  existing enum values.
- Best-effort loss and partial deployment hours remain visible in every
  archive; they are never converted into zero activity.

## Explicit follow-ups, not implementation escape hatches

1. Establish authoritative event/webhook trigger-origin vocabulary at ingress
   and carry it through trigger settlement before adding telemetry kinds.
2. Measure hourly table cardinality and export latency before proposing native
   partitions or hourly-to-daily compaction.
3. Define an explicit, auditable telemetry-only retention/deletion contract if
   measured volume requires it; canonical LLM/product records remain untouched.
4. Add histogram sketches only if percentile latency is a validated BI need.
5. Define official activation/retention/win-back criteria only after product
   owners choose core events/windows; the hourly facts need no schema rewrite.
6. Build a separate central ingestion/database design if IronClaw later needs
   cross-deployment company/global analytics.
7. Add cost/revenue only from an authoritative billing ledger, never from a
   telemetry-side price estimate.
