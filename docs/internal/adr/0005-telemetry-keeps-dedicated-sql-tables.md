# ADR 0005: tenant telemetry keeps dedicated SQL tables

**Status:** Accepted 2026-08-26 (tenant BI telemetry foundation, PR1 Task 1)

**Issue / rows:** tenant BI telemetry v0; target architecture §6.1.7,
§6.4.16, §11.2.6

## Context

The default persistence idiom for Reborn domain records is the
`RootFilesystem`/`ScopedFilesystem` fabric and its bounded CAS operations.
That default remains correct for ordinary domain state. Tenant BI telemetry
has a different storage shape: model-safe observations are grouped by tenant
and time, written in batches, aggregated hourly, and exported by time range.

The telemetry boundary is deliberately split into a neutral contract crate,
`ironclaw_telemetry_contracts`, and a substrate-layer domain crate,
`ironclaw_telemetry`. This decision charters the persistence exception and
crate placement only. The initial shells contain no observations, SQL,
migrations, queues, producers, composition wiring, ProductSurface, or WebUI.

## Decision

`ironclaw_telemetry` may use dedicated PostgreSQL/libSQL tables, with indexes
keyed by tenant and time, for the future telemetry recorder and aggregation
worker. The contract crate remains provider-neutral and may depend only on
`ironclaw_host_api`. The domain crate may depend on the contract crate and the
existing `ironclaw_libsql_runtime` admission substrate; future PostgreSQL and
libSQL driver dependencies are private to adapters and no driver type escapes
the public API.

The exception is **existing admission only**. Composition opens each physical
database once and passes the existing PostgreSQL pool or shared
`Arc<LibSqlRuntime>` into telemetry adapters. Telemetry must not create a
second pool, parse a database URL or path, open a runtime, or establish a
competing connection plane. A future batch write uses one admitted writer and
one transaction for its grouped rows. The architecture driver allowlist and
same-layer inventory make this boundary explicit and shrink-only.

## Why dedicated grouped tables

Grouped upserts and tenant/time range scans are the load-bearing operations.
They require a single transaction to merge a batch across rows and indexes
that make a tenant's time window efficient. Per-document CAS can detect a
superseded document, but it cannot express grouped row upserts, relational
unique keys, or the indexed range scans without rebuilding a database inside
the filesystem document layer. Keeping the tables in the telemetry domain
preserves those semantics while retaining the filesystem fabric as the
default for other domains.

## Why not the event log

The event log is durable, replayable system evidence with its own retention,
redaction, and projection contract. Telemetry is an aggregate-oriented,
best-effort analytics record and must not become a second source of replayable
truth or couple event schemas to BI dimensions. Telemetry records also carry
no prompts, model content, or raw tool payloads. Event-log persistence is
therefore not a substitute for this boundary.

## Boundaries and rollback

This ADR does not authorize a migration, queue, producer, exporter, or product
surface. Those additions must preserve typed tenant identity, model-safe
payloads, existing connection admission, backend parity, and the private
driver boundary. If grouped atomic writes and indexed tenant/time queries can
later be expressed by a stronger RootFilesystem contract without losing
performance or transaction semantics, reopen this ADR and converge. If
telemetry no longer needs grouped writes or a supported SQL backend is retired,
revisit the exception and remove the driver allowlist entry.
