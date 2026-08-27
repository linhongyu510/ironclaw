# Task 3 report — tenant BI telemetry repository

## Scope

Implemented the six schema-v0 telemetry tables and their tenant/time indexes,
shared repository contract, libSQL adapter, PostgreSQL adapter, typed scan
requests/pages/cursors, additive hourly upserts, lifecycle idempotency, and
single-transaction batch writes. The adapters accept only an admitted
`Arc<LibSqlRuntime>` or an already-created PostgreSQL pool. No queue, worker,
producer, composition, product, WebUI, or generic export endpoint was added.

## Test-first evidence

The conformance test was written before the repository implementation. The
initial run was a meaningful RED:

```text
cargo test -p ironclaw_telemetry --test repository_contract
error[E0432]: unresolved imports ... LibSqlTelemetryRepository,
PostgresTelemetryRepository, TelemetryRepository, TelemetryScanPageRequest,
TelemetryScanRequest
```

After implementation, the shared `assert_repository_contract` harness is
invoked by both the libSQL and PostgreSQL tests and covers migration replay,
additive replay, tenant isolation, all six row families, timestamp range
ordering, half-open ranges, open-hour exclusion/inclusion, provider/model
filters, deterministic cursor pagination, overflow rollback, and lifecycle
replay behavior.

## Verification

Passed:

```text
cargo test -p ironclaw_telemetry --test repository_contract
  2 passed (libSQL passed; PostgreSQL leg reported the unavailable Docker
  client and returned only in the non-strict deployment shape)

cargo test -p ironclaw_telemetry --all-targets --all-features
  17 passed, 0 failed

cargo clippy -p ironclaw_telemetry --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo test -p ironclaw_architecture_tests --test reborn_dependency_boundaries \
  -- reborn_crate_dependency_boundaries_hold
cargo test -p ironclaw_architecture_tests --test reborn_persistence_driver_boundary
```

The strict PostgreSQL command fails as required when Docker is unavailable:

```text
IRONCLAW_REQUIRE_POSTGRES=1 cargo test -p ironclaw_telemetry --test repository_contract
  1 passed, 1 failed
  PostgreSQL is required but Docker could not start it:
  failed to initialize a docker client: Socket not found: /var/run/docker.sock
```

The environment has no `/var/run/docker.sock`, so live PostgreSQL parity is
not verified in this worktree. PostgreSQL compiles with the same typed contract
and migration/upsert/scan implementation, but the container leg must be rerun
on a Docker-enabled machine before calling cross-backend runtime parity proven.

## Implementation notes and limitations

- libSQL timestamps are canonical nanosecond RFC3339 UTC text; PostgreSQL uses
  `TIMESTAMPTZ`.
- Every non-empty `upsert_batch` acquires one writer/client, opens one
  transaction, preflights signed-counter overflow, writes every family, then
  commits. A failure before commit drops the whole transaction.
- Hourly counters use checked preflight accumulation and database additive
  `existing + excluded` expressions. Lifecycle conflicts are deterministic
  no-ops on `(tenant_id,event_id)`.
- Scans are tenant-bound, half-open, bounded to 2,000 rows per page, ordered by
  the documented key tuple, and use opaque length-prefixed cursors.
- The repository layer intentionally does not create pools/runtimes, parse
  URLs or filesystem paths, select a backend, or expose a worker/recorder.
- Unknown persisted enum strings fail closed with a typed
  `UnknownEnum` error. Product-facing sanitization and export framing remain
  follow-up tasks.

Commit: `feat(telemetry): persist hourly facts with backend parity`
