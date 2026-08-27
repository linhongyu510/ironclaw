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

The review-fix cycle also began with this focused RED before the fixes:

```text
cargo test -p ironclaw_telemetry --lib -- --nocapture
5 failed: activity/model bind layouts, nullable PostgreSQL model filters,
delimiter-based cursor decoding, and nanosecond timestamp output
```

Those cases now pass, with additional shared tests for persisted-field causes,
all six table/key and four index shapes, admission count, rollback after a
database error, unknown persisted enums, and sub-microsecond normalization.

After implementation, the shared `assert_repository_contract` harness is
invoked by both the libSQL and PostgreSQL tests and covers migration replay,
additive replay, tenant/user/hour/provider/model/origin/kind isolation, all six
row families, timestamp range ordering, half-open ranges, open-hour
exclusion/inclusion, provider/model filters, delimiter-safe deterministic
cursor pagination across three pages, overflow rollback, rollback after a
mid-transaction database error, and lifecycle replay behavior.

## Verification

Passed:

```text
cargo test -p ironclaw_telemetry --test repository_contract
  2 passed (libSQL passed; PostgreSQL leg reported the unavailable Docker
  client and returned only in the non-strict deployment shape)

cargo test -p ironclaw_telemetry --all-targets --all-features
  27 passed, 0 failed (10 unit, 15 hour-bucket, 2 repository-contract)

cargo clippy -p ironclaw_telemetry --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo test -p ironclaw_architecture_tests --test reborn_dependency_boundaries \
  -- reborn_crate_dependency_boundaries_hold
cargo test -p ironclaw_architecture_tests --test reborn_persistence_driver_boundary
  17 passed, 0 failed (including the telemetry public driver-containment
  ratchet)

cargo test -p ironclaw_architecture_tests --no-fail-fast
  316 listed architecture tests passed across the full package
```

The strict PostgreSQL command fails as required when Docker is unavailable:

```text
IRONCLAW_REQUIRE_POSTGRES=1 cargo test -p ironclaw_telemetry --test repository_contract -- --nocapture
  1 passed, 1 failed
  PostgreSQL is required but Docker could not start it:
  failed to initialize a docker client: Socket not found: /var/run/docker.sock
```

The environment has no `/var/run/docker.sock`, so live PostgreSQL parity is
not verified in this worktree. PostgreSQL compiles with the same typed contract
and migration/upsert/scan implementation, but the container leg must be rerun
on a Docker-enabled machine before calling cross-backend runtime parity proven.

## Implementation notes and limitations

- Both adapters normalize timestamps to UTC microsecond precision before
  persistence, range binding, and cursor encoding. libSQL stores canonical
  RFC3339 UTC text; PostgreSQL uses `TIMESTAMPTZ`.
- Every non-empty `upsert_batch` acquires one writer/client, opens one
  transaction, preflights signed-counter overflow, writes every family, then
  commits. A failure before commit drops the whole transaction.
- Hourly counters use checked preflight accumulation and database additive
  `existing + excluded` expressions. Lifecycle conflicts are deterministic
  no-ops on `(tenant_id,event_id)`.
- Scans are tenant-bound, half-open, bounded to 2,000 rows per page, ordered by
  the documented key tuple, and use opaque length-prefixed cursors.
- Backend modules and constructors are private. The public repository handle
  accepts only an already-admitted opaque conversion, and repository errors
  carry neutral boxed causes rather than driver types.
- The repository layer intentionally does not create pools/runtimes, parse
  URLs or filesystem paths, select a backend, or expose a worker/recorder.
- Unknown persisted enum strings fail closed with a typed `UnknownEnum` error;
  corrupt persisted identifiers return `InvalidPersistedField` with the
  original validation cause. Product-facing sanitization and export framing
  remain follow-up tasks.
- Docker was unavailable (`/var/run/docker.sock` absent), so strict PostgreSQL
  runtime parity could not be exercised locally. The strict command fails
  loudly with 1 passing libSQL test and 1 failing PostgreSQL test, as required;
  rerun it on a Docker-enabled machine.

Initial implementation commit: `feat(telemetry): persist hourly facts with backend parity`.
Review-fix commit: `fix(telemetry): close repository parity review gaps`.
