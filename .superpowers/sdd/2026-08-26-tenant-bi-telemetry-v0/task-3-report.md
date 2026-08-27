# Task 3 report — tenant BI telemetry repository

## Scope

Implemented the six schema-v0 telemetry tables and their tenant/time indexes,
shared repository contract, libSQL adapter, PostgreSQL adapter, typed scan
requests/pages/cursors, additive hourly upserts, lifecycle idempotency, and
single-transaction batch writes. Backend constructors remain private pending
the later composition bridge. No queue, worker, producer, composition,
product, WebUI, or generic export endpoint was added.

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
all six complete table/key/type/nullability/check shapes and four indexes,
one-acquisition/one-transaction admission count (including the empty-batch
zero-acquisition case), rollback after a database error, unknown persisted
enums, and sub-microsecond normalization. The schema helper compares each
normalized table body exactly, rejects defaults, and is called by both adapter
migration tests.

The second review-fix cycle also had a controlled runtime-hook RED. Removing
the admission hook from both adapters while leaving the shared test intact
produced this focused failure:

```text
cargo test -p ironclaw_telemetry --lib repository_contract_tests::libsql_repository_contract -- --nocapture
1 failed: assertion `left == right` failed
left: AdmissionStats { acquisitions: 0, transaction_starts: 0, releases: 0, max_active: 0 }
right: AdmissionStats { acquisitions: 1, transaction_starts: 1, releases: 1, max_active: 1 }
```

Restoring the runtime hooks made the same test pass. This pins the neutral
instrumented seam rather than counting source-string occurrences.

After implementation, the shared `assert_repository_contract` harness is
invoked by both private libSQL and PostgreSQL adapter tests and covers migration replay,
additive replay, tenant/user/hour/provider/model/origin/kind isolation, all six
row families, timestamp range ordering, half-open ranges, open-hour
exclusion/inclusion, provider/model filters, delimiter-safe deterministic
cursor pagination across three pages, overflow rollback, rollback after a
mid-transaction database error, and lifecycle replay behavior.

## Verification

Passed:

```text
cargo test -p ironclaw_telemetry --test repository_contract -- --nocapture
  3 passed (public request checks plus the Docker availability gate; backend
  parity runs in crate unit tests because constructors are intentionally private)

cargo test -p ironclaw_telemetry --all-targets --all-features
  28 passed, 0 failed (10 library, 15 hour-bucket, 3 repository-contract)

cargo test -p ironclaw_telemetry --lib -- --nocapture
  10 passed, 0 failed (shared backend parity harness included)

cargo test -p ironclaw_telemetry --test repository_contract -- --nocapture
  3 passed, 0 failed (public request checks plus non-strict Docker gate)

cargo clippy -p ironclaw_telemetry --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo test -p ironclaw_architecture_tests --test reborn_dependency_boundaries \
  -- reborn_crate_dependency_boundaries_hold
cargo test -p ironclaw_architecture_tests --test reborn_persistence_driver_boundary
  17 passed, 0 failed (including the telemetry public driver-containment
  ratchet, which recursively scans the complete telemetry production source
  tree)

cargo test -p ironclaw_architecture_tests --no-fail-fast
  316 listed architecture tests passed across the full package
```

The strict PostgreSQL command fails as required when Docker is unavailable:

```text
IRONCLAW_REQUIRE_POSTGRES=1 cargo test -p ironclaw_telemetry --test repository_contract -- --nocapture
  2 passed, 1 failed
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
  commits. A neutral instrumented admission seam proves one acquisition,
  transaction start, and release with no nested/parallel admission for both
  adapters; empty batches return without acquiring a handle.
- The shared parity assertions check additive values for activity, model,
  failure, automation, and coverage rows—not only row counts—and verify every
  schema-v0 column type, nullability, default absence, check constraint, key,
  and tenant-leading index shape.
- Hourly counters use checked preflight accumulation and database additive
  `existing + excluded` expressions. Lifecycle conflicts are deterministic
  no-ops on `(tenant_id,event_id)`.
- Scans are tenant-bound, half-open, bounded to 2,000 rows per page, ordered by
  the documented key tuple, and use opaque length-prefixed cursors.
- Backend modules and constructors are private, with no public repository
  adapter bridge in this task. The later composition task owns the admitted
  handle bridge; repository errors carry neutral boxed causes rather than
  driver types.
- The repository layer intentionally does not create pools/runtimes, parse
  URLs or filesystem paths, select a backend, or expose a worker/recorder.
- Unknown persisted enum strings fail closed with a typed `UnknownEnum` error;
  corrupt persisted identifiers return `InvalidPersistedField` with the
  original validation cause. Product-facing sanitization and export framing
  remain follow-up tasks.
- Docker was unavailable (`/var/run/docker.sock` absent), so strict PostgreSQL
  runtime parity could not be exercised locally. The strict command fails
  loudly with 2 request checks passing and 1 PostgreSQL availability check
  failing, as required; rerun the private backend contract on a Docker-enabled
  machine.

Initial implementation commit: `feat(telemetry): persist hourly facts with backend parity`.
Review-fix commit: `fix(telemetry): close repository parity review gaps`.
Second review-fix commit: this commit (runtime admission seam, private
adapter boundary, full schema ratchet, and shared additive assertions).
