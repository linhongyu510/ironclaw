# Task 4 report — bounded asynchronous tenant telemetry recorder

## Scope

Task 4 is implemented in the telemetry domain only. The public construction
shape is:

```text
BufferedTelemetryRecorder::spawn(config, repository, clock)
  -> (Arc<dyn TelemetryRecorder>, BufferedTelemetryRecorderHandle)
```

The implementation does not add producers, composition wiring, `ProductSurface`,
WebUI routes, SQL migrations, or an export endpoint.

## Test-first evidence

The original contract tests were written before the recorder and worker existed.
The first run of the focused command failed because the recorder types and
clock were missing; enabling Tokio's test-time support was also required for
the paused-clock tests.

For the review-fix round, the new coverage, shutdown accounting, invalid
preflight, and concurrent close/send tests were run before the corresponding
production changes. The focused run initially failed at compilation because
`BufferedTelemetryRecorderHandle::close_intake` was not yet present. After the
implementation, the final focused run passed all 14 tests.

## Queue and worker semantics

- There is one bounded Tokio MPSC queue, with an 8,192-observation default.
- An open producer call performs one synchronous `try_send`; it never awaits,
  acquires a repository handle, or holds a lock across I/O.
- Intake closure and `try_send` are linearized under one narrow synchronous
  state lock. Once closure wins, the observation is never passed to
  `try_send`, so `DroppedClosed` cannot describe an enqueued observation.
- Outcomes are `Accepted`, `DroppedQueueFull`, `DroppedClosed`, and
  `DroppedInvalid`.
- The single worker drains at most 512 observations or waits at most one
  second, aggregates before persistence, and performs sequential repository
  upserts with no overlapping workers.
- A repository failure drops only the ambiguous drain, records its typed
  failure class, carries count-only write-failure coverage forward, and lets
  later drains continue without retrying the failed drain.

## Count-only coverage and invalid handling

Queue-full, closed, and invalid producer outcomes enter a bounded side
accumulator keyed only by `(tenant_id, UTC hour)`. It retains at most 8,192
distinct keys; once full, the global overflow diagnostic records that
attribution was unavailable rather than allowing producer-side memory to grow.
The worker merges these deltas into `CollectorCoverage` rows. Contract tests
verify durable queue-full, closed, invalid-preflight, and invalid-aggregate
coverage values.

`DroppedInvalid` is synchronous. A bounded pure preflight checks supported UTC
timestamp years/hour conversion, signed durable counter ranges, and lifecycle
user attribution before queue admission. A validly constructed run at year
10,000 exercises the timestamp path. Aggregate-only overflow remains an
`Accepted` drain fact and is recorded in coverage as an invalid aggregate
without a repository write for that drain.

Collector instance ID resolution now handles construction errors explicitly,
records a typed diagnostic, and attempts the valid count-only fallback ID;
coverage is not silently disabled by an ignored constructor error.

## Shutdown and loss accounting

Shutdown closes intake, cancels the worker, and allows a bounded tail flush for
no more than five seconds. If a repository write remains stalled, the worker is
aborted at the timeout and diagnostics report `ShutdownTimeout`, typed write
loss, and the exact number of accepted observations still queued or in flight.
The paused-time stalled-write test proves two observations (one in flight and
one queued) are accounted exactly and that shutdown completes at the five
second budget boundary. It also verifies that no batch is claimed persisted
when the stalled repository produced none. Losses whose database write could
not complete are therefore reported as abandoned/write-loss facts, not as
successful durable coverage; known durable coverage is retained for successful
later drains.

## Privacy and diagnostics

Operational state contains only counts, timings, typed failure classes, and the
tenant/hour key needed for count-only coverage. No observation payload,
provider/model content, identifiers beyond the approved tenant/hour key, or
raw repository error text is logged or placed in diagnostics.

## Validation

The following checks passed after the review fixes:

```text
cargo test -p ironclaw_telemetry --test buffered_recorder_contract
14 passed; 0 failed

cargo test -p ironclaw_telemetry --all-targets --all-features
42 passed; 0 failed (10 unit + 14 recorder + 15 hour-bucket + 3 repository)

cargo clippy -p ironclaw_telemetry --all-targets --all-features -- -D warnings
finished with no warnings

cargo fmt --all -- --check
passed

cargo test -p ironclaw_architecture_tests --test reborn_dependency_boundaries
42 passed; 0 failed
```

## Commit

Implementation and review-fix commit: `1c0c4ba1c6`
