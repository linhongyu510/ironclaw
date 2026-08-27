# Task 4 report — bounded recorder and single batch worker

## Scope

Implemented the domain-owned asynchronous telemetry recorder only. The change
does not wire producers, composition, `ProductSurface`, WebUI, SQL migrations,
or an export endpoint.

The public shape is:

```text
BufferedTelemetryRecorder::spawn(config, repository, clock)
  -> (Arc<dyn TelemetryRecorder>, BufferedTelemetryRecorderHandle)
```

The recorder owns one bounded Tokio MPSC queue and calls `try_send` exactly once
per producer call. The lifecycle handle owns one consumer task. The consumer
aggregates each drain with the existing `aggregate_batch` contract, performs a
single sequential `upsert_batch`, and never holds a lock across repository I/O.

## Test-first evidence

### RED

Before adding production recorder/worker code, the new contract test was run:

```text
cargo test -p ironclaw_telemetry --test buffered_recorder_contract
```

It failed because `BufferedRecorderConfig`, `BufferedTelemetryRecorder`,
`RecordOutcome`, and `TelemetryClock` did not yet exist. Tokio test-time
advancement was also initially unavailable until the test-only `test-util`
feature was added. This was the expected missing-behavior failure, not a typo in
the fake repository.

### GREEN

The final focused run passes 9 tests:

```text
cargo test -p ironclaw_telemetry --test buffered_recorder_contract
```

The tests cover synchronous producer behavior and typed queue pressure, the
512-observation threshold, one-second virtual-time flushing, non-overlapping
repository writes, one failed drain followed by a successful drain, coverage
counter carry-forward, invalid aggregate handling, graceful tail flushing,
five-second stalled-write abort, and a fresh worker after shutdown.

All timing tests use `#[tokio::test(start_paused = true)]` and
`tokio::time::advance`; no real sleeps are used. `FixedClock` supplies the
injected wall-clock value, and flush latency is derived from that injected
clock, making diagnostics deterministic.

## Failure and coverage semantics

- Producer outcomes are `Accepted`, `DroppedQueueFull`, and `DroppedClosed`;
  typed observations are validated by the contracts crate before they reach
  this port.
- Aggregation failures drop that drain, increment the invalid count, and do not
  call the repository.
- Repository errors drop only the ambiguous drain, increment write-loss and a
  typed repository failure class, and do not retry it. Later drains continue.
- Successful coverage rows include accepted observations and carry forward
  invalid/write-failed facts from prior failed or invalid drains. Coverage is
  grouped by tenant and UTC hour and remains count-only.
- Queue and lifecycle pressure are retained as count-only diagnostics; no
  observation fields are logged or included in diagnostics.

## Shutdown

Shutdown closes intake, cancels the consumer, synchronously drains the bounded
tail through sequential repository writes, and waits no longer than the typed
five-second budget. A stalled repository call is aborted at the budget boundary;
the product path is never made to await telemetry.

## Validation

Passing checks:

```text
cargo test -p ironclaw_telemetry --test buffered_recorder_contract  # 9 passed
cargo test -p ironclaw_telemetry --all-targets --all-features      # 37 passed
cargo clippy -p ironclaw_telemetry --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo test -p ironclaw_architecture_tests --test reborn_dependency_boundaries
```

The architecture dependency-boundary suite passed all 42 tests. The only
lockfile change is the telemetry package's direct `tokio-util` dependency.

## Commit

`1932c536f1 feat(telemetry): batch best-effort observations asynchronously`
