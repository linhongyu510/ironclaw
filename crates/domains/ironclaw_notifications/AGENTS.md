# ironclaw_notifications — working rules

- Own durable user Inbox record grammar and lifecycle invariants only.
- Store metadata and typed references only; never persist message bodies,
  prompts, tool inputs/outputs, secrets, host paths, or backend diagnostics.
- Keep read, resolved, and archived timestamps orthogonal.
- Publication is idempotent by stable notification id for every record the
  snapshot still holds; conflicting reuse of a held id fails closed. That window
  is finite, not unbounded — see the bound below — so a producer must not treat
  an arbitrarily delayed retry as guaranteed deduplication.
- Recipient scope is mandatory on every read and mutation.
- Retention is explicit: never delete unread or unarchived records to make room.
- The snapshot carries a 1,000-record bound, and that bound *is* the idempotency
  window: a publish at the bound reclaims the oldest record that is both
  resolved and archived, and a later retry for a reclaimed id is admitted as a
  new record rather than recognised as a duplicate. When nothing is closed the
  publish fails instead of evicting live state, so a full inbox of open gates is
  never silently thinned. Widening the window means retaining durable
  deduplication state for reclaimed ids, which is a persisted-schema change and
  needs its own rollback review.
- Persistence uses `ScopedFilesystem` plus bounded CAS; backend selection stays
  in composition.
- Notification production and product read policy belong to the originating
  workflow in `ironclaw_assistant`; external delivery belongs to
  `ironclaw_outbound`.

## Validation

- `cargo test -p ironclaw_notifications`
- `cargo clippy -p ironclaw_notifications --all-targets -- -D warnings`
- `cargo test -p ironclaw_architecture_tests`
