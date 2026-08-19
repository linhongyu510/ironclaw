# ironclaw_notifications — working rules

- Own durable user Inbox record grammar and lifecycle invariants only.
- Store metadata and typed references only; never persist message bodies,
  prompts, tool inputs/outputs, secrets, host paths, or backend diagnostics.
- Keep read, resolved, and archived timestamps orthogonal.
- Publication is idempotent by stable notification id; conflicting reuse fails
  closed.
- Recipient scope is mandatory on every read and mutation.
- Retention is explicit: never delete unread or unarchived records to make room.
- The snapshot carries a 1,000-record bound. At the bound a publish reclaims the
  oldest record that is both resolved and archived: it is terminal and already
  dismissed, so the only stable-ID reuse it stops absorbing is a stale producer
  retry. When nothing is closed the publish fails instead of evicting live
  state, so a full inbox of open gates is never silently thinned.
- Persistence uses `ScopedFilesystem` plus bounded CAS; backend selection stays
  in composition.
- Notification production and product read policy belong to the originating
  workflow in `ironclaw_assistant`; external delivery belongs to
  `ironclaw_outbound`.

## Validation

- `cargo test -p ironclaw_notifications`
- `cargo clippy -p ironclaw_notifications --all-targets -- -D warnings`
- `cargo test -p ironclaw_architecture_tests`
