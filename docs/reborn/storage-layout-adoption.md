# Reborn Storage Layout Adoption Runbook

This is the operator procedure for moving one supported released Reborn home
to the profile-stable layout. It is a bounded operation performed either by a
deployment-authorized migration startup or by the manual recovery command. It
does not merge deployments, discover arbitrary directories, or make profiles
interchangeable.

## Target layout and boundary

`IRONCLAW_REBORN_HOME` is the one installation storage boundary. After a
successful adoption, its durable filesystem layout is:

```text
<IRONCLAW_REBORN_HOME>/
├── config.toml and providers.json
├── layout.toml
├── state/
│   ├── reborn-local-dev.db and recognized libSQL sidecars
│   └── .reborn-local-dev-secrets-master-key
├── system/
│   ├── extensions/
│   ├── prompts/
│   └── skills/
├── workspaces/users/<tenant-user-digest>/
└── runtime/layout-adoption/
    ├── journal.toml
    └── snapshot/<legacy-source>/
```

`state/` is authoritative application state. `system/` contains host-managed
extensions, prompts, and skills. `workspaces/users/<tenant-user-digest>/` is a
persistent tenant-plus-user workspace leaf. `runtime/` contains provider and
process bookkeeping plus bounded adoption recovery. Cache and temporary
invocation data are disposable and never replace any of these authoritative
namespaces.

There is no deployment-id directory and no profile-named state directory. The
root `layout.toml` is published last and records the durable-state and security
envelope that startup admits. Until it exists and validates, normal startup
refuses to open stores or start traffic.

## Before touching a populated home

1. Stop every `ironclaw` process and service that could use the home. Verify
   this operationally; lack of a known PID or socket is not proof of quiescence.
2. Take and retain a filesystem/volume snapshot or backup of the entire home.
   Automatic adoption retains its own rollback snapshot, but that snapshot is
   on the same storage and is not protection against volume loss.
3. Perform a read-only inventory. There is no write-free `storage adopt`
   mode. `doctor` checks binary/configuration readiness only; it does **not**
   inspect `layout.toml`, adoption journals, legacy candidates, or security
   envelope compatibility. Run the normal startup admission under the
   validate-only profile, using the same production database/environment
   configuration the deployment will use:

   ```bash
   export IRONCLAW_REBORN_HOME=/absolute/path/to/ironclaw-reborn
   find "$IRONCLAW_REBORN_HOME" -maxdepth 2 -mindepth 1 -print | sort
   IRONCLAW_REBORN_PROFILE=migration-dry-run ironclaw serve
   ```

   This command is expected to exit non-zero after validation with
   `profile=migration-dry-run ... must not start live Reborn runtime traffic`.
   An earlier layout, journal, candidate, envelope, or production-storage
   error means admission failed and must be resolved first. The validate-only
   profile neither adopts nor initializes a layout and never starts a listener
   or live runtime traffic.

4. Identify the single supported populated legacy source. `local-dev/` and
   `hosted-single-tenant-volume/` are released sources; the bare-home DB/key
   set is a separate legacy candidate. More than one populated candidate is a
   conflict. The command makes no writes, chooses no source, and never merges
   them.
5. A populated `hosted-single-tenant-volume-sandboxed/` root is unreleased.
   It is not an adoption source. Preserve it for inspection and explicitly
   archive it under operator control; do not expect automatic workspace merge.

## Deployment-authorized automatic adoption

Normal startup never treats the presence of a legacy root as proof that old
replicas are stopped. Without explicit cutover authority it exits before
creating a journal or moving the source and prints the recovery command.

After the deployment has stopped every old replica, authorize the migration
startup with the exact versioned value:

```bash
IRONCLAW_REBORN_STORAGE_CUTOVER=legacy-layout-v1 ironclaw serve
```

Startup performs automatic adoption only for exactly one supported legacy
source or a compatible interrupted journal. It takes a new-binary cutover lock,
revalidates the source or journal under that lock, verifies the production
store, runs the existing journaled state machine, publishes `layout.toml` last,
and starts traffic only after the canonical stores reopen successfully. A
competing new replica fails before verification or source mutation.

Remove `IRONCLAW_REBORN_STORAGE_CUTOVER` after the canonical layout is ready.
Later starts see the valid manifest and do not need migration authority.

The environment value is an operator/deployment attestation, not a process
probe. Never set it while an old binary can still write the legacy database.
Old releases do not participate in the new cutover or adoption locks.

Automatic startup refuses multiple roots, unknown content, the unreleased
sandbox root, incompatible security envelopes, invalid journals, and journals
that contain an external workspace import. Those cases remain manual.

## Manual adoption and recovery

For an ambiguous deployment, an explicit external workspace import, or manual
recovery, keep services stopped and run:

```bash
ironclaw storage adopt \
  --confirm-processes-stopped \
  --confirm-backup-snapshot
```

The command uses one journaled source, takes ownership of its retained snapshot
under `runtime/layout-adoption/snapshot/`, stages into journal-owned paths, and
publishes `layout.toml` only after the canonical store and secret resolver
verify. It never automatically deletes the source snapshot, adoption journal,
or an external workspace source.

For embedded libSQL, verification reopens the adopted database and encrypted
secret resolver. For hosted PostgreSQL, the command validates both operator
acknowledgements before opening the configured pool or running production
filesystem migrations. It then constructs the encrypted secret store and, when
existing encrypted secret or credential-account records are present,
authenticates one of those records with the configured master key before making
any filesystem mutation. An empty store has no existing ciphertext against
which a key can be checked. Connection, migration, or key-verification failures
leave the legacy source in place and do not publish `layout.toml`.

Released tenant/user skill trees under
`tenants/<tenant>/users/<user>/skills/` remain in the retained adoption
snapshot and are imported through the normal boot importer into the canonical
database. Any other content under a legacy `tenants/` tree is rejected rather
than guessed or broadened to another owner.

If automatic adoption is interrupted, leave the home in place and keep old
services stopped. Retry startup with the same versioned cutover value when the
journal has no external workspace import; otherwise rerun the explicit manual
command. Both paths resume only the exact journaled phase and snapshot. They
refuse unexplained partial layouts, unsupported journal or manifest versions,
symlinks, unknown source content, or canonical conflicts. Do not manually
combine staged files, database sidecars, or workspace leaves.

## Profiles, workspaces, and credentials

A profile selects runtime policy and process backend only. It may be changed
only by an operator-controlled restart. Startup compares the requested profile
with the persisted `layout.toml` security envelope and rejects changes that
alter durable backend, tenancy, or weaken per-caller workspace isolation.

For Docker, a sandbox gets exactly one selected
`workspaces/users/<tenant-user-digest>` leaf as `/workspace`. It never receives
the Reborn home, `state/`, the cached master key, `system/`, `runtime/`, a
workspace parent, sibling workspaces, provider credentials, Railway tokens, or
a Docker socket. Railway checkpoints use the same typed scope but are
provider-specific; they are not a portable migration of Docker workspace
contents, and changing provider/environment requires a separate operator plan.

## Rollback and retention

Keep the external backup and the retained adoption snapshot through the agreed
rollback window. A compatible profile rollback after adoption is only a
restart with another admitted policy and reuses the same canonical layout.

Rolling back to an old binary is one-way and operational: stop IronClaw,
preserve/archive the canonical target, then restore the retained snapshot to
its original legacy location (or restore the full pre-adoption backup/home)
before starting the old binary. An old binary cannot safely read the canonical
layout. Never run old and new binaries against diverging copies. This procedure
does not delete any source, snapshot, journal, or workspace.

## Regression commands

The bounded layout state machine is covered by
`crates/app/ironclaw_cli/src/runtime/storage_layout.rs` tests. The canonical
path and transition contract is covered by
`crates/app/ironclaw_config/tests/profile_contract.rs`; run:

```bash
cargo test -p ironclaw_config --test profile_contract
cargo test -p ironclaw storage_layout
cargo test -p ironclaw --test storage_adoption
cargo test -p ironclaw_composition --test profile_acceptance
IRONCLAW_REQUIRE_DOCKER_TESTS=1 \
  cargo test -p ironclaw_sandbox --test user_sandbox_docker_live -- --nocapture
IRONCLAW_REQUIRE_DOCKER_TESTS=1 \
  cargo test -p ironclaw_integration_tests --test reborn_integration_sandbox_shell_turn -- --nocapture
```

The Railway live canary remains provider-specific and opt-in:

```bash
cargo test -p ironclaw_sandbox --test railway_sandbox_live -- --ignored --nocapture
```
