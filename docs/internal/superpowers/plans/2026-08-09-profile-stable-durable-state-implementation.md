# Profile-Stable Durable State Implementation Plan

Status: approved and implemented on `design/profile-stable-state`. This plan is
the retained implementation record; its historical current-main evidence and
legacy-layout inventory remain intentionally descriptive.

## Objective

Make `IRONCLAW_REBORN_HOME` the installation storage boundary for every
filesystem-backed Reborn profile. Runtime profiles may select policy and a
process backend, but they must not select physical application-state or system
content directories.

The implementation must preserve released local state, reject ambiguous
legacy layouts, keep profile transitions restart-only and operator-controlled,
and ensure a sandbox receives only the authenticated tenant/user workspace
leaf as `/workspace`.

## Current-main evidence

The branch was refreshed against `origin/main` at
`89285c8e700d5d55d8e838f5cf351016be0754f6`. The branch is two documentation
commits ahead. Before this uncommitted plan was drafted, its only tree
difference from `origin/main` was the design specification.

The live implementation still has the reported coupling:

- `RebornProfile::local_runtime_storage_subdir` maps profiles to
  `local-dev`, `hosted-single-tenant`, `hosted-single-tenant-volume`, or the
  unreleased sandbox root.
- The CLI joins that value directly beneath `IRONCLAW_REBORN_HOME`.
- The selected root owns `reborn-local-dev.db`, the cached secrets master key,
  and host-backed system extensions, prompts, and skills.
- Docker workspaces live below the selected sandbox profile root, while
  Railway workspaces live in provider checkpoints.

Two existing caller-level assertions can demonstrate red-before/green-after:

1. `ironclaw_config/tests/profile_contract.rs` currently requires the
   profile-derived directory names.
2. `ironclaw_cli/src/runtime/mod.rs` currently requires
   `<home>/hosted-single-tenant-volume` for the hosted-volume profile.

The current `profile_contract` suite passes 10/10, proving that the old layout
is the contract on current main rather than a documentation-only claim.

## Released layout inventory

| Legacy directory | Released status | Authoritative contents | Adoption rule |
| --- | --- | --- | --- |
| `local-dev/` | Released in v1.0.0 and v1.1.0 | Embedded libSQL application state, encrypted secrets, cached master key, system content | Supported embedded-state source |
| `hosted-single-tenant/` | Released | PostgreSQL is authoritative application state; this directory may contain system content | Supported only as a system-content source for the same PostgreSQL deployment; never treated as an embedded-state source |
| `hosted-single-tenant-volume/` | Released | Embedded libSQL application state, encrypted secrets, cached master key, system content | Supported embedded-state source |
| `hosted-single-tenant-volume-sandboxed/` | Unreleased | Embedded state plus Docker user workspaces | Never auto-adopt; fail with inspect/archive guidance |
| `hosted-single-tenant-volume-sandboxed-railway/` | Never a distinct directory | Railway state is provider-owned | Never a local adoption source |
| bare `<IRONCLAW_REBORN_HOME>` DB/key set | Released command-path behavior | `config set` and onboarding can create a second libSQL secret store and cached key directly at home | Treat as an independent legacy candidate; if it coexists with a populated profile root, fail closed and never merge |

`production` and `migration-dry-run` happen to map to `local-dev` in the old
compatibility helper, but their authoritative state is operator-supplied.
Changing embedded libSQL to PostgreSQL remains an explicit storage migration,
not layout adoption.

## Target filesystem layout

Keep released filenames when doing so makes adoption safer. In particular,
preserving the libSQL basename keeps any crash-recovery sidecars paired with
the database and avoids a second compatibility rename.

```text
<IRONCLAW_REBORN_HOME>/
|-- layout.toml
|-- config.toml
|-- providers.json
|-- state/
|   |-- reborn-local-dev.db
|   |-- reborn-local-dev.db-*
|   `-- .reborn-local-dev-secrets-master-key
|-- system/
|   |-- extensions/
|   |-- prompts/
|   `-- skills/
|-- workspaces/
|   `-- users/
|       `-- <tenant-user-digest>/
|-- runtime/
|   |-- docker/
|   |-- railway/
|   `-- layout-adoption/
|       |-- journal.toml
|       `-- snapshot/
|-- logs/
|-- cache/
`-- tmp/
```

The `runtime/layout-adoption/snapshot/` tree is migration evidence, not an
active profile root. It may retain the source profile name in metadata because
normal reads and writes never resolve through it.

The first implementation does not need to create empty `logs/`, `cache/`,
`tmp/`, or provider-runtime directories eagerly. Their path ownership is
reserved now; each owner creates its directory when it has real data.

Scope decision: a flatter first release with the DB/key directly at Reborn
home would reduce composition churn, but it is intentionally not selected. It
would defer the reviewed `state/` namespace, retain the overloaded application
root, and leave the current `/projects -> root` hazard to solve later. This plan
accepts the broader state/system/workspace split because that split is the
stated target, while containing its migration risk behind a deployment-authorized
cutover, the same bounded manual recovery command, and manifest-last commit. If reviewers want the narrow flat-root release
instead, that is a product-scope change requiring approval before coding.

### 2026-08-10 adoption amendment

The reviewed implementation combines Designs A and B. Ordinary startup still
does not infer that a legacy source is safe to move. When exactly one supported
source (or a compatible interrupted journal) is present, startup mutates it
only when the deployment supplies the exact, versioned cutover attestation
`IRONCLAW_REBORN_STORAGE_CUTOVER=legacy-layout-v1` after every old replica has
stopped. New binaries serialize that migration, revalidate the source or
journal under the cutover lock, verify the configured store, publish
`layout.toml` last, and only then start traffic.

Without that attestation, or for ambiguous/unsafe state, startup fails before
source mutation and prints the manual recovery command. The manual command
remains required for explicit external-workspace ownership and exceptional
recovery. This does not reverse the old-binary safety finding below: the
environment value is deployment authority, not evidence the binary can derive
locally, and it must never be used during a rolling old/new deployment.

## Designs considered

### Design A: locked boot-time adoption into the canonical layout

Every stateful boot acquires one installation-layout lock, inspects
`layout.toml`, detects legacy roots, and either initializes a new canonical
layout or resumes a one-time adoption. Exactly one supported populated source
is snapshotted and copied into canonical paths. `layout.toml` is written last,
after the canonical store opens and read-back verification succeeds.

Advantages:

- State and system content upgrade without a separate command when no
  externally rooted legacy workspace needs an ownership decision.
- The normal runtime has no standing legacy-path branch.
- A durable journal makes interruption and retry explicit.
- The preserved snapshot gives operators a defined rollback source.

Costs:

- Adoption temporarily needs enough space for the active canonical copy and
  the snapshot.
- Startup owns a small, carefully bounded filesystem state machine.
- A populated cwd-backed legacy workspace stops automatic adoption until the
  operator supplies its tenant/user owner through the explicit adoption
  command described below; the product must not guess that ownership.

Fatal limitation for unconditional adoption: old binaries do not participate in the
new lock. A still-running process may retain DB/WAL file descriptors while the
new binary renames or copies the legacy root, so a consistent libSQL snapshot
cannot be guaranteed. Therefore automatic physical adoption is admitted only
after the deployment supplies the versioned cutover attestation described in
the amendment above; otherwise startup fails closed.

### Design B: explicit offline `ironclaw storage adopt` command

Normal startup detects legacy or partial-layout state and refuses to proceed
without mutating it. After stopping every old IronClaw process and taking an
operator backup/snapshot, an operator runs a dedicated command. The command
checks fixed candidates, records one source, creates migration-owned staging,
verifies the canonical copy, and commits `layout.toml` last. IronClaw is
started separately after the command succeeds.

Advantages:

- Migration side effects are maximally explicit.
- It never copies a database as an automatic side effect of ordinary startup.
- Operational backup and disk-capacity checks are easy to place in a runbook.

Costs:

- Existing unattended deployments stop after upgrade until an operator acts.
- The operator must establish quiescence; a new lock cannot exclude an old
  binary that does not know about it.
- A small command surface is maintained alongside read-only boot detection.

Original recommendation: use this design despite the operational stop. The
2026-08-10 amendment preserves its quiescence requirement while allowing the
deployment to authorize the same state machine during startup. Optional workspace import
uses `--workspace-source <path> --tenant <id> --user <id>`; it previews the
source and destination, requires confirmation, records the decision in the
same journal, and never deletes the external source. This remains one bounded
layout command, not a generic migration framework.

### Design C: permanent legacy-path compatibility adapter

`layout.toml` points normal reads and writes at an existing profile directory,
with canonical paths acting as aliases or symlinks.

Advantages:

- Minimal initial data movement.
- Old binaries can continue finding the original directory.

Costs:

- Profile-named paths remain authoritative.
- Every store open retains migration-era branching.
- Symlink/alias containment adds security and rollback ambiguity.
- The intended direct-at-home layout is never actually reached.

Reject for the target implementation.

## Rust types and ownership

### `ironclaw_config`: pure boot and layout contracts

Add `storage_layout.rs` containing side-effect-light values only:

```rust
pub enum StateLayoutVersion { V1 }
pub enum DurableStateKind { EmbeddedLibSql, ExternalPostgres }
pub enum TenancyModel { SingleUser, MultiUser }
pub enum WorkspaceAccessFloor { SingleTrustedOperator, PerCallerIsolated }

pub struct DeploymentSecurityEnvelope {
    pub tenancy: TenancyModel,
    pub workspace_access_floor: WorkspaceAccessFloor,
}

pub struct RebornStoragePaths { /* validated paths derived from RebornHome */ }
pub struct LayoutManifest { /* version, state kind, security envelope */ }
pub enum ProfileTransitionAdmission { Allowed, Rejected { reason: String } }
```

`RebornStoragePaths` derives `state/`, `system/`, `workspaces/`, and `runtime/`
directly from `RebornHome`; it accepts no profile argument. `LayoutManifest`
uses `serde(deny_unknown_fields)` and a versioned TOML wire shape.

This crate parses/validates the manifest and performs the pure compatibility
decision between a stored envelope and a caller-supplied requested envelope.
It does not map profiles, acquire locks, copy files, open databases, or write
application state. Manifest fields are fixed versions/enums only—never paths
or transient process authority.

The canonical profile-to-policy mapping remains
`ironclaw_composition::DeploymentConfig::for_profile`. Add one pure method on
that resolved value to derive the requested storage/security requirement from
its existing deployment kind and `workspace_scoped_per_caller` axes. CLI boot
uses that result for admission before any store or runtime owner is built;
there is no second profile-policy table in `ironclaw_config`.

### `ironclaw_cli`: installation-layout adoption and boot orchestration

Add `runtime/storage_layout.rs` as the sole physical adoption owner. Startup
uses a valid ready manifest, initializes a genuinely fresh empty layout, or
classifies legacy state. A single supported source or compatible journal may
enter the bounded adoption state machine only with the exact deployment
cutover attestation; otherwise startup fails before migration writes. Multiple,
unknown, incompatible, or workspace-bearing states remain manual failures.

The explicit command:

- acquires an advisory lock under the selected Reborn home;
- detects populated supported and unsupported legacy roots;
- requires explicit confirmation that old IronClaw processes are stopped and
  that an operator backup/snapshot exists; known PID/socket checks are useful
  diagnostics but are not represented as proof against old binaries;
- creates and atomically updates the adoption journal;
- snapshots one selected legacy root;
- copies known entries into one journal-owned staging tree using no-follow
  file operations;
- syncs files and parent directories, installs complete `state/` and `system/`
  trees, opens the canonical store for bounded verification, and atomically
  writes and syncs `layout.toml` last.

There is no runtime completion token. Every stateful command first calls the
same ready-layout prerequisite; pure/read-only commands remain side-effect
free. If no valid manifest exists, normal stateful commands cannot open
canonical or legacy stores.

The prerequisite applies to every CLI path that opens or writes the standalone
database, cached master key, or secret store, not only commands that build the
full runtime. In particular, `config set`, onboarding, master-key provisioning,
and OAuth credential fallback must resolve the canonical layout first and
receive its explicit `state_root`; none may call the legacy profile-root helper.

Do not put migration policy in the composition root and do not create a
generic migration registry.

### `ironclaw_host_api`: one neutral tenant/user workspace identity

Add a neutral value such as `TenantUserWorkspaceKey`, built only from typed
`TenantId` plus `UserId`. It retains the existing length-prefixed SHA-256
formula and exposes a stable digest segment, not a host path.

This type has three real consumers, so it earns its place:

1. composition's caller-scoped `/workspace` mount target;
2. the local host process alias resolver;
3. Docker/Railway sandbox workspace and checkpoint naming.

Delete the duplicated sandbox-only tenant/user digest implementation after all
callers use the neutral key. Keep the separate broader sandbox scope key used
for saved-output/container scope where agent/project/thread identity is
intentional.

### `ironclaw_composition`: consume explicit paths and wire existing owners

Replace the overloaded local `root: PathBuf` input with explicit canonical
state, system, and workspace paths while preserving the existing single
`RebornStorageInput` construction path. The concrete input may be a small value
object, but it must not become a new factory hierarchy.

- libSQL and the secrets master-key resolver receive `state_root`;
- host extension, prompt, and bundled-skill seeding receive `system_root`;
- filesystem project mounts receive the configured workspace root;
- legacy disk-skill import receives only the journal's preserved snapshot
  source, when present;
- event-store configuration receives the canonical libSQL path;
- composition continues selecting existing filesystem backends and runtime
  process ports.

Composition validates that the supplied paths are disjoint and beneath the
selected home. It does not choose a legacy root, mutate the adoption journal,
or decide whether a profile transition is safe.

The disk mount catalog must stop mapping `/projects` to the old overloaded
root. Mount `/projects/workspace` directly to the selected canonical caller
workspace, mount only the reviewed `/system/*` leaves from `system_root`, and
keep libSQL/key paths out of every disk-backed agent mount. A released
cwd-backed coding directory is a legacy import source, not a permanent
profile-specific storage exception.

### `ironclaw_sandbox` and `ironclaw_host_runtime`: converge on one workspace

For local Docker:

- configure `RebornSandboxConfig.workspace_root` as
  `<home>/workspaces`;
- make composition's caller mount target
  `/projects/workspace/users/<tenant-user-digest>`;
- make the host process alias resolver use the same target formula;
- extend the sandbox transport's mandatory-workspace resolver so a
  `/workspace` grant is accepted only when its virtual target exactly equals
  the current typed caller key; resolve it directly to the already prepared
  `<home>/workspaces/users/<digest>` leaf rather than through a trusted parent
  mount source;
- reject the bare workspace root, a different digest, an empty tail, and any
  canonical or symlink escape outside that exact leaf;
- mount that leaf, and only that leaf, as `/workspace`.

This closes the current gap where file tools and Docker shell execution use
different physical workspace roots. It reuses
`RuntimeProcessPort -> UserSandboxProcessPort -> SandboxCommandTransport` and
does not add another process abstraction.

Railway keeps provider-owned workspace/checkpoint storage, but uses the same
typed tenant/user key. Switching Docker and Railway does not imply workspace
content migration.

No state path, database, master key, host home, provider credential, Docker
socket, sibling workspace, or Reborn-home parent is registered as a trusted
sandbox mount source.

## Layout manifest and transition admission

Proposed ready manifest:

```toml
schema_version = 1
state_layout_version = 1
durable_state = "embedded-libsql"

[security]
tenancy = "multi-user"
workspace_access_floor = "per-caller-isolated"
```

The manifest records established storage assumptions. It is not a persisted
runtime-policy source. Trusted boot configuration still resolves the current
runtime policy and process backend on every restart.

Admission happens after config/profile parsing and before store opening,
sandbox backend construction, extension activation, or listener startup.

`workspace_access_floor` records the minimum safe storage-access model, not
the current process backend. Process-disabled, Docker, and Railway boots can
therefore satisfy the same `per-caller-isolated` floor. Unrestricted host
execution cannot.

The implementation starts with an exhaustive caller/profile inventory pinned
in tests rather than deriving behavior from names:

| Profile | Durable state | Target system/workspace | Process backend | Manifest/adoption behavior |
| --- | --- | --- | --- | --- |
| disabled | none | none | none | no state layout |
| local-dev | embedded libSQL | canonical system + one operator-owned workspace leaf | existing local host policy | ready manifest required; legacy cwd import is explicit |
| local-dev-yolo | embedded libSQL | same canonical paths as local-dev | disclosed unrestricted host | same manifest; allowed only for single-trusted-operator envelope |
| hosted-single-tenant | external PostgreSQL | canonical system + caller-scoped workspace leaves | existing local-host runtime | manifest records external backend and single-trusted-operator access assumption |
| hosted-single-tenant-volume | embedded libSQL | canonical system + caller-scoped leaves | disabled | ready manifest required |
| hosted-single-tenant-volume-sandboxed | embedded libSQL | same canonical paths | Docker per-user sandbox | ready manifest and exact-leaf sandbox required |
| hosted-single-tenant-volume-sandboxed-railway | embedded libSQL | canonical system; Railway workspace is provider-backed | Railway per-user sandbox | same state manifest; workspace portability is not implied |
| production | operator-supplied backend | canonical local namespaces only when configured | operator-supplied policy | backend/envelope must match; normal traffic only after admission |
| migration-dry-run | same operator-supplied backend as production | validation only | no live process traffic | no layout/adoption writes; report what production would admit |

Before editing callers, inventory every use of `local_runtime_storage_root`,
standalone DB/key open, and runtime construction. Classify it as pure/read-only,
stateful without a runtime, or runtime-building, and pin whether it may write.
No stateful command is omitted from ready-layout admission.

| Stored envelope / requested change | Default result | Reason |
| --- | --- | --- |
| Same profile/security requirement | Allow | No assumption changes |
| Single-user `local-dev` <-> `local-dev-yolo` | Allow with existing yolo disclosure | Still one trusted user; authority change remains explicit at boot |
| Hosted volume with processes disabled -> Docker or Railway per-user sandbox | Allow | Requested runtime still satisfies the per-caller-isolated access floor |
| Docker <-> Railway per-user sandbox | Allow | Same tenancy and access floor; provider persistence differs |
| Docker/Railway sandbox -> hosted volume with processes disabled | Allow | Removes process authority |
| Multi-user scoped/sandboxed -> either local host profile | Reject | Host process can inspect sibling workspace leaves |
| Single-user -> multi-user | Reject | Requires ownership/auth/workspace migration |
| Multi-user -> single-user | Reject | Requires ownership conversion |
| Embedded libSQL <-> PostgreSQL | Reject | Requires explicit data migration |
| Different Reborn home or volume | No implicit transition | It is a different installation boundary; move/restore is operator-controlled |
| Production <-> migration dry run with the same external store/envelope | Allow validation only | Dry run never performs adoption writes or starts traffic |

The compatibility relation is explicit rather than inferred from enum order.
Adding a tenancy or access-floor variant must make the match non-exhaustive
until its transition rules and tests are supplied.

## Bounded legacy-adoption state machine

The state machine is deliberately finite and specific to this layout change.
There is no generic migration registry.

```text
BootInspect -> Ready | FreshInit | AdoptionRequired | Conflict

AuthorizedStartupOrManualAdopt:
Inspect -> QuiescenceConfirmed -> SnapshotOwned -> Staged
        -> CanonicalInstalled -> StoreVerified -> Ready
```

### Inspect

Startup performs this inspection before migration writes:

1. If a supported `layout.toml` exists, validate transition admission and use
   canonical paths. A leftover journal is recovery evidence only: verify that
   it names the same completed adoption, then retain it without resuming copy.
2. If an adoption journal exists without a ready manifest, automatic startup
   may resume only when the journal is valid and compatible, has no external
   workspace import, and the deployment supplied the exact cutover authority.
   Otherwise fail with the manual resume command.
3. Otherwise inspect only the fixed legacy candidate list.
4. A candidate is populated when it has an authoritative DB/key, non-empty
   system content, or non-empty known workspace content. Empty directories do
   not count.
5. The bare-home DB/key set is its own candidate. It is never folded into a
   profile-root candidate; coexistence is a multiple-source conflict.
6. Unknown entries in a populated candidate fail before mutation with an
   inventory diagnostic; migration does not silently discard them.
7. Separately inspect the currently selected legacy workspace root, which is
   cwd-backed in released builds and is not beneath the profile directory.
   Never treat arbitrary cwd contents as installation state or infer a user
   owner from the process account.

Outcomes:

- no populated candidate and no canonical content: initialize canonical
  directories and atomically write/sync the ready manifest last;
- exactly one supported compatible candidate: require the exact deployment
  cutover authority, then adopt automatically; without it refuse startup and
  print the stopped-service recovery command;
- more than one populated released candidate: fail with all paths listed;
- any populated unreleased sandbox candidate: fail with inspect/archive
  guidance, even if it is the only candidate.

Workspace outcome is independent of profile-root selection:

- an empty external legacy workspace needs no import;
- a known caller-scoped `tenants/<tenant>/users/<user>` tree may be imported by
  the offline command only after validating every typed owner and mapping each
  leaf to its stable digest without conflicts;
- an ambient or otherwise ambiguous populated workspace blocks before source
  mutation and requires the explicit `storage adopt --workspace-source ...`
  owner decision;
- because released builds did not persist cwd identity, startup cannot discover
  workspaces from earlier working directories. The operator command accepts
  such a source explicitly; no filesystem-wide search is attempted.

### Quiescence, prepare, and snapshot

1. Require either the manual command's explicit confirmations or the startup
   path's exact versioned deployment cutover attestation. Both assert that all
   old processes are stopped; neither a PID/socket probe nor a new-binary lock
   proves quiescence against an old release. Capacity preflight is advisory.
2. Persist and sync `journal.toml` with source identity, source-derived
   security envelope, expected inventory, optional workspace decision, and
   phase `prepare`.
3. Atomically rename the selected profile directory to
   `runtime/layout-adoption/snapshot/<source>` on the same home/volume.
   For a bare-home candidate, move only the exact journaled DB/key set into its
   snapshot directory; never rename the installation home.
4. Sync both parent directories, then persist/sync phase `snapshot-owned`.

Crash handling is observational: if the journal says `prepare` and the source
is already absent while the exact snapshot exists, resume at
`snapshot-owned`. Any third shape fails closed.

### Staging and canonical install

Copy from the immutable snapshot into a journal-owned staging tree, never
directly into active canonical paths:

- `reborn-local-dev.db` and every recognized sidecar copy as one named set to
  `state/`, preserving basenames; the implementation must pin the exact
  libSQL-version sidecar allowlist in tests before enabling adoption;
- `.reborn-local-dev-secrets-master-key` copies to `state/` with mode/ACL
  verification;
- `system/extensions`, `system/prompts`, and `system/skills` copy to `system/`;
- legacy host-disk skill trees remain in the snapshot and are imported through
  the existing one-time DB-backed skill importer;
- an explicitly selected external workspace source copies into only its
  journaled tenant/user digest leaf. The source remains untouched for rollback;
  no ambient directory is merged with another user's leaf.

Every destination is create-new. Existing non-empty canonical content is a
conflict, never overwritten or merged. Source roots and entries must be
ordinary no-follow files/directories; lexical containment alone is
insufficient. Pin the exact supported libSQL sidecar set for the shipped
version and treat it as one unit. Sync every file and staging directory before
persisting `staged`.

Install complete staged `state/` and `system/` trees with atomic sibling
renames and parent-directory syncs. Because two directory renames cannot be
one filesystem transaction, `layout.toml` is the sole visibility/ready commit:
without it no normal command opens either tree. If install is interrupted,
the shared adoption state machine removes only journal-owned installed/staged trees and
recopies the whole DB unit from the preserved snapshot; it does not reuse
individually matching DB/WAL files.

### Store verification and completion

The adoption phase performs no listener or capability activation. Its bounded
completion check opens the configured canonical store, runs the existing
idempotent migrations, constructs the existing secret resolver from the
canonical key, and closes those handles. Content-preservation tests, not
migration-only discovery APIs, prove representative records remain readable
after a subsequent normal restart:

- thread/message state;
- an encrypted secret resolved host-side;
- extension installation state and settings;
- skills, prompts, and typed tenant/user ownership;
- retained legacy disk skills through the existing one-time importer.

After verification, persist/sync journal phase `store-verified`, then
atomically write and parent-sync `layout.toml` as the sole ready commit point.
If the process crashes after the manifest rename but before any optional
journal cleanup, the next boot validates the manifest plus journal and starts
normally. No listener or command side effect may start before the manifest
commit.

## Conflict, interruption, and rollback behavior

- Multiple populated released roots: no writes, no source choice, no merge.
- Populated unreleased sandbox root: no writes; operator must inspect/archive
  it explicitly.
- Existing canonical content without a valid manifest/journal: normal boot
  fails closed as an unrecognized partial layout.
- Crash before snapshot rename: deployment-authorized startup or the manual
  command resumes from the source.
- Crash after snapshot rename: deployment-authorized startup resumes only a
  compatible journal without external workspace ownership; otherwise only the
  manual command resumes from the exact journaled snapshot.
- Crash/ENOSPC during staging or install: source/snapshot remains intact, no
  manifest exists, and only journal-owned staging/installed trees may be
  discarded before a whole-unit recopy.
- Store verification failure: canonical layout remains non-ready; startup
  refuses traffic and tells the operator how to retry an authorized cutover or
  resume manual verification.
- Unsupported manifest/journal version: fail closed without mutation.
- Old-binary rollback after adoption is not a normal profile rollback. Stop
  IronClaw, archive the incomplete/canonical target, and restore the preserved
  snapshot to its original legacy directory. Document this as an operator
  procedure; never run old and new binaries against diverging copies.
- Compatible profile rollback after adoption simply reuses the canonical
  layout and reruns transition/backend admission.

The implementation does not automatically delete the snapshot, external
workspace source, or journal. Cleanup is a separate, explicit operator action
after backup and rollback windows expire.

## Test-first implementation sequence

### Task 1: Pin the profile-independent path contract red

Extend `crates/app/ironclaw_config/tests/profile_contract.rs` and the existing
CLI runtime-root test so current main fails because profiles still append a
directory.

Commands:

```bash
cargo test -p ironclaw_config --test profile_contract
cargo test -p ironclaw local_runtime_storage_root
```

### Task 2: Add pure layout, manifest, and transition types

Implement `ironclaw_config::storage_layout` and table-driven tests for every
profile transition above. Keep filesystem mutation out of this crate.

### Task 3: Add the bounded CLI adoption state machine

Add one focused test module beside the new owner. Test fresh init, root-level
DB/key candidates, one-source deployment-authorized startup adoption, every
durable interruption point, idempotent startup/command resume, unknown files, unsupported versions,
canonical conflicts, two populated roots, and unreleased sandbox roots.

Use temporary directories and a narrow filesystem-operation seam for fault
injection. Do not introduce a general migration framework or mock application
stores. Use separate processes for the advisory-lock race and stopped-service
precondition; temp-directory fault injection is not evidence about a live
libSQL writer. Startup without cutover authority asserts detection performs
zero migration writes.

Drive the real CLI prerequisite from incompatible-manifest tests and assert
rejection occurs before any store open, process/backend construction,
extension activation, listener startup, or canonical-layout mutation. Cover
the explicit external-workspace preview/confirmation path and owner-preserving
per-caller import.

### Task 4: Split composition's overloaded storage root

Pass explicit state/system/workspace paths through the existing build input.
Update database, secret, bootstrap, extension, prompt, and skill call sites.
Run architecture tests because the public app-layer input changes.

Update every standalone DB/secret writer outside full runtime assembly,
including `config set`, onboarding, master-key provisioning, and OAuth
fallback. Add regressions proving none can recreate a profile-named root after
canonical adoption.

### Task 5: Unify host tools and Docker on the tenant/user workspace key

Add the neutral key, replace the sandbox-only user key, update caller-scoped
mount targets and host-process resolution, and add the exact mandatory-leaf
resolver without registering the workspace parent as a request-resolvable
trusted mount source. Extend existing tests rather than adding parallel suites.

### Task 6: Add production-wired restart/adoption coverage

Split proof by the boundary it actually exercises:

- CLI/process tests drive deployment-authorized stopped-service adoption,
  conflicts, interrupted staging, manifest-last commit, and zero migration
  writes when cutover authority is absent.
- An existing composition cold-reopen harness opens the adopted canonical
  paths and verifies after restart:

- thread plus message;
- encrypted secret resolved host-side;
- extension installation/membership;
- user and system skill;
- system prompt and setting;
- unchanged tenant/user ownership.

- A Docker-gated wiring test constructs a real Reborn home, drives the CLI
  sandbox-profile input path, and verifies the emitted bind is exactly one
  user leaf. The existing transport-only Docker test remains lane evidence.
- Run a compatible base -> Docker -> Railway profile sequence with recording
  process transports; provider-specific live tests remain separate.

### Task 7: Extend sandbox isolation evidence

Extend `ironclaw_sandbox/tests/user_sandbox_docker_live.rs` for lane-level leaf
and prohibited-env assertions. In the CLI-wired Docker test, prove the
container cannot read state, system, the master key, the Reborn home, or a
sibling user's sentinel. Add bare-root, wrong-digest, empty-tail,
sibling-symlink, and leaf-symlink escape denials at the resolver tier.

Keep the Railway live test ignored/opt-in and assert its control-service token
never enters the inner worker. Do not claim provider-verified workspace
portability from hermetic tests.

### Task 8: Update literal consumers and operator documentation

Search scripts, QA helpers, tests, docs, and fixtures for `local-dev/`,
`hosted-single-tenant-volume/`, `sandbox-workspaces`,
`reborn-local-dev.db`, and the cached key filename. Update active path
consumers to `state/` and document the one-way old-binary rollback procedure.
Do not edit generated `openwiki/`.

## Focused verification

```bash
cargo fmt --check
cargo test -p ironclaw_config
cargo test -p ironclaw
cargo test -p ironclaw_host_api
cargo test -p ironclaw_composition
cargo test -p ironclaw_sandbox
cargo test -p ironclaw_architecture_tests
bash scripts/ci/check-composition-budget.sh
```

Caller/runtime coverage:

```bash
cargo test -p ironclaw_composition --test profile_acceptance
IRONCLAW_REQUIRE_DOCKER_TESTS=1 cargo test -p ironclaw_sandbox --test user_sandbox_docker_live -- --nocapture
IRONCLAW_REQUIRE_DOCKER_TESTS=1 cargo test -p ironclaw_integration_tests --test reborn_integration_sandbox_shell_turn -- --nocapture
bash scripts/reborn-e2e-rust.sh
```

Provider canary, reported separately from local proof:

```bash
cargo test -p ironclaw_sandbox --test railway_sandbox_live -- --ignored --nocapture
```

## Security and compatibility gates before completion

- No production `.unwrap()`/`.expect()` in changed files.
- No credential or master-key bytes in logs, manifests, journals, snapshots
  diagnostics, or sandbox input.
- No sandbox bind source at the Reborn home, `state/`, `system/`, workspace
  parent above the selected user leaf, host home, or Docker socket. The
  mandatory workspace resolver may know the canonical workspace parent only
  to derive and validate the exact typed caller leaf; it can never emit that
  parent as a bind or resolve arbitrary request tails beneath it.
- Missing Docker/Railway backend continues to fail closed with no host fallback.
- `migration-dry-run` performs no adoption writes and starts no traffic.
- Every changed trait/input enumerates all implementations, adapters, and test
  doubles.
- Architecture and composition-budget gates remain green.
- The owning design/contract documents name their regression tests and exact
  commands.

## Deliberately deferred

- Embedded libSQL to PostgreSQL migration.
- Automatic merging of multiple legacy roots.
- Automatic adoption of the unreleased sandbox root.
- Docker/Railway workspace-content portability.
- Distributed Railway checkpoint ownership.
- Credentialed sandbox traffic until an infrastructure-enforced egress and
  credential-broker boundary is production-wired.
- Automatic deletion of migration snapshots.
