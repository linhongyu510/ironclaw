# Profile-Stable Durable State Design

Status: discussion draft. This document records the problem, design options, and recommended direction. It does not authorize implementation.

## Context

IronClaw currently uses `RebornProfile` for more than one concern. A profile selects deployment and runtime behavior, but it also contributes the subdirectory beneath `IRONCLAW_REBORN_HOME` that contains durable application state.

That coupling is visible in the current hosted-volume profiles:

- `hosted-single-tenant-volume` selects `hosted-single-tenant-volume`.
- `hosted-single-tenant-volume-sandboxed` selects `hosted-single-tenant-volume-sandboxed`.
- `hosted-single-tenant-volume-sandboxed-railway` also selects `hosted-single-tenant-volume-sandboxed`.

The selected root contains the embedded libSQL database and state backed by it, including conversation history, encrypted secrets, extension installation state, skills, prompts, and settings. As a result, changing an existing deployment from the base hosted-volume profile to a sandboxed profile can make its existing state appear to disappear even though the original database still exists under the old root.

This is the wrong long-term boundary. Enabling Docker or Railway sandbox execution should change how capabilities execute, not select a new identity for the deployment's durable application state.

The sandbox profiles have not been released and the profile-specific sandbox state has no production users to preserve. That lets the initial correction remain small, but the design must still establish a durable rule for future profile changes, rollbacks, and storage migrations.

## Goals

1. Preserve chat history, extensions, secrets, skills, prompts, and settings when an operator changes among compatible hosted-volume profiles.
2. Keep sandbox activation operator-controlled at boot. Users and models cannot toggle a deployment into or out of sandbox mode.
3. Treat Docker and Railway as interchangeable process-execution backends beneath the same sandbox policy contract where their capabilities permit it.
4. Fail closed when a selected sandbox backend cannot initialize. Never silently fall back to host execution.
5. Make deployment upgrades and rollbacks predictable without inventing a broad migration framework for an unreleased profile.
6. Give future storage-backend migrations an explicit boundary instead of encoding them as profile-name changes.

## Non-goals

- Hot-swapping profiles while the process is running.
- Automatically merging two populated databases or state roots.
- Migrating embedded libSQL state to Postgres in this change.
- Giving users a WebUI sandbox toggle.
- Generalizing every profile field into a trait or plugin.
- Moving credentials into a sandbox, even transiently.
- Automatically deleting an old profile-specific directory.
- Making Railway checkpoint storage the authoritative store for IronClaw conversations, extensions, or secrets.

## Core invariants

### The Reborn home is the deployment storage boundary

The configured `IRONCLAW_REBORN_HOME` is the physical storage boundary for one IronClaw installation. When it is unset, the local default is `$HOME/.ironclaw/reborn`. A profile name must not add another namespace layer beneath that home.

There is intentionally no `<deployment-id>` directory. The selected home or mounted volume already identifies the deployment. Multiple independent IronClaw installations must use different homes or storage backends rather than sharing one home and depending on an additional path segment for isolation.

The target shape is:

```text
<IRONCLAW_REBORN_HOME>/
|-- layout.toml
|-- config.toml
|-- providers.json
|-- state/
|   |-- reborn.db
|   `-- secrets-master-key
|-- system/
|   |-- extensions/
|   |-- prompts/
|   `-- skills/
|-- workspaces/
|   `-- users/
|       `-- <tenant-user-digest>/
|-- runtime/
|   |-- docker/
|   `-- railway/
|-- logs/
|-- cache/
`-- tmp/
```

The exact filenames remain subject to compatibility design, but the ownership boundaries are decided:

- `state/` is authoritative application state and is profile-agnostic.
- `system/` is host-managed product content and is profile-agnostic.
- `workspaces/` is persistent user-created content, keyed by typed tenant plus user identity.
- `runtime/` contains provider-specific bookkeeping, never authoritative conversations, extensions, or secrets.
- `cache/` and `tmp/` are disposable.

Profiles that use the same home must not produce directories such as `local-dev/`, `hosted-single-tenant-volume/`, or `hosted-single-tenant-volume-sandboxed/` in the target layout. Runtime policy and process backend selection must not alter storage paths.

### Runtime policy is recomputed at every boot

Reusing durable state does not mean reusing prior execution authority. On every boot, the selected profile must independently resolve and validate:

- capability availability;
- sandbox requirement;
- process backend;
- network policy;
- filesystem and workspace exposure;
- readiness and production-blocking diagnostics.

Switching to a less restrictive profile can expose more execution authority, so it must remain an explicit operator configuration change and should be auditable. Persisted data must never cause automatic fallback to a less restrictive runtime.

### Application state and sandbox workspace state are different

The application-state root contains IronClaw-owned durable records. A sandbox workspace contains user-created files and installed tools used during sandbox execution.

These have different lifecycle and portability guarantees:

- Application state must survive compatible profile swaps and backend changes.
- Local Docker workspace persistence may use host-owned per-user directories.
- Railway workspace persistence is provider-owned and checkpoint-based.
- Processes, memory, sockets, and other live runtime state are not application state.

Provider-specific workspace or checkpoint metadata must not be placed where changing the process backend could accidentally reinterpret it as the canonical application database.

### Scope remains typed

Sharing one deployment state root does not collapse tenant or user isolation. Tenant IDs and user IDs remain the authority for records and workspace selection. A profile name, display name, or Railway sandbox ID must never be used to re-derive actor scope.

The host may resolve the complete physical workspace path, but a user sandbox receives only its leaf workspace mounted as `/workspace`:

```text
Host: <IRONCLAW_REBORN_HOME>/workspaces/users/<tenant-user-digest>/
                                      |
                                      | one scoped bind/checkpoint view
                                      v
Sandbox:                         /workspace/
```

The sandbox must not receive the Reborn home, `state/`, `system/`, another user's workspace, the secrets master key, or provider credentials.

### Common storage does not make profiles freely swappable

Removing profile names from paths solves state fragmentation; it does not establish that every profile transition is safe. A profile can change the security assumptions under which users and workspaces were admitted. For example, enabling an unrestricted host shell in a multi-user installation could let one user inspect or modify sibling workspace directories even though application records remain correctly scoped.

Profile selection remains restart-only and operator-controlled. Startup must compare the requested profile against a persisted deployment security envelope and reject incompatible transitions unless a separately designed administrative migration has occurred.

The envelope should describe stable assumptions rather than the profile name itself, for example:

```toml
state_layout_version = 1
tenancy_model = "multi-user"
workspace_isolation = "per-user-sandbox"
```

This manifest must not persist transient execution authority or become a user-controlled policy source. Trusted boot configuration still selects the current runtime policy; the manifest prevents that policy from violating the storage installation's established tenancy and isolation assumptions.

## Recommended model

Keep `RebornProfile` as the external operator-facing preset, but resolve it once into a structured deployment plan with independent axes:

```text
RebornProfile
    |
    v
ResolvedDeploymentPlan
    |-- storage: DeploymentStorage
    |     |-- reborn_home
    |     |-- durable backend
    |     |-- state layout version
    |     `-- workspace backing
    |-- security_envelope: DeploymentSecurityEnvelope
    |-- runtime_policy: RuntimePolicyPreset
    |-- process_backend: Host | Docker | Railway
    |-- product/listener configuration
    `-- readiness requirements
```

The exact names are illustrative. The important contracts are that storage paths cannot accidentally vary because a new execution profile was added, and a shared path cannot accidentally authorize an unsafe profile transition.

The first implementation does not need a trait for each box. Strong enums and value objects in `ironclaw_config`, followed by exhaustive profile resolution, are likely sufficient. A trait is justified only when there are multiple behavior-bearing implementations that need substitution or testing behind a stable port.

Composition should consume the resolved plan and wire existing owners. It should not own profile migration policy, storage adoption, or sandbox-specific domain logic.

## Design-pattern interpretation

Patterns are vocabulary, not a requirement to add abstractions.

### Strategy: useful for execution backend selection

Docker and Railway are variants of process execution beneath a common host-runtime contract. Strategy is a useful model when the caller should depend on required behavior while the selected backend implements the variant. Existing runtime ports should be reused before adding another strategy interface.

Do not apply Strategy to passive configuration values or create one implementation per profile field.

### Bridge: useful as an architectural test

Durable storage topology and runtime execution policy are dimensions that should vary independently. Bridge captures that separation conceptually: adding a new sandbox backend should not create another durable-state namespace, and adding a new storage backend should not duplicate every runtime policy.

This does not require a literal GoF class hierarchy. A resolved plan containing orthogonal strong types can enforce the same boundary more directly in Rust.

### Factory or Builder: reuse the existing composition path

Profile resolution already acts like creation configuration for the composition root. Extend that resolution so it produces an explicit plan; do not add a parallel `SandboxFactory` or `ProfileFactory` unless existing owners cannot express the required construction cleanly.

### Adapter: reserve for legacy-state adoption

If a released version later needs to recognize an old directory layout, a narrow compatibility adapter can map the legacy layout into a one-time adoption operation. It should not remain in every normal read/write path.

### State and Memento: not the application model here

A profile is an operator-selected boot preset, not an object-internal lifecycle state, so the State pattern would blur ownership. Backups and snapshots are valuable migration safeguards, but durable database migration should use explicit storage operations and verification rather than being modeled as an in-memory Memento abstraction.

## Options considered

### Option A: stable state identity plus structured profile resolution

Remove profile-named storage roots, resolve one Reborn-home layout, and represent storage, the deployment security envelope, runtime policy, and process backend as independent fields in a resolved plan.

Advantages:

- Fixes the immediate history-disappearance problem and prevents equivalent fragmentation between other profiles.
- Establishes the invariant that prevents the same bug when another backend is added.
- Keeps operator UX as a single profile selector.
- Supports focused compatibility and rollback tests.
- Avoids speculative polymorphism.

Cost:

- Requires auditing code that reads profile-specific paths and deciding whether each path is application state, system content, user workspace, provider runtime state, or disposable data.
- Requires a compatibility plan for existing populated `local-dev/` and hosted-volume roots.
- May require small type/API changes beyond changing one string mapping.

Recommendation: choose this option.

### Option B: change only the profile-to-directory string mapping

Return one existing profile directory for several variants without removing profile-derived storage from the model.

Advantages:

- Smallest diff.
- Corrects the immediate behavior.

Risks:

- Leaves the conceptual coupling in `RebornProfile::local_runtime_storage_subdir`.
- A future profile can repeat the mistake because the type system does not distinguish runtime policy from state identity.
- Makes migration decisions harder to locate and review.

Use only as an intentionally temporary patch accompanied by the structured contract in the same release. It should not be the final design.

### Option C: configurable namespaces and a generic migration registry

Allow every profile to configure arbitrary state namespaces and register migration handlers between them.

Advantages:

- Maximum flexibility.

Risks:

- Solves hypothetical migrations before their backend contracts exist.
- Adds ambiguous source-selection and merge behavior.
- Creates significant security, rollback, and interruption-testing obligations.
- Makes a simple unreleased-profile correction harder to review.

Recommendation: reject for this scope.

## Profile-transition admission

| Change | Same application state? | Default admission | Additional behavior |
|---|---|---|---|
| Docker sandbox -> Railway sandbox | Yes | Allow only when tenancy and per-user isolation requirements remain satisfied | Change process backend; workspace portability is a separate contract |
| Railway sandbox -> Docker sandbox | Yes | Allow only when tenancy and per-user isolation requirements remain satisfied | Change process backend; do not imply automatic Railway checkpoint import |
| Unsandboxed single-user -> sandboxed single-user | Yes | Allow as a security-tightening restart | Validate backend and require sandbox routing |
| Sandboxed multi-user -> unrestricted host shell | Yes physically | Reject | Requires an explicit administrative security-model migration, not a profile edit |
| Single-user -> multi-user | Potentially | Reject | Requires ownership, authentication, workspace, and isolation migration |
| Multi-user -> single-user | Potentially | Reject | Requires explicit ownership conversion |
| Embedded volume -> Postgres | Logical state may migrate | Reject as profile swap | Use a versioned storage migration |
| Change `IRONCLAW_REBORN_HOME` or mounted volume | No implicit sharing | Reject as profile swap | Use an operator-controlled move or restore |
| Compatible profile rollback | Yes | Allow only if the prior policy still satisfies the envelope | Revalidate backend and fail closed on unavailable sandboxing |

The admission result should be a typed boot validation outcome with a useful operator diagnostic. It must not silently choose another profile, create another state root, or fall back from sandbox execution to host execution.

## Compatibility and adoption policy

The sandbox-specific root is unreleased and has no production state that must be preserved, but existing local and hosted installations can have populated profile roots such as `local-dev/` and `hosted-single-tenant-volume/`. Removing all profile directories therefore requires compatibility design rather than a blind path change.

For the initial sandbox correction:

1. Do not merge or prefer the unreleased `hosted-single-tenant-volume-sandboxed` root automatically.
2. Identify which existing profile roots can contain released user state.
3. Specify a one-time adoption path from each supported legacy root into the profile-agnostic layout.
4. Treat cleanup of known throwaway sandbox roots as a separate operator action after inspection.
5. Do not ship the physical layout change until interruption, conflict, and rollback behavior is agreed and tested.

Future released layout changes need a stricter adoption protocol:

1. Resolve the profile-agnostic canonical layout and layout version before opening stores.
2. Acquire exclusive boot/migration ownership.
3. Detect candidate legacy roots without mutating them.
4. If no legacy root is populated, initialize normally.
5. If exactly one supported legacy root is populated, snapshot it, adopt or migrate it atomically where possible, and write a durable completion marker.
6. Verify authoritative records can be read before reporting success.
7. Make restart after interruption idempotent.
8. If multiple candidate roots are populated, fail closed with a diagnostic and require an explicit administrator decision. Never guess, silently choose the newest, or merge automatically.

Migration execution should live with the bootstrap/storage owner that can coordinate filesystem and database operations. `ironclaw_config` may describe layout identity and compatibility versions, but it must remain side-effect-light and must not perform state writes.

## Security review points

- A selected sandbox profile must make `sandboxed: true` execution mandatory for shell calls.
- Backend initialization or routing failure must fail the request or startup; it must not execute on the host.
- The canonical state root, secret master key, provider tokens, and host credentials must not be mounted or injected into sandbox containers.
- A shared application database must continue enforcing tenant and user scope at typed service boundaries.
- Profile changes must not create a new route around authorization, approvals, host mediation, network policy, or redaction.
- Runtime policy is derived from current trusted boot configuration, never persisted user-controlled state.
- Logs and readiness diagnostics should identify the selected profile, state-layout version, security-envelope class, and process backend without printing secret values or sensitive physical paths.

## Validation strategy

### Contract tests

- Assert that no profile contributes a physical state subdirectory and all local filesystem-backed presets resolve the same layout beneath the selected Reborn home.
- Assert that Docker and Railway profiles resolve to different process backends while requiring sandbox execution.
- Assert that a missing selected sandbox backend cannot fall back to host execution.
- Assert that incompatible tenancy/isolation profile transitions fail before stores and capability runtimes become available.
- Assert that compatible profile changes do not move or duplicate state.

### Restart and profile-swap integration tests

Seed state under each supported legacy layout, adopt it into the profile-agnostic layout, then restart with compatible Docker and Railway sandbox profiles and verify:

- the same thread and messages are visible;
- an encrypted secret can still be resolved host-side;
- installed extensions, skills, prompts, and settings remain visible;
- tenant and user ownership are unchanged;
- shell execution uses the selected sandbox backend;
- credentials remain absent inside the sandbox;
- rollback to the original profile reads the same state.

Where a real Railway canary is required, keep it ignored/opt-in and separately report local contract coverage versus provider-verified behavior.

### Migration tests for a future released layout change

Only when migration machinery is introduced, test:

- interruption and restart at every durable phase;
- idempotent completion;
- snapshot/read-back failure;
- two populated roots failing closed;
- unsupported layout versions;
- rollback compatibility or a documented irreversible boundary.

## Rollout and rollback

Before releasing the profile-agnostic layout:

1. Inventory released profile roots and define supported source-layout versions.
2. Implement and test bounded, idempotent adoption into the canonical Reborn-home layout.
3. Deploy with the same `IRONCLAW_REBORN_HOME` and mounted volume used previously.
4. Verify readiness reports the selected profile, state-layout version, security envelope, and sandbox backend.
5. Verify pre-existing conversation, extension, skill, setting, and secret state.
6. Verify each sandbox sees only its tenant/user leaf workspace.
7. Verify shell calls report `sandboxed: true` and fail closed if the backend is unavailable.
8. Exercise a compatible profile rollback and confirm the same durable state remains visible.

After adoption, a compatible profile rollback on a layout-v1-capable binary is a
configuration rollback, not a database rollback. Binary rollback across the
physical-layout adoption boundary is intentionally one-way: a released older
binary looks for profile-indexed roots and cannot reopen the canonical layout,
regardless of whether it understands every `layout.toml` field. The manifest
therefore remains strict (`deny_unknown_fields`), and migration metadata such as
the retained remote-memory namespace stays in that single authoritative record
rather than a compatibility sidecar that could drift.

An operator who must return to a pre-layout-v1 binary stops every replica,
preserves the failed canonical home, restores the pre-deployment authoritative
store backup, and restores the journal-owned immutable legacy snapshot to its
original profile root. There is no automatic reverse migration or in-place
downgrade. The rollout gate must prove the backup and snapshot are readable
before adoption and retain them until the operator's rollback window closes.

## Decisions and remaining questions before implementation

These questions have recommended defaults so a new session can continue the discussion without inventing assumptions:

1. **What names the deployment's durable state?** Decided: the selected `IRONCLAW_REBORN_HOME` plus a versioned state layout, never the profile name and never a Railway deployment ID.
2. **Is there a `<deployment-id>` directory?** Decided: no. Separate deployments use separate Reborn homes or storage backends.
3. **Where does local Docker per-user workspace state live?** Decided target: `<IRONCLAW_REBORN_HOME>/workspaces/users/<tenant-user-digest>`, mounted one leaf at a time. The migration of existing workspace paths remains to be designed.
4. **How is Railway workspace portability represented?** Recommended: provider-owned checkpoint identity keyed by typed tenant/user scope; do not imply that changing to Docker migrates Railway workspace contents.
5. **Can profiles be changed without restart?** Decided: no. Profile resolution, transition admission, authority, backend validation, and store construction happen at boot.
6. **Which profile transitions are safe?** Decided principle: only transitions satisfying the persisted tenancy and workspace-isolation envelope are admitted automatically. The exact typed compatibility matrix remains to be proposed and reviewed.
7. **Should hosted Postgres profiles share the same logical state identity?** Recommended: use the same conceptual installation identity, but treat switching the physical backend as an explicit data migration rather than path aliasing.
8. **What happens to an existing populated unreleased sandbox root?** Recommended for current deployments: inspect and archive or delete operationally; do not add automatic merge logic to product code.
9. **How are existing populated `local-dev/` and hosted-volume roots adopted?** Open: inventory released layouts, define conflict behavior, and select an atomic or snapshot-backed migration mechanism before implementation.

## New-session handoff

Worktree:

```text
/Users/henry/worktrees/ironclaw/profile-stable-state-design
```

Branch and base at document creation:

```text
branch: design/profile-stable-state
origin/main: 89285c8e700d5d55d8e838f5cf351016be0754f6
```

The sandbox implementation from PR #7214 is already present in this `origin/main` snapshot.

Before editing code, the next agent should:

1. Read the root `AGENTS.md`, `crates/AGENTS.md`, and the guidance for `ironclaw_config`, CLI/bootstrap, composition, filesystem, and host runtime.
2. Fetch and compare against current `origin/main`; do not assume the base SHA above remains current.
3. Reconfirm the live path flow from profile resolution to `IRONCLAW_REBORN_HOME`, the embedded database, encrypted secrets, extension state, and sandbox workspace selection.
4. Inventory every currently released profile-derived root and classify its contents as application state, system content, host workspace, sandbox workspace, cache, or provider metadata before changing it.
5. Produce a concrete target layout, adoption state machine, typed security-envelope proposal, and profile-transition compatibility matrix for review. Do not begin implementation until Henry approves that design.
6. Prefer strong enums/value objects and existing ports. Do not add a trait, factory, migration registry, or composition-root branch without a demonstrated second implementation or boundary need.
7. Keep the correction scoped. Do not modify generated `openwiki` content, commit secrets, or bundle verbose unrelated design artifacts.
8. Do not push or open a PR without explicit instruction.

Useful live-code anchors at the time of writing:

- `crates/app/ironclaw_config/src/profile.rs`: profile-to-storage-subdirectory resolution.
- `crates/app/ironclaw_config/src/home.rs`: default `$HOME/.ironclaw/reborn` resolution and `IRONCLAW_REBORN_HOME` validation.
- `crates/app/ironclaw_cli/src/runtime/mod.rs`: construction of the local runtime storage root.
- `crates/app/ironclaw_composition/src/filesystem_assembly.rs`: embedded database placement.
- `crates/app/ironclaw_composition/src/factory/production_build_assembly.rs`: filesystem and event-store assembly.
- `crates/app/ironclaw_config/tests/profile_contract.rs`: compatibility assertions for profile mappings.

The repository code graph was not initialized in this clean worktree when this document was created. Use repository guidance and targeted live-code inspection unless the graph is initialized later.

## Pattern references

- [Refactoring.Guru design-pattern catalog](https://refactoring.guru/design-patterns/catalog)
- [Strategy](https://refactoring.guru/design-patterns/strategy)
- [Bridge](https://refactoring.guru/design-patterns/bridge)
- [Adapter](https://refactoring.guru/design-patterns/adapter)
- [Memento](https://refactoring.guru/design-patterns/memento)
