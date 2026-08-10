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

### Durable state follows deployment identity and storage topology

Profiles that represent the same deployment and use the same durable storage topology must resolve to the same application-state root. Runtime policy and process backend selection must not alter that root.

For the current hosted-volume family, the canonical durable root should remain:

```text
<IRONCLAW_REBORN_HOME>/hosted-single-tenant-volume
```

The base, Docker-sandboxed, and Railway-sandboxed hosted-volume presets should all use that root.

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

## Recommended model

Keep `RebornProfile` as the external operator-facing preset, but resolve it once into a structured deployment plan with independent axes:

```text
RebornProfile
    |
    v
ResolvedDeploymentPlan
    |-- durable_state: DurableStateSelection
    |     |-- topology/backend
    |     `-- stable namespace/root
    |-- runtime_policy: RuntimePolicyPreset
    |-- process_backend: Host | Docker | Railway
    |-- product/listener configuration
    `-- readiness requirements
```

The exact names are illustrative. The important contract is that durable-state selection is explicit and cannot accidentally vary because a new execution backend profile was added.

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

Map all hosted-volume presets to one canonical durable-state identity and represent durable state, runtime policy, and process backend as independent fields in a resolved plan.

Advantages:

- Fixes the immediate history-disappearance problem.
- Establishes the invariant that prevents the same bug when another backend is added.
- Keeps operator UX as a single profile selector.
- Supports focused compatibility and rollback tests.
- Avoids speculative polymorphism.

Cost:

- Requires auditing code that reads profile-specific paths and deciding whether each path is application state or provider workspace state.
- May require small type/API changes beyond changing one string mapping.

Recommendation: choose this option.

### Option B: change only the profile-to-directory string mapping

Return `hosted-single-tenant-volume` for all three hosted-volume profile variants without introducing an explicit durable-state concept.

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

## Profile-swap behavior

| Change | Durable application state | Runtime action | Migration behavior |
|---|---|---|---|
| Hosted volume -> Docker sandbox | Reuse canonical hosted-volume state | Validate Docker and require sandbox routing | None |
| Hosted volume -> Railway sandbox | Reuse canonical hosted-volume state | Validate Railway configuration and require sandbox routing | None |
| Docker sandbox -> Railway sandbox | Reuse canonical hosted-volume state | Change process backend; preserve user/tenant scope | No application DB migration; sandbox workspace portability is separate |
| Sandboxed -> unsandboxed hosted volume | Reuse canonical hosted-volume state | Explicit operator change; recompute authority and warn/audit | None |
| Profile rollback | Reuse canonical hosted-volume state | Revalidate the selected backend and policy | None |
| Embedded volume -> Postgres | Different storage topology | Explicit deployment migration | Versioned, separately designed migration |
| Change `IRONCLAW_REBORN_HOME` or mounted volume | Different deployment storage location | Operator-controlled move or restore | Explicit operational procedure |
| Change tenant/deployment identity | Do not implicitly share | Build separately scoped services | Explicit import/export if desired |

## Compatibility and adoption policy

For the initial sandbox release, the sandbox-specific root is unreleased and has no production state that must be migrated. Therefore:

1. Use the existing `hosted-single-tenant-volume` root as canonical.
2. Do not automatically merge, rename, or delete `hosted-single-tenant-volume-sandboxed`.
3. Treat cleanup of known throwaway roots as a separate operator action after inspection.

Future released layout changes need a stricter adoption protocol:

1. Resolve a canonical layout and layout version before opening stores.
2. Acquire exclusive boot/migration ownership.
3. Detect candidate legacy roots without mutating them.
4. If no legacy root is populated, initialize normally.
5. If exactly one supported legacy root is populated, snapshot it, adopt or migrate it atomically where possible, and write a durable completion marker.
6. Verify authoritative records can be read before reporting success.
7. Make restart after interruption idempotent.
8. If multiple candidate roots are populated, fail closed with a diagnostic and require an explicit administrator decision. Never guess or merge automatically.

Migration execution should live with the bootstrap/storage owner that can coordinate filesystem and database operations. `ironclaw_config` may describe layout identity and compatibility versions, but it must remain side-effect-light and must not perform state writes.

## Security review points

- A selected sandbox profile must make `sandboxed: true` execution mandatory for shell calls.
- Backend initialization or routing failure must fail the request or startup; it must not execute on the host.
- The canonical state root, secret master key, provider tokens, and host credentials must not be mounted or injected into sandbox containers.
- A shared application database must continue enforcing tenant and user scope at typed service boundaries.
- Profile changes must not create a new route around authorization, approvals, host mediation, network policy, or redaction.
- Runtime policy is derived from current trusted boot configuration, never persisted user-controlled state.
- Logs and readiness diagnostics should identify the selected profile, durable-state identity, and process backend without printing secret values or sensitive physical paths.

## Validation strategy

### Contract tests

- Assert that all hosted-volume profile presets resolve to the same durable-state identity and canonical root.
- Assert that Docker and Railway profiles resolve to different process backends while requiring sandbox execution.
- Assert that a missing selected sandbox backend cannot fall back to host execution.
- Keep local-development profiles' existing compatibility behavior unless separately changed.

### Restart and profile-swap integration tests

Seed state under the base hosted-volume profile, then restart with Docker and Railway sandbox profiles and verify:

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

Before the first sandbox release:

1. Resolve all hosted-volume presets to the canonical existing state root.
2. Deploy a sandbox profile with the same `IRONCLAW_REBORN_HOME` and mounted volume used by the base profile.
3. Verify readiness reports the selected profile and sandbox backend.
4. Verify pre-existing conversation, extension, skill, setting, and secret state.
5. Verify shell calls report `sandboxed: true` and fail closed if the backend is unavailable.
6. Exercise a profile-only rollback and confirm the same durable state remains visible.

Rollback is a profile/configuration rollback, not a database rollback, because compatible profiles share one durable state identity. Any future schema migration must define its own rollback contract.

## Questions to settle before implementation

These questions have recommended defaults so a new session can continue the discussion without inventing assumptions:

1. **What names the deployment's durable state?** Recommended: a strong storage-topology/state-layout identity resolved from trusted boot configuration, not a profile string.
2. **Where does local Docker per-user workspace state live?** Recommended: under a clearly provider/runtime-owned namespace outside the application database namespace, while preserving current data until compatibility is decided.
3. **How is Railway workspace portability represented?** Recommended: provider-owned checkpoint identity keyed by typed tenant/user scope; do not imply that changing to Docker migrates Railway workspace contents.
4. **Can profiles be changed without restart?** Recommended: no. Profile resolution, authority, backend validation, and store construction happen at boot.
5. **Should hosted Postgres profiles share the same logical state identity?** Recommended: define the same conceptual deployment identity, but treat switching physical backend as an explicit data migration rather than path aliasing.
6. **What happens to an existing populated unreleased sandbox root?** Recommended for current deployments: inspect and archive or delete operationally; do not add automatic merge logic to product code.

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
4. Classify every profile-derived path as application state, host workspace, sandbox workspace, cache, or provider metadata before changing it.
5. Produce a concrete type/API proposal and compatibility matrix for review. Do not begin implementation until Henry approves the design.
6. Prefer strong enums/value objects and existing ports. Do not add a trait, factory, migration registry, or composition-root branch without a demonstrated second implementation or boundary need.
7. Keep the correction scoped. Do not modify generated `openwiki` content, commit secrets, or bundle verbose unrelated design artifacts.
8. Do not push or open a PR without explicit instruction.

Useful live-code anchors at the time of writing:

- `crates/app/ironclaw_config/src/profile.rs`: profile-to-storage-subdirectory resolution.
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
