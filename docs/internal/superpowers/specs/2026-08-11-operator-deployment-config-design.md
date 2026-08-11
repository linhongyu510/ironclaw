# Operator-Authored Deployment Configuration Design

Status: proposed follow-up design. This document does not authorize implementation. It is intentionally separate from the profile-stable durable-state implementation in PR #7456.

Companion design: [Profile-Stable Durable State Design](2026-08-09-profile-stable-durable-state-design.md).

## Context

IronClaw currently overloads the word "profile" across three different concerns:

1. A boot profile such as `local-dev`, `hosted-single-tenant-volume`, or `hosted-single-tenant-volume-sandboxed-railway` selects a deployment preset.
2. A runtime-policy profile selects filesystem, process, network, secret, approval, and audit behavior.
3. A run profile selects per-run behavior such as capability-surface breadth, resource budgets, checkpointing, steering, and runner choice.

The profile-stable durable-state work removes the boot profile from physical storage identity. It makes `IRONCLAW_REBORN_HOME` plus the versioned storage layout the installation boundary and persists resolved security assumptions rather than a profile name.

That work exposes the next architectural simplification: a boot profile is only a convenient way to construct deployment data. Operators should be able to review and edit that data directly in a versioned `deployment.toml` instead of selecting one opaque name that controls several independent axes.

The current composition model is already close to this boundary. `DeploymentConfig` carries deployment behavior as fields, and its profile field is documented as a logging and telemetry label. This design changes the source of those fields without changing the durable-state layout, authorization stages, extension ownership model, or runtime process ports.

## Relationship to profile-stable durable state

This design is a follow-up to PR #7456, not an expansion of it.

PR #7456 should finish with this shape:

```text
legacy RebornProfile preset
            |
            v
typed DeploymentConfig
            |
            +-- storage layout requirement
            +-- deployment security envelope
            +-- workspace isolation
            `-- runtime/process policy
```

The follow-up changes only the operator input:

```text
operator deployment.toml
            |
            v
typed DeploymentConfig
            |
            +-- same storage layout requirement
            +-- same deployment security envelope
            +-- same workspace isolation
            `-- same runtime/process policy
```

Keeping the changes separate gives storage adoption and configuration adoption independent validation, rollback, and failure diagnosis. The current work must avoid introducing new profile-named persistence or profile matching below the compatibility-preset boundary, but it must not create, require, or migrate `deployment.toml`.

## Goals

1. Make an operator-authored, self-contained TOML file the authoritative declaration of deployment policy.
2. Represent every behavior currently selected by a boot profile as typed operator intent or a typed value derived from that intent.
3. Keep secrets and platform-provided values outside the TOML through explicit environment-variable references.
4. Preserve authorization, approval, obligation, ownership, and dispatch as independent enforcement stages. Configuration may establish ceilings; it must not mint per-user authority.
5. Reject unsafe or contradictory combinations before opening stores, adopting legacy state, starting listeners, or constructing capability runtimes.
6. Preserve convenient presets as explicit initialization templates without making their names runtime authority.
7. Provide a staged compatibility path from `IRONCLAW_REBORN_PROFILE` and existing deployment templates.
8. Keep local, Docker, and Railway deployment behavior inspectable and reproducible across upgrades and rollbacks.

## Non-goals

- Combining this configuration transition with profile-stable storage adoption.
- Moving secrets, credentials, database passwords, OAuth client secrets, or provider tokens into TOML.
- Allowing arbitrary combinations of low-level resolved policy fields.
- Replacing extension installation records, manifests, tenant policy, or per-user capability grants with static configuration.
- Letting an operator configuration bypass product security floors.
- Hot-reloading deployment authority while the process is running.
- Adding a generic configuration plugin or deployment factory registry.
- Automatically rewriting an operator's configuration during an upgrade.
- Treating a preset name as durable deployment identity.

## Core decisions

### The TOML is authoritative operator intent

The selected file is the source of truth for deployment policy. Security-sensitive policy fields cannot be overridden by ordinary environment variables or CLI flags.

Environment variables have two permitted roles:

- bootstrap discovery of the TOML file or Reborn home;
- values referenced explicitly by TOML fields, especially secrets and platform-provided endpoints.

CLI flags have two permitted roles:

- select the configuration file for an invocation;
- request an operational action such as initialization, validation, explanation, migration dry-run, or recovery.

If both an authoritative TOML and the legacy `IRONCLAW_REBORN_PROFILE` selector are present during the compatibility period, startup fails with a conflict diagnostic. IronClaw must not silently choose one.

### Presets generate complete files

Presets are versioned initialization templates built into the shipping CLI. They are not inherited at runtime.

```bash
ironclaw deployment presets list
ironclaw deployment presets show railway-single-tenant-sandboxed
ironclaw deployment init --preset railway-single-tenant-sandboxed
ironclaw deployment validate
```

`deployment init` writes a complete configuration. Informational metadata records the source preset and IronClaw version, but changing or removing a preset in a later release cannot change an existing deployment.

There is no runtime `extends = "preset"` field.

Initialization refuses to overwrite an existing file unless a separate, explicitly destructive replacement workflow is designed. Ordinary installation and upgrade commands never rewrite the file.

### Configuration declares ceilings, not grants

Capability execution remains an intersection:

```text
deployment capability ceiling
        intersect
installed and owner-visible capability
        intersect
manifest-declared effects and resources
        intersect
run-surface policy
        intersect
authorization and approval
        intersect
runtime availability
        =
dispatchable capability
```

The TOML can provision or forbid runtime lanes, select built-in capability families, and constrain effects and budgets. It cannot create an extension installation, assign installation ownership, grant a capability to a user, satisfy an approval, or bypass dispatch authorization.

### Product security floors remain code-owned

The operator can make a deployment stricter, but cannot disable universal product invariants. Examples include:

- credentials never enter an untrusted sandbox;
- financial, approval-modifying, and budget-modifying effects retain their hard approval floor;
- a sandbox-required process policy cannot fall back to host execution;
- multi-user deployments cannot expose sibling workspaces through a shared host mount;
- external traffic and secrets cross their mediated host boundaries;
- unknown enum values and unknown TOML fields fail closed.

These invariants appear in redacted effective-configuration output, but are not removable TOML switches.

## Configuration discovery

Discovery is deterministic:

1. `--deployment-config <path>` for the current invocation.
2. `IRONCLAW_DEPLOYMENT_CONFIG` as a bootstrap-only path override.
3. `${XDG_CONFIG_HOME:-$HOME/.config}/ironclaw/deployment.toml`.

Only the path is overridden. Neither `IRONCLAW_DEPLOYMENT_CONFIG` nor other environment variables may carry inline deployment policy.

Container images set `XDG_CONFIG_HOME=/etc`, making the conventional path `/etc/ironclaw/deployment.toml`. Docker repositories mount or copy a reviewed file there. Railway repositories copy the reviewed file during image construction. The config file is not placed inside `IRONCLAW_REBORN_HOME`; it must remain available when the durable volume is restored, replaced, or moved.

The selected path is canonicalized and reported in startup diagnostics without printing referenced secret values. The file is read once during boot. Changes require restart.

## Proposed wire schema

The first schema is `schema_version = 1`. Serde decoding uses `deny_unknown_fields` at every table boundary. Known enums are closed at the wire boundary even when internal neutral enums are non-exhaustive.

```toml
schema_version = 1

[metadata]
name = "railway-production"
generated_from = "railway-single-tenant-sandboxed"
generated_by = "ironclaw-v1.4.0"

[deployment]
mode = "hosted"

[identity]
tenancy = "single-tenant"
workspace_ownership = "tenant-user"

[authentication]
mode = "sso"
issuer_url_from_env = "IRONCLAW_SSO_ISSUER_URL"
client_id_from_env = "IRONCLAW_SSO_CLIENT_ID"
client_secret_from_env = "IRONCLAW_SSO_CLIENT_SECRET"

[storage]
backend = "libsql"
home_from_env = "IRONCLAW_REBORN_HOME"
durability = "required"

[storage.events]
durability = "required"

[workspace]
isolation = "per-user"
sandbox_mount = "/workspace"

[runtime.process]
backend = "railway-sandbox"
sandbox_required = true

[runtime.process.railway]
api_url_from_env = "RAILWAY_API_URL"
token_from_env = "RAILWAY_API_TOKEN"
project_id_from_env = "RAILWAY_PROJECT_ID"
environment_id_from_env = "RAILWAY_ENVIRONMENT_ID"

[runtime.network]
mode = "brokered"
private_network = "deny"

[runtime.secrets]
mode = "brokered-handles"

[runtime.approvals]
mode = "ask-writes"

[runtime.audit]
mode = "standard"
durable = true

[capabilities]
allowed_runtimes = ["first-party", "wasm", "mcp", "sandbox"]

[capabilities.builtin]
catalog_version = 1
families = [
  "conversation",
  "workspace",
  "projects",
  "memory",
  "skills",
  "extensions",
  "sandbox-process",
]
deny = []

[capabilities.extensions]
installation = "admin-only"
ownership = "per-user"
allowed_runtimes = ["wasm", "mcp", "sandbox"]

[limits.processes]
max_running_per_owner = 4
max_sandboxes_per_owner = 1

[limits.processes.by_class]
shell = 2
sandbox = 1
extension = 4

[limits.runs]
catalog_version = 1
default_class = "interactive"
allowed_classes = ["interactive", "scheduled"]

[limits.runs.ceilings]
max_model_calls = 32
max_capability_invocations = 64
max_checkpoint_bytes = 65536
allow_broad_capability_surface = false
allow_raw_runtime_backend_selection = false

[traffic]
mode = "serve"
required_readiness = "validated"
```

### Metadata

`metadata.name`, `generated_from`, and `generated_by` are diagnostics only. No policy code branches on them, and they are not persisted as security identity.

### Deployment and identity

`deployment.mode` describes the machine and trust boundary using operator-facing values such as `local` and `hosted`. `identity.tenancy` and `workspace_ownership` independently describe actor isolation. A deployment advertised as single-tenant still uses typed tenant-plus-user ownership so expanding the product surface later cannot accidentally collapse data ownership.

### Storage

`storage.backend` selects `libsql` or `postgres`. Backend connection values are environment references. The local filesystem root continues to be `IRONCLAW_REBORN_HOME`; no configuration field introduces a profile, deployment-id, or tenant directory above the canonical layout.

Changing storage backends is a data migration, not a configuration-only transition. Startup admission rejects a backend change when the persisted layout envelope identifies another authoritative backend and no completed migration receipt exists.

### Workspace

`workspace.isolation` is `single-trusted-operator` or `per-user`. The sandbox mount destination is fixed to `/workspace` in schema version 1; any other value is rejected rather than creating a configurable route to host data.

`per-user` resolves the existing tenant-plus-user workspace key. A sandbox receives only that leaf. The Reborn home, database, master key, provider credentials, sibling workspaces, and host runtime directories are never mount candidates.

### Runtime policy

The operator provides high-level intent. The sanctioned runtime-policy resolver derives the effective filesystem, process, network, secret, approval, and audit policy. The TOML does not accept a serialized `EffectiveRuntimePolicy`, because that would permit contradictory or resolver-bypassing combinations.

`runtime.process.backend` initially supports `none`, `host`, `docker-sandbox`, and `railway-sandbox`. `sandbox_required = true` makes backend initialization a startup requirement and forbids fallback.

Minimal approvals and unrestricted host execution require a separate explicit acknowledgement captured by the initialization or validation workflow. A permanent `true` boolean copied casually into a hosted file is insufficient. The acknowledgement is scoped to a local trusted-operator deployment and recorded in auditable startup evidence.

### Capabilities

Built-in capabilities are configured through stable product-owned families rather than an exhaustive list of internal capability IDs. Each family expands through the explicitly selected `catalog_version` to a test-pinned set of capability IDs. IronClaw retains old catalog mappings while their schema version is supported. Adding a capability requires a new catalog version; an existing deployment therefore does not acquire it merely by upgrading the binary. The change is called out in release notes and surfaced by `deployment diff-preset`.

`capabilities.builtin.deny` accepts exact capability IDs and can only narrow the selected families. It cannot add an ID outside them.

Extension configuration establishes installation authority, ownership shape, and permitted runtime lanes. Durable installation records and manifests continue to determine which extensions actually exist and which caller can see them.

### Limits and run classes

Deployment configuration establishes process limits and maximum run ceilings. Individual run classes and tenant policy may choose lower limits. They cannot exceed deployment ceilings.

The existing run-profile concept remains an internal typed run-policy contract during this change, but operator-facing configuration calls these values run classes to avoid conflating them with boot presets. `limits.runs.catalog_version` pins the built-in semantics of each named class across upgrades, while the explicit ceilings can only narrow those semantics. Users may request only classes listed in `allowed_classes`, and ordinary users cannot request privileged dimensions such as broad capability surfaces, high budgets, special drivers, or runner pools without the existing typed authority.

### Traffic and operational modes

`traffic.mode` is `serve` or `validate-only`. Migration dry-run becomes an operational command that forces validate-only behavior; it is not a deployment profile. A CLI command may narrow `serve` to `validate-only`, but it cannot promote a validate-only file to serving traffic.

Readiness diagnostics are derived output, not editable configuration. The configured requirement states the minimum readiness contract; composition reports concrete diagnostics for missing dependencies.

## Typed ownership and resolution

### `ironclaw_config`

Owns:

- configuration discovery;
- `DeploymentFileV1` wire types;
- strict deserialization and schema-version errors;
- environment-reference syntax and redacted resolution;
- built-in preset templates;
- legacy boot-profile translation during the compatibility period.

It does not open stores, resolve runtime authority, or construct composition services.

### Runtime-policy owner

The existing runtime-policy resolver owns conversion from validated operator intent to `EffectiveRuntimePolicy`. It remains the only sanctioned constructor for effective filesystem, process, network, secret, approval, and audit values.

### `ironclaw_composition`

Consumes a validated deployment request plus the resolved runtime policy and builds the existing `DeploymentConfig`/service graph. Composition wires concrete backends but does not decide whether a configuration transition is safe.

Live trait objects, pools, runtime ports, registrars, OAuth callbacks, and provider implementations remain host bindings rather than TOML fields.

### Filesystem and startup admission owners

The existing layout requirement and deployment security envelope are derived from the validated deployment config. Startup compares them with `layout.toml` before opening authoritative stores or constructing capability runtimes.

The persisted envelope records stable properties such as authoritative storage kind, tenancy model, and workspace-access floor. It never records `metadata.name`, `generated_from`, or a legacy profile name as authority.

## Resolution pipeline

```text
discover deployment.toml
        |
        v
strict parse + schema-version check
        |
        v
resolve explicitly referenced environment values
        |
        v
validate cross-field invariants
        |
        +---- invalid/ambiguous ----> fail before stores
        |
        v
resolve runtime policy through sanctioned resolver
        |
        v
derive storage layout requirement + security envelope
        |
        v
admit configuration transition against layout.toml
        |
        +---- incompatible ---------> fail with recovery guidance
        |
        v
open/migrate stores under existing adoption protocol
        |
        v
construct capability/runtime services
        |
        v
evaluate readiness and optionally serve traffic
```

The redacted resolved plan receives a stable digest. Startup logs the schema version, digest, storage kind, tenancy model, workspace-isolation class, process backend, capability families, and readiness result. It does not log environment values or sensitive physical paths.

## Validation matrix

The following combinations are rejected before store construction:

| Configuration | Result | Reason |
|---|---|---|
| Multi-user tenancy + single-trusted-operator workspace | Reject | A user could address sibling workspace data |
| Multi-user tenancy + host process backend | Reject | Host execution cannot enforce sibling workspace isolation |
| `sandbox_required = true` + `backend = "host"` or `"none"` | Reject | Required isolation is unavailable |
| Railway sandbox backend without referenced Railway configuration | Reject | Backend cannot be constructed safely |
| Docker sandbox backend without a reachable validated Docker boundary | Reject readiness/startup | Never fall back to host execution |
| Sandboxed process backend + inherited environment secrets | Reject | Credentials could enter the sandbox |
| Hosted deployment + unrestricted/minimal-approval runtime | Reject | Trusted-laptop authority is incompatible with hosted users |
| `serve` + unmet configured readiness | Reject traffic startup | Validation cannot be bypassed |
| Postgres backend + missing TLS policy for a remote endpoint | Reject | Existing transport floor remains enforced |
| Capability deny entry outside selected families | Reject | Prevents misleading or stale policy files |
| Run default class absent from allowed classes | Reject | Default must be requestable |
| Per-class process limit above owner-wide limit | Reject | Contradictory limit would be ambiguous |
| Unknown field, enum, family, runtime, or run class | Reject | Configuration changes must be explicit |
| TOML plus `IRONCLAW_REBORN_PROFILE` | Reject during compatibility period | No silent precedence |

Validation may normalize ordering and defaults but must not silently reduce an unsafe request into another deployment. A resolver reduction caused by explicit organization ceilings is reported as a distinct audited outcome.

## Operator experience

### Local

The interactive installer or an explicit command initializes the safe local template:

```bash
ironclaw deployment init --preset local
```

The file is written to `~/.config/ironclaw/deployment.toml`. Ordinary startup fails with an actionable path when a config is required and absent; it does not create policy as a side effect.

### Docker

The repository maintainer commits a reviewed file and mounts it read-only:

```yaml
services:
  ironclaw:
    environment:
      XDG_CONFIG_HOME: /etc
      IRONCLAW_REBORN_HOME: /data/reborn
    volumes:
      - ./deploy/ironclaw.docker.toml:/etc/ironclaw/deployment.toml:ro
      - ironclaw-data:/data/reborn
```

Secrets remain Docker secrets or environment values referenced by name from the TOML.

### Railway

The repository maintainer commits `deploy/ironclaw.railway.toml`, and the image copies it to `/etc/ironclaw/deployment.toml`. Railway variables provide only referenced values such as `IRONCLAW_REBORN_HOME`, database URLs, sandbox credentials, and OAuth secrets.

Changing Railway variables cannot switch tenancy, disable sandboxing, widen capabilities, or select host execution. Those changes require a reviewed TOML change and restart.

## Commands

The initial operator surface is:

```text
ironclaw deployment presets list
ironclaw deployment presets show <name>
ironclaw deployment init --preset <name> [--output <path>]
ironclaw deployment validate [--deployment-config <path>]
ironclaw deployment explain [--deployment-config <path>]
ironclaw deployment diff-preset --preset <name> [--deployment-config <path>]
```

`validate` performs parsing, environment-reference resolution, cross-field validation, runtime-policy resolution, and security-envelope compatibility checks without opening listeners or applying storage migrations.

`explain` prints the redacted effective plan, immutable product floors, derived layout requirement, and whether the current persisted envelope admits it.

`diff-preset` compares the operator's explicit fields with a current built-in template. It never edits the file and clearly distinguishes security-widening, security-narrowing, and operational differences.

## Compatibility and rollout

### Phase 1: introduce TOML without changing existing deployments

- Add strict parsing, validation, explain, and preset commands.
- Keep the existing profile selector as a compatibility input only when no TOML is selected.
- Translate each legacy profile into the same validated deployment request in memory.
- Add equivalence tests proving the translated profile and generated preset resolve to identical observable deployment axes.
- Emit a deprecation diagnostic with the exact `deployment init --preset ...` command.

### Phase 2: make TOML required for hosted and container deployments

- Update Docker and Railway templates to ship reviewed self-contained files.
- Refuse hosted startup without TOML.
- Retain the safe local compatibility default for one additional release so CLI installer upgrades do not strand local users.
- Keep profile translation available for rollback and explicit migration tooling.

### Phase 3: remove boot-profile authority

- Remove `IRONCLAW_REBORN_PROFILE` from normal startup.
- Remove profile-derived constructors after all call sites consume validated deployment data.
- Keep preset template names only in CLI initialization metadata.
- Rename remaining internal run-profile concepts only when that can be done without conflating this deployment-config rollout with run-policy redesign.

No phase rewrites `layout.toml`, moves durable state, or re-runs legacy storage adoption merely because configuration input changed. Equivalent profile and TOML inputs produce the same layout requirement and security envelope.

## Rollback

During Phases 1 and 2, operators can roll back the binary by restoring the prior startup selector and leaving `deployment.toml` unused. Because configuration adoption does not mutate application state, rollback is a configuration rollback rather than a data rollback.

Operators must preserve the current durable volume and `layout.toml`. An older binary may still be rejected if it cannot satisfy the persisted security envelope; rollback never authorizes a weaker workspace or process boundary.

A failed TOML validation leaves stores unopened and state unchanged. A failure after layout admission follows the existing storage-adoption journal and recovery contract; the configuration layer does not invent a second migration journal.

## Testing strategy

### Configuration contract tests

- Parse every generated preset under strict schema-v1 decoding.
- Reject unknown fields, unknown enum variants, duplicate tables, missing required fields, and inline secret values.
- Verify environment references resolve only declared value fields and cannot override policy fields.
- Verify redacted diagnostics never contain resolved secrets.
- Snapshot generated templates and their metadata separately from effective policy.

### Legacy equivalence tests

For every released `RebornProfile`, compare its compatibility translation with the corresponding generated TOML preset. Assert equality across:

- storage shape and durability requirement;
- tenancy and workspace isolation;
- runtime-policy request and resolved effective policy;
- traffic and readiness requirement;
- hosted extension-installation behavior;
- capability families and runtime lanes;
- process concurrency and run ceilings;
- derived security envelope.

The profile name and template metadata are excluded because they are labels only.

### Security validation tests

- Table-drive every rejected combination in the validation matrix.
- Assert validation happens before database, secrets, extension, process, network, and listener construction.
- Assert a config can narrow but cannot bypass immutable product floors.
- Assert a TOML cannot mint extension ownership, user grants, approvals, or trusted ingress.
- Assert sandbox configurations cannot expose the Reborn home, database, master key, provider credentials, or sibling workspaces.

### Capability and limit tests

- Pin each stable capability family to its exact member IDs.
- Assert family expansion only affects provisioning/ceiling and still requires owner-visible installation, grants, authorization, approvals, and provider trust.
- Assert exact deny entries only narrow selected families.
- Assert run requests are clamped to deployment ceilings and privileged dimensions still require typed authority.
- Assert process owner and class limits are enforced through the existing process journal/store path.

### Startup and integration tests

- Local, Docker-sandbox, and Railway-sandbox files resolve through the production startup path.
- Equivalent legacy profile and TOML boots read the same canonical state and workspace leaf.
- Incompatible security-envelope transitions fail before stores and runtimes become available.
- Missing sandbox backends fail closed without host fallback.
- `validate-only` never starts traffic or applies migration side effects.
- Configuration conflicts and missing-file diagnostics include exact recovery commands.

## Alternatives considered

### Keep boot profiles as the authoritative interface

This is simple for operators but keeps unrelated storage, tenancy, runtime, capability, and readiness choices bundled behind opaque names. Adding a deployment variant continues to require another enum case and risks profile-derived behavior leaking into lower layers.

### Runtime preset inheritance

A short file containing `extends = "railway-single-tenant-sandboxed"` is convenient, but its meaning can change when a new binary changes the preset. That creates silent authority changes across upgrades and makes rollback difficult to reason about.

### Fully arbitrary low-level policy TOML

Serializing every field of `EffectiveRuntimePolicy` gives maximum flexibility but bypasses the sanctioned resolver and permits contradictory or unsupported combinations. It also exposes implementation details as a permanent operator contract.

### Recommendation

Use a complete operator-authored TOML containing high-level, independently meaningful policy axes. Generate it from versioned presets for convenience, resolve it through existing typed policy owners, enforce immutable product floors, and retain legacy profiles only as a temporary compatibility translator.

## Decision summary

1. `deployment.toml` becomes the authoritative operator-edited deployment contract.
2. Presets generate complete files and have no runtime inheritance semantics.
3. Environment variables supply only discovery, secrets, and explicitly referenced platform values.
4. Boot-profile choices, capability ceilings, runtime lanes, process limits, and run ceilings are represented in the TOML or derived by the sanctioned resolver.
5. Capability configuration uses stable families plus exact deny entries; it cannot mint authority.
6. Product security floors remain code-owned and visible in effective-plan diagnostics.
7. The persisted security envelope records resolved properties, never profile or preset names.
8. Configuration changes are restart-only and admitted before stores or runtimes are constructed.
9. The implementation is a separate follow-up to PR #7456 with a staged compatibility rollout.
