# ironclaw_sandbox guardrails

The sandboxed-process lane. Merged in WS3 from `ironclaw_process_sandbox`
(plan contract), `ironclaw_host_runtime::sandbox_process` (Docker / broker /
credential-firewall / CA), and `ironclaw_scripts` (script lane + Docker
execution path). PROPOSAL §6.6.4.

## Why one crate

The `bollard`/`rcgen`/`libc` cone lives here and **nowhere else in the
workspace** — keeping it out of the kernel is the point. `ironclaw_host_runtime`
no longer declares any of the three.

## Wiring status — read before assuming this is dead code

**Three** production call paths cross this crate today, and none of them is
execution. Only the first is plan validation — do not delete the other two as
dead code on the strength of a "plan validation only" reading:

- `ironclaw_host_runtime::production::host_runtime_spawn_input_for_capability`
  parses and validates `SandboxProcessPlan` → `ValidatedSandboxProcessPlan` on
  the spawn path, rejecting bad plans as model-visible tool errors, and
  `services::process_executor` routes such requests away from the dispatch
  executor.
- `ironclaw_loop_host` compares against
  `ironclaw_host_api::capability::PROCESS_SANDBOX_CAPABILITY_ID`.
- `ironclaw_host_runtime::process_output` uses `RebornSandboxScopeKey` to derive
  the scoped saved-output directory — a production path through this crate's
  scope-key digest.

There is still **no production execution backend** for
`system.process_sandbox.run`: the Docker/CA machinery and the script lane have
no production constructor (`with_script_runtime` and
`RebornScopedSandboxCommandTransport::new` are called only from tests). The
`#[allow(dead_code)] // consumed by W6` markers are accurate.

## Ownership

- `plan` — typed `SandboxProcessPlan` / `ValidatedSandboxProcessPlan`. Accept
  only typed plan input: no raw Docker flags, raw host paths, host environment
  inheritance, or raw secret material from plan JSON. Keep install and
  credentialed-run phases separate: install may declare scoped tool/cache state
  with no secrets; credentialed run declares brokered secrets and read-only
  tool/cache state.
- `sandbox_process` — the execution machinery behind
  `ironclaw_host_api::process::SandboxCommandTransport`: Docker connect, network
  broker and allowlist, credential firewall, container identity, the sandbox CA,
  mounts, scope/user keys, shell limits, activity registry.
- `script` — `ScriptRuntime`, the `ScriptExecutor`/`ScriptBackend` traits,
  `DockerScriptBackend`, `ScriptRuntimeHttpAdapter`, and the normalized
  request/result/error types.

## Do not move in here

- Ambient credentials. The credential-firewall design stays: secret values live
  behind broker/lease seams and redaction helpers, and never appear in plan
  JSON, validation errors, debug output, or logs.
- Dispatcher composition. This crate must not expose `RuntimeAdapter`-shaped
  surface or depend on `ironclaw_capabilities` — script/MCP dispatch adapters
  are host-runtime-private composition (pinned by
  `reborn_dependency_boundaries.rs`).
- Manual credentials, direct provider HTTP, or duplicated
  dispatcher/process/resource policy.
- Docker mount-root or executor configuration: that belongs with whatever crate
  eventually wires a real backend.

## Known debt

- **Direct process spawning.** `script.rs` still shells out with
  `std::process::Command` (`Command::new("docker")`) rather than going through
  `SandboxCommandTransport`. CHECKLIST WS3 calls for routing all process
  spawning through the transport seam; the merge colocated the two halves that
  makes that possible but did **not** perform the rewiring, because that is a
  behavior change and this was a move.
- **The Docker fail-closed switch is wired to nothing (pre-existing, inherited
  with the move).** `tests/support/docker_gate.rs` says
  `IRONCLAW_REQUIRE_DOCKER_TESTS=1` is what turns a missing daemon or image from
  a silent skip into a hard failure, and that "CI sets this". **Nothing sets
  it** — the name appears only in `docker_gate.rs` and `attribution_tests.rs`,
  in this tree and on `main`. So every real-Docker test in this crate skips-and-
  passes everywhere, which is the exact gap the gate's own comment says let
  sandbox security bugs ship unnoticed. Separately, `tests/docker_security.rs`
  does not use the gate at all: it open-codes its own `docker version` check and
  three `return`s, so it would not fail closed even once something does set the
  variable. WS3 only *enrolled* that test in the required Rust e2e lane
  (`scripts/reborn-e2e-rust.sh`); it did not author the skip. Fixing this means
  setting the variable in the lanes that have a daemon **and** repointing
  `docker_security.rs` onto `docker_gate` — a CI-behavior change, deliberately
  not made inside a move PR. Guardrail-claim-vs-reality, the #6945 class.
- **`ironclaw_resources` dependency.** The lane holds a `runtimes → kernel`
  layer-matrix exception because it takes `&dyn ResourceGovernor` and constructs
  `ResourceError`. See that exception's `reason` field in
  `reborn_dependency_boundaries.rs` for the measured evidence and what actually
  clears it.

## Validation

- Fast local check: `cargo test -p ironclaw_sandbox`
- Boundary check after dependency/API changes: `cargo test -p ironclaw_architecture`
- Contracts: `docs/reborn/contracts/scripts.md`,
  `docs/reborn/contracts/runtime-workflows.md`,
  `docs/reborn/contracts/network.md`
