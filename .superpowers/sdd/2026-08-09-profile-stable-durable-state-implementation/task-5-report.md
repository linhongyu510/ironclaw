# Task 5 — Neutral workspace identity and mandatory sandbox leaf report

## Outcome

Implemented the Task 5 neutral tenant/user workspace key and migrated the
named consumers to it. The released length-prefixed SHA-256 digest remains
byte-for-byte stable, while host path construction remains outside
`ironclaw_host_api`.

`/workspace` is now a mandatory bind: Docker accepts only the current
caller’s exact virtual target and the exact prepared
`<workspace-root>/users/<digest>` host leaf. It rejects the workspace parent,
a sibling digest, an extra child, arbitrary host directories, and symlinked
users/leaf paths.

## Changes

- Added `TenantUserWorkspaceKey` to `ironclaw_host_api::ids` with constructors
  from typed tenant/user values and `ResourceScope`, exposing only its opaque
  digest segment.
- Removed the sandbox-local `RebornSandboxUserKey` codec; Docker, Railway,
  registry, and live-test checkpoint naming now use the neutral key.
- Moved per-caller composition mounts, WebUI browse mounts, host-process
  workspace aliases, invocation tests, approval lease terms, and CLI adoption
  journals to `/projects/workspace/users/<digest>`.
- Replaced the CLI’s temporary local adoption digest helper with the neutral
  key directly.
- Added the exact-leaf bind resolver and hostile-target tests in the existing
  sandbox mount suite. Generic trusted mounts retain their existing catalog
  path, but `/workspace` no longer uses it.
- Raised the explicit host-api architecture size ratchet from 18,800 to
  18,906 with a Task 5 ownership rationale. The added type is neutral contract
  vocabulary; filesystem paths and execution remain in composition/sandbox.

## Test-first evidence

Red tests captured before the relevant implementation:

```text
cargo test -p ironclaw_host_api tenant_user_workspace_key_preserves_the_released_digest_codec
# failed: cannot find type TenantUserWorkspaceKey in this scope

cargo test -p ironclaw_sandbox workspace_grant_rejects_a_sibling_user_leaf
# failed: old bind construction accepted a sibling caller leaf

cargo test -p ironclaw_sandbox workspace_grant_rejects_a_host_directory_other_than_the_caller_leaf
# failed: old bind construction accepted an arbitrary host directory
```

Green focused and package checks:

```text
cargo test -p ironclaw_host_api                         # 209 passed
cargo test -p ironclaw_sandbox                          # 219 passed
cargo test -p ironclaw_composition runtime_mounts::tests # 7 passed
cargo test -p ironclaw_composition --lib per_caller_workspace_policy_leases_only_the_gates_own_subtree
cargo test -p ironclaw_host_runtime --lib the_workspace_alias_is_narrowed_to_the_caller
cargo test -p ironclaw_host_runtime --lib hosted_tenant_workspace_uses_the_invocations_scoped_mounts
cargo test -p ironclaw external_workspace_requires_preview_confirmation_and_preserves_the_source
cargo test -p ironclaw tampered_workspace_journal_identity_is_rejected_before_snapshot_or_install
cargo clippy -p ironclaw_host_api -p ironclaw_sandbox -p ironclaw_host_runtime -p ironclaw_composition -p ironclaw --all-targets -- -D warnings
cargo test -p ironclaw_architecture_tests --test reborn_dependency_boundaries reborn_contracts_crates_carry_a_checked_size_ceiling
cargo fmt --check
git diff --check
```

The clippy command completed successfully in 1m15s. The Railway provider
canary stayed ignored because it requires Railway credentials and creates
billable resources; the normal Docker isolation test ran and passed.

## Trusted mount-source audit

Production composition creates Docker only through
`RebornSandboxConfig::new(paths.workspace_root())`; no production caller uses
`with_local_mount_source`. Therefore no workspace parent, Reborn home, state,
system content, credentials, or socket is registered in the trusted source
catalog. `/projects` and `/projects/workspace` are rejected at registration,
and the mandatory `/workspace` bind bypasses the generic catalog entirely.

The generic-source test fixture uses only `/artifacts/test-fixture`; it is not
production wiring and does not model a system or credentials mount.

## Remaining validation limitations

- The full architecture rerun was user-aborted after 10 seconds before a
  terminal result:
  `cargo fmt --check && cargo test -p ironclaw_architecture_tests`.
  The one previously failing size-ratchet test then passed.
- The composition caller integration test produced no terminal result in the
  command harness despite a 45-second direct-test bound:
  `perl -e 'alarm 45; exec @ARGV' target/debug/deps/ironclaw_composition-b7ed8c87ee5d1c14 runtime::capability_host::workspace_scoping_tests::hosted_profile_lands_agent_workspace_writes_in_the_callers_own_subtree --exact --nocapture`.
  Direct mount-policy and approval caller tests passed.
- `bash scripts/ci/check-composition-budget.sh` remains red: 41,997 production
  LOC exceeds its effective 41,731 ceiling by 266. Task 5 is a net +44 lines
  under `ironclaw_composition/src`; the HEAD-equivalent count is still 41,953,
  222 over the same ceiling. The gate predates this task’s full overage, and no
  budget change was made.
