//! Tenant-level concurrency ceiling for the `hosted-single-tenant-volume-sandboxed`
//! profile (D3-2).
//!
//! `ironclaw_authorization::obligations_for_grant` already emits a
//! `ReserveResources` obligation for every `EffectKind::SpawnProcess`
//! capability grant (D3-1), and `ironclaw_host_runtime::obligations::
//! reserve_resource_obligation` already reserves against whatever
//! `ResourceGovernor` composition wires in. Both are no-ops today because no
//! deployment ever calls `set_limit` for a `SpawnProcess`-relevant account —
//! this module is the one caller that does, for the sandboxed profile only.
//!
//! Kept as its own module (not inlined into `factory.rs`, which is already
//! thousands of lines) so the boot call site stays a single line.

use std::sync::Arc;

use ironclaw_host_api::{TenantId, UserId};
use ironclaw_resources::{ResourceAccount, ResourceError, ResourceGovernor, ResourceLimits};

/// Overrides the sandboxed profile's per-tenant concurrent `SpawnProcess`
/// ceiling. Unset, or set to a non-positive/unparseable value, falls back to
/// [`DEFAULT_SANDBOX_MAX_CONCURRENT`].
pub(crate) const SANDBOX_MAX_CONCURRENT_ENV: &str = "IRONCLAW_SANDBOX_MAX_CONCURRENT";

/// Default per-tenant concurrent sandbox-process ceiling when
/// [`SANDBOX_MAX_CONCURRENT_ENV`] is not set. Deliberately small: the
/// sandboxed profile runs one Docker container per shell invocation, and an
/// unbounded ceiling defeats the point of D3-2 (bounding a single tenant's
/// concurrent container fan-out).
pub(crate) const DEFAULT_SANDBOX_MAX_CONCURRENT: u32 = 4;

/// Resolves the configured ceiling from [`SANDBOX_MAX_CONCURRENT_ENV`],
/// falling back to [`DEFAULT_SANDBOX_MAX_CONCURRENT`] when the env var is
/// absent, empty, non-numeric, or zero (zero would mean "no sandboxed shell
/// calls ever succeed", which is never an intentional deployment choice —
/// operators who want that should not enable the sandboxed profile).
pub(crate) fn sandbox_max_concurrent_from_env() -> u32 {
    resolve_sandbox_max_concurrent_from_raw(std::env::var(SANDBOX_MAX_CONCURRENT_ENV).ok())
}

/// Pure resolution of the sandbox max-concurrency ceiling from an already-read
/// raw env value. Kept separate from [`sandbox_max_concurrent_from_env`] so
/// tests can exercise the parse/validate/default logic directly with an
/// explicit `Some`/`None` input instead of mutating process env — a raw
/// `std::env::var` read does not observe
/// `ironclaw_common::env_helpers::set_runtime_env`'s thread-local override,
/// so round-tripping through real env vars in tests is both unnecessary and
/// unreliable under parallel test execution.
pub(crate) fn resolve_sandbox_max_concurrent_from_raw(raw: Option<String>) -> u32 {
    raw.and_then(|raw| raw.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_SANDBOX_MAX_CONCURRENT)
}

/// Sets the tenant-wide `max_concurrency_slots` ceiling on `governor` for
/// `tenant_id` — a shared pool across every user in the tenant, not a
/// per-user ceiling. Composition calls this once at boot, only for the
/// `hosted-single-tenant-volume-sandboxed` profile — every other profile
/// leaves the account unlimited, matching D3-1's "no-op until D3-2" note.
///
/// Phase-A-scoped, deliberately: `ResourceAccount::cascade` only checks
/// levels that carry an explicit `set_limit`, so setting the limit on
/// `ResourceAccount::user(tenant_id, owner_user_id)` alone left every OTHER
/// authenticated user in the tenant genuinely unbounded — a P2 gap, not
/// "unfair but bounded". Applying it at `ResourceAccount::tenant(tenant_id)`
/// instead closes that hole by reusing the existing cascade: it trades
/// strict per-user fairness (one user CAN starve a sibling by exhausting the
/// shared pool) for a real, tenant-wide bound on the sandboxed profile's
/// container fan-out. Lazy per-user ceiling registration at the obligation
/// dispatcher — so each authenticated user gets their OWN bounded account —
/// is the deferred follow-up; it needs the governor + ceiling threaded into
/// a profile-agnostic dispatcher and is out of scope here.
///
/// This is what turns the D3-1 `ReserveResources` obligation from a no-op
/// into an actual gate: `FilesystemResourceGovernor`/
/// `InMemoryResourceGovernor::reserve_with_outcome` check `max_concurrency_slots`
/// against the account's current outstanding reservations, so the
/// `N+1`th concurrent `SpawnProcess` reservation anywhere in the tenant is
/// denied as a model-visible outcome (never a host error) once this ceiling
/// is set.
pub(crate) fn apply_sandbox_user_ceiling(
    governor: &Arc<dyn ResourceGovernor>,
    tenant_id: TenantId,
    // Kept on the signature (unused in the body) so the sole call site
    // (`sandbox_composition.rs`) does not need churn; retained for the
    // lazy per-user follow-up described above, which will need it again.
    _owner_user_id: UserId,
    max_concurrent: u32,
) -> Result<(), ResourceError> {
    governor.set_limit(
        ResourceAccount::tenant(tenant_id),
        ResourceLimits::default().set_max_concurrency_slots(max_concurrent),
    )
}

/// Resolves the tenant id the sandboxed-profile boot ceiling applies to:
/// the local-runtime identity's tenant when one was supplied, else the same
/// `reborn_cli()` default identity every other local-runtime call site falls
/// back to (mirrors `local_dev_extension_lifecycle_surface_context` in
/// `factory.rs`).
pub(crate) fn resolve_local_runtime_tenant_id(
    local_runtime_identity: Option<&crate::input::RebornLocalRuntimeIdentity>,
) -> Result<TenantId, crate::RebornBuildError> {
    if let Some(identity) = local_runtime_identity {
        return Ok(identity.tenant_id.clone());
    }
    let default_identity = crate::runtime_input::RebornRuntimeIdentity::reborn_cli();
    TenantId::new(default_identity.tenant_id).map_err(|error| {
        crate::RebornBuildError::InvalidConfig {
            reason: error.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use ironclaw_host_api::{InvocationId, ResourceEstimate, ResourceScope, UserId};
    use ironclaw_resources::InMemoryResourceGovernor;

    use super::*;

    fn tenant(id: &str) -> TenantId {
        TenantId::new(id.to_string()).expect("valid tenant id")
    }

    fn scope_for(tenant_id: &TenantId, user_id: &UserId) -> ResourceScope {
        ResourceScope {
            tenant_id: tenant_id.clone(),
            user_id: user_id.clone(),
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        }
    }

    #[test]
    fn env_override_is_read_and_validated() {
        assert_eq!(
            resolve_sandbox_max_concurrent_from_raw(None),
            DEFAULT_SANDBOX_MAX_CONCURRENT,
            "unset falls back to the default"
        );

        assert_eq!(
            resolve_sandbox_max_concurrent_from_raw(Some("7".to_string())),
            7,
            "a valid number is used"
        );

        assert_eq!(
            resolve_sandbox_max_concurrent_from_raw(Some("0".to_string())),
            DEFAULT_SANDBOX_MAX_CONCURRENT,
            "zero must not disable the sandboxed profile entirely"
        );

        assert_eq!(
            resolve_sandbox_max_concurrent_from_raw(Some("not-a-number".to_string())),
            DEFAULT_SANDBOX_MAX_CONCURRENT,
            "unparseable falls back to the default"
        );
    }

    /// D3-2's headline behavior, scoped per-TENANT (a shared pool across
    /// every user in the tenant, not per-user): once the ceiling is applied
    /// for the boot owner's tenant, the `N+1`th concurrent reservation is
    /// *denied* — a model-visible outcome from `ResourceGovernor::reserve`,
    /// never a host panic/error — REGARDLESS of which user in the tenant
    /// makes it. This is deliberately a tenant-wide pool, not strict
    /// per-user fairness: `ResourceAccount::cascade` only checks levels that
    /// carry an explicit `set_limit`, and `apply_sandbox_user_ceiling` used
    /// to call `set_limit` on `ResourceAccount::user(tenant, owner_user_id)`
    /// only — so any authenticated user OTHER than the boot owner was
    /// genuinely unbounded (the P2 gap this test now pins shut). A sibling
    /// (non-owner) user sharing the tenant's pool is exactly the fix.
    #[test]
    fn ceiling_denies_the_second_concurrent_reservation_from_any_user_in_the_tenant() {
        let governor: Arc<dyn ResourceGovernor> = Arc::new(InMemoryResourceGovernor::new());
        let tenant_id = tenant("sandboxed-tenant");
        let owner_user_id = UserId::new("owner-user").expect("valid user id");

        apply_sandbox_user_ceiling(&governor, tenant_id.clone(), owner_user_id.clone(), 1)
            .expect("setting a finite ceiling on an empty account succeeds");

        let first = governor
            .reserve(
                scope_for(&tenant_id, &owner_user_id),
                ResourceEstimate::default().set_concurrency_slots(1),
            )
            .expect("first reservation is within the ceiling");

        // A NON-owner user in the SAME tenant must be bounded by the same
        // shared ceiling — this is the fix: pre-fix, only the boot owner's
        // own `ResourceAccount::user` account carried a limit, so any other
        // authenticated user's reservation cascaded past every limited
        // level and was never denied.
        let non_owner_user = UserId::new("non-owner-user").expect("valid user id");
        let second = governor.reserve(
            scope_for(&tenant_id, &non_owner_user),
            ResourceEstimate::default().set_concurrency_slots(1),
        );
        assert!(
            second.is_err(),
            "a non-owner user's concurrent reservation must be bounded by the tenant's shared \
             sandbox ceiling, not left unlimited"
        );

        drop(first);
    }
}
