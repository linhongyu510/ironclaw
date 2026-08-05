//! Labels-as-identity container registry for the persistent per-user
//! sandbox model. Two responsibilities:
//!
//! 1. Docker label construction/parsing for `{tenant, user, created_at}`
//!    identity — crash-safe (survives daemon restart), no DB.
//! 2. A push-based in-memory last-activity map. The exec transport calls
//!    [`SandboxActivityRegistry::touch`] after every successful command;
//!    the reaper only ever reads via `idle_for`/`last_activity` — it
//!    never inspects container stats to infer activity. Labels are
//!    immutable post-create and NEVER carry this mutable state.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use bollard::models::ContainerSummary;
use chrono::{DateTime, Utc};
use ironclaw_host_api::ids::{TenantId, UserId};

use super::user_key::RebornSandboxUserKey;

pub(crate) fn label_tenant(prefix: &str) -> String {
    format!("{prefix}.tenant")
}
pub(crate) fn label_user(prefix: &str) -> String {
    format!("{prefix}.user")
}
pub(crate) fn label_created_at(prefix: &str) -> String {
    format!("{prefix}.created_at")
}

/// Stamps the container with the security-posture generation
/// [`super::exec_transport::security_posture_stamp`] computed at create
/// time — the container-side analogue of `verify_existing_egress_network_
/// posture`'s network check. `ensure_container` reads this label back on
/// every subsequent lookup and recycles the container the moment the stamp
/// no longer matches what the running code would create today, so a
/// hardening change (e.g. W1's non-root PID 1) reaches existing containers
/// on their next use instead of waiting up to the reaper's 7-day forced
/// recycle.
pub(crate) fn label_security_posture(prefix: &str) -> String {
    format!("{prefix}.security_posture")
}

pub(crate) fn build_user_container_labels(
    prefix: &str,
    tenant_id: &TenantId,
    user_id: &UserId,
    security_posture_stamp: &str,
) -> HashMap<String, String> {
    HashMap::from([
        (label_tenant(prefix), tenant_id.as_str().to_string()),
        (label_user(prefix), user_id.as_str().to_string()),
        (label_created_at(prefix), Utc::now().to_rfc3339()),
        (
            label_security_posture(prefix),
            security_posture_stamp.to_string(),
        ),
    ])
}

pub(crate) fn user_container_label_filter(
    prefix: &str,
    tenant_id: &TenantId,
    user_id: &UserId,
) -> HashMap<String, Vec<String>> {
    HashMap::from([(
        "label".to_string(),
        vec![
            format!("{}={}", label_tenant(prefix), tenant_id.as_str()),
            format!("{}={}", label_user(prefix), user_id.as_str()),
        ],
    )])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserContainerCandidate {
    pub(crate) container_id: String,
    pub(crate) created_at: DateTime<Utc>,
}

impl UserContainerCandidate {
    pub(crate) fn from_summary(container: &ContainerSummary, label_prefix: &str) -> Option<Self> {
        let container_id = container.id.clone()?;
        let labels = container.labels.as_ref()?;
        let created_at = labels
            .get(&label_created_at(label_prefix))
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))?;
        Some(Self {
            container_id,
            created_at,
        })
    }
}

/// Push-based in-memory map of per-user last-activity timestamps, keyed on
/// [`RebornSandboxUserKey`]. Cross-crate consumers (e.g. the reborn runtime
/// composition wiring that owns the reaper loop) need to construct and pass
/// this registry, so it is `pub` and re-exported at the crate root — unlike
/// the label helpers and candidate type above, which stay internal to this
/// crate.
#[derive(Debug, Default)]
pub struct SandboxActivityRegistry {
    last_activity: Mutex<HashMap<RebornSandboxUserKey, Instant>>,
    active_invocations: Mutex<HashMap<RebornSandboxUserKey, usize>>,
    lifecycle_gates: Mutex<HashMap<RebornSandboxUserKey, Weak<tokio::sync::Mutex<()>>>>,
}

/// RAII marker for one in-flight sandbox command.
///
/// The lease begins before any per-user container lifecycle or exec work and
/// decrements the active count on every return path, including cancellation.
pub(crate) struct SandboxInvocationLease<'a> {
    registry: &'a SandboxActivityRegistry,
    key: RebornSandboxUserKey,
}

impl Drop for SandboxInvocationLease<'_> {
    fn drop(&mut self) {
        self.registry.finish_invocation(&self.key);
    }
}

/// Exclusive access to one user's container lifecycle.
///
/// Gates are keyed by user, so Docker I/O for one user never blocks another.
/// The weak-map entry is removed when the last holder or waiter releases its
/// gate, bounding registry growth without a global cleanup sweep.
pub(crate) struct SandboxLifecycleGuard<'a> {
    registry: &'a SandboxActivityRegistry,
    key: RebornSandboxUserKey,
    gate: Arc<tokio::sync::Mutex<()>>,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for SandboxLifecycleGuard<'_> {
    fn drop(&mut self) {
        self.guard.take();
        if Arc::strong_count(&self.gate) != 1 {
            return;
        }

        let mut gates = self.registry.lock_lifecycle_gates();
        let remove = gates
            .get(&self.key)
            .and_then(Weak::upgrade)
            .is_some_and(|registered| Arc::ptr_eq(&registered, &self.gate));
        if remove && Arc::strong_count(&self.gate) == 1 {
            gates.remove(&self.key);
        }
    }
}

impl SandboxActivityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<RebornSandboxUserKey, Instant>> {
        // Recover from poisoning rather than panic: a background reaper
        // must never crash the whole process over a prior panic elsewhere
        // that poisoned this unrelated mutex.
        self.last_activity
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn lock_active(&self) -> std::sync::MutexGuard<'_, HashMap<RebornSandboxUserKey, usize>> {
        self.active_invocations
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn lock_lifecycle_gates(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<RebornSandboxUserKey, Weak<tokio::sync::Mutex<()>>>>
    {
        self.lifecycle_gates
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Takes exclusive lifecycle ownership for `key`. The process-wide map
    /// mutex is held only while cloning or inserting the keyed gate; callers
    /// wait on and hold only that user's asynchronous mutex across Docker I/O.
    pub(crate) async fn lock_user_lifecycle(
        &self,
        key: &RebornSandboxUserKey,
    ) -> SandboxLifecycleGuard<'_> {
        let gate = {
            let mut gates = self.lock_lifecycle_gates();
            if let Some(gate) = gates.get(key).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(tokio::sync::Mutex::new(()));
                gates.insert(key.clone(), Arc::downgrade(&gate));
                gate
            }
        };
        let guard = Arc::clone(&gate).lock_owned().await;
        SandboxLifecycleGuard {
            registry: self,
            key: key.clone(),
            gate,
            guard: Some(guard),
        }
    }

    /// Marks one command active. Call this while holding the user's lifecycle
    /// gate so a reaper teardown and a new invocation cannot pass each other.
    pub(crate) fn begin_invocation(
        &self,
        key: &RebornSandboxUserKey,
    ) -> SandboxInvocationLease<'_> {
        let mut active = self.lock_active();
        let count = active.entry(key.clone()).or_default();
        *count = count.saturating_add(1);
        SandboxInvocationLease {
            registry: self,
            key: key.clone(),
        }
    }

    fn finish_invocation(&self, key: &RebornSandboxUserKey) {
        let mut active = self.lock_active();
        let Some(count) = active.get_mut(key) else {
            return;
        };
        if *count <= 1 {
            active.remove(key);
        } else {
            *count -= 1;
        }
    }

    pub(crate) fn has_active_invocations(&self, key: &RebornSandboxUserKey) -> bool {
        self.lock_active().get(key).copied().unwrap_or_default() > 0
    }

    /// Acquires exclusive lifecycle ownership only when no invocation is
    /// active. A new invocation cannot become active until the returned guard
    /// is dropped because invocation startup takes this same gate first.
    pub(crate) async fn lock_user_for_reap(
        &self,
        key: &RebornSandboxUserKey,
    ) -> Option<SandboxLifecycleGuard<'_>> {
        let guard = self.lock_user_lifecycle(key).await;
        if self.has_active_invocations(key) {
            None
        } else {
            Some(guard)
        }
    }

    /// Records successful command activity for a persistent user container.
    /// Runtime owners that share this registry with a reaper use this as the
    /// push-side of the idle-lifecycle contract.
    pub fn touch(&self, key: &RebornSandboxUserKey) {
        self.lock().insert(key.clone(), Instant::now());
    }

    pub(crate) fn last_activity(&self, key: &RebornSandboxUserKey) -> Option<Instant> {
        self.lock().get(key).copied()
    }

    pub(crate) fn forget(&self, key: &RebornSandboxUserKey) {
        self.lock().remove(key);
    }

    pub(crate) fn idle_for(&self, key: &RebornSandboxUserKey, now: Instant) -> Option<Duration> {
        self.last_activity(key)
            .map(|activity| now.saturating_duration_since(activity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_host_api::ids::{TenantId, UserId};

    fn user_key(tenant: &str, user: &str) -> RebornSandboxUserKey {
        RebornSandboxUserKey::from_tenant_user(
            &TenantId::new(tenant).expect("valid tenant"),
            &UserId::new(user).expect("valid user"),
        )
    }

    #[test]
    fn label_filter_targets_tenant_and_user_labels_only() {
        let tenant = TenantId::new("tenant-a").unwrap();
        let user = UserId::new("user-a").unwrap();

        let filter = user_container_label_filter("ironclaw", &tenant, &user);

        assert_eq!(
            filter.get("label").unwrap(),
            &vec![
                "ironclaw.tenant=tenant-a".to_string(),
                "ironclaw.user=user-a".to_string(),
            ]
        );
    }

    #[test]
    fn candidate_parses_created_at_and_ignores_missing_labels() {
        let tenant = TenantId::new("tenant-a").unwrap();
        let user = UserId::new("user-a").unwrap();
        let labels = build_user_container_labels("ironclaw", &tenant, &user, "stamp-abc");
        let container = ContainerSummary {
            id: Some("abc123".to_string()),
            labels: Some(labels),
            ..Default::default()
        };

        let candidate = UserContainerCandidate::from_summary(&container, "ironclaw")
            .expect("round-tripped labels must parse");

        assert_eq!(candidate.container_id, "abc123");

        let missing = ContainerSummary {
            id: Some("no-labels".to_string()),
            labels: None,
            ..Default::default()
        };
        assert!(UserContainerCandidate::from_summary(&missing, "ironclaw").is_none());
    }

    #[test]
    fn activity_registry_touch_then_idle_for_reports_elapsed_duration() {
        let registry = SandboxActivityRegistry::new();
        let tenant = TenantId::new("t").unwrap();
        let user = UserId::new("u").unwrap();
        let scope = ironclaw_host_api::resource::ResourceScope {
            tenant_id: tenant,
            user_id: user,
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: ironclaw_host_api::ids::InvocationId::new(),
        };
        let key = RebornSandboxUserKey::from_scope(&scope);

        assert!(registry.last_activity(&key).is_none());
        registry.touch(&key);
        let idle = registry.idle_for(&key, Instant::now() + Duration::from_secs(5));
        assert!(idle.unwrap() >= Duration::from_secs(5));
    }

    #[test]
    fn activity_registry_forget_clears_the_entry() {
        let registry = SandboxActivityRegistry::new();
        let scope = ironclaw_host_api::resource::ResourceScope {
            tenant_id: TenantId::new("t").unwrap(),
            user_id: UserId::new("u").unwrap(),
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: ironclaw_host_api::ids::InvocationId::new(),
        };
        let key = RebornSandboxUserKey::from_scope(&scope);
        registry.touch(&key);

        registry.forget(&key);

        assert!(registry.last_activity(&key).is_none());
    }

    #[tokio::test]
    async fn same_user_container_lifecycle_is_serialized() {
        let registry = Arc::new(SandboxActivityRegistry::new());
        let key = user_key("tenant", "user");
        let first_create = registry.lock_user_lifecycle(&key).await;
        let (attempted_tx, attempted_rx) = tokio::sync::oneshot::channel();
        let (acquired_tx, mut acquired_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();

        let second_registry = Arc::clone(&registry);
        let second_key = key.clone();
        let second_create = tokio::spawn(async move {
            let _ = attempted_tx.send(());
            let _guard = second_registry.lock_user_lifecycle(&second_key).await;
            let _ = acquired_tx.send(());
            let _ = release_rx.await;
        });

        attempted_rx.await.expect("second create must start");
        tokio::task::yield_now().await;
        assert!(matches!(
            acquired_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        drop(first_create);
        acquired_rx.await.expect("second create must acquire next");
        let _ = release_tx.send(());
        second_create.await.expect("second create task must finish");
    }

    #[tokio::test]
    async fn different_users_have_independent_lifecycle_gates() {
        let registry = Arc::new(SandboxActivityRegistry::new());
        let first_key = user_key("tenant", "user-a");
        let second_key = user_key("tenant", "user-b");
        let first_guard = registry.lock_user_lifecycle(&first_key).await;
        let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel();

        let second_registry = Arc::clone(&registry);
        let second_user = tokio::spawn(async move {
            let _guard = second_registry.lock_user_lifecycle(&second_key).await;
            let _ = acquired_tx.send(());
        });

        tokio::time::timeout(Duration::from_secs(1), acquired_rx)
            .await
            .expect("user-b must not wait for user-a")
            .expect("user-b acquisition signal must arrive");
        drop(first_guard);
        second_user.await.expect("user-b task must finish");
    }

    #[test]
    fn invocation_lease_releases_active_count_on_drop() {
        let registry = SandboxActivityRegistry::new();
        let key = user_key("tenant", "user");

        let lease = registry.begin_invocation(&key);
        assert!(registry.has_active_invocations(&key));

        drop(lease);
        assert!(!registry.has_active_invocations(&key));
    }
}
