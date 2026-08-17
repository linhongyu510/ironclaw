//! Reserve + reconcile collapse into a single durable spend delta (#7701).
//!
//! The reservation half of budget accounting is *coordination*: it stops
//! concurrent runs in this process from overshooting a limit. The spend half
//! is *money*: it must be durable and replayable. These tests pin that split.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ironclaw_filesystem::{
    BackendCapabilities, CasExpectation, DirEntry, Entry, FileStat, FilesystemError,
    InMemoryBackend, RecordVersion, RootFilesystem, ScopedFilesystem, SeqNo, VersionedEntry,
};
use ironclaw_host_api::{
    ids::{InvocationId, ProjectId, TenantId, UserId},
    mount::{MountGrant, MountPermissions, MountView},
    path::{MountAlias, VirtualPath},
    resource::{ResourceEstimate, ResourceScope, ResourceUsage},
};
use ironclaw_resources::{
    FilesystemResourceGovernor, ReservationDurability, ResourceAccount, ResourceError,
    ResourceGovernor, ResourceLimits,
};
use rust_decimal_macros::dec;

/// Counts every durable journal record the governor appends.
struct CountingFilesystem {
    inner: InMemoryBackend,
    appended_records: AtomicUsize,
}

impl CountingFilesystem {
    fn new() -> Self {
        Self {
            inner: InMemoryBackend::new(),
            appended_records: AtomicUsize::new(0),
        }
    }

    fn appended_records(&self) -> usize {
        self.appended_records.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl RootFilesystem for CountingFilesystem {
    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    async fn put(
        &self,
        path: &VirtualPath,
        entry: Entry,
        cas: CasExpectation,
    ) -> Result<RecordVersion, FilesystemError> {
        self.inner.put(path, entry, cas).await
    }

    async fn get(&self, path: &VirtualPath) -> Result<Option<VersionedEntry>, FilesystemError> {
        self.inner.get(path).await
    }

    async fn list_dir(&self, path: &VirtualPath) -> Result<Vec<DirEntry>, FilesystemError> {
        self.inner.list_dir(path).await
    }

    async fn stat(&self, path: &VirtualPath) -> Result<FileStat, FilesystemError> {
        self.inner.stat(path).await
    }

    async fn delete(&self, path: &VirtualPath) -> Result<(), FilesystemError> {
        self.inner.delete(path).await
    }

    async fn append(&self, path: &VirtualPath, payload: Vec<u8>) -> Result<SeqNo, FilesystemError> {
        self.appended_records.fetch_add(1, Ordering::SeqCst);
        self.inner.append(path, payload).await
    }

    async fn append_batch(
        &self,
        path: &VirtualPath,
        payloads: Vec<Vec<u8>>,
    ) -> Result<Vec<SeqNo>, FilesystemError> {
        self.appended_records
            .fetch_add(payloads.len(), Ordering::SeqCst);
        self.inner.append_batch(path, payloads).await
    }

    async fn tail(
        &self,
        path: &VirtualPath,
        from: SeqNo,
    ) -> Result<Vec<ironclaw_filesystem::EventRecord>, FilesystemError> {
        self.inner.tail(path, from).await
    }
}

fn scoped(backend: Arc<CountingFilesystem>) -> Arc<ScopedFilesystem<CountingFilesystem>> {
    let mounts = MountView::new(vec![MountGrant::new(
        MountAlias::new("/resources").expect("alias"),
        VirtualPath::new("/tenants/tenant1/users/user1/resources").expect("target"),
        MountPermissions::read_write_list_delete(),
    )])
    .expect("mount view");
    Arc::new(ScopedFilesystem::with_fixed_view(backend, mounts))
}

fn sample_scope() -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new("tenant1").expect("tenant"),
        user_id: UserId::new("user1").expect("user"),
        agent_id: None,
        project_id: Some(ProjectId::new("project1").expect("project")),
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

fn usd(amount: rust_decimal::Decimal) -> ResourceEstimate {
    ResourceEstimate {
        usd: Some(amount),
        ..ResourceEstimate::default()
    }
}

fn spent(amount: rust_decimal::Decimal) -> ResourceUsage {
    ResourceUsage {
        usd: amount,
        ..ResourceUsage::default()
    }
}

fn tenant_limit(governor: &FilesystemResourceGovernor<CountingFilesystem>, max_usd: &str) {
    governor
        .set_limit(
            ResourceAccount::tenant(sample_scope().tenant_id),
            ResourceLimits {
                max_usd: Some(max_usd.parse().expect("limit")),
                ..ResourceLimits::default()
            },
        )
        .expect("set limit");
}

/// The headline saving: one durable record per model call, not two.
#[test]
fn reserve_then_reconcile_appends_one_durable_record() {
    let backend = Arc::new(CountingFilesystem::new());
    let governor = FilesystemResourceGovernor::new(scoped(Arc::clone(&backend)));
    tenant_limit(&governor, "1.00");
    let before = backend.appended_records();

    let reservation = governor
        .reserve(sample_scope(), usd(dec!(0.25)))
        .expect("reserve");
    governor
        .reconcile(reservation.id, spent(dec!(0.20)))
        .expect("reconcile");

    assert_eq!(
        backend.appended_records() - before,
        1,
        "a model call must cost exactly one durable journal record: the spend"
    );
}

/// Cancellation returns reserved-but-unspent budget and costs nothing durable.
#[test]
fn release_returns_unspent_budget_without_a_durable_record() {
    let backend = Arc::new(CountingFilesystem::new());
    let governor = FilesystemResourceGovernor::new(scoped(Arc::clone(&backend)));
    tenant_limit(&governor, "1.00");
    let before = backend.appended_records();

    let reservation = governor
        .reserve(sample_scope(), usd(dec!(0.90)))
        .expect("reserve");
    governor.release(reservation.id).expect("release");

    assert_eq!(
        backend.appended_records() - before,
        0,
        "a released reservation spent nothing, so it must write nothing durable"
    );
    governor
        .reserve(sample_scope(), usd(dec!(0.90)))
        .expect("released budget must be available to the next reservation");
}

/// Spend is money: it must survive a process restart via the delta log.
#[test]
fn spend_totals_after_restart_match_the_durable_delta_log() {
    let backend = Arc::new(CountingFilesystem::new());
    let account = ResourceAccount::tenant(sample_scope().tenant_id);
    {
        let governor = FilesystemResourceGovernor::new(scoped(Arc::clone(&backend)));
        tenant_limit(&governor, "1.00");
        for amount in [dec!(0.10), dec!(0.15), dec!(0.05)] {
            let reservation = governor
                .reserve(sample_scope(), usd(dec!(0.30)))
                .expect("reserve");
            governor
                .reconcile(reservation.id, spent(amount))
                .expect("reconcile");
        }
    }

    let reloaded = FilesystemResourceGovernor::new(scoped(backend));
    reloaded.warm_authority().expect("warm");
    let snapshot = reloaded
        .account_snapshot(&account)
        .expect("snapshot")
        .expect("account exists");

    assert_eq!(
        snapshot.ledger.spent.usd,
        dec!(0.30),
        "replayed spend must equal the sum of reconciled actuals"
    );
    assert_eq!(
        snapshot.ledger.reserved.usd,
        dec!(0),
        "closed reservations hold nothing after replay"
    );
    assert!(
        snapshot
            .limits
            .as_ref()
            .and_then(|limits| limits.max_usd)
            .is_some(),
        "limits must still replay from the durable log"
    );
}

/// Fail closed: an exhausted budget still denies, before and after restart.
#[test]
fn exhausted_budget_still_denies_after_restart() {
    let backend = Arc::new(CountingFilesystem::new());
    {
        let governor = FilesystemResourceGovernor::new(scoped(Arc::clone(&backend)));
        tenant_limit(&governor, "1.00");
        let reservation = governor
            .reserve(sample_scope(), usd(dec!(0.95)))
            .expect("reserve");
        governor
            .reconcile(reservation.id, spent(dec!(0.95)))
            .expect("reconcile");
        assert!(
            matches!(
                governor.reserve(sample_scope(), usd(dec!(0.50))),
                Err(ResourceError::LimitExceeded { .. })
            ),
            "an exhausted budget must deny in-process"
        );
    }

    let reloaded = FilesystemResourceGovernor::new(scoped(backend));
    assert!(
        matches!(
            reloaded.reserve(sample_scope(), usd(dec!(0.50))),
            Err(ResourceError::LimitExceeded { .. })
        ),
        "an exhausted budget must still deny after a restart"
    );
}

/// The in-memory reservation ledger is the concurrency guard: within one
/// process there is no overshoot at all.
#[test]
fn concurrent_reservations_never_exceed_the_limit() {
    let backend = Arc::new(CountingFilesystem::new());
    let governor = Arc::new(FilesystemResourceGovernor::new(scoped(backend)));
    tenant_limit(&governor, "1.00");
    let barrier = Arc::new(std::sync::Barrier::new(20));

    let admitted: usize = (0..20)
        .map(|_| {
            let governor = Arc::clone(&governor);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                usize::from(governor.reserve(sample_scope(), usd(dec!(0.10))).is_ok())
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|handle| handle.join().expect("reservation thread"))
        .sum();

    assert_eq!(
        admitted, 10,
        "concurrent reservations must be admitted strictly up to the limit"
    );
}

/// The documented cost of the collapse: a reservation that never reconciled
/// is not resurrected after a restart, because only spend is durable.
#[test]
fn unreconciled_reservations_do_not_survive_a_restart() {
    let backend = Arc::new(CountingFilesystem::new());
    let account = ResourceAccount::tenant(sample_scope().tenant_id);
    {
        let governor = FilesystemResourceGovernor::new(scoped(Arc::clone(&backend)));
        tenant_limit(&governor, "1.00");
        governor
            .reserve(sample_scope(), usd(dec!(0.90)))
            .expect("reserve");
    }

    let reloaded = FilesystemResourceGovernor::new(scoped(backend));
    let snapshot = reloaded
        .account_snapshot(&account)
        .expect("snapshot")
        .expect("account exists");

    assert_eq!(
        snapshot.ledger.reserved.usd,
        dec!(0),
        "in-flight holds are process-local coordination and do not survive a crash"
    );
}

/// The knob: operators that want crash-exact reservations pay two records.
#[test]
fn durable_reservation_mode_keeps_the_pre_call_record() {
    let backend = Arc::new(CountingFilesystem::new());
    let governor = FilesystemResourceGovernor::new(scoped(Arc::clone(&backend)))
        .with_reservation_durability(ReservationDurability::Durable);
    tenant_limit(&governor, "1.00");
    let before = backend.appended_records();

    let reservation = governor
        .reserve(sample_scope(), usd(dec!(0.25)))
        .expect("reserve");
    governor
        .reconcile(reservation.id, spent(dec!(0.20)))
        .expect("reconcile");

    assert_eq!(
        backend.appended_records() - before,
        2,
        "Durable mode restores the pre-call reservation record"
    );
}

/// Durable mode must still replay to the same spend total.
#[test]
fn durable_reservation_mode_replays_the_same_spend() {
    let backend = Arc::new(CountingFilesystem::new());
    let account = ResourceAccount::tenant(sample_scope().tenant_id);
    {
        let governor = FilesystemResourceGovernor::new(scoped(Arc::clone(&backend)))
            .with_reservation_durability(ReservationDurability::Durable);
        tenant_limit(&governor, "1.00");
        let reservation = governor
            .reserve(sample_scope(), usd(dec!(0.30)))
            .expect("reserve");
        governor
            .reconcile(reservation.id, spent(dec!(0.25)))
            .expect("reconcile");
    }

    let reloaded = FilesystemResourceGovernor::new(scoped(backend));
    let snapshot = reloaded
        .account_snapshot(&account)
        .expect("snapshot")
        .expect("account exists");

    assert_eq!(snapshot.ledger.spent.usd, dec!(0.25));
    assert_eq!(snapshot.ledger.reserved.usd, dec!(0));
}
