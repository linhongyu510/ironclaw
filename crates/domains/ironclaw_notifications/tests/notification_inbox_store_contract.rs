#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use ironclaw_filesystem::{
    BackendCapabilities, CasExpectation, DirEntry, Entry, FileStat, FilesystemError, Filter,
    InMemoryBackend, IndexSpec, LibSqlRootFilesystem, Page, RecordVersion, RootFilesystem,
    ScopedFilesystem, VersionedEntry,
};
use ironclaw_host_api::{
    ids::{TenantId, ThreadId, UserId},
    mount::{MountGrant, MountPermissions, MountView},
    path::{MountAlias, VirtualPath},
    turn::TurnRunId,
};
use ironclaw_notifications::{
    ListNotificationsRequest, MarkAllNotificationsReadRequest, NOTIFICATION_INBOX_MAX_RECORDS,
    NOTIFICATION_PAGE_LIMIT_MAX, NotificationAction, NotificationId, NotificationInboxError,
    NotificationInboxStore, NotificationInboxStorePort, NotificationKind,
    NotificationMutationRequest, NotificationRecipient, NotificationSeverity, NotificationSource,
    PublishNotificationRequest,
};
use tokio::sync::Mutex;

const TEST_ROOT: &str = "/engine/tenants/test/users/test/notifications";

fn scoped<F: RootFilesystem>(backend: Arc<F>) -> Arc<ScopedFilesystem<F>> {
    let mounts = MountView::new(vec![MountGrant::new(
        MountAlias::new("/notifications").expect("alias"),
        VirtualPath::new(TEST_ROOT).expect("target"),
        MountPermissions::read_write_list_delete(),
    )])
    .expect("mount view");
    Arc::new(ScopedFilesystem::with_fixed_view(backend, mounts))
}

fn recipient() -> NotificationRecipient {
    NotificationRecipient {
        tenant_id: TenantId::new("test").expect("tenant"),
        user_id: UserId::new("test").expect("user"),
    }
}

fn request(id: &str, timestamp: i64) -> PublishNotificationRequest {
    let thread_id = ThreadId::new(format!("thread-{id}")).expect("thread");
    PublishNotificationRequest {
        id: NotificationId::new(id).expect("id"),
        recipient: recipient(),
        kind: NotificationKind::ApprovalRequired,
        severity: NotificationSeverity::Warning,
        source: NotificationSource {
            thread_id: thread_id.clone(),
            turn_run_id: Some(TurnRunId::new()),
            lifecycle_ref: Some(format!("gate-{id}")),
        },
        action: NotificationAction::OpenThread { thread_id },
        occurred_at: Utc.timestamp_opt(timestamp, 0).single().expect("time"),
    }
}

#[tokio::test]
async fn notification_inbox_is_durable_paginated_and_idempotent() {
    let backend = Arc::new(InMemoryBackend::new());
    let first = NotificationInboxStore::new(scoped(Arc::clone(&backend)));
    let first_request = request("notification-1", 1_700_000_001);
    first
        .publish(first_request.clone())
        .await
        .expect("publish first");
    first
        .publish(first_request)
        .await
        .expect("idempotent retry");
    first
        .publish(request("notification-2", 1_700_000_002))
        .await
        .expect("publish second");

    let reopened = NotificationInboxStore::new(scoped(backend));
    let page = reopened
        .list(ListNotificationsRequest {
            recipient: recipient(),
            limit: 1,
            cursor: None,
            include_archived: false,
        })
        .await
        .expect("list first page");
    assert_eq!(page.notifications.len(), 1);
    assert_eq!(page.notifications[0].id.as_str(), "notification-2");
    assert_eq!(page.unread_count, 2);
    let cursor = page.next_cursor.expect("second page cursor");
    reopened
        .archive(NotificationMutationRequest {
            recipient: recipient(),
            notification_id: NotificationId::new("notification-2").expect("id"),
            occurred_at: Utc.timestamp_opt(1_700_000_010, 0).single().expect("time"),
        })
        .await
        .expect("archive page anchor");
    let second_page = reopened
        .list(ListNotificationsRequest {
            recipient: recipient(),
            limit: 1,
            cursor: Some(cursor),
            include_archived: false,
        })
        .await
        .expect("resume after archived anchor");
    assert_eq!(second_page.notifications[0].id.as_str(), "notification-1");
}

#[tokio::test]
async fn notification_lifecycle_is_scoped_archivable_and_idempotent() {
    let backend = Arc::new(InMemoryBackend::new());
    let store = NotificationInboxStore::new(scoped(backend));
    store
        .publish(request("notification-lifecycle", 1_700_000_001))
        .await
        .expect("publish notification");
    store
        .publish(request("notification-unread", 1_700_000_002))
        .await
        .expect("publish unread notification");
    store
        .publish(request("notification-archived", 1_700_000_003))
        .await
        .expect("publish archived notification");

    let read_at = Utc.timestamp_opt(1_700_000_010, 0).single().expect("time");
    let lifecycle = NotificationMutationRequest {
        recipient: recipient(),
        notification_id: NotificationId::new("notification-lifecycle").expect("id"),
        occurred_at: read_at,
    };
    store.mark_read(lifecycle.clone()).await.expect("mark read");
    store
        .mark_read(lifecycle.clone())
        .await
        .expect("idempotent mark read");
    store
        .resolve(lifecycle)
        .await
        .expect("resolve notification");

    let archived_at = Utc.timestamp_opt(1_700_000_020, 0).single().expect("time");
    store
        .archive(NotificationMutationRequest {
            recipient: recipient(),
            notification_id: NotificationId::new("notification-archived").expect("id"),
            occurred_at: archived_at,
        })
        .await
        .expect("archive notification");
    store
        .mark_all_read(MarkAllNotificationsReadRequest {
            recipient: recipient(),
            occurred_at: Utc.timestamp_opt(1_700_000_030, 0).single().expect("time"),
        })
        .await
        .expect("mark visible notifications read");

    let visible = store
        .list(ListNotificationsRequest {
            recipient: recipient(),
            limit: 10,
            cursor: None,
            include_archived: false,
        })
        .await
        .expect("list visible");
    assert_eq!(visible.notifications.len(), 2);
    assert_eq!(visible.unread_count, 0);
    let lifecycle = visible
        .notifications
        .iter()
        .find(|record| record.id.as_str() == "notification-lifecycle")
        .expect("lifecycle notification");
    assert_eq!(lifecycle.read_at, Some(read_at));
    assert!(lifecycle.resolved_at.is_some());

    let all = store
        .list(ListNotificationsRequest {
            recipient: recipient(),
            limit: 10,
            cursor: None,
            include_archived: true,
        })
        .await
        .expect("list archived");
    let archived = all
        .notifications
        .iter()
        .find(|record| record.id.as_str() == "notification-archived")
        .expect("archived notification");
    assert_eq!(archived.archived_at, Some(archived_at));
    assert_eq!(archived.read_at, Some(archived_at));

    let foreign = NotificationRecipient {
        tenant_id: recipient().tenant_id,
        user_id: UserId::new("foreign").expect("user"),
    };
    assert!(matches!(
        store
            .list(ListNotificationsRequest {
                recipient: foreign,
                limit: 10,
                cursor: None,
                include_archived: false,
            })
            .await,
        Err(NotificationInboxError::AccessDenied)
    ));
    assert!(matches!(
        store
            .mark_read(NotificationMutationRequest {
                recipient: recipient(),
                notification_id: NotificationId::new("missing").expect("id"),
                occurred_at: read_at,
            })
            .await,
        Err(NotificationInboxError::NotificationNotFound)
    ));
}

#[tokio::test]
async fn notification_inbox_enforces_limits_and_bounds_cas_retries() {
    let backend = Arc::new(InMemoryBackend::new());
    let store = NotificationInboxStore::new(scoped(Arc::clone(&backend)));
    for limit in [0, NOTIFICATION_PAGE_LIMIT_MAX + 1] {
        assert!(matches!(
            store
                .list(ListNotificationsRequest {
                    recipient: recipient(),
                    limit,
                    cursor: None,
                    include_archived: false,
                })
                .await,
            Err(NotificationInboxError::InvalidRequest { .. })
        ));
    }

    for index in 0..NOTIFICATION_INBOX_MAX_RECORDS {
        store
            .publish(request(
                &format!("notification-capacity-{index}"),
                1_700_001_000 + index as i64,
            ))
            .await
            .expect("publish within capacity");
    }
    assert!(matches!(
        store
            .publish(request("notification-capacity-overflow", 1_700_009_000))
            .await,
        Err(NotificationInboxError::InvalidRequest { .. })
    ));

    let racing = Arc::new(VersionRacingBackend::new(Arc::new(InMemoryBackend::new())));
    let racing_store = NotificationInboxStore::new(scoped(Arc::clone(&racing)));
    racing.arm(TEST_ROOT, 1).await;
    racing_store
        .publish(request("notification-cas-retry", 1_700_010_000))
        .await
        .expect("retry transient CAS conflict");
    assert_eq!(racing.injected_count().await, 1);

    racing.arm(TEST_ROOT, u32::MAX).await;
    assert!(matches!(
        racing_store
            .publish(request("notification-cas-exhausted", 1_700_010_001))
            .await,
        Err(NotificationInboxError::Backend)
    ));
    let surviving = racing_store
        .list(ListNotificationsRequest {
            recipient: recipient(),
            limit: 10,
            cursor: None,
            include_archived: false,
        })
        .await
        .expect("surviving page");
    assert_eq!(surviving.notifications.len(), 1);
}

#[tokio::test]
async fn notification_inbox_persists_across_libsql_reopen() {
    let directory = tempfile::tempdir().expect("temporary libSQL directory");
    let database_path = directory.path().join("notification-inbox.db");
    {
        let database = Arc::new(
            libsql::Builder::new_local(&database_path)
                .build()
                .await
                .expect("build database"),
        );
        let root = Arc::new(LibSqlRootFilesystem::new(database).expect("build root filesystem"));
        root.run_migrations().await.expect("run migrations");
        let store = NotificationInboxStore::new(scoped(root));
        store
            .publish(request("notification-libsql", 1_700_000_001))
            .await
            .expect("persist notification");
    }

    let database = Arc::new(
        libsql::Builder::new_local(&database_path)
            .build()
            .await
            .expect("reopen database"),
    );
    let root = Arc::new(LibSqlRootFilesystem::new(database).expect("reopen root filesystem"));
    root.run_migrations().await.expect("rerun migrations");
    let reopened = NotificationInboxStore::new(scoped(root));
    let page = reopened
        .list(ListNotificationsRequest {
            recipient: recipient(),
            limit: 10,
            cursor: None,
            include_archived: false,
        })
        .await
        .expect("read reopened notification");
    assert_eq!(page.unread_count, 1);
    assert_eq!(page.notifications[0].id.as_str(), "notification-libsql");
}

struct VersionRacingBackend {
    inner: Arc<InMemoryBackend>,
    state: Mutex<RacingState>,
}

struct RacingState {
    target_prefix: Option<String>,
    injected: u32,
    remaining: u32,
}

impl VersionRacingBackend {
    fn new(inner: Arc<InMemoryBackend>) -> Self {
        Self {
            inner,
            state: Mutex::new(RacingState {
                target_prefix: None,
                injected: 0,
                remaining: 0,
            }),
        }
    }

    async fn arm(&self, prefix: &str, count: u32) {
        let mut state = self.state.lock().await;
        state.target_prefix = Some(prefix.to_string());
        state.injected = 0;
        state.remaining = count;
    }

    async fn injected_count(&self) -> u32 {
        self.state.lock().await.injected
    }
}

#[async_trait]
impl RootFilesystem for VersionRacingBackend {
    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    async fn put(
        &self,
        path: &VirtualPath,
        entry: Entry,
        cas: CasExpectation,
    ) -> Result<RecordVersion, FilesystemError> {
        {
            let mut state = self.state.lock().await;
            if state.remaining > 0
                && state
                    .target_prefix
                    .as_deref()
                    .is_some_and(|prefix| path.as_str().starts_with(prefix))
            {
                state.remaining -= 1;
                state.injected += 1;
                return Err(FilesystemError::VersionMismatch {
                    path: path.clone(),
                    expected: None,
                    found: None,
                });
            }
        }
        self.inner.put(path, entry, cas).await
    }

    async fn get(&self, path: &VirtualPath) -> Result<Option<VersionedEntry>, FilesystemError> {
        self.inner.get(path).await
    }

    async fn list_dir(&self, path: &VirtualPath) -> Result<Vec<DirEntry>, FilesystemError> {
        self.inner.list_dir(path).await
    }

    async fn query(
        &self,
        path: &VirtualPath,
        filter: &Filter,
        page: Page,
    ) -> Result<Vec<VersionedEntry>, FilesystemError> {
        self.inner.query(path, filter, page).await
    }

    async fn ensure_index(
        &self,
        path: &VirtualPath,
        spec: &IndexSpec,
    ) -> Result<(), FilesystemError> {
        self.inner.ensure_index(path, spec).await
    }

    async fn stat(&self, path: &VirtualPath) -> Result<FileStat, FilesystemError> {
        self.inner.stat(path).await
    }

    async fn delete(&self, path: &VirtualPath) -> Result<(), FilesystemError> {
        self.inner.delete(path).await
    }
}
