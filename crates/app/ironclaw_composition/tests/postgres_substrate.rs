#[path = "support/postgres.rs"]
mod postgres_support;
mod support;

use std::{sync::Arc, time::Duration};

use deadpool_postgres::tokio_postgres;
use ironclaw_composition::{
    PostgresProductionSubstrateConfig, RebornBuildError, RebornCompositionError,
    RebornCompositionProfile, RebornHostBindings, RebornProductionRuntimePolicy,
    build_postgres_production_host_runtime_services, verify_hosted_postgres_store_for_adoption,
};
use ironclaw_event_store::RebornEventStoreConfig;
use ironclaw_filesystem::PostgresRootFilesystem;
use ironclaw_host_api::process::{
    CommandExecutionOutput, CommandExecutionRequest, RuntimeProcessError, SandboxCommandTransport,
};
use ironclaw_host_api::runtime_policy::{
    AuditMode, DeploymentMode, FilesystemBackendKind, NetworkMode, ProcessBackendKind,
    RuntimeProfile, SecretMode, {ApprovalPolicy, EffectiveRuntimePolicy},
};
use ironclaw_host_api::{
    ids::{InvocationId, SecretHandle, UserId},
    resource::ResourceScope,
};
use ironclaw_host_runtime::{CapabilitySurfaceVersion, ProductionWiringConfig};
use ironclaw_secrets::{SecretMaterial, SecretStore, SecretStorePort, SecretsCrypto};
use ironclaw_turns::{TurnRunWake, TurnRunWakeNotifier, TurnRunWakeNotifyError};
use postgres_support::assert_postgres_accepts_connections;
use secrecy::SecretString;
use support::production_readiness::{
    assert_required_backend_readiness_diagnostics, required_backend_parity_config,
};
use tokio::sync::Mutex;

static SECRETS_MASTER_KEY_ENV_LOCK: Mutex<()> = Mutex::const_new(());

struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: tests serialize process-env mutation with
        // SECRETS_MASTER_KEY_ENV_LOCK and restore the prior value on drop.
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: EnvVarGuard is only constructed while
        // SECRETS_MASTER_KEY_ENV_LOCK is held by this test module.
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

#[tokio::test]
async fn postgres_substrate_builder_wires_production_components_without_local_only_seams() {
    let Some((_container, pool, database_url)) = postgres_pool_or_skip().await else {
        return;
    };

    let services = build_postgres_test_services(pool, database_url).await;

    let production_config = ProductionWiringConfig::new([])
        .require_runtime_http_egress()
        .require_credential_broker();
    services
        .validate_production_wiring(&production_config)
        .expect("postgres substrate production wiring should not use fake seams");
}

#[tokio::test]
async fn postgres_substrate_readiness_diagnostics_cover_required_backend_gaps() {
    let Some((_container, pool, database_url)) = postgres_pool_or_skip().await else {
        return;
    };
    let services = build_postgres_test_services(pool, database_url).await;

    let report = services
        .validate_production_wiring(&required_backend_parity_config())
        .expect_err("required runtime gaps should block production readiness");

    assert_required_backend_readiness_diagnostics(&report);
}

#[tokio::test]
async fn postgres_substrate_builder_rejects_invalid_secret_master_key() {
    let Some((_container, pool, database_url)) = postgres_pool_or_skip().await else {
        return;
    };

    let result =
        build_postgres_production_host_runtime_services(PostgresProductionSubstrateConfig {
            pool,
            event_store: RebornEventStoreConfig::Postgres {
                url: SecretString::from(database_url),
                tls_options: Default::default(),
            },
            process_local_resource_governor_singleton: true,
            secret_master_key: Some(SecretString::from("too-short")),
            trust_policy: Arc::new(ironclaw_trust::HostTrustPolicy::fail_closed()),
            runtime_policy: RebornProductionRuntimePolicy::with_user_sandbox_process_port(
                production_runtime_policy(),
                sandbox_process_port(),
            )
            .unwrap(),
            turn_run_wake_notifier: Arc::new(RecordingSchedulerWakeNotifier),
            surface_version: CapabilitySurfaceVersion::new("test-surface").unwrap(),
        })
        .await;

    assert!(matches!(
        result,
        Err(RebornCompositionError::Secret(
            ironclaw_secrets::SecretError::InvalidMasterKey
        ))
    ));
}

#[tokio::test]
async fn postgres_adoption_verifier_accepts_empty_and_existing_correct_secret_state() {
    let Some((_container, pool, _database_url)) = postgres_pool_or_skip().await else {
        return;
    };
    let root = tempfile::tempdir().expect("tempdir");
    let key = "01234567890123456789012345678901";

    verify_hosted_postgres_store_for_adoption(postgres_adoption_bindings(
        pool.clone(),
        root.path(),
        key,
    ))
    .await
    .expect("an empty hosted store accepts its configured master key");

    seed_postgres_secret(&pool, key).await;

    verify_hosted_postgres_store_for_adoption(postgres_adoption_bindings(pool, root.path(), key))
        .await
        .expect("an existing hosted secret authenticates with its configured master key");
}

#[tokio::test]
async fn postgres_adoption_verifier_rejects_existing_state_under_a_wrong_master_key() {
    let Some((_container, pool, _database_url)) = postgres_pool_or_skip().await else {
        return;
    };
    let root = tempfile::tempdir().expect("tempdir");
    let valid_key = "01234567890123456789012345678901";

    seed_postgres_secret(&pool, valid_key).await;

    let error = verify_hosted_postgres_store_for_adoption(postgres_adoption_bindings(
        pool,
        root.path(),
        "abcdef0123456789abcdef0123456789",
    ))
    .await
    .expect_err("a hosted store must reject a different valid master key during adoption");

    assert!(matches!(
        error,
        RebornBuildError::SecretStateVerification(_)
    ));
}

#[tokio::test]
async fn postgres_substrate_builder_rejects_weak_env_secret_master_key() {
    let _guard = SECRETS_MASTER_KEY_ENV_LOCK.lock().await;
    let _env = EnvVarGuard::set(
        ironclaw_secrets::keychain::SECRETS_MASTER_KEY_ENV,
        "correct horse battery staple pad!!",
    );
    let Some((_container, pool, database_url)) = postgres_pool_or_skip().await else {
        return;
    };

    let result =
        build_postgres_production_host_runtime_services(PostgresProductionSubstrateConfig {
            pool,
            event_store: RebornEventStoreConfig::Postgres {
                url: SecretString::from(database_url),
                tls_options: Default::default(),
            },
            process_local_resource_governor_singleton: true,
            secret_master_key: None,
            trust_policy: Arc::new(ironclaw_trust::HostTrustPolicy::fail_closed()),
            runtime_policy: RebornProductionRuntimePolicy::with_user_sandbox_process_port(
                production_runtime_policy(),
                sandbox_process_port(),
            )
            .unwrap(),
            turn_run_wake_notifier: Arc::new(RecordingSchedulerWakeNotifier),
            surface_version: CapabilitySurfaceVersion::new("test-surface").unwrap(),
        })
        .await;

    assert!(matches!(
        result,
        Err(RebornCompositionError::Secret(
            ironclaw_secrets::SecretError::InvalidMasterKey
        ))
    ));
}

#[tokio::test]
async fn postgres_substrate_builder_rejects_without_singleton_resource_governor_authority() {
    let Some((_container, pool, database_url)) = postgres_pool_or_skip().await else {
        return;
    };

    let result =
        build_postgres_production_host_runtime_services(PostgresProductionSubstrateConfig {
            pool,
            event_store: RebornEventStoreConfig::Postgres {
                url: SecretString::from(database_url),
                tls_options: Default::default(),
            },
            process_local_resource_governor_singleton: false,
            secret_master_key: Some(SecretString::from("01234567890123456789012345678901")),
            trust_policy: Arc::new(ironclaw_trust::HostTrustPolicy::fail_closed()),
            runtime_policy: RebornProductionRuntimePolicy::with_user_sandbox_process_port(
                production_runtime_policy(),
                sandbox_process_port(),
            )
            .unwrap(),
            turn_run_wake_notifier: Arc::new(RecordingSchedulerWakeNotifier),
            surface_version: CapabilitySurfaceVersion::new("test-surface").unwrap(),
        })
        .await;

    assert!(matches!(
        result,
        Err(RebornCompositionError::InvalidConfig { reason }) if reason.contains("singleton or elected resource-governor owner")
    ));
}

fn production_runtime_policy() -> EffectiveRuntimePolicy {
    EffectiveRuntimePolicy {
        deployment: DeploymentMode::HostedMultiTenant,
        requested_profile: RuntimeProfile::HostedSafe,
        resolved_profile: RuntimeProfile::HostedSafe,
        filesystem_backend: FilesystemBackendKind::TenantWorkspace,
        process_backend: ProcessBackendKind::UserSandbox,
        network_mode: NetworkMode::Brokered,
        secret_mode: SecretMode::TenantBroker,
        approval_policy: ApprovalPolicy::AskDestructive,
        audit_mode: AuditMode::Standard,
    }
}

async fn build_postgres_test_services(
    pool: deadpool_postgres::Pool,
    database_url: String,
) -> ironclaw_composition::PostgresProductionHostRuntimeServices {
    build_postgres_production_host_runtime_services(PostgresProductionSubstrateConfig {
        pool,
        event_store: RebornEventStoreConfig::Postgres {
            url: SecretString::from(database_url),
            tls_options: Default::default(),
        },
        process_local_resource_governor_singleton: true,
        secret_master_key: Some(SecretString::from("01234567890123456789012345678901")),
        trust_policy: Arc::new(ironclaw_trust::HostTrustPolicy::fail_closed()),
        runtime_policy: RebornProductionRuntimePolicy::with_user_sandbox_process_port(
            production_runtime_policy(),
            sandbox_process_port(),
        )
        .unwrap(),
        turn_run_wake_notifier: Arc::new(RecordingSchedulerWakeNotifier),
        surface_version: CapabilitySurfaceVersion::new("test-surface").unwrap(),
    })
    .await
    .unwrap()
}

fn postgres_adoption_bindings(
    pool: deadpool_postgres::Pool,
    root: &std::path::Path,
    master_key: &str,
) -> RebornHostBindings {
    RebornHostBindings::hosted_single_tenant_postgres(
        RebornCompositionProfile::HostedSingleTenant,
        "postgres-adoption-owner",
        ironclaw_config::RebornStoragePaths::from_installation_root(root),
        pool,
        SecretMaterial::from(master_key),
    )
    .expect("hosted PostgreSQL test bindings")
}

async fn seed_postgres_secret(pool: &deadpool_postgres::Pool, master_key: &str) {
    let filesystem = Arc::new(PostgresRootFilesystem::new(pool.clone()));
    filesystem
        .run_migrations()
        .await
        .expect("seed filesystem migrations");
    let crypto = Arc::new(
        SecretsCrypto::new(SecretMaterial::from(master_key)).expect("valid seed master key"),
    );
    let store = SecretStore::new(ironclaw_composition::wrap_scoped(filesystem), crypto);
    let scope = ResourceScope::local_default(
        UserId::new("postgres-adoption-user").expect("user id"),
        InvocationId::new(),
    )
    .expect("local scope");
    store
        .put(
            scope,
            SecretHandle::new("postgres-adoption-secret").expect("secret handle"),
            SecretMaterial::from("seed secret"),
            None,
        )
        .await
        .expect("seed encrypted Postgres secret");
}

fn sandbox_process_port() -> Arc<ironclaw_host_runtime::UserSandboxProcessPort> {
    Arc::new(ironclaw_host_runtime::UserSandboxProcessPort::new(
        Arc::new(RecordingSandboxTransport),
    ))
}

#[derive(Debug)]
struct RecordingSandboxTransport;

#[async_trait::async_trait]
impl SandboxCommandTransport for RecordingSandboxTransport {
    async fn run_command(
        &self,
        _request: CommandExecutionRequest,
    ) -> Result<CommandExecutionOutput, RuntimeProcessError> {
        Ok(CommandExecutionOutput {
            output: String::new(),
            saved_output: None,
            exit_code: 0,
            sandboxed: true,
            duration: Duration::ZERO,
        })
    }
}

async fn postgres_pool_or_skip() -> Option<(
    testcontainers_modules::testcontainers::ContainerAsync<
        testcontainers_modules::postgres::Postgres,
    >,
    deadpool_postgres::Pool,
    String,
)> {
    let (container, database_url) = start_postgres_container().await?;
    assert_postgres_accepts_connections(&database_url).await;
    let config: tokio_postgres::Config = database_url
        .parse()
        .expect("testcontainer database URL must parse");
    let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
    let pool = deadpool_postgres::Pool::builder(manager)
        .max_size(4)
        .build()
        .expect("Postgres pool must build");
    Some((container, pool, database_url))
}

async fn start_postgres_container() -> Option<(
    testcontainers_modules::testcontainers::ContainerAsync<
        testcontainers_modules::postgres::Postgres,
    >,
    String,
)> {
    use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};

    let image = testcontainers_modules::postgres::Postgres::default()
        .with_db_name("ironclaw_test")
        .with_user("postgres")
        .with_password("postgres")
        .with_tag("16-alpine");

    let container = match image.start().await {
        Ok(container) => container,
        Err(error) => {
            eprintln!(
                "skipping Postgres composition tests: docker/testcontainers unavailable ({error})"
            );
            return None;
        }
    };
    let host = match container.get_host().await {
        Ok(host) => host,
        Err(error) => {
            eprintln!(
                "skipping Postgres composition tests: could not resolve container host ({error})"
            );
            return None;
        }
    };
    let port = match container.get_host_port_ipv4(5432).await {
        Ok(port) => port,
        Err(error) => {
            eprintln!(
                "skipping Postgres composition tests: could not resolve container port ({error})"
            );
            return None;
        }
    };
    Some((
        container,
        format!("postgres://postgres:postgres@{host}:{port}/ironclaw_test"),
    ))
}

#[derive(Debug)]
struct RecordingSchedulerWakeNotifier;

impl TurnRunWakeNotifier for RecordingSchedulerWakeNotifier {
    fn notify_queued_run(&self, _wake: TurnRunWake) -> Result<(), TurnRunWakeNotifyError> {
        Ok(())
    }
}
