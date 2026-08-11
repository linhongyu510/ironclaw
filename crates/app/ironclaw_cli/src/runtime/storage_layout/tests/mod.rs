#![allow(unused_imports)] // Scenario submodules share this private fixture prelude.

use std::fs;
#[cfg(any(unix, windows))]
use std::process::Command;
#[cfg(any(unix, windows))]
use std::thread;
#[cfg(any(unix, windows))]
use std::time::{Duration, Instant};

use ironclaw_composition::LegacySkillSnapshotSource;
use ironclaw_config::{
    DeploymentSecurityEnvelope, DurableStateKind, LayoutManifest, LayoutRequirement, RebornHome,
    TenancyModel, WorkspaceAccessFloor,
};
use ironclaw_host_api::ids::{TenantId, TenantUserWorkspaceKey, UserId};

use super::test_support::*;
use super::*;
use super::{admission::*, adoption::*, filesystem::*, locks::*, model::*};

pub(super) fn embedded_single_user_requirement() -> LayoutRequirement {
    LayoutRequirement {
        durable_state: DurableStateKind::EmbeddedLibSql,
        security: DeploymentSecurityEnvelope {
            tenancy: TenancyModel::SingleUser,
            workspace_access_floor: WorkspaceAccessFloor::SingleTrustedOperator,
        },
    }
}

#[test]
fn startup_adoption_authority_requires_the_exact_versioned_cutover_value() {
    let missing = StartupAdoptionAuthority::from_environment_value(None)
        .expect_err("missing deployment authority fails closed");
    assert!(missing.to_string().contains(StartupAdoptionAuthority::ENV));

    let malformed = StartupAdoptionAuthority::from_environment_value(Some("true"))
        .expect_err("generic truthy values do not authorize migration");
    assert!(
        malformed
            .to_string()
            .contains(StartupAdoptionAuthority::LEGACY_LAYOUT_V1)
    );

    StartupAdoptionAuthority::from_environment_value(Some(
        StartupAdoptionAuthority::LEGACY_LAYOUT_V1,
    ))
    .expect("the versioned cutover value authorizes this one migration protocol");
}

#[test]
fn automatic_startup_cutover_lock_serializes_competing_new_replicas() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let authority = StartupAdoptionAuthority::from_environment_value(Some(
        StartupAdoptionAuthority::LEGACY_LAYOUT_V1,
    ))
    .expect("cutover authority");

    let _permit = prepare_automatic_adoption(&home, requirement, authority)
        .expect("first new replica owns the cutover");
    let contention = match prepare_automatic_adoption(&home, requirement, authority) {
        Ok(_) => panic!("second new replica must fail before verification and mutation"),
        Err(error) => error,
    };

    assert!(contention.to_string().contains("automatic storage cutover"));
    assert!(legacy.join("reborn-local-dev.db").is_file());
    assert!(!temp.path().join(LAYOUT_MANIFEST_FILE).exists());
    assert!(
        !temp
            .path()
            .join("runtime")
            .join(ADOPTION_DIR)
            .join(JOURNAL_FILE)
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn automatic_cutover_holder_subprocess() {
    let Ok(home_path) = std::env::var("IRONCLAW_TEST_CUTOVER_HOME") else {
        return;
    };
    let ready = std::env::var("IRONCLAW_TEST_CUTOVER_READY").expect("cutover ready path");
    let release = std::env::var("IRONCLAW_TEST_CUTOVER_RELEASE").expect("cutover release path");
    let home = reborn_home(std::path::Path::new(&home_path));
    let authority = StartupAdoptionAuthority::from_environment_value(Some(
        StartupAdoptionAuthority::LEGACY_LAYOUT_V1,
    ))
    .expect("cutover authority");
    let _permit = prepare_automatic_adoption(&home, embedded_single_user_requirement(), authority)
        .expect("subprocess holds automatic cutover lock");
    fs::write(ready, b"ready").expect("signal held cutover lock");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&release).is_file() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        std::path::Path::new(&release).is_file(),
        "parent did not release cutover holder within the bounded test interval"
    );
}

#[cfg(unix)]
#[test]
fn automatic_cutover_lock_serializes_separate_processes_and_reuses_its_inode() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = reborn_home(temp.path());
    let requirement = embedded_single_user_requirement();
    let legacy = temp.path().join("local-dev");
    seed_legacy_embedded_store(&legacy);
    let ready = temp.path().join("cutover-ready");
    let release = temp.path().join("cutover-release");
    let test_binary = std::env::current_exe().expect("test binary");
    let mut child = Command::new(test_binary)
        .args([
            "--exact",
            "runtime::storage_layout::tests::automatic_cutover_holder_subprocess",
            "--nocapture",
        ])
        .env("IRONCLAW_TEST_CUTOVER_HOME", temp.path())
        .env("IRONCLAW_TEST_CUTOVER_READY", &ready)
        .env("IRONCLAW_TEST_CUTOVER_RELEASE", &release)
        .spawn()
        .expect("spawn automatic cutover holder");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        ready.is_file(),
        "cutover holder reached its critical section"
    );
    let authority = StartupAdoptionAuthority::from_environment_value(Some(
        StartupAdoptionAuthority::LEGACY_LAYOUT_V1,
    ))
    .expect("cutover authority");
    let contention = match prepare_automatic_adoption(&home, requirement, authority) {
        Ok(_) => panic!("a separate process must serialize automatic cutover"),
        Err(error) => error,
    };
    assert!(
        contention.to_string().contains("automatic storage cutover"),
        "{contention:#}"
    );
    assert!(legacy.join(DB_FILE).is_file());
    assert!(!temp.path().join(LAYOUT_MANIFEST_FILE).exists());
    assert!(
        !temp
            .path()
            .join("runtime")
            .join(ADOPTION_DIR)
            .join(JOURNAL_FILE)
            .exists()
    );

    fs::write(&release, b"release").expect("release cutover holder");
    let status = child.wait().expect("wait for released cutover holder");
    assert!(status.success(), "cutover holder exits cleanly");
    let _permit = prepare_automatic_adoption(&home, requirement, authority)
        .expect("the persistent lock inode is reusable after process exit");
}

pub(super) fn external_single_user_requirement() -> LayoutRequirement {
    LayoutRequirement {
        durable_state: DurableStateKind::ExternalPostgres,
        security: DeploymentSecurityEnvelope {
            tenancy: TenancyModel::SingleUser,
            workspace_access_floor: WorkspaceAccessFloor::SingleTrustedOperator,
        },
    }
}

pub(super) fn embedded_multi_user_requirement() -> LayoutRequirement {
    LayoutRequirement {
        durable_state: DurableStateKind::EmbeddedLibSql,
        security: DeploymentSecurityEnvelope {
            tenancy: TenancyModel::MultiUser,
            workspace_access_floor: WorkspaceAccessFloor::PerCallerIsolated,
        },
    }
}

pub(super) fn confirmed_options() -> AdoptOptions {
    AdoptOptions {
        confirm_processes_stopped: true,
        confirm_backup_snapshot: true,
        workspace_import: None,
    }
}

#[cfg(any(unix, windows))]
#[test]
fn advisory_lock_holder_subprocess() {
    let Ok(adoption_root) = std::env::var("IRONCLAW_TEST_ADOPTION_LOCK_ROOT") else {
        return;
    };
    let ready = std::env::var("IRONCLAW_TEST_ADOPTION_LOCK_READY").expect("lock holder ready path");
    let release =
        std::env::var("IRONCLAW_TEST_ADOPTION_LOCK_RELEASE").expect("lock holder release path");
    let _lock = acquire_adoption_lock(std::path::Path::new(&adoption_root))
        .expect("subprocess holds adoption lock");
    fs::write(ready, b"ready").expect("signal held lock");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&release).is_file() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        std::path::Path::new(&release).is_file(),
        "parent did not release lock holder within the bounded test interval"
    );
}

#[cfg(any(unix, windows))]
#[test]
fn advisory_lock_recovers_after_a_terminated_process() {
    let temp = tempfile::tempdir().expect("tempdir");
    let adoption_root = temp.path().join("layout-adoption");
    fs::create_dir(&adoption_root).expect("adoption root");
    let ready = temp.path().join("lock-ready");
    let test_binary = std::env::current_exe().expect("test binary");
    let mut child = Command::new(test_binary)
        .args([
            "--exact",
            "runtime::storage_layout::tests::advisory_lock_holder_subprocess",
            "--nocapture",
        ])
        .env("IRONCLAW_TEST_ADOPTION_LOCK_ROOT", &adoption_root)
        .env("IRONCLAW_TEST_ADOPTION_LOCK_READY", &ready)
        .env(
            "IRONCLAW_TEST_ADOPTION_LOCK_RELEASE",
            temp.path().join("lock-release"),
        )
        .spawn()
        .expect("spawn lock holder");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(ready.is_file(), "lock holder reached its critical section");
    let contention = match acquire_adoption_lock(&adoption_root) {
        Ok(_) => panic!("live lock holder prevents concurrent adoption"),
        Err(error) => error,
    };
    assert!(
        !format!("{contention:#}").is_empty(),
        "contention exposes a diagnostic error"
    );
    child.kill().expect("terminate lock holder");
    let _status = child.wait().expect("reap terminated lock holder");

    let _lock = acquire_adoption_lock(&adoption_root)
        .expect("OS advisory lock is released after a holder process is terminated");
}

pub(super) fn workspace_import(
    source: std::path::PathBuf,
    confirmed: bool,
) -> WorkspaceImportOptions {
    WorkspaceImportOptions {
        source,
        tenant: TenantId::new("tenant-a").expect("tenant id"),
        user: UserId::new("user-a").expect("user id"),
        confirmed,
    }
}

pub(super) fn reborn_home(path: &std::path::Path) -> RebornHome {
    RebornHome::resolve_from_env_parts(Some(path.as_os_str().to_os_string()), None, None)
        .expect("test Reborn home")
}

pub(super) fn seed_legacy_embedded_store(root: &std::path::Path) {
    fs::create_dir_all(root).expect("legacy root");
    let key = ironclaw_secrets::keychain::generate_master_key_hex();
    fs::write(
        root.join(ironclaw_composition::STANDALONE_SECRETS_MASTER_KEY_PATH),
        key,
    )
    .expect("legacy key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(
            root.join(ironclaw_composition::STANDALONE_SECRETS_MASTER_KEY_PATH),
            fs::Permissions::from_mode(0o600),
        )
        .expect("owner-only legacy key");
    }
    crate::runtime::block_on_cli({
        let root = root.to_path_buf();
        async move {
            ironclaw_composition::open_standalone_secret_store(&root)
                .await
                .map(|_| ())
        }
    })
    .expect("seed legacy libSQL store");
}

mod admission_adoption;
mod filesystem_security;
mod recovery;
mod workspace;
