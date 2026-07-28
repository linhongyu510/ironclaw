//! `$HOME`-rooted tempdir + unique-identity helpers for the sandbox-shell
//! integration lane (`tests/integration/reborn_sandbox_shell_turn.rs`,
//! `support/harness/profiles/sandbox_shell.rs`).
//!
//! Every other harness path builds its storage root with `tempfile::tempdir()`,
//! which resolves under the process's `$TMPDIR`. On a colima/Docker-Desktop dev
//! setup, the VM's virtiofs mount excludes macOS's default `$TMPDIR`, so a
//! `TenantSandbox` bind-mount source rooted there becomes a phantom root-owned
//! directory inside the VM and every container exec fails with a misleading
//! `Permission denied` — never a "no such directory" that would point at the
//! real cause. Rooting explicitly under `$HOME` sidesteps the mount exclusion
//! regardless of whatever `$TMPDIR` the test process happens to inherit.
//!
//! Container/workspace-directory collisions are the second hazard: the sandbox
//! transport names containers and bind-mount directories deterministically
//! from `(tenant_id, user_id)` (`ironclaw_host_runtime::RebornSandboxUserKey`),
//! so two concurrently-running tests sharing a tenant/user literal would
//! collide on the same container name and workspace directory.
//! `unique_test_tenant_id`/`unique_test_user_id` mint a fresh identifier per
//! harness build (pid + a per-process monotonic counter + wall-clock nanos) so
//! concurrent test binaries — and repeated calls within one binary — can never
//! collide.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ironclaw_host_api::{HostApiError, TenantId, UserId};

static UNIQUE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A short, collision-resistant suffix: this process's pid, a per-process
/// monotonic counter, and wall-clock nanoseconds. Any one alone would do for
/// a single test process; combining all three means the suffix stays unique
/// across concurrently-running test binaries (distinct pids), repeated calls
/// within one binary (the counter), and even a coarse system clock (the pid
/// and counter don't depend on clock resolution at all).
fn unique_suffix() -> String {
    let sequence = UNIQUE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default(); // silent-ok: clock-skew fallback for a uniqueness suffix only, not a correctness-bearing timestamp
    format!("{}-{sequence}-{nanos}", std::process::id())
}

/// Fresh `TenantId` for one harness build, so concurrent sandbox-shell tests
/// never share a `(tenant, user)` scope — and therefore never share a
/// deterministic container name or bind-mount workspace directory.
pub(crate) fn unique_test_tenant_id(prefix: &str) -> Result<TenantId, HostApiError> {
    TenantId::new(format!("{prefix}-{}", unique_suffix()))
}

/// Fresh `UserId`; see [`unique_test_tenant_id`].
pub(crate) fn unique_test_user_id(prefix: &str) -> Result<UserId, HostApiError> {
    UserId::new(format!("{prefix}-{}", unique_suffix()))
}

/// A tempdir rooted under `$HOME/.ironclaw-test-tmp` (never the process's
/// ambient `$TMPDIR`), for any harness storage root a `TenantSandbox`
/// container bind-mounts. See the module doc for why plain
/// `tempfile::tempdir()` is unsafe for that purpose under colima.
pub(crate) fn home_rooted_tempdir(prefix: &str) -> std::io::Result<tempfile::TempDir> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        std::io::Error::other("HOME env var must be set to build a $HOME-rooted sandbox tempdir")
    })?;
    let base = PathBuf::from(home).join(".ironclaw-test-tmp");
    std::fs::create_dir_all(&base)?;
    tempfile::Builder::new()
        .prefix(&format!("{prefix}-"))
        .tempdir_in(&base)
}
