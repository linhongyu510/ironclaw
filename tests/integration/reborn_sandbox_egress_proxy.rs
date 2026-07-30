//! Docker-real integration test: the sandboxed shell's egress allowlist
//! proxy enforces the allowlist end-to-end through the PRODUCTION
//! composition path (Phase C Task 3 of
//! `docs/plans/2026-07-21-persistent-sandbox-container-design.md`).
//!
//! Drives `ironclaw_reborn_composition::tenant_sandbox_process_binding` —
//! the exact function `build_local_runtime` calls to assemble the
//! `TenantSandbox` process-port binding for the sandboxed profile. The
//! function always spawns its own default `EgressAllowlistProxy` (Phase C
//! Tasks 1-2; there is no operator-pointed external-proxy override — see
//! `sandbox_boot.rs`'s doc for why) the same way every production
//! deployment does. A shell command run through the resulting
//! `TenantSandboxProcessPort` then proves the proxy actually mediates
//! egress: an allowlisted host succeeds, a non-allowlisted host is blocked
//! with a `403` from the proxy.
//!
//! Requires a reachable Docker daemon AND a locally-built sandbox worker
//! image. Neither is available on a typical dev machine (this worktree has
//! no Docker) — the test is authored to run for real in CI/hosted lanes
//! that have both, and skips cleanly (a visible `SKIP: ...` line, never a
//! silent pass) everywhere else, per `tests/integration/CLAUDE.md`.
//!
//! Task 7 (`docs/plans/...` Phase C) extends this SAME file with the
//! secret-lease-daemon Docker-real test, reusing this file's
//! `#[path] mod docker_gate;`.

#[path = "support/docker_gate.rs"]
mod docker_gate;

use std::collections::HashMap;

use ironclaw_host_api::{AgentId, InvocationId, ProjectId, ResourceScope, TenantId, UserId};
use ironclaw_host_runtime::{CommandExecutionRequest, RuntimeProcessPort};
use ironclaw_reborn_composition::{RebornRuntimeProcessBinding, tenant_sandbox_process_binding};

fn test_scope() -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new("sandbox-egress-proxy-tenant").expect("valid tenant id"),
        user_id: UserId::new("sandbox-egress-proxy-user").expect("valid user id"),
        agent_id: Some(AgentId::new("agent").expect("valid agent id")),
        project_id: Some(ProjectId::new("project").expect("valid project id")),
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

/// Docker label every `TenantSandbox` user container carries for
/// `test_scope()`'s fixed tenant id. Mirrors
/// `reborn_sandbox_shell_turn.rs`'s `ITEST_TENANT_LABEL_FILTER` /
/// `remove_itest_sandbox_containers`: this test's scope (and therefore its
/// container's Docker labels) is fixed across runs, but the container's
/// `/workspace` bind mount source is a fresh `tempfile::tempdir()` created
/// only for THIS process and removed when it exits. The persistent-container
/// design (`exec_transport::ensure_container`) reuses any existing container
/// matching the label filter without checking whether its bind source still
/// exists on disk, so a container left over from a prior run of this test
/// binds `/workspace` to an already-deleted host directory — every exec
/// inside it then fails with `mkdir: cannot create directory
/// '/workspace/.ironclaw': No such file or directory`. Remove any such
/// leftover container before building a fresh binding so this test's own
/// tempdir always backs the container it actually talks to.
const EGRESS_PROXY_TEST_TENANT_LABEL_FILTER: &str =
    "label=ironclaw.tenant=sandbox-egress-proxy-tenant";

fn remove_egress_proxy_test_sandbox_containers() {
    let Ok(list) = std::process::Command::new("docker")
        .args([
            "ps",
            "-a",
            "-q",
            "--filter",
            EGRESS_PROXY_TEST_TENANT_LABEL_FILTER,
        ])
        .output()
    else {
        return;
    };
    for id in String::from_utf8_lossy(&list.stdout).lines() {
        let id = id.trim();
        if !id.is_empty() {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", id])
                .output();
        }
    }
}

#[tokio::test]
async fn sandbox_egress_proxy_enforces_allowlist_through_composition() {
    if !docker_gate::docker_available() {
        eprintln!(
            "SKIP: no docker daemon reachable — sandbox_egress_proxy_enforces_allowlist_through_composition requires a real Docker daemon (CI/hosted Docker lane only)"
        );
        return;
    }
    let image = docker_gate::configured_sandbox_image();
    if !docker_gate::docker_image_available(&image) {
        eprintln!(
            "SKIP: sandbox worker image {image:?} is not built locally — sandbox_egress_proxy_enforces_allowlist_through_composition requires a locally-built ironclaw-worker image (CI/hosted Docker lane only)"
        );
        return;
    }

    // Remove any leftover persistent container from a PRIOR local run of this
    // test before building a fresh workspace tempdir — see
    // `remove_egress_proxy_test_sandbox_containers`'s doc for why: this
    // scope's Docker labels are fixed across runs but the bind-mount source
    // below is not.
    remove_egress_proxy_test_sandbox_containers();

    let workspace_root = tempfile::tempdir().expect("tempdir for sandbox workspace root");

    // Production composition path: `tenant_sandbox_process_binding` always
    // spawns its own default `EgressAllowlistProxy` (the same call
    // `build_local_runtime` makes for the sandboxed profile) and points the
    // container's `http_proxy`/`https_proxy` env at it via the Docker
    // host-gateway address.
    let binding = tenant_sandbox_process_binding(workspace_root.path().to_path_buf())
        .await
        .expect("real docker connect + default egress proxy spawn should succeed");
    let egress_proxy = binding.egress_proxy.expect(
        "tenant_sandbox_process_binding should always spawn and return ownership of its own \
         default egress proxy",
    );

    // W6 phase 2 gate: the production factory
    // (`ironclaw_host_runtime::bind_sandbox_egress_proxy_with_tls_intercept`)
    // must have wired TLS interception (and, on top of it, the credential
    // swap) into this proxy — not merely returned `Ok`. `bound_hosts` is
    // deliberately empty until the sandbox's CA-trust-distribution follow-up
    // lands (see `egress_proxy.rs::interception_bound_hosts`'s doc), so this
    // does NOT assert any given CONNECT is actually intercepted; it asserts
    // the interception SEAM itself is live on every sandbox-profile boot.
    assert!(
        egress_proxy.tls_intercept_active(),
        "REGRESSION: the production sandbox egress proxy was built without TLS interception \
         wired in — bind_sandbox_egress_proxy_with_tls_intercept has no effective production \
         caller"
    );

    let process_port = match binding.binding {
        RebornRuntimeProcessBinding::TenantSandbox { process_port } => process_port,
        RebornRuntimeProcessBinding::None => {
            panic!("tenant_sandbox_process_binding must return a TenantSandbox binding")
        }
    };

    let scope = test_scope();

    // Allowed: pypi.org is in DEFAULT_SANDBOX_ALLOWED_DOMAINS
    // (network_allowlist.rs) — curl -f fails (nonzero exit) on any HTTP
    // error or connection failure, so a 0 exit here proves the proxy let
    // the CONNECT tunnel through and the request completed for real.
    let allowed = process_port
        .run_command(CommandExecutionRequest {
            scope: scope.clone(),
            mounts: None,
            command: "curl -sS -f -o /dev/null https://pypi.org".to_string(),
            workdir: None,
            timeout_secs: Some(30),
            extra_env: HashMap::new(),
            output_limit_bytes: None,
            background: false,
        })
        .await
        .expect("allowed-host curl should complete");
    assert_eq!(
        allowed.exit_code, 0,
        "curl to the allowlisted host pypi.org should succeed through the egress proxy: {}",
        allowed.output
    );

    // Denied: example.com is NOT in DEFAULT_SANDBOX_ALLOWED_DOMAINS. The
    // proxy replies `403 Forbidden` to the CONNECT request itself (before
    // any TLS handshake with the origin), which curl surfaces as exit 56
    // ("CONNECT tunnel failed, response 403") — capture stderr into the
    // recorded output so the 403 signal is directly assertable, not just an
    // opaque nonzero exit that could also mean a network hiccup.
    let denied = process_port
        .run_command(CommandExecutionRequest {
            scope: scope.clone(),
            mounts: None,
            command: "curl -sS -o /dev/null https://example.com 2>&1".to_string(),
            workdir: None,
            timeout_secs: Some(30),
            extra_env: HashMap::new(),
            output_limit_bytes: None,
            background: false,
        })
        .await
        .expect(
            "denied-host curl should complete (proxy denial surfaces as a nonzero exit code, \
             not a transport error)",
        );
    assert_ne!(
        denied.exit_code, 0,
        "curl to the non-allowlisted host example.com must be blocked by the egress proxy: {}",
        denied.output
    );
    assert!(
        denied.output.contains("403"),
        "expected curl to report the egress proxy's 403 Forbidden CONNECT denial; got: {}",
        denied.output
    );

    // E1 bypass assertion (the arbiter for Task 2's amended network
    // topology — REQUIRED, per
    // `docs/plans/2026-07-21-persistent-sandbox-container-plan.md` Task 3).
    // Clear every proxy env var the container was given and dial a
    // non-allowlisted host DIRECTLY. If the container still has a route to
    // the internet (e.g. it is still on Docker's default bridge, which NATs
    // out), this connects — proving the proxy is merely advisory, not the
    // only way out. On the pinned internal `internal: true` network
    // (E1's fix — no default route off-host), this must time out /
    // fail to connect, with no help from the proxy at all.
    let bypass_hostname = process_port
        .run_command(CommandExecutionRequest {
            scope: scope.clone(),
            mounts: None,
            command: "env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
                      -u IRONCLAW_REBORN_HTTP_PROXY curl -sf --max-time 5 https://example.com"
                .to_string(),
            workdir: None,
            timeout_secs: Some(30),
            extra_env: HashMap::new(),
            output_limit_bytes: None,
            background: false,
        })
        .await
        .expect("bypass-attempt curl should complete (as a failure, not a transport error)");
    assert_ne!(
        bypass_hostname.exit_code, 0,
        "with proxy env cleared, a direct dial to a non-allowlisted host must fail to connect — \
         a success here means the container has a route off-host that skips the proxy \
         entirely (E1 is broken, egress enforcement is advisory only): {}",
        bypass_hostname.output
    );

    // Same bypass attempt against a raw IP literal, to rule out a DNS-only
    // enforcement mechanism (e.g. a container-local resolver override) that
    // would leave a route-level bypass open for anything not resolved by
    // name.
    let bypass_raw_ip = process_port
        .run_command(CommandExecutionRequest {
            scope: scope.clone(),
            mounts: None,
            command: "env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
                      -u IRONCLAW_REBORN_HTTP_PROXY curl -sf --max-time 5 https://1.1.1.1"
                .to_string(),
            workdir: None,
            timeout_secs: Some(30),
            extra_env: HashMap::new(),
            output_limit_bytes: None,
            background: false,
        })
        .await
        .expect("bypass-attempt curl (raw IP) should complete (as a failure)");
    assert_ne!(
        bypass_raw_ip.exit_code, 0,
        "with proxy env cleared, a direct dial to a non-allowlisted raw IP must fail to \
         connect — DNS-only enforcement would let this through even though E1 blocks named \
         hosts: {}",
        bypass_raw_ip.output
    );

    // E2 hardening #1: a private-IP target reached THROUGH the proxy (env
    // left intact) must be refused — no SSRF to the dind host's cloud
    // metadata endpoint via the allowlist proxy.
    let metadata_ssrf = process_port
        .run_command(CommandExecutionRequest {
            scope,
            mounts: None,
            command: "curl -sf --max-time 5 http://169.254.169.254/latest/meta-data/".to_string(),
            workdir: None,
            timeout_secs: Some(30),
            extra_env: HashMap::new(),
            output_limit_bytes: None,
            background: false,
        })
        .await
        .expect("metadata-endpoint curl should complete (as a failure)");
    assert_ne!(
        metadata_ssrf.exit_code, 0,
        "the egress proxy must refuse a private-IP target (169.254.169.254, the cloud \
         metadata address) even through the allowlist path: {}",
        metadata_ssrf.output
    );
}

/// Sidecar dual-homed topology, ADDITIONAL to
/// `sandbox_egress_proxy_enforces_allowlist_through_composition` above (does
/// NOT replace it — that test targets the production gateway-IP topology,
/// which genuinely cannot work under colima on macOS: the sandbox network is
/// `internal: true` with no route off its own bridge, so
/// `host.docker.internal` can never reach a proxy bound on the macOS host.
/// This module builds a topology that is fully hermetic and reachable from a
/// local colima/Docker Desktop dev machine, proving the SAME isolation claim
/// (allowed-through / denied-by-proxy / no-bypass-route / origin-observed)
/// with the real `EgressAllowlistProxy` binary (built unmodified from
/// production code via `docker/sandbox-egress-proxy.Dockerfile`), a
/// dual-homed proxy container, and two recording HTTP origins — no
/// `tenant_sandbox_process_binding` / Docker host-gateway wiring involved, so
/// it is a genuinely different (complementary) code path from the test
/// above, not a weakened duplicate of it.
mod dual_homed_topology {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    // `PROXY_IMAGE` is a shared, content-addressed build cache (see
    // `content_digest_tag` below) — it is never mutated by a running test,
    // only built-or-reused, so concurrent tests sharing it is not a
    // resource-contention hazard the way live containers/networks are.
    pub const PROXY_IMAGE: &str = "ironclaw-egress-proxy-standalone:test";
    pub const ORIGIN_ALLOWED_BODY: &str = "allowed-origin-response-body";
    pub const ORIGIN_DENIED_BODY: &str = "denied-origin-response-body";

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn docker(args: &[&str]) -> Output {
        Command::new("docker")
            .args(args)
            .output()
            .expect("docker CLI invocation should spawn")
    }

    /// Cheap process-local-ish uniqueness for a resource-name suffix. Two
    /// tests in the same process racing to call this within the same
    /// nanosecond is not observed in practice (each call additionally
    /// crosses a `docker` subprocess spawn before its name is used), and a
    /// collision would only cost an extra `docker rm -f`/`network rm`
    /// no-op in the losing test's `cleanup()`, never cross-test data
    /// corruption — so this doesn't need a true UUID dependency.
    fn unique_suffix() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        format!("{nanos:x}-{:?}", std::thread::current().id())
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect()
    }

    /// Derives a `/24` subnet for `net_egress`, unique per topology, from
    /// its `unique_suffix()` string — deterministically hashed into
    /// `198.18.0.0/15` (IANA's benchmarking-methodology range, RFC 2544:
    /// not private/loopback/link-local/CGNAT/documentation/multicast, so it
    /// passes the SSRF guard the same way the module-level fixed subnet
    /// used to). That `/15` covers 512 distinct `/24`s
    /// (`198.18.0.0/24`..`198.19.255.0/24`); Docker rejects a network whose
    /// subnet overlaps an already-existing one regardless of name, so a
    /// shared fixed subnet would still collide two concurrently-running
    /// topologies even after their names stopped colliding.
    fn unique_egress_subnet(suffix: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        suffix.hash(&mut hasher);
        let slot = (hasher.finish() % 512) as u16;
        let second_octet = 18 + slot / 256;
        let third_octet = slot % 256;
        format!("198.{second_octet}.{third_octet}.0/24")
    }

    /// Docker resource names for ONE test's topology, suffixed uniquely per
    /// `setup()` call so concurrent tests (default `cargo test` parallelism,
    /// which is what CI runs) never contend over the same network/container
    /// name — see this file's module doc for the concurrent-failure history
    /// this fixes.
    pub struct Topology {
        pub net_internal: String,
        pub net_egress: String,
        pub proxy_name: String,
        pub origin_allowed_name: String,
        pub origin_denied_name: String,
        pub worker_name: String,
        /// This topology's own `--subnet=` CIDR for `net_egress`. Docker's
        /// default bridge driver rejects creating a SECOND network whose
        /// subnet overlaps an existing one, even under different names — so
        /// giving every topology a unique NAME but the same fixed
        /// `198.18.0.0/24` subnet still collides two topologies together
        /// under concurrent tests (this was caught turning up as a second,
        /// distinct failure once name collisions were fixed: "creating the
        /// normal-bridge egress network should succeed"). Deriving a
        /// distinct /24 per topology from its own suffix, still inside the
        /// SSRF-guard-safe `198.18.0.0/15` benchmarking range (see the
        /// call site's doc), fixes this the same way the unique names do.
        pub net_egress_subnet: String,
    }

    impl Topology {
        fn new() -> Self {
            let suffix = unique_suffix();
            Self {
                net_internal: format!("ironclaw-egress-test-internal-{suffix}"),
                net_egress: format!("ironclaw-egress-test-egress-{suffix}"),
                proxy_name: format!("ironclaw-egress-test-proxy-{suffix}"),
                origin_allowed_name: format!("ironclaw-egress-test-origin-allowed-{suffix}"),
                origin_denied_name: format!("ironclaw-egress-test-origin-denied-{suffix}"),
                worker_name: format!("ironclaw-egress-test-worker-{suffix}"),
                net_egress_subnet: unique_egress_subnet(&suffix),
            }
        }

        /// Best-effort teardown of every resource THIS topology (and only
        /// this one — every name carries this instance's unique suffix)
        /// created; safe to call before setup (idempotent against a
        /// leftover from a prior ungraceful kill of a run carrying the SAME
        /// suffix, vanishingly unlikely but harmless to attempt) and is
        /// always called at the end via `TopologyGuard`'s `Drop`, so a
        /// panicking assertion still cleans up this test's own resources
        /// without touching any concurrently-running sibling test's.
        fn cleanup(&self) {
            for name in [
                &self.worker_name,
                &self.proxy_name,
                &self.origin_allowed_name,
                &self.origin_denied_name,
            ] {
                let _ = docker(&["rm", "-f", name]);
            }
            for net in [&self.net_internal, &self.net_egress] {
                let _ = docker(&["network", "rm", net]);
            }
        }
    }

    pub struct TopologyGuard {
        topology: Topology,
    }

    impl std::ops::Deref for TopologyGuard {
        type Target = Topology;

        fn deref(&self) -> &Topology {
            &self.topology
        }
    }

    impl Drop for TopologyGuard {
        fn drop(&mut self) {
            self.topology.cleanup();
        }
    }

    /// Content-addressed tag for the proxy image: a sha256 over every file
    /// under `crates/ironclaw_host_runtime/` (the crate that builds into the
    /// `egress_proxy_standalone` binary — its lib code, including
    /// `sandbox_process/ca.rs` and `egress_proxy.rs`, is what actually ends
    /// up in the image) plus the Dockerfile itself.
    ///
    /// `ensure_proxy_image_built` keys its "already built" check off this
    /// tag rather than the fixed `PROXY_IMAGE` name. Without this, the image
    /// was cached forever under a fixed tag and a source regression in the
    /// proxy binary (e.g. breaking CA distribution) would never invalidate
    /// it — the live TLS-interception test would keep passing against a
    /// stale binary on any machine (including CI runners) that persist
    /// Docker state across runs. Hashing file contents (not mtimes) means a
    /// no-op edit that doesn't change bytes still hits the cache, and any
    /// real source change gets a fresh tag and forces a rebuild.
    fn content_digest_tag() -> String {
        use sha2::{Digest, Sha256};

        let root = repo_root();
        let crate_dir = root.join("crates/ironclaw_host_runtime");
        let dockerfile = root.join("docker/sandbox-egress-proxy.Dockerfile");

        let mut files: Vec<PathBuf> = Vec::new();
        collect_files(&crate_dir, &mut files);
        files.push(dockerfile);
        // Sort for a deterministic hash regardless of filesystem walk order.
        files.sort();

        let mut hasher = Sha256::new();
        for path in &files {
            let relative = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .into_owned();
            hasher.update(relative.as_bytes());
            hasher.update(b"\0");
            let contents = std::fs::read(path)
                .unwrap_or_else(|e| panic!("reading {} for content digest: {e}", path.display()));
            hasher.update(&contents);
            hasher.update(b"\0");
        }
        let digest = hasher.finalize();
        format!(
            "ironclaw-egress-proxy-standalone:src-{}",
            hex::encode(digest)
        )
    }

    fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => panic!("reading dir {} for content digest: {e}", dir.display()),
        };
        for entry in entries {
            let entry = entry.expect("dir entry should be readable");
            let path = entry.path();
            let file_type = entry.file_type().expect("file type should be readable");
            if file_type.is_dir() {
                // Skip build output; it's not a build input and would make
                // the digest depend on stale artifacts from prior runs.
                if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                    continue;
                }
                collect_files(&path, out);
            } else if file_type.is_file() {
                out.push(path);
            }
        }
    }

    /// Builds the proxy image (from the REAL `EgressAllowlistProxy`, see
    /// `crates/ironclaw_host_runtime/examples/egress_proxy_standalone.rs`)
    /// if an image tagged with the current content digest isn't already
    /// present locally, so repeat local runs don't pay the full workspace
    /// compile every time a source file is untouched — but any change to
    /// the crate or the Dockerfile mints a new tag and forces a real
    /// rebuild. See `content_digest_tag` for why this can't be keyed off
    /// the fixed `PROXY_IMAGE` name.
    pub fn ensure_proxy_image_built() {
        let digest_tag = content_digest_tag();
        let inspect = docker(&["image", "inspect", &digest_tag]);
        if inspect.status.success() {
            // Content unchanged since the last build: re-point the stable
            // `PROXY_IMAGE` alias at the already-built content-addressed
            // image instead of rebuilding.
            assert!(
                docker(&["tag", &digest_tag, PROXY_IMAGE]).status.success(),
                "re-tagging the cached proxy image as {PROXY_IMAGE} should succeed"
            );
            return;
        }
        let dockerfile = repo_root().join("docker/sandbox-egress-proxy.Dockerfile");
        let output = Command::new("docker")
            .args([
                "build",
                "-f",
                dockerfile.to_str().expect("valid utf8 path"),
                "-t",
                &digest_tag,
                "-t",
                PROXY_IMAGE,
                ".",
            ])
            .current_dir(repo_root())
            .output()
            .expect("docker build should spawn");
        assert!(
            output.status.success(),
            "building the egress proxy standalone image failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    pub fn setup(worker_image: &str) -> TopologyGuard {
        let topology = Topology::new();
        // Idempotent against a leftover from a prior ungraceful kill under
        // this exact (vanishingly unlikely to repeat) suffix; never touches
        // a concurrently-running sibling test's differently-suffixed
        // resources, unlike the old fixed-name `cleanup()` this replaces.
        topology.cleanup();

        assert!(
            docker(&["network", "create", "--internal", &topology.net_internal])
                .status
                .success(),
            "creating the internal (no-route-off-host) network should succeed"
        );
        // `EgressAllowlistProxy::new` (the only public constructor) always
        // sets `deny_private_ips: true` with no builder to override it — by
        // design, the proxy refuses to dial ANY resolved RFC1918/loopback/
        // link-local/CGNAT/documentation address regardless of hostname
        // allowlisting (`ironclaw_network::network_denies_resolved_ip`).
        // Docker's normal auto-assigned bridge subnets (172.17-31.0.0/16,
        // 192.168.x) all fall inside that deny set, so an origin container
        // on a default-subnet bridge network would be denied even though
        // its hostname is allowlisted. Pin this network's subnet to
        // 198.18.0.0/15 (IANA's benchmarking-methodology range, RFC 2544) —
        // not private/loopback/link-local/CGNAT/documentation/multicast, so
        // it passes the SSRF guard — while still being a purely local Docker
        // bridge with no real route to the internet.
        //
        // Docker rejects creating a network whose subnet overlaps an
        // EXISTING one regardless of name — a shared fixed `/24` here would
        // still collide two concurrently-running topologies even after
        // their names stopped colliding, so each topology gets its own
        // subnet derived from its unique suffix (`net_egress_subnet`, see
        // `Topology`'s doc).
        assert!(
            docker(&[
                "network",
                "create",
                &format!("--subnet={}", topology.net_egress_subnet),
                &topology.net_egress,
            ])
            .status
            .success(),
            "creating the normal-bridge egress network should succeed"
        );

        let origin_script = repo_root()
            .join("tests/integration/support/sandbox_egress_topology/recording_origin.py");
        let origin_script = origin_script.to_str().expect("valid utf8 path");

        for (name, body) in [
            (&topology.origin_allowed_name, ORIGIN_ALLOWED_BODY),
            (&topology.origin_denied_name, ORIGIN_DENIED_BODY),
        ] {
            let run = docker(&[
                "run",
                "-d",
                "--rm",
                "--name",
                name,
                "--network",
                &topology.net_egress,
                "-v",
                &format!("{origin_script}:/recording_origin.py:ro"),
                "-e",
                &format!("ORIGIN_RESPONSE_BODY={body}"),
                "python:3.11-alpine",
                "python3",
                "/recording_origin.py",
                "80",
            ]);
            assert!(
                run.status.success(),
                "starting origin container {name} should succeed: {}",
                String::from_utf8_lossy(&run.stderr)
            );
        }

        // Dual-homed proxy: created on net-internal (so it's reachable from
        // the internal-only worker), then additionally connected to
        // net-egress (so it can reach the origins) — mirrors production's
        // "worker has no direct route out; the proxy is its only path"
        // semantics.
        // `pypi.org` is appended to the standalone proxy's allowlist
        // alongside the local recording origin. It plays no role in
        // assertions 1-4 above (a plain-HTTP dual-homed topology test); its
        // purpose is `sandbox_egress_proxy_dual_homed_tls_interception`
        // below, which needs a REAL, exact-match allowlisted host with a
        // publicly-trusted TLS certificate so `bind_sandbox_egress_proxy_
        // with_tls_intercept`'s `interception_bound_hosts` binds it (exact
        // match, no wildcard) and the proxy's `VerifiedOriginConnector`
        // (real system roots) can actually verify the real origin when
        // re-originating. The dual-homed proxy reaches it over
        // `net_egress` (a normal, non-`--internal` bridge — NATs to the
        // real internet), while the worker stays on the internal-only
        // network and can only reach it through the proxy.
        let run_proxy = docker(&[
            "run",
            "-d",
            "--rm",
            "--name",
            &topology.proxy_name,
            "--network",
            &topology.net_internal,
            "-e",
            "EGRESS_PROXY_BIND_ADDR=0.0.0.0:8080",
            "-e",
            &format!(
                "EGRESS_PROXY_ALLOWED_HOSTS={},pypi.org",
                topology.origin_allowed_name
            ),
            PROXY_IMAGE,
        ]);
        assert!(
            run_proxy.status.success(),
            "starting the proxy container should succeed: {}",
            String::from_utf8_lossy(&run_proxy.stderr)
        );
        let connect_proxy_to_egress = docker(&[
            "network",
            "connect",
            &topology.net_egress,
            &topology.proxy_name,
        ]);
        assert!(
            connect_proxy_to_egress.status.success(),
            "dual-homing the proxy onto the egress network should succeed: {}",
            String::from_utf8_lossy(&connect_proxy_to_egress.stderr)
        );

        // Worker: internal network ONLY — no route to net-egress at all.
        let run_worker = docker(&[
            "run",
            "-d",
            "--rm",
            "--name",
            &topology.worker_name,
            "--network",
            &topology.net_internal,
            "--entrypoint",
            "sh",
            worker_image,
            "-c",
            "sleep 600",
        ]);
        assert!(
            run_worker.status.success(),
            "starting the worker container should succeed: {}",
            String::from_utf8_lossy(&run_worker.stderr)
        );

        TopologyGuard { topology }
    }

    impl TopologyGuard {
        /// Runs `command` inside the worker container via `docker exec`.
        pub fn exec_worker(&self, command: &str) -> Output {
            docker(&["exec", &self.worker_name, "sh", "-c", command])
        }

        /// Reads the recording origin's structured request log back out of
        /// its container (proves the origin observed real bytes, not
        /// asserted state).
        pub fn read_origin_log(&self, container_name: &str) -> String {
            let output = docker(&[
                "exec",
                container_name,
                "cat",
                "/var/log/origin_requests.log",
            ]);
            String::from_utf8_lossy(&output.stdout).into_owned()
        }

        /// `docker cp`s the proxy's exported CA trust bundle out to a fresh
        /// host tempfile and returns its path. The standalone binary writes
        /// the bundle synchronously before it starts serving, but `docker
        /// run -d` returns as soon as the container is created — so this
        /// polls `docker cp` for up to 5s rather than assuming the file
        /// already exists the instant the container is reported running.
        pub fn export_ca_bundle_from_proxy(&self) -> PathBuf {
            let dest =
                std::env::temp_dir().join(format!("ironclaw-egress-test-ca-{}", unique_suffix()));
            for _ in 0..50 {
                let cp = docker(&[
                    "cp",
                    &format!("{}:{CA_BUNDLE_EXPORT_PATH}", self.proxy_name),
                    dest.to_str().expect("valid utf8 path"),
                ]);
                if cp.status.success() {
                    return dest;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            panic!(
                "timed out waiting for the proxy container to export its CA bundle to \
                 {CA_BUNDLE_EXPORT_PATH}"
            );
        }

        /// `docker cp`s a host file into the worker container at
        /// `dest_path`. `docker cp` writes directly into the container's
        /// filesystem without needing a bind mount declared at `docker run`
        /// time, so this can run against the already-started worker
        /// container from `setup` above — exactly the shape production's
        /// read-only bind mount achieves via a different mechanism
        /// (host-side file present before container create), proven here
        /// through the equivalent "file exists at a fixed path inside the
        /// container" outcome.
        pub fn install_file_into_worker(&self, host_path: &Path, dest_path: &str) {
            let cp = docker(&[
                "cp",
                host_path.to_str().expect("valid utf8 path"),
                &format!("{}:{dest_path}", self.worker_name),
            ]);
            assert!(
                cp.status.success(),
                "docker cp into the worker container should succeed: {}",
                String::from_utf8_lossy(&cp.stderr)
            );
        }

        /// The container's IPv4 address on this topology's egress network,
        /// for the raw-IP bypass assertion (rules out a DNS-only
        /// enforcement gap: even with no hostname to resolve, the internal
        /// network still must not route to this address).
        pub fn ip_on_egress_network(&self, container_name: &str) -> String {
            // The network name contains hyphens, which the Go template
            // parser cannot traverse via plain dot-field access
            // (`.Networks.foo-bar` fails to parse) — `index` looks the key
            // up as a map access instead.
            let output = docker(&[
                "inspect",
                "-f",
                &format!(
                    "{{{{index .NetworkSettings.Networks \"{}\" \"IPAddress\"}}}}",
                    self.net_egress
                ),
                container_name,
            ]);
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
    }

    /// The path the standalone proxy binary
    /// (`examples/egress_proxy_standalone.rs`) writes its container trust
    /// bundle to, inside its OWN container.
    pub const CA_BUNDLE_EXPORT_PATH: &str = "/ca-bundle.pem";
}

#[tokio::test]
async fn sandbox_egress_proxy_dual_homed_isolation_topology() {
    use dual_homed_topology as topo;

    if !docker_gate::docker_available() {
        eprintln!(
            "SKIP: no docker daemon reachable — sandbox_egress_proxy_dual_homed_isolation_topology requires a real Docker daemon (CI/hosted Docker lane only)"
        );
        return;
    }
    let worker_image = docker_gate::configured_sandbox_image();
    if !docker_gate::docker_image_available(&worker_image) {
        eprintln!(
            "SKIP: sandbox worker image {worker_image:?} is not built locally — sandbox_egress_proxy_dual_homed_isolation_topology requires a locally-built ironclaw-worker image (CI/hosted Docker lane only)"
        );
        return;
    }

    topo::ensure_proxy_image_built();
    let guard = topo::setup(&worker_image);

    // Assertion 1: allowed host succeeds THROUGH the proxy, and the exact
    // response body the origin sent comes back byte-for-byte.
    let allowed = guard.exec_worker(&format!(
        "curl -sS -x http://{}:8080 http://{}/hello",
        guard.proxy_name, guard.origin_allowed_name
    ));
    let allowed_body = String::from_utf8_lossy(&allowed.stdout);
    assert!(
        allowed.status.success() && allowed_body.contains(topo::ORIGIN_ALLOWED_BODY),
        "curl through the proxy to the allowed origin should return its exact response body; \
         status={:?} stdout={allowed_body} stderr={}",
        allowed.status,
        String::from_utf8_lossy(&allowed.stderr)
    );

    // Assertion 2: denied host is refused BY THE PROXY — assert on the
    // proxy's own 403 response shape (`write_denied_response`'s exact body
    // format), not merely a failed connection, so this could only have come
    // from the proxy's allowlist check, never a network hiccup or the
    // (never-dialed) origin.
    let denied = guard.exec_worker(&format!(
        "curl -sS -o /dev/null -w '%{{http_code}}' -x http://{}:8080 http://{}/",
        guard.proxy_name, guard.origin_denied_name
    ));
    let denied_status_code = String::from_utf8_lossy(&denied.stdout).into_owned();
    assert_eq!(
        denied_status_code,
        "403",
        "the proxy should reply 403 for a non-allowlisted host: stderr={}",
        String::from_utf8_lossy(&denied.stderr)
    );
    let denied_body = guard.exec_worker(&format!(
        "curl -sS -x http://{}:8080 http://{}/",
        guard.proxy_name, guard.origin_denied_name
    ));
    let denied_body_text = String::from_utf8_lossy(&denied_body.stdout);
    assert!(
        denied_body_text.contains("egress denied: host not in allowlist"),
        "the denial body must be the proxy's own denial text (proves the 403 came from the \
         proxy's allowlist check, not the origin or a transport error): {denied_body_text}"
    );

    // Assertion 3 (THE ISOLATION PROOF): the worker, on the internal-only
    // network, attempts to reach the allowed origin DIRECTLY, bypassing the
    // proxy entirely (no `-x`). No DNS entry for the origin's name exists on
    // the worker's network, and the internal network has no route off its
    // own bridge — this must fail, or the sandbox's whole isolation claim is
    // false.
    let bypass_by_name = guard.exec_worker(&format!(
        "curl -sf --max-time 5 http://{}/hello",
        guard.origin_allowed_name
    ));
    assert!(
        !bypass_by_name.status.success(),
        "a direct (non-proxied) curl from the internal-only worker to the allowed origin's \
         NAME must fail — success here means the isolation claim is false: stdout={} stderr={}",
        String::from_utf8_lossy(&bypass_by_name.stdout),
        String::from_utf8_lossy(&bypass_by_name.stderr)
    );

    // Same bypass attempt against the origin's raw IP literal on the egress
    // network, ruling out a DNS-only enforcement mechanism (worker has no
    // name to resolve here at all, only a route to prove or disprove).
    let allowed_origin_ip = guard.ip_on_egress_network(&guard.origin_allowed_name);
    assert!(
        !allowed_origin_ip.is_empty(),
        "should be able to read the allowed origin's IP on the egress network"
    );
    let bypass_by_ip = guard.exec_worker(&format!(
        "curl -sf --max-time 5 http://{allowed_origin_ip}/hello"
    ));
    assert!(
        !bypass_by_ip.status.success(),
        "a direct (non-proxied) curl from the internal-only worker to the allowed origin's RAW \
         IP must also fail — success here would mean enforcement is DNS-only and a route-level \
         bypass is open for anything not resolved by name: stdout={} stderr={}",
        String::from_utf8_lossy(&bypass_by_ip.stdout),
        String::from_utf8_lossy(&bypass_by_ip.stderr)
    );

    // Assertion 4: the origin observed the request — read back its
    // structured request log (real bytes it received, not asserted state)
    // and confirm the allowed-origin request that assertion 1 sent actually
    // arrived, addressed to the expected host.
    let allowed_origin_log = guard.read_origin_log(&guard.origin_allowed_name);
    assert!(
        allowed_origin_log.contains("\"method\": \"GET\"")
            && allowed_origin_log.contains("/hello")
            && allowed_origin_log.contains(&guard.origin_allowed_name),
        "the allowed origin's own request log should show the GET /hello request the proxy \
         forwarded, addressed to its own host — proving the request reached the origin for \
         real: {allowed_origin_log}"
    );

    // The denied origin must NEVER have been dialed — its log must stay
    // empty, proving the proxy's allowlist check ran strictly before any
    // connection attempt (mirrors the composition-path test's
    // `origin_saw_a_connection` proof, read back through the real log
    // instead of a probe future).
    let denied_origin_log = guard.read_origin_log(&guard.origin_denied_name);
    assert!(
        denied_origin_log.trim().is_empty(),
        "the denied origin must never have been dialed by the proxy; found log entries: \
         {denied_origin_log}"
    );
}

/// Docker-real, colima-compatible proof that CA distribution actually makes
/// TLS interception work end to end — the specific gap this task closes.
/// `sandbox_egress_proxy_enforces_allowlist_through_composition` (top of
/// this file) cannot prove this under colima (its production gateway-IP
/// topology is unreachable from the host — see that test's own doc), so
/// this reuses `dual_homed_topology` (the colima-compatible shape) exactly
/// like `sandbox_egress_proxy_dual_homed_isolation_topology`, adding a real
/// CONNECT/TLS leg against `pypi.org` (a real, exact-match allowlisted host
/// with a publicly-trusted certificate — required because the proxy's
/// origin-verification leg uses real system roots, so a locally faked
/// origin certificate could never pass it).
///
/// Two curls against the SAME bound host prove BOTH halves of the fix:
///
/// 1. WITHOUT the CA bundle installed, the worker's own system trust store
///    rejects the intercepted leaf (proves interception is real — a plain
///    opaque tunnel would have shown pypi.org's own, genuinely
///    publicly-trusted certificate and this curl would have succeeded).
/// 2. WITH the CA bundle installed at the exact path/env-var mechanism
///    `exec_transport::user_container_launch_config` wires in production
///    (`SSL_CERT_FILE`), the curl succeeds AND its verbose output names our
///    own CA as the certificate issuer — proving the container trusted the
///    distributed CA, not merely that the request happened to succeed.
#[tokio::test]
async fn sandbox_egress_proxy_dual_homed_tls_interception() {
    use dual_homed_topology as topo;

    if !docker_gate::docker_available() {
        eprintln!(
            "SKIP: no docker daemon reachable — sandbox_egress_proxy_dual_homed_tls_interception requires a real Docker daemon (CI/hosted Docker lane only)"
        );
        return;
    }
    let worker_image = docker_gate::configured_sandbox_image();
    if !docker_gate::docker_image_available(&worker_image) {
        eprintln!(
            "SKIP: sandbox worker image {worker_image:?} is not built locally — sandbox_egress_proxy_dual_homed_tls_interception requires a locally-built ironclaw-worker image (CI/hosted Docker lane only)"
        );
        return;
    }

    topo::ensure_proxy_image_built();
    let guard = topo::setup(&worker_image);

    let host_bundle_path = guard.export_ca_bundle_from_proxy();
    const WORKER_BUNDLE_PATH: &str = "/tmp/ironclaw-ca-bundle.pem";
    guard.install_file_into_worker(&host_bundle_path, WORKER_BUNDLE_PATH);

    // Assertion 1: WITHOUT the distributed CA bundle, the worker's own
    // baked-in system trust store (`ca-certificates`, real Mozilla-derived
    // roots) must REJECT the intercepted leaf — proving a real MITM leaf is
    // presented here, not pypi.org's own genuinely-trusted certificate that
    // an opaque tunnel would pass straight through.
    let without_bundle = guard.exec_worker(&format!(
        "curl -sS -o /dev/null -x http://{}:8080 https://pypi.org/simple/ 2>&1",
        guard.proxy_name
    ));
    assert!(
        !without_bundle.status.success(),
        "curl to the bound host through the proxy must FAIL certificate verification when the \
         container has not been given the sandbox CA — success here means either interception \
         never fired (an opaque tunnel would trivially pass pypi.org's own real cert) or the \
         container already, wrongly, trusts our CA by some other path: {}",
        String::from_utf8_lossy(&without_bundle.stdout)
    );
    let without_bundle_output =
        String::from_utf8_lossy(&without_bundle.stdout).to_ascii_lowercase();
    assert!(
        without_bundle_output.contains("certificate") || without_bundle_output.contains("ssl"),
        "the failure must be a certificate-verification failure specifically, not some other \
         transport error: {without_bundle_output}"
    );

    // Assertion 2 (THE PROOF): WITH the exact same distribution mechanism
    // production wires (`SSL_CERT_FILE` pointed at the bind-mounted
    // bundle), the curl succeeds AND its verbose handshake output names our
    // own sandbox CA as the issuer — the direct, load-bearing proof that
    // interception actually happened for this connection, not merely that
    // curl exited 0 (which an opaque tunnel to the real pypi.org would also
    // do).
    let with_bundle = guard.exec_worker(&format!(
        "SSL_CERT_FILE={WORKER_BUNDLE_PATH} curl -sS -v -o /dev/null -x http://{}:8080 \
         https://pypi.org/simple/ 2>&1",
        guard.proxy_name
    ));
    let with_bundle_output = String::from_utf8_lossy(&with_bundle.stdout);
    assert!(
        with_bundle.status.success(),
        "curl to the bound host through the proxy must SUCCEED once the container trusts the \
         distributed sandbox CA: {with_bundle_output}"
    );
    assert!(
        with_bundle_output.contains("IronClaw Sandbox Egress CA"),
        "the TLS handshake's certificate issuer must be our own sandbox CA — proves the \
         container's curl actually terminated TLS against OUR leaf (interception), not \
         pypi.org's real certificate through an opaque tunnel: {with_bundle_output}"
    );
}
