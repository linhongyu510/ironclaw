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
    use std::path::PathBuf;
    use std::process::{Command, Output};

    pub const NET_INTERNAL: &str = "ironclaw-egress-test-internal";
    pub const NET_EGRESS: &str = "ironclaw-egress-test-egress";
    pub const PROXY_IMAGE: &str = "ironclaw-egress-proxy-standalone:test";
    pub const PROXY_NAME: &str = "ironclaw-egress-test-proxy";
    pub const ORIGIN_ALLOWED_NAME: &str = "ironclaw-egress-test-origin-allowed";
    pub const ORIGIN_DENIED_NAME: &str = "ironclaw-egress-test-origin-denied";
    pub const WORKER_NAME: &str = "ironclaw-egress-test-worker";
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

    /// Best-effort teardown of every resource this module creates; safe to
    /// call before setup (idempotent against a leftover run) and is always
    /// called at the end via `TopologyGuard`'s `Drop`, so a panicking
    /// assertion still cleans up.
    pub fn cleanup() {
        for name in [
            WORKER_NAME,
            PROXY_NAME,
            ORIGIN_ALLOWED_NAME,
            ORIGIN_DENIED_NAME,
        ] {
            let _ = docker(&["rm", "-f", name]);
        }
        for net in [NET_INTERNAL, NET_EGRESS] {
            let _ = docker(&["network", "rm", net]);
        }
    }

    pub struct TopologyGuard;

    impl Drop for TopologyGuard {
        fn drop(&mut self) {
            cleanup();
        }
    }

    /// Builds the proxy image (from the REAL `EgressAllowlistProxy`, see
    /// `crates/ironclaw_host_runtime/examples/egress_proxy_standalone.rs`)
    /// if it isn't already present locally, so repeat local runs don't pay
    /// the full workspace compile every time.
    pub fn ensure_proxy_image_built() {
        let inspect = docker(&["image", "inspect", PROXY_IMAGE]);
        if inspect.status.success() {
            return;
        }
        let dockerfile = repo_root().join("docker/sandbox-egress-proxy.Dockerfile");
        let output = Command::new("docker")
            .args([
                "build",
                "-f",
                dockerfile.to_str().expect("valid utf8 path"),
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
        cleanup();
        let guard = TopologyGuard;

        assert!(
            docker(&["network", "create", "--internal", NET_INTERNAL])
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
        assert!(
            docker(&["network", "create", "--subnet=198.18.0.0/24", NET_EGRESS,])
                .status
                .success(),
            "creating the normal-bridge egress network should succeed"
        );

        let origin_script = repo_root()
            .join("tests/integration/support/sandbox_egress_topology/recording_origin.py");
        let origin_script = origin_script.to_str().expect("valid utf8 path");

        for (name, body) in [
            (ORIGIN_ALLOWED_NAME, ORIGIN_ALLOWED_BODY),
            (ORIGIN_DENIED_NAME, ORIGIN_DENIED_BODY),
        ] {
            let run = docker(&[
                "run",
                "-d",
                "--rm",
                "--name",
                name,
                "--network",
                NET_EGRESS,
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
        let run_proxy = docker(&[
            "run",
            "-d",
            "--rm",
            "--name",
            PROXY_NAME,
            "--network",
            NET_INTERNAL,
            "-e",
            "EGRESS_PROXY_BIND_ADDR=0.0.0.0:8080",
            "-e",
            &format!("EGRESS_PROXY_ALLOWED_HOSTS={ORIGIN_ALLOWED_NAME}"),
            PROXY_IMAGE,
        ]);
        assert!(
            run_proxy.status.success(),
            "starting the proxy container should succeed: {}",
            String::from_utf8_lossy(&run_proxy.stderr)
        );
        let connect_proxy_to_egress = docker(&["network", "connect", NET_EGRESS, PROXY_NAME]);
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
            WORKER_NAME,
            "--network",
            NET_INTERNAL,
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

        guard
    }

    /// Runs `command` inside the worker container via `docker exec`.
    pub fn exec_worker(command: &str) -> Output {
        docker(&["exec", WORKER_NAME, "sh", "-c", command])
    }

    /// Reads the recording origin's structured request log back out of its
    /// container (proves the origin observed real bytes, not asserted
    /// state).
    pub fn read_origin_log(container_name: &str) -> String {
        let output = docker(&[
            "exec",
            container_name,
            "cat",
            "/var/log/origin_requests.log",
        ]);
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// The container's IPv4 address on `NET_EGRESS`, for the raw-IP bypass
    /// assertion (rules out a DNS-only enforcement gap: even with no
    /// hostname to resolve, the internal network still must not route to
    /// this address).
    pub fn ip_on_egress_network(container_name: &str) -> String {
        // `NET_EGRESS` contains hyphens, which the Go template parser cannot
        // traverse via plain dot-field access (`.Networks.foo-bar` fails to
        // parse) — `index` looks the key up as a map access instead.
        let output = docker(&[
            "inspect",
            "-f",
            &format!("{{{{index .NetworkSettings.Networks \"{NET_EGRESS}\" \"IPAddress\"}}}}"),
            container_name,
        ]);
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }
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
    let _guard = topo::setup(&worker_image);

    // Assertion 1: allowed host succeeds THROUGH the proxy, and the exact
    // response body the origin sent comes back byte-for-byte.
    let allowed = topo::exec_worker(&format!(
        "curl -sS -x http://{}:8080 http://{}/hello",
        topo::PROXY_NAME,
        topo::ORIGIN_ALLOWED_NAME
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
    let denied = topo::exec_worker(&format!(
        "curl -sS -o /dev/null -w '%{{http_code}}' -x http://{}:8080 http://{}/",
        topo::PROXY_NAME,
        topo::ORIGIN_DENIED_NAME
    ));
    let denied_status_code = String::from_utf8_lossy(&denied.stdout).into_owned();
    assert_eq!(
        denied_status_code,
        "403",
        "the proxy should reply 403 for a non-allowlisted host: stderr={}",
        String::from_utf8_lossy(&denied.stderr)
    );
    let denied_body = topo::exec_worker(&format!(
        "curl -sS -x http://{}:8080 http://{}/",
        topo::PROXY_NAME,
        topo::ORIGIN_DENIED_NAME
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
    let bypass_by_name = topo::exec_worker(&format!(
        "curl -sf --max-time 5 http://{}/hello",
        topo::ORIGIN_ALLOWED_NAME
    ));
    assert!(
        !bypass_by_name.status.success(),
        "a direct (non-proxied) curl from the internal-only worker to the allowed origin's \
         NAME must fail — success here means the isolation claim is false: stdout={} stderr={}",
        String::from_utf8_lossy(&bypass_by_name.stdout),
        String::from_utf8_lossy(&bypass_by_name.stderr)
    );

    // Same bypass attempt against the origin's raw IP literal on
    // `NET_EGRESS`, ruling out a DNS-only enforcement mechanism (worker has
    // no name to resolve here at all, only a route to prove or disprove).
    let allowed_origin_ip = topo::ip_on_egress_network(topo::ORIGIN_ALLOWED_NAME);
    assert!(
        !allowed_origin_ip.is_empty(),
        "should be able to read the allowed origin's IP on the egress network"
    );
    let bypass_by_ip = topo::exec_worker(&format!(
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
    let allowed_origin_log = topo::read_origin_log(topo::ORIGIN_ALLOWED_NAME);
    assert!(
        allowed_origin_log.contains("\"method\": \"GET\"")
            && allowed_origin_log.contains("/hello")
            && allowed_origin_log.contains(topo::ORIGIN_ALLOWED_NAME),
        "the allowed origin's own request log should show the GET /hello request the proxy \
         forwarded, addressed to its own host — proving the request reached the origin for \
         real: {allowed_origin_log}"
    );

    // The denied origin must NEVER have been dialed — its log must stay
    // empty, proving the proxy's allowlist check ran strictly before any
    // connection attempt (mirrors the composition-path test's
    // `origin_saw_a_connection` proof, read back through the real log
    // instead of a probe future).
    let denied_origin_log = topo::read_origin_log(topo::ORIGIN_DENIED_NAME);
    assert!(
        denied_origin_log.trim().is_empty(),
        "the denied origin must never have been dialed by the proxy; found log entries: \
         {denied_origin_log}"
    );
}
