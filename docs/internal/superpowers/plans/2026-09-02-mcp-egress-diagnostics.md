# MCP Egress Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve the known `response_leak_blocked` sentinel for MCP callers and emit safe structured byte-count diagnostics without exposing arbitrary host-runtime error details.

**Architecture:** Centralize the existing response-leak sentinel in `ironclaw_host_api`, but keep the global `RuntimeHttpEgressReasonCode` enum unchanged. The MCP adapter recognizes only that shared sentinel, names it through the closed `McpEgressCause` vocabulary, and logs only stable reason codes plus request/response byte counts.

**Tech Stack:** Rust, Tokio, `async_trait`, `tracing`, `tracing-test`, Cargo workspace tests, IronClaw MCP and host-runtime contracts.

---

## Worktree and branch

The design commit lives on `design/8009-mcp-egress-diagnostics` and must not
enter the implementation PR. Create a clean implementation worktree from the
latest upstream `main`:

```bash
git fetch origin --prune
git worktree add \
  "/Users/bytedance/.trae-cn/work/6a9459814501b12642e355dc/ironclaw-8009-impl" \
  -b fix/8009-mcp-egress-diagnostics \
  origin/main
```

All commands below run from that worktree.

## File map

| File | Responsibility |
|---|---|
| `crates/contracts/ironclaw_host_api/src/http.rs` | Own the existing stable response-leak sentinel without expanding the global reason enum. |
| `crates/kernel/ironclaw_host_runtime/src/egress/sanitize.rs` | Produce the shared sentinel when response leak scanning blocks headers or body content. |
| `crates/kernel/ironclaw_host_runtime/tests/runtime_http_egress_contract.rs` | Lock sentinel identity, byte-count preservation, and secret-redaction behavior. |
| `crates/lanes/ironclaw_mcp/src/diagnostics.rs` | Own the caller-visible `McpEgressCause::ResponseLeakBlocked` vocabulary entry. |
| `crates/lanes/ironclaw_mcp/src/egress.rs` | Classify the sentinel and emit safe structured diagnostics. |
| `crates/lanes/ironclaw_mcp/tests/mcp_adapter_contract.rs` | Prove adapter and full client behavior, logging fields, and non-leak guarantees. |

No new file, dependency, feature, serialized type, config, or migration is
required.

### Task 1: Centralize the host response-leak sentinel

**Files:**
- Modify: `crates/contracts/ironclaw_host_api/src/http.rs`
- Modify: `crates/kernel/ironclaw_host_runtime/src/egress/sanitize.rs`
- Modify: `crates/kernel/ironclaw_host_runtime/tests/runtime_http_egress_contract.rs`

- [ ] **Step 1: Add a failing contract import**

In `runtime_http_egress_contract.rs`, add the constant to the existing HTTP
imports:

```rust
use ironclaw_host_api::http::{
    RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED,
    // retain all existing imports
};
```

Replace existing assertions against the literal:

```rust
assert_eq!(
    error.reason(),
    Some(RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED)
);
```

- [ ] **Step 2: Run the focused contract test and verify compilation fails**

Run:

```bash
cargo test -p ironclaw_host_runtime \
  --test runtime_http_egress_contract \
  response_leak
```

Expected result: compilation fails because
`RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED` is not defined.

- [ ] **Step 3: Add the shared constant**

In `crates/contracts/ironclaw_host_api/src/http.rs`, next to the existing
response-body-limit sentinel, add:

```rust
pub const RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED: &str =
    "response_leak_blocked";
```

Do not add a `RuntimeHttpEgressReasonCode` variant and do not change
`stable_runtime_reason()`.

- [ ] **Step 4: Replace runtime string literals**

In `sanitize.rs`, import:

```rust
use ironclaw_host_api::http::RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED;
```

Replace each existing construction:

```rust
reason: "response_leak_blocked".to_string(),
```

with:

```rust
reason: RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED.to_string(),
```

There must be no remaining `response_leak_blocked` literal in
`ironclaw_host_runtime`.

- [ ] **Step 5: Run the host-runtime contract tests**

Run:

```bash
cargo test -p ironclaw_host_runtime \
  --test runtime_http_egress_contract
```

Expected result: all tests pass. Existing assertions must still prove that
byte counts survive while raw credential material is absent from rendered
errors.

- [ ] **Step 6: Verify the global reason contract did not expand**

Run:

```bash
git diff -- \
  crates/contracts/ironclaw_host_api/src/http.rs \
  crates/kernel/ironclaw_host_runtime/src/egress/sanitize.rs
```

Expected result: the diff contains one constant and literal replacement only;
`RuntimeHttpEgressReasonCode` and `stable_runtime_reason()` are unchanged.

- [ ] **Step 7: Commit the sentinel change**

```bash
git add \
  crates/contracts/ironclaw_host_api/src/http.rs \
  crates/kernel/ironclaw_host_runtime/src/egress/sanitize.rs \
  crates/kernel/ironclaw_host_runtime/tests/runtime_http_egress_contract.rs
git commit -m "refactor(egress): centralize response leak reason"
```

### Task 2: Preserve the sentinel through the MCP caller path

**Files:**
- Modify: `crates/lanes/ironclaw_mcp/src/diagnostics.rs`
- Modify: `crates/lanes/ironclaw_mcp/src/egress.rs`
- Modify: `crates/lanes/ironclaw_mcp/tests/mcp_adapter_contract.rs`

- [ ] **Step 1: Add a deterministic failing egress fake**

In `mcp_adapter_contract.rs`, add the constant to the existing host HTTP
imports:

```rust
RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED,
```

Add this fake near `SecretEchoRuntimeEgress`:

```rust
#[derive(Debug)]
struct LeakBlockedRuntimeEgress;

#[async_trait]
impl RuntimeHttpEgress for LeakBlockedRuntimeEgress {
    async fn execute(
        &self,
        _request: RuntimeHttpEgressRequest,
    ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
        Err(RuntimeHttpEgressError::Response {
            reason: RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED.to_string(),
            request_bytes: 74,
            response_bytes: 109_922,
        })
    }
}
```

- [ ] **Step 2: Add the full caller-path regression**

Near the existing concrete MCP HTTP client tests, add:

```rust
#[tokio::test]
async fn concrete_mcp_http_client_preserves_response_leak_blocked_reason() {
    let client = McpHostHttpClient::new(
        McpRuntimeHttpAdapter::new(Arc::new(LeakBlockedRuntimeEgress)),
        StaticMcpHostHttpEgressPlanner::new(host_http_plan()),
    );

    let error = client
        .call_tool(McpClientRequest {
            provider: ExtensionId::new("github-mcp").unwrap(),
            capability_id: CapabilityId::new("github-mcp.search").unwrap(),
            scope: sample_scope(),
            transport: "http".to_string(),
            command: None,
            args: vec![],
            url: Some("https://mcp.example.test/mcp".to_string()),
            input: json!({"query": "ironclaw"}),
            max_output_bytes: 4096,
        })
        .await
        .expect_err("response leak blocking must fail the MCP call");

    assert_eq!(error.stable_reason(), "response_leak_blocked");
}
```

This test intentionally fails on current `main`, where the stable reason is
`response_error`.

- [ ] **Step 3: Run the regression and verify the red state**

Run:

```bash
cargo test -p ironclaw_mcp \
  --test mcp_adapter_contract \
  concrete_mcp_http_client_preserves_response_leak_blocked_reason \
  -- --exact
```

Expected result: assertion failure showing:

```text
left: "response_error"
right: "response_leak_blocked"
```

- [ ] **Step 4: Add the bounded MCP cause**

In `diagnostics.rs`, import the shared constant:

```rust
use ironclaw_host_api::http::RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED;
```

Extend `McpEgressCause`:

```rust
pub(crate) enum McpEgressCause {
    RuntimeEgressPanicked,
    ResponseLeakBlocked,
    RuntimeEgressFailed(&'static str),
}
```

Extend `into_reason()`:

```rust
Self::ResponseLeakBlocked => {
    RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED.to_string()
}
```

Add or extend the diagnostics unit test:

```rust
assert_eq!(
    egress_failure(McpEgressCause::ResponseLeakBlocked),
    "response_leak_blocked"
);
```

- [ ] **Step 5: Classify only the shared sentinel**

In `egress.rs`, import:

```rust
RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED,
```

Replace `mcp_http_error()` with:

```rust
fn mcp_http_error(error: RuntimeHttpEgressError) -> McpHostHttpError {
    let cause = match &error {
        RuntimeHttpEgressError::Response { reason, .. }
            if reason == RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED =>
        {
            McpEgressCause::ResponseLeakBlocked
        }
        _ => McpEgressCause::RuntimeEgressFailed(
            error.stable_runtime_reason(),
        ),
    };

    McpHostHttpError::Egress {
        reason: egress_failure(cause),
    }
}
```

Do not compare or expose any other raw reason.

- [ ] **Step 6: Run MCP unit and caller-path tests**

Run:

```bash
cargo test -p ironclaw_mcp \
  diagnostics::tests::egress_failures_use_stable_codes
cargo test -p ironclaw_mcp \
  --test mcp_adapter_contract \
  concrete_mcp_http_client_preserves_response_leak_blocked_reason \
  -- --exact
```

Expected result: both commands pass.

- [ ] **Step 7: Run the module charter**

Run:

```bash
cargo test -p ironclaw_mcp --test module_charter
```

Expected result: pass. The charter must not detect a new inline failure token
in `egress.rs`.

- [ ] **Step 8: Commit the MCP mapping**

```bash
git add \
  crates/lanes/ironclaw_mcp/src/diagnostics.rs \
  crates/lanes/ironclaw_mcp/src/egress.rs \
  crates/lanes/ironclaw_mcp/tests/mcp_adapter_contract.rs
git commit -m "fix(mcp): preserve response leak diagnostics"
```

### Task 3: Add safe structured byte-count diagnostics

**Files:**
- Modify: `crates/lanes/ironclaw_mcp/src/egress.rs`
- Modify: `crates/lanes/ironclaw_mcp/tests/mcp_adapter_contract.rs`

- [ ] **Step 1: Import the existing log-capture helper**

In `mcp_adapter_contract.rs`, add:

```rust
use tracing_test::traced_test;
```

- [ ] **Step 2: Add a failing log-field regression**

Add a direct adapter test:

```rust
#[tokio::test]
#[traced_test]
async fn mcp_host_http_adapter_logs_safe_response_leak_diagnostics() {
    let adapter = McpRuntimeHttpAdapter::new(Arc::new(LeakBlockedRuntimeEgress));

    let error = adapter
        .request(CapabilityHostHttpRequest {
            scope: sample_scope(),
            capability_id: CapabilityId::new("github-mcp.search").unwrap(),
            method: NetworkMethod::Get,
            url: "https://mcp.example.test/mcp".to_string(),
            headers: vec![],
            body: vec![],
            network_policy: mcp_http_policy(),
            credential_injections: vec![],
            response_body_limit: Some(4096),
            timeout_ms: Some(1000),
        })
        .await
        .expect_err("response leak blocking must fail closed");

    assert!(error.to_string().contains("response_leak_blocked"));
    assert!(logs_contain("runtime_reason=response_error"));
    assert!(logs_contain("mcp_reason=response_leak_blocked"));
    assert!(logs_contain("request_bytes=74"));
    assert!(logs_contain("response_bytes=109922"));
}
```

- [ ] **Step 3: Run the log regression and verify the red state**

Run:

```bash
cargo test -p ironclaw_mcp \
  --test mcp_adapter_contract \
  mcp_host_http_adapter_logs_safe_response_leak_diagnostics \
  -- --exact
```

Expected result: failure because the MCP adapter does not emit the structured
diagnostic fields.

- [ ] **Step 4: Emit the safe warning**

In `mcp_http_error()`, build the stable reason once, then log only safe fields:

```rust
let runtime_reason = error.stable_runtime_reason();
let reason = egress_failure(cause);

tracing::warn!(
    runtime_reason,
    mcp_reason = %reason,
    request_bytes = error.request_bytes(),
    response_bytes = error.response_bytes(),
    "MCP host HTTP egress failed"
);

McpHostHttpError::Egress { reason }
```

Do not add `error = %error`, `error = ?error`, the inner raw reason, URL,
headers, or body fields.

- [ ] **Step 5: Run the log regression**

Run:

```bash
cargo test -p ironclaw_mcp \
  --test mcp_adapter_contract \
  mcp_host_http_adapter_logs_safe_response_leak_diagnostics \
  -- --exact
```

Expected result: pass with all four structured fields observed.

- [ ] **Step 6: Commit the structured diagnostics**

```bash
git add \
  crates/lanes/ironclaw_mcp/src/egress.rs \
  crates/lanes/ironclaw_mcp/tests/mcp_adapter_contract.rs
git commit -m "feat(mcp): log safe egress byte diagnostics"
```

### Task 4: Lock the negative security contract

**Files:**
- Modify: `crates/lanes/ironclaw_mcp/tests/mcp_adapter_contract.rs`

- [ ] **Step 1: Extend the existing secret-echo regression**

Annotate the existing
`mcp_host_http_adapter_returns_sanitized_shared_egress_errors` test:

```rust
#[tokio::test]
#[traced_test]
async fn mcp_host_http_adapter_returns_sanitized_shared_egress_errors() {
```

Keep the existing caller assertions and add:

```rust
assert!(logs_contain("runtime_reason=network_error"));
assert!(logs_contain("mcp_reason=network_error"));
assert!(logs_contain("request_bytes=0"));
assert!(logs_contain("response_bytes=0"));
assert!(!logs_contain("sk-test-secret"));
assert!(!logs_contain("10.0.0.7"));
```

- [ ] **Step 2: Add an unknown-response fake**

Add:

```rust
#[derive(Debug)]
struct UnknownSecretResponseRuntimeEgress;

#[async_trait]
impl RuntimeHttpEgress for UnknownSecretResponseRuntimeEgress {
    async fn execute(
        &self,
        _request: RuntimeHttpEgressRequest,
    ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
        Err(RuntimeHttpEgressError::Response {
            reason: "provider 10.0.0.9 returned sk-private-response".to_string(),
            request_bytes: 91,
            response_bytes: 4_096,
        })
    }
}
```

- [ ] **Step 3: Add the unknown-reason closure regression**

```rust
#[tokio::test]
#[traced_test]
async fn mcp_host_http_adapter_keeps_unknown_response_reasons_closed() {
    let adapter =
        McpRuntimeHttpAdapter::new(Arc::new(UnknownSecretResponseRuntimeEgress));

    let error = adapter
        .request(CapabilityHostHttpRequest {
            scope: sample_scope(),
            capability_id: CapabilityId::new("github-mcp.search").unwrap(),
            method: NetworkMethod::Get,
            url: "https://mcp.example.test/mcp".to_string(),
            headers: vec![],
            body: vec![],
            network_policy: mcp_http_policy(),
            credential_injections: vec![],
            response_body_limit: Some(4096),
            timeout_ms: Some(1000),
        })
        .await
        .expect_err("unknown response failures must fail closed");

    let rendered = error.to_string();
    assert!(rendered.contains("response_error"));
    assert!(!rendered.contains("sk-private-response"));
    assert!(!rendered.contains("10.0.0.9"));
    assert!(logs_contain("runtime_reason=response_error"));
    assert!(logs_contain("mcp_reason=response_error"));
    assert!(logs_contain("request_bytes=91"));
    assert!(logs_contain("response_bytes=4096"));
    assert!(!logs_contain("sk-private-response"));
    assert!(!logs_contain("10.0.0.9"));
}
```

- [ ] **Step 4: Run all three security-sensitive regressions**

Run:

```bash
cargo test -p ironclaw_mcp \
  --test mcp_adapter_contract \
  mcp_host_http_adapter_ \
  -- --nocapture
```

Expected result: leak-blocked, secret-network, unknown-response, and panic
adapter tests pass. No assertion output contains a secret marker or private IP.

- [ ] **Step 5: Commit the negative tests**

```bash
git add crates/lanes/ironclaw_mcp/tests/mcp_adapter_contract.rs
git commit -m "test(mcp): lock egress diagnostic redaction"
```

### Task 5: Run the complete validation matrix

**Files:**
- No production change expected.
- Update only code required to fix failures caused by this patch.

- [ ] **Step 1: Run the MCP crate**

```bash
cargo test -p ironclaw_mcp
```

Expected result: all MCP unit, adapter, diagnostics, and module-charter tests
pass.

- [ ] **Step 2: Run the host-runtime contract**

```bash
cargo test -p ironclaw_host_runtime \
  --test runtime_http_egress_contract
```

Expected result: all host egress contract tests pass.

- [ ] **Step 3: Run architecture tests**

```bash
cargo test -p ironclaw_architecture_tests
```

Expected result: all dependency, runtime, and module charter gates pass.

- [ ] **Step 4: Run formatting**

```bash
cargo fmt --all -- --check
```

Expected result: exit code 0 with no diff.

- [ ] **Step 5: Run full-feature clippy**

```bash
SKIP_FRONTEND_BUILD=1 cargo clippy \
  --all --benches --tests --examples --all-features -- -D warnings
```

Expected result: exit code 0 with no warnings.

- [ ] **Step 6: Audit the final diff for forbidden data flow**

Run:

```bash
git diff origin/main...HEAD -- \
  crates/contracts/ironclaw_host_api/src/http.rs \
  crates/kernel/ironclaw_host_runtime/src/egress/sanitize.rs \
  crates/kernel/ironclaw_host_runtime/tests/runtime_http_egress_contract.rs \
  crates/lanes/ironclaw_mcp/src/diagnostics.rs \
  crates/lanes/ironclaw_mcp/src/egress.rs \
  crates/lanes/ironclaw_mcp/tests/mcp_adapter_contract.rs
```

Expected result:

- no `error = %error` or `error = ?error`;
- no raw response reason in caller output or logs;
- no global reason-code enum expansion;
- no automatic retry change;
- no unrelated file change.

- [ ] **Step 7: Verify commit and repository state**

```bash
git diff --check
git status --short
git log --oneline origin/main..HEAD
```

Expected result: no whitespace errors, a clean worktree, and four focused
commits:

```text
test(mcp): lock egress diagnostic redaction
feat(mcp): log safe egress byte diagnostics
fix(mcp): preserve response leak diagnostics
refactor(egress): centralize response leak reason
```

### Task 6: Prepare the Draft PR

**Files:**
- No code change.

- [ ] **Step 1: Push the implementation branch**

```bash
git push -u fork fix/8009-mcp-egress-diagnostics
```

- [ ] **Step 2: Create a Draft PR against `nearai/ironclaw:main`**

Use a title scoped to observable behavior:

```text
fix(mcp): preserve response leak diagnostics
```

The PR body must state:

- `Closes #8009`;
- `response_leak_blocked` is the only newly specific caller token;
- unknown response reasons remain `response_error`;
- logs contain stable codes and byte counts only;
- no raw reason, payload, URL, header, credential, or private address is logged;
- no retry, partial-catalog, permission, policy, or global error-enum change;
- exact red/green test commands and final gate results;
- rollback is a single commit revert with no persisted state.

- [ ] **Step 3: Keep the PR Draft until review-track confirmation**

Recommend Track C evidence because the patch changes diagnostics at a security
boundary. Do not mark ready until a maintainer confirms the review track and
the repository-required checks are visible.

