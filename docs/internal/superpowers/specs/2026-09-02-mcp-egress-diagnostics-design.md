# MCP Egress Diagnostics Design

## Status

Proposed design for [nearai/ironclaw#8009](https://github.com/nearai/ironclaw/issues/8009).

The selected scope is an MCP-specific safe mapping. It does not expand the
global `RuntimeHttpEgressReasonCode` enum and does not change retry behavior.

## Problem

`RuntimeHttpEgressError` retains the host egress failure reason and byte counts.
The MCP adapter currently maps it through `stable_runtime_reason()`, which
intentionally collapses every ordinary response failure to `response_error`.

For a leak-blocked MCP catalog response, the current data flow is:

```text
RuntimeHttpEgressError::Response {
    reason: "response_leak_blocked",
    request_bytes: 74,
    response_bytes: 109922,
}
    -> stable_runtime_reason()
    -> "response_error"
    -> McpHostHttpError
    -> McpClientError::Client("response_error")
```

The caller cannot distinguish a catalog that the safety scanner rejected from
an ordinary response failure. Operators also lose the request and response byte
counts at the MCP boundary.

The raw `reason` cannot be forwarded or logged indiscriminately. Host egress
errors may contain URLs, private addresses, provider detail, or credential
material. The MCP crate contract requires every caller-visible token to be
bounded and enumerable in `diagnostics.rs`.

## Goals

- Surface `response_leak_blocked` to MCP callers as a stable, sanitized token.
- Preserve `response_error` for unknown response reasons.
- Record request and response byte counts in structured MCP diagnostics.
- Keep raw host error reasons, response bodies, headers, URLs, and credentials
  out of caller-visible errors and logs.
- Exercise the complete MCP caller path, not only a private mapping helper.
- Preserve all existing network, policy, body-limit, panic, and credential
  mappings.

## Non-goals

- No automatic retry or retryability changes.
- No partial-catalog recovery from issue #8008.
- No global `RuntimeHttpEgressReasonCode` variant.
- No raw `RuntimeHttpEgressError::reason` propagation.
- No request or response payload logging.
- No MCP protocol, JSON-RPC, session, or resource-accounting changes.
- No refactor of `McpClientError` or `McpHostHttpError`.
- No new dependency or Cargo feature.

## Considered approaches

### MCP-specific safe mapping

Add a shared host reason constant, classify that sentinel at the MCP egress
boundary, name it through `McpEgressCause`, and log only safe codes and byte
counts.

This is the selected approach. It fixes the reported operational gap without
changing unrelated runtime consumers.

### Global reason-code expansion

Add `ResponseLeakBlocked` to `RuntimeHttpEgressReasonCode`.

This would require updating exhaustive matches across WASM, first-party HTTP,
G Suite, web access, extension installation, channel egress, onboarding, and
their contract tests. Those consumers have different product-level error
semantics, so this is disproportionate to an MCP diagnostics bug.

### Logging only

Log a safe reason and byte counts while continuing to return `response_error`.

This improves operator diagnostics but leaves the MCP caller unable to
distinguish a non-retryable catalog safety rejection from an ordinary response
failure.

### Raw reason propagation

Forward or log `error.to_string()` or the inner `reason`.

This violates the MCP failure-vocabulary charter and can expose credential
material or transport internals. It is rejected.

## Contract

### Shared host sentinel

`ironclaw_host_api::http` owns a public constant:

```rust
pub const RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED: &str =
    "response_leak_blocked";
```

`ironclaw_host_runtime::egress::sanitize` uses this constant when response
headers or body content fail the leak detector. This centralizes an existing
wire token without changing host-runtime behavior.

The constant does not become a new `RuntimeHttpEgressReasonCode` variant.
Outside the MCP-specific mapping, `stable_runtime_reason()` continues to
classify it as `response_error`.

### MCP cause

`McpEgressCause` gains:

```rust
ResponseLeakBlocked,
```

`diagnostics.rs` maps that cause to the shared stable sentinel. No module
outside `diagnostics.rs` constructs the caller-visible failure token.

### MCP classification

`mcp_http_error()` inspects the host error before reducing it:

```rust
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
```

The resulting caller contract is:

| Host egress failure | MCP caller token |
|---|---|
| Response leak blocked | `response_leak_blocked` |
| Response body limit exceeded | `response_body_limit_exceeded` |
| Network failure | `network_error` |
| Policy denial | `policy_denied` |
| Credential unavailable | `credential_unavailable` |
| Unknown response reason | `response_error` |
| Egress future panic | `runtime_http_egress_panicked` |

Unknown `Response.reason` strings are never forwarded.

## Structured diagnostics

Before returning `McpHostHttpError`, the adapter emits one structured warning:

```rust
tracing::warn!(
    runtime_reason = error.stable_runtime_reason(),
    mcp_reason = %reason,
    request_bytes = error.request_bytes(),
    response_bytes = error.response_bytes(),
    "MCP host HTTP egress failed"
);
```

Allowed fields:

- stable host-owned runtime reason;
- stable MCP-owned reason;
- request byte count;
- response byte count.

Forbidden fields:

- `error = %error` or `error = ?error`;
- the inner raw `reason`;
- URL, request headers, response headers;
- request body or response body;
- credentials or provider messages.

For the issue fixture, the log contains:

```text
runtime_reason=response_error
mcp_reason=response_leak_blocked
request_bytes=74
response_bytes=109922
```

It does not contain the response text that triggered the leak detector.

## Data flow

```text
host runtime response sanitizer
    -> RuntimeHttpEgressError::Response(shared sentinel, byte counts)
    -> McpRuntimeHttpAdapter
    -> MCP-specific sentinel classification
    -> safe structured warning
    -> McpHostHttpError::Egress(stable MCP token)
    -> mcp_client_http_error()
    -> McpClientError::Client(stable MCP token)
    -> discovery or tool-call caller
```

## File changes

### `crates/contracts/ironclaw_host_api/src/http.rs`

- Add `RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED`.
- Keep `RuntimeHttpEgressReasonCode` unchanged.
- Keep `stable_runtime_reason()` unchanged for non-MCP consumers.

### `crates/kernel/ironclaw_host_runtime/src/egress/sanitize.rs`

- Replace the three `response_leak_blocked` string literals with the shared
  constant.
- Do not alter leak-detector behavior or response sanitization.

### `crates/kernel/ironclaw_host_runtime/tests/runtime_http_egress_contract.rs`

- Replace literal comparisons with the shared constant.
- Retain the existing assertions that the token is absent from the rendered
  secret-bearing error and that byte counts survive.

### `crates/lanes/ironclaw_mcp/src/diagnostics.rs`

- Add `McpEgressCause::ResponseLeakBlocked`.
- Name the cause using the shared sentinel.
- Add a unit assertion for the stable token.

### `crates/lanes/ironclaw_mcp/src/egress.rs`

- Classify only the shared response-leak sentinel specially.
- Build the caller token through `egress_failure()`.
- Emit the safe structured warning.
- Continue mapping every other error through `stable_runtime_reason()`.

### `crates/lanes/ironclaw_mcp/tests/mcp_adapter_contract.rs`

- Add a deterministic leak-blocked runtime egress fake.
- Exercise `McpRuntimeHttpAdapter` and `McpHostHttpClient`.
- Capture logs with the existing `tracing-test` dev dependency.
- Add negative leakage assertions.

## Test design

### Adapter-level leak classification

A fake returns:

```rust
RuntimeHttpEgressError::Response {
    reason: RUNTIME_HTTP_REASON_RESPONSE_LEAK_BLOCKED.to_string(),
    request_bytes: 74,
    response_bytes: 109_922,
}
```

Assertions:

- `McpHostHttpError` contains `response_leak_blocked`;
- it does not contain `response_error`;
- logs contain the stable MCP reason;
- logs contain both byte counts;
- logs do not contain a credential-shaped marker or response fixture text.

### Caller-path regression

Drive:

```text
McpHostHttpClient
    -> McpRuntimeHttpAdapter
    -> failing RuntimeHttpEgress fake
    -> McpClientError
```

Assert:

```rust
assert_eq!(error.stable_reason(), "response_leak_blocked");
```

This is the acceptance regression. A direct helper-only test is insufficient.

### Unknown response reason remains closed

A fake returns a response reason containing a secret marker and private IP.

Assertions:

- caller token remains `response_error`;
- rendered errors contain neither marker nor private IP;
- captured logs contain neither marker nor private IP;
- byte counts remain available in safe structured fields.

### Existing mapping matrix

Retain or extend coverage for:

- `network_error`;
- `policy_denied`;
- `response_body_limit_exceeded`;
- `credential_unavailable`;
- `runtime_http_egress_panicked`.

### Charter gate

`cargo test -p ironclaw_mcp` must keep
`tests/module_charter.rs` green. No new inline failure reason is permitted in
`egress.rs`.

## Validation

Run:

```bash
cargo test -p ironclaw_mcp
cargo test -p ironclaw_host_runtime --test runtime_http_egress_contract
cargo test -p ironclaw_architecture_tests
cargo fmt --all -- --check
SKIP_FRONTEND_BUILD=1 cargo clippy \
  --all --benches --tests --examples --all-features -- -D warnings
```

The architecture suite is included because a shared contract module changes,
even though no dependency edge is added.

## Compatibility

- Existing MCP callers receive a more specific token only for the known
  response-leak sentinel.
- Unknown response reasons remain closed as `response_error`.
- Other runtime lanes and first-party HTTP consumers retain their existing
  global reason-code behavior.
- No serialized type, database schema, config, environment variable, public
  trait, or Cargo feature changes.

## Security review

The change improves diagnostics at a trust boundary. Prepare review evidence at
Track C depth even if maintainers ultimately classify the small patch as Track
B:

- caller-path red/green regression;
- explicit log and error non-leak assertions;
- stable-token matrix;
- blast-radius statement;
- rollback path.

The rollback is a single commit revert. No persisted state or migration is
involved.

## Acceptance criteria

- MCP leak-blocked responses surface as `response_leak_blocked`.
- Unknown response reasons still surface as `response_error`.
- Request and response byte counts are visible in structured MCP logs.
- No raw reason, body, URL, header, credential, or private address appears in
  caller-visible errors or logs.
- Existing body-limit, network, policy, credential, and panic mappings remain
  unchanged.
- MCP, host-runtime contract, architecture, formatting, and clippy gates pass.

