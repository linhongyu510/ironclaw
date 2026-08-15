# `packages/mnesis` — the Mnesis `[memory]` provider

**Crate:** `ironclaw_memory_mnesis` · **Layer:** `substrates` · **Extension id:**
`mnesis.hosted.memory` · **Linked by:** the binary only.

## What this is

The third `[memory]` provider, alongside `memory-native` (filesystem, the
default) and `mem0` (external mem0 REST). Mnesis differs from both in a way that
shapes the whole crate: it is reached over a **published hosted-MCP boundary**
with a bearer identity, and it exposes **two separately authorized lanes** —
retrieval (`knowledge_search`) and memory (`memory_search`) — rather than one
service with one credential.

## When you want this

You want Mnesis when retrieval quality and provenance matter more than local
simplicity: it carries generation identity, policy epoch, feedback ids, and
per-result provenance that the filesystem provider has no concept of. You want
`memory-native` when memory must work with no network and no operator
configuration. You want `mem0` when the deployment already runs a self-hosted
mem0 and wants its recall model.

## Shape

| File | Owns |
| --- | --- |
| `src/config.rs` | Typed configuration. Carries a `SecretHandle`, never credential material. |
| `src/url_check.rs` | The endpoint gate. Stricter than mem0's, see below. |
| `src/transport.rs` | The `MnesisTransport` seam, the rustls client, and the test mock. |
| `src/error.rs` | Provider-internal causes, mapped to sanitized `MemoryServiceError`. |

## Endpoint posture

Stricter than the sibling mem0 adapter, because a bearer credential rides every
request rather than an optional local API key:

- **TLS is mandatory off-loopback.** Plain `http` to a remote host is refused
  outright, never downgraded.
- **Loopback `http` requires an explicit development profile.** The production
  profile refuses it too, so a development override cannot survive into a
  deployed configuration by accident.
- **Always-blocked literals** are refused under every profile: cloud metadata
  (`169.254.169.254`), link-local, multicast, unspecified, and their
  IPv4-mapped-IPv6 spellings.
- **The operator allowlist is exact, not a suffix match.** A wildcard would let
  a compromised subdomain of a permitted apex through.
- **No DNS resolution.** A name that resolves to a blocked address is an egress
  policy concern owned by the deployment; making provider startup depend on a
  resolver would trade one failure mode for a worse one. The allowlist is the
  operator-facing control.

## Transport bounds

Redirects disabled (a compromised boundary must not bounce a credentialed
request elsewhere). Explicit connect, request, and total deadlines. Bounded
connection pool. **No automatic decompression** — `gzip`/`brotli`/`deflate` are
deliberately absent from the `reqwest` features, so a compressed body cannot
expand past the ceiling after the cap is applied. The response body is bounded
**while streaming**, before deserialization, so an oversized or hostile body is
abandoned rather than buffered. Retry is refused for anything not marked
idempotent, and backoff is bounded by the remaining total deadline.

The bearer credential is consumed at construction into a header marked
sensitive, is never stored on the struct, and `Debug` renders neither it nor the
client that holds it.

## Testing

```bash
cargo test -p ironclaw_memory_mnesis --all-features
cargo clippy -p ironclaw_memory_mnesis --all-targets --all-features -- -D warnings
```

`test-support` exposes `MockMnesisTransport` so downstream crates can drive the
provider with no live endpoint. The mock is panic-free and records every
request, so a test can assert what the production caller actually sent.
