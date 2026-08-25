# mnesis-rar — Mnesis retrieval hosted-MCP extension

The Mnesis retrieval lane: corpus search and ingestion administration,
discovered from the Mnesis RAR MCP server. Extension id: `mnesis-rar`. This is
a **data-only package**: a hosted-MCP extension declares `[mcp]` (server,
namespace, max_tools, credentials) in place of a `[runtime]` section, and past
activation a discovered tool is an ordinary tool surface.

This package is the model-visible half of the Mnesis integration. The ambient
half lives in `crates/extensions/packages/mnesis/`, which declares
`[runtime] kind = "first_party"` plus `[memory]` lifecycle hooks. The two
cannot be one package: a v3 manifest may declare `[runtime]` **or** `[mcp]`,
never both (`ManifestV3Error::RuntimeDeclaration`).

- **Surfaces:** `[mcp]` hosted server + 1 statically pinned tool (`mnesis-rar.search_knowledge` — model-visible from first boot, replaced by the live catalog after a successful `tools/list` discovery) + `[auth.mnesis]` (api_key)
- **Vendor (credential authority):** `mnesis` — the retrieval-lane bearer token, distinct from the memory lane's; Mnesis authorizes the two lanes independently
- **Runtime:** MCP loader (discovery owned by `ironclaw_extension_host`)
- **Contents:** `manifest.toml`, `schemas/`. Embed module: `ironclaw_extension_support::packages::mnesis_rar` — deliberately **not** in the `PACKAGES` table, because the shipped `[mcp].server` is a placeholder the host rewrites from deployment configuration; read that module's header before "fixing" the omission
- **Tests:** manifest projection — `cargo test -p ironclaw_extension_registry`; host-side discovery/registration — `cargo test -p ironclaw_extension_host`

Why discovery rather than a static catalog: the tool surface a Mnesis tenant
exposes is a function of that tenant's granted permissions, so a catalog
captured at build time is correct only for the tenant it was captured against.
Discovery makes each deployment's surface self-describing.

Family model and the package rules: `crates/extensions/AGENTS.md`.
