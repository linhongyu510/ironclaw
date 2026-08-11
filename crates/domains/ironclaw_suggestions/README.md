# ironclaw_suggestions

The automation suggestion cards domain: persisted record shapes
(`SuggestionCard`, `SuggestionsDoc`, `GenerationState`), the derived wire view
(`SuggestionsView`, `derive_suggestions_view`), and the single-writer
`SuggestionsStore`. Split out of `ironclaw_assistant` (product layer) into its
own domain crate because `SuggestionCard` is also the `render_suggestions`
first-party tool's input schema type in `ironclaw_host_runtime` (kernel
layer, below product) — the same shape as `ironclaw_triggers` sitting below
`ironclaw_host_runtime` for `TriggerRepository`.

- **Family / layer:** `domains` / `substrates` · **Package:** `ironclaw_suggestions` · **Manifest:** `crates/domains/ironclaw_suggestions/Cargo.toml`
- **Use this when:** reading or writing persisted suggestion-card records,
  deriving the wire-facing `SuggestionsView`, or claiming/completing a
  suggestion generation run through `SuggestionsStore`.
- **Don't use this when:** rendering suggestion cards to a channel or the
  WebUI (product tier) or deciding whether a suggestion may be generated
  (kernel authority) — this crate only owns the record shape and the
  single-writer store.

## Public surface

- Types: `SuggestionCard`, `SuggestionsDoc`, `SuggestionsView`,
  `GenerationState`, `GenerationView`, `ActiveJob`, `LastError`,
  `LastResult`, `RunLiveness`, `SUGGESTIONS_SCHEMA_VERSION`.
- View derivation: `derive_suggestions_view`.
- Store: `SuggestionsStore`, `SuggestionsStoreError`, `ClaimOutcome`.

## Depends on / consumed by

- **Normal deps:** `ironclaw_filesystem`, `ironclaw_host_api`.
- **Consumed by:** `ironclaw_assistant`, `ironclaw_composition`,
  `ironclaw_host_runtime` (the `render_suggestions` first-party tool's input
  schema).

## Tests

```bash
cargo test -p ironclaw_suggestions
```

(Unit tests live in `src/tests.rs`.)

## See also

- Family boundary: [`../AGENTS.md`](../AGENTS.md) (this crate has no separate
  working-rules file; this README is its crate guidance).
