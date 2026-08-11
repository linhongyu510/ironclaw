//! Automation suggestion cards domain crate (#7038): persisted record
//! shapes, the derived wire view, and the single-writer `SuggestionsStore`.
//!
//! Split out of `ironclaw_assistant` (product layer) into a domain crate
//! because `SuggestionCard` is also the `render_suggestions` first-party
//! tool's input schema type in `ironclaw_host_runtime` (kernel layer, below
//! product) — the design doc's "one schema struct is the single source of
//! truth" requirement (spec §4) means the type must live somewhere both
//! layers can reach, the same shape as `ironclaw_triggers` sitting below
//! `ironclaw_host_runtime` for `TriggerRepository`.

#![forbid(unsafe_code)]

mod store;
mod types;

pub use store::{ClaimOutcome, SuggestionsStore, SuggestionsStoreError};
pub use types::{
    ActiveJob, GenerationState, GenerationView, LastError, LastResult, RunLiveness,
    SUGGESTIONS_SCHEMA_VERSION, SuggestionCard, SuggestionsDoc, SuggestionsView,
    derive_suggestions_view,
};

#[cfg(test)]
mod tests;
