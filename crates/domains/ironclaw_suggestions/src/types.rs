//! Persisted record shapes and the derived wire view for automation
//! suggestion cards (#7038). See `SuggestionsStore` (`store.rs`) for the
//! single writer and `derive_suggestions_view` below for the one function
//! that computes `generation.state` — it is never persisted (spec §4).

use chrono::{DateTime, Utc};
use ironclaw_host_api::ids::ThreadId;
use ironclaw_host_api::turn::TurnRunId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current wire schema version. A `SuggestionsDoc` read with a different
/// value is treated as absent (spec §4: "the entire migration story").
pub const SUGGESTIONS_SCHEMA_VERSION: u32 = 1;

/// One suggestion card. The single source of truth for the shape shared by
/// the `render_suggestions` tool input, the stored doc, and the HTTP
/// response (spec §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestionCard {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_id: Option<String>,
    pub requires_connection: bool,
    pub suggested_prompt: String,
    pub category: String,
}

/// Persisted fact: a generation run currently claimed and in flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveJob {
    pub job_id: Uuid,
    pub thread_id: ThreadId,
    pub run_id: TurnRunId,
    pub started_at: DateTime<Utc>,
}

/// Persisted fact: the most recent successful generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastResult {
    pub cards: Vec<SuggestionCard>,
    pub completed_at: DateTime<Utc>,
}

/// Persisted fact: the most recent generation failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastError {
    pub message: String,
    pub failed_at: DateTime<Utc>,
}

/// The persisted document. Only facts live here — `generation.state` is
/// derived at read time, never stored (spec §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestionsDoc {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub active_job: Option<ActiveJob>,
    #[serde(default)]
    pub last_result: Option<LastResult>,
    #[serde(default)]
    pub last_error: Option<LastError>,
}

fn default_schema_version() -> u32 {
    SUGGESTIONS_SCHEMA_VERSION
}

impl SuggestionsDoc {
    /// The doc a user with no generation history sees — same derived view as
    /// a doc that has never been written (spec §4: "no separate idle
    /// encoding").
    pub fn empty() -> Self {
        Self {
            schema_version: SUGGESTIONS_SCHEMA_VERSION,
            active_job: None,
            last_result: None,
            last_error: None,
        }
    }
}

/// Whether the run an `ActiveJob` references is still live. Resolved by the
/// caller (the product service, via `TurnCoordinator::get_run_state`) before
/// calling [`derive_suggestions_view`] — this module stays pure and
/// synchronous so it is unit-testable without a turn runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunLiveness {
    Live,
    Terminal,
    Missing,
}

/// Wire `generation.state` (spec §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationState {
    Running,
    Ready,
    Failed,
    None,
}

/// Wire `generation` object (spec §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationView {
    pub state: GenerationState,
    pub job_id: Option<Uuid>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

/// The full derived GET response (spec §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestionsView {
    pub schema_version: u32,
    pub generation: GenerationView,
    pub cards: Vec<SuggestionCard>,
}

/// Synthetic error text for the one case with no stored message: a crashed
/// host left `active_job` set with no `last_error` ever written. No janitor
/// repairs this — the next read simply derives `failed` (spec §5).
const DEAD_RUN_ERROR_MESSAGE: &str = "suggestion generation did not complete";

/// The one function that computes `generation.state` (spec §4/§7-item-1).
/// Never persisted. Precedence (first match wins):
///
/// 1. `active_job` set and its run live → `running`.
/// 2. `active_job` set but its run is terminal/missing → `failed` (crash
///    recovery path — no stored error message, so a synthetic one is used).
/// 3. `last_error` newer than `last_result` (or no `last_result` at all) →
///    `failed`, carrying the stored message.
/// 4. `last_result` present → `ready`.
/// 5. Otherwise → `none`.
///
/// `cards` always serializes from `last_result`, independent of `state`
/// (spec §4: stale cards may render alongside a `failed` retry banner).
///
/// `active_job_liveness` is consulted only when `doc.active_job.is_some()`;
/// pass `None` when the caller has no live-run answer (e.g. it could not be
/// resolved) — this fails toward `failed`, never toward a permanently stuck
/// `running`.
pub fn derive_suggestions_view(
    doc: &SuggestionsDoc,
    active_job_liveness: Option<RunLiveness>,
) -> SuggestionsView {
    let cards = doc
        .last_result
        .as_ref()
        .map(|result| result.cards.clone())
        .unwrap_or_default();

    let generation = if let Some(active_job) = &doc.active_job {
        match active_job_liveness.unwrap_or(RunLiveness::Missing) {
            RunLiveness::Live => GenerationView {
                state: GenerationState::Running,
                job_id: Some(active_job.job_id),
                started_at: Some(active_job.started_at),
                completed_at: None,
                error: None,
            },
            RunLiveness::Terminal | RunLiveness::Missing => GenerationView {
                state: GenerationState::Failed,
                job_id: Some(active_job.job_id),
                started_at: Some(active_job.started_at),
                completed_at: None,
                error: Some(DEAD_RUN_ERROR_MESSAGE.to_string()),
            },
        }
    } else if let Some(last_error) = &doc.last_error {
        let error_is_newer = doc
            .last_result
            .as_ref()
            .is_none_or(|result| last_error.failed_at > result.completed_at);
        if error_is_newer {
            GenerationView {
                state: GenerationState::Failed,
                job_id: None,
                started_at: None,
                completed_at: None,
                error: Some(last_error.message.clone()),
            }
        } else {
            ready_generation_view(doc.last_result.as_ref())
        }
    } else if let Some(last_result) = &doc.last_result {
        ready_generation_view(Some(last_result))
    } else {
        GenerationView {
            state: GenerationState::None,
            job_id: None,
            started_at: None,
            completed_at: None,
            error: None,
        }
    };

    SuggestionsView {
        schema_version: SUGGESTIONS_SCHEMA_VERSION,
        generation,
        cards,
    }
}

fn ready_generation_view(last_result: Option<&LastResult>) -> GenerationView {
    GenerationView {
        state: GenerationState::Ready,
        job_id: None,
        started_at: None,
        completed_at: last_result.map(|result| result.completed_at),
        error: None,
    }
}
