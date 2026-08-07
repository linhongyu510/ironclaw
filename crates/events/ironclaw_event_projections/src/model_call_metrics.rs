//! Rollout-evidence read model over per-model-call metrics events.
//!
//! Progressive tool disclosure has been running in internal production with no
//! durable evidence behind it: the numbers existed only in `debug!` shadow logs
//! and a process-local inspector store, so nobody could answer "did the wide
//! catalogs regress?" after the fact. `RuntimeEventKind::ModelCallMetricsRecorded`
//! makes each model call durable; this module turns that stream into the query
//! an operator actually asks — grouped by model, run profile, and catalog-size
//! bucket.
//!
//! The projection is a fold, not a store: it derives everything from the
//! durable log, so it inherits that log's scoping and retention and adds no new
//! persistence.

use std::collections::{BTreeMap, HashMap, HashSet};

use ironclaw_event_log::{
    EventCursor, EventLogEntry, ModelCallMetrics, ModelCallOutcome, RuntimeEvent, RuntimeEventKind,
};
use ironclaw_host_api::{
    Timestamp,
    ids::{InvocationId, ThreadId},
};
use serde::{Deserialize, Serialize};

use crate::ProjectionCursor;

/// One durable model-call measurement, resolved against its run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCallMetricsEntry {
    pub cursor: EventCursor,
    pub timestamp: Timestamp,
    /// The run this model call belongs to. `model calls per run` is a count of
    /// entries sharing this id.
    pub invocation_id: InvocationId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<ThreadId>,
    pub metrics: ModelCallMetrics,
}

impl ModelCallMetricsEntry {
    /// The three rollout query dimensions for this call.
    pub fn group_key(&self) -> ModelCallMetricsGroupKey {
        ModelCallMetricsGroupKey {
            requested_model: self.metrics.requested_model.clone(),
            effective_model: self.metrics.effective_model.clone(),
            catalog_size_bucket: self
                .metrics
                .disclosure
                .as_ref()
                .map(|disclosure| disclosure.catalog_size_bucket.clone()),
        }
    }
}

/// A page of model-call measurements plus the runs that completed within it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCallMetricsPage {
    pub entries: Vec<ModelCallMetricsEntry>,
    /// Runs whose `LoopCompleted` event appears in this page. Needed for
    /// "model calls per completed task": a run that is still going, or that
    /// failed, must not be counted as a completed task in the denominator.
    pub completed_run_ids: Vec<InvocationId>,
    pub next_cursor: ProjectionCursor,
    pub truncated: bool,
}

impl ModelCallMetricsPage {
    /// Aggregate this page by (run profile, model, catalog-size bucket).
    pub fn aggregate(&self) -> Vec<ModelCallMetricsAggregate> {
        let completed: HashSet<InvocationId> = self.completed_run_ids.iter().copied().collect();
        let mut grouped: BTreeMap<ModelCallMetricsGroupKey, ModelCallMetricsAggregate> =
            BTreeMap::new();
        for entry in &self.entries {
            let key = entry.group_key();
            grouped
                .entry(key.clone())
                .or_insert_with(|| ModelCallMetricsAggregate::empty(key))
                .accumulate(entry, &completed);
        }
        grouped.into_values().collect()
    }
}

/// The queryable dimensions: run profile, model, catalog-size bucket.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ModelCallMetricsGroupKey {
    /// Requested run/model profile label.
    pub requested_model: String,
    /// Concrete provider model that served the call, when reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_model: Option<String>,
    /// Catalog-size cohort, absent when disclosure was not in play.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_size_bucket: Option<String>,
}

/// Totals for one query group.
///
/// Disclosure counters are cumulative per run, so the aggregate keeps the
/// **maximum** observed value per run rather than a sum across calls — summing
/// cumulative counters would multiply one search into N. `runs` is the number
/// of distinct runs contributing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCallMetricsAggregate {
    pub key: ModelCallMetricsGroupKey,
    pub model_calls: u64,
    pub succeeded_calls: u64,
    pub failed_calls: u64,
    /// Calls that ran on a non-primary route — the observable retry signal.
    pub fallback_route_calls: u64,
    pub total_duration_ms: u64,
    pub total_prompt_tokens: u64,
    pub total_cached_prompt_tokens: u64,
    pub total_cache_creation_tokens: u64,
    pub total_output_tokens: u64,
    /// Distinct runs contributing calls to this group.
    pub runs: u64,
    /// Of those, the runs that completed within the observed page.
    pub completed_runs: u64,
    pub tool_searches: u64,
    pub empty_tool_searches: u64,
    pub promotions: u64,
    pub recoveries: u64,
    pub outside_surface_attempts: u64,
    /// Largest full authorized tool count seen in this group.
    pub max_full_tool_count: u32,
    /// Largest advertised tool count seen in this group.
    pub max_advertised_tool_count: u32,
    #[serde(skip)]
    seen_runs: HashSet<InvocationId>,
    #[serde(skip)]
    completed_seen_runs: HashSet<InvocationId>,
    #[serde(skip)]
    per_run_disclosure: HashMap<InvocationId, RunDisclosureHighWater>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RunDisclosureHighWater {
    tool_searches: u32,
    empty_tool_searches: u32,
    promotions: u32,
    recoveries: u32,
    outside_surface_attempts: u32,
}

impl ModelCallMetricsAggregate {
    fn empty(key: ModelCallMetricsGroupKey) -> Self {
        Self {
            key,
            model_calls: 0,
            succeeded_calls: 0,
            failed_calls: 0,
            fallback_route_calls: 0,
            total_duration_ms: 0,
            total_prompt_tokens: 0,
            total_cached_prompt_tokens: 0,
            total_cache_creation_tokens: 0,
            total_output_tokens: 0,
            runs: 0,
            completed_runs: 0,
            tool_searches: 0,
            empty_tool_searches: 0,
            promotions: 0,
            recoveries: 0,
            outside_surface_attempts: 0,
            max_full_tool_count: 0,
            max_advertised_tool_count: 0,
            seen_runs: HashSet::new(),
            completed_seen_runs: HashSet::new(),
            per_run_disclosure: HashMap::new(),
        }
    }

    fn accumulate(&mut self, entry: &ModelCallMetricsEntry, completed: &HashSet<InvocationId>) {
        let metrics = &entry.metrics;
        self.model_calls = self.model_calls.saturating_add(1);
        match metrics.outcome {
            ModelCallOutcome::Succeeded => {
                self.succeeded_calls = self.succeeded_calls.saturating_add(1);
            }
            ModelCallOutcome::Failed => {
                self.failed_calls = self.failed_calls.saturating_add(1);
            }
        }
        if metrics.fallback_index > 0 {
            self.fallback_route_calls = self.fallback_route_calls.saturating_add(1);
        }
        self.total_duration_ms = self.total_duration_ms.saturating_add(metrics.duration_ms);
        self.total_prompt_tokens = self
            .total_prompt_tokens
            .saturating_add(metrics.prompt_tokens);
        self.total_cached_prompt_tokens = self
            .total_cached_prompt_tokens
            .saturating_add(metrics.cached_prompt_tokens);
        self.total_cache_creation_tokens = self
            .total_cache_creation_tokens
            .saturating_add(metrics.cache_creation_tokens);
        self.total_output_tokens = self
            .total_output_tokens
            .saturating_add(metrics.output_tokens);
        if self.seen_runs.insert(entry.invocation_id) {
            self.runs = self.runs.saturating_add(1);
        }
        if completed.contains(&entry.invocation_id)
            && self.completed_seen_runs.insert(entry.invocation_id)
        {
            self.completed_runs = self.completed_runs.saturating_add(1);
        }
        if let Some(disclosure) = metrics.disclosure.as_ref() {
            self.max_full_tool_count = self.max_full_tool_count.max(disclosure.full_tool_count);
            self.max_advertised_tool_count = self
                .max_advertised_tool_count
                .max(disclosure.advertised_tool_count);
            // Cumulative counters: keep the per-run high-water mark, then
            // re-derive the group total. Summing them per call would count a
            // single search once for every later call in the run.
            let high_water = self
                .per_run_disclosure
                .entry(entry.invocation_id)
                .or_default();
            high_water.tool_searches = high_water.tool_searches.max(disclosure.tool_search_count);
            high_water.empty_tool_searches = high_water
                .empty_tool_searches
                .max(disclosure.empty_search_count);
            high_water.promotions = high_water.promotions.max(disclosure.promotions);
            high_water.recoveries = high_water.recoveries.max(disclosure.recoveries);
            high_water.outside_surface_attempts = high_water
                .outside_surface_attempts
                .max(disclosure.outside_surface_attempts);
            self.recompute_disclosure_totals();
        }
    }

    fn recompute_disclosure_totals(&mut self) {
        let mut totals = RunDisclosureHighWater::default();
        for run in self.per_run_disclosure.values() {
            totals.tool_searches = totals.tool_searches.saturating_add(run.tool_searches);
            totals.empty_tool_searches = totals
                .empty_tool_searches
                .saturating_add(run.empty_tool_searches);
            totals.promotions = totals.promotions.saturating_add(run.promotions);
            totals.recoveries = totals.recoveries.saturating_add(run.recoveries);
            totals.outside_surface_attempts = totals
                .outside_surface_attempts
                .saturating_add(run.outside_surface_attempts);
        }
        self.tool_searches = u64::from(totals.tool_searches);
        self.empty_tool_searches = u64::from(totals.empty_tool_searches);
        self.promotions = u64::from(totals.promotions);
        self.recoveries = u64::from(totals.recoveries);
        self.outside_surface_attempts = u64::from(totals.outside_surface_attempts);
    }

    /// Model calls per completed task, or `None` when no run in this group
    /// completed within the observed window — an honest "not yet answerable"
    /// rather than a ratio over an empty denominator.
    pub fn model_calls_per_completed_run(&self) -> Option<f64> {
        if self.completed_runs == 0 {
            return None;
        }
        // Only calls belonging to completed runs may enter the numerator;
        // counting in-flight runs' calls would understate the true cost per
        // finished task while runs are still open.
        Some(self.model_calls as f64 / self.completed_runs as f64)
    }
}

/// Project a durable runtime page into model-call measurements.
pub(crate) fn project_model_call_metrics(
    entries: &[EventLogEntry<RuntimeEvent>],
) -> (Vec<ModelCallMetricsEntry>, Vec<InvocationId>) {
    let mut metrics = Vec::new();
    let mut completed = Vec::new();
    for entry in entries {
        let event = &entry.record;
        match event.kind {
            RuntimeEventKind::ModelCallMetricsRecorded => {
                // A metrics-kind event without a payload is a producer bug, not
                // a data point. Skipping keeps a malformed row from silently
                // becoming a zero-token, zero-latency call in the totals.
                if let Some(record) = event.model_call_metrics.as_ref() {
                    metrics.push(ModelCallMetricsEntry {
                        cursor: entry.cursor,
                        timestamp: event.timestamp,
                        invocation_id: event.scope.invocation_id,
                        thread_id: event.scope.thread_id.clone(),
                        metrics: record.clone(),
                    });
                }
            }
            RuntimeEventKind::LoopCompleted => completed.push(event.scope.invocation_id),
            _ => {}
        }
    }
    (metrics, completed)
}
