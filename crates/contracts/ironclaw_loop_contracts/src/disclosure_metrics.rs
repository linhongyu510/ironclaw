//! Per-model-call progressive-tool-disclosure measurements.
//!
//! Progressive tool disclosure (`tool_search` / `tool_describe` / `tool_call`)
//! already computes every number an operator needs to judge the rollout —
//! catalog size, advertised size, estimated schema tokens, how often the model
//! searched, whether a search came back empty, which rank it eventually picked,
//! how many deferred tools were promoted, how many recoverable failures the
//! bridge absorbed, and how many calls aimed outside the disclosed surface.
//! Until now those numbers only reached ephemeral `debug!` shadow logs.
//!
//! This module defines the neutral, closed-vocabulary carrier for those
//! measurements. It is deliberately numbers-only: no tool names, no queries, no
//! schemas, no descriptions. That is what lets the record cross into the
//! durable runtime event log, which is redaction-bound.
//!
//! The counters are cumulative over the disclosure port's lifetime (one run),
//! so a per-call delta is a subtraction between consecutive records and a
//! per-run total is the last record. Cumulative was chosen over per-call deltas
//! because a dropped or best-effort-skipped record then loses precision, not
//! correctness.

use serde::{Deserialize, Serialize};

/// Coarse catalog-size bucket, the third rollout query dimension alongside
/// model and run profile.
///
/// Buckets are anchored on the disclosure caps that gate deferral
/// (`DisclosureCaps::default().max_tools == 32`): `AtOrBelowCaps` is the
/// "stays direct, pays no discovery round trip" cohort the issue calls out
/// separately from the wide catalogs deferral exists for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogSizeBucket {
    /// No authorized tools at all (no-tool chat).
    Empty,
    /// 1–8 tools.
    Tiny,
    /// 9–32 tools — at or below the default disclosure caps.
    AtOrBelowCaps,
    /// 33–96 tools.
    Wide,
    /// More than 96 tools.
    VeryWide,
}

impl CatalogSizeBucket {
    /// Classify a full (authorized, policy-effective) tool count.
    pub const fn from_tool_count(full_tool_count: u32) -> Self {
        match full_tool_count {
            0 => Self::Empty,
            1..=8 => Self::Tiny,
            9..=32 => Self::AtOrBelowCaps,
            33..=96 => Self::Wide,
            _ => Self::VeryWide,
        }
    }

    /// Stable closed-vocabulary label for durable events and queries.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Tiny => "tiny",
            Self::AtOrBelowCaps => "at_or_below_caps",
            Self::Wide => "wide",
            Self::VeryWide => "very_wide",
        }
    }

    /// Parse a label produced by [`Self::as_str`]. Unknown labels are rejected
    /// rather than silently bucketed, so a future bucket cannot masquerade as
    /// an existing cohort in a rollout comparison.
    pub fn from_str_label(label: &str) -> Option<Self> {
        match label {
            "empty" => Some(Self::Empty),
            "tiny" => Some(Self::Tiny),
            "at_or_below_caps" => Some(Self::AtOrBelowCaps),
            "wide" => Some(Self::Wide),
            "very_wide" => Some(Self::VeryWide),
            _ => None,
        }
    }
}

/// Disclosure measurements observed at one model call.
///
/// Every field is already computed inside the disclosure port; this type only
/// carries them. See the module docs for the cumulative-counter contract.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDisclosureCallMetrics {
    /// Whether this call actually deferred (bridged) rather than advertising
    /// the full surface flat. Disclosure can be wired but inert below caps.
    pub deferred: bool,
    /// Authorized, policy-effective tool count before narrowing.
    pub full_tool_count: u32,
    /// Tool count actually advertised to the provider on this call.
    pub advertised_tool_count: u32,
    /// Estimated schema tokens for the full authorized surface.
    pub full_schema_tokens: u32,
    /// Estimated schema tokens actually advertised on this call.
    pub advertised_schema_tokens: u32,
    /// Cumulative `tool_search` invocations.
    pub tool_search_count: u32,
    /// Cumulative `tool_search` invocations that returned zero results.
    pub empty_search_count: u32,
    /// 1-based rank, within its originating `tool_search` result list, of the
    /// most recently selected (invoked or promoted) deferred tool. `None` when
    /// nothing ranked has been selected yet.
    pub selected_result_rank: Option<u32>,
    /// Cumulative earned promotions of a deferred tool to the flat surface.
    pub promotions: u32,
    /// Cumulative recoverable outcomes the bridge returned instead of ending
    /// the run — describe-first schema returns and recoverable bridge failures.
    pub recoveries: u32,
    /// Cumulative attempts to search, describe, or call a tool that is not on
    /// the authorized disclosed surface.
    pub outside_surface_attempts: u32,
}

impl ToolDisclosureCallMetrics {
    /// Catalog-size bucket for this call's full authorized surface.
    pub const fn catalog_size_bucket(&self) -> CatalogSizeBucket {
        CatalogSizeBucket::from_tool_count(self.full_tool_count)
    }

    /// Schema-token reduction achieved on this call, in percent, or `None`
    /// when the full surface estimated zero tokens (nothing to reduce).
    pub fn schema_token_reduction_pct(&self) -> Option<f64> {
        if self.full_schema_tokens == 0 {
            return None;
        }
        Some(
            100.0
                * (1.0
                    - (f64::from(self.advertised_schema_tokens)
                        / f64::from(self.full_schema_tokens))),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_buckets_split_on_the_disclosure_cap_boundary() {
        // The cap boundary is the load-bearing one: 32 is the last catalog that
        // stays direct, 33 is the first that pays for discovery. A rollout
        // comparison that blurs those two cohorts cannot answer "did small
        // catalogs regress".
        assert_eq!(
            CatalogSizeBucket::from_tool_count(0),
            CatalogSizeBucket::Empty
        );
        assert_eq!(
            CatalogSizeBucket::from_tool_count(8),
            CatalogSizeBucket::Tiny
        );
        assert_eq!(
            CatalogSizeBucket::from_tool_count(32),
            CatalogSizeBucket::AtOrBelowCaps
        );
        assert_eq!(
            CatalogSizeBucket::from_tool_count(33),
            CatalogSizeBucket::Wide
        );
        assert_eq!(
            CatalogSizeBucket::from_tool_count(97),
            CatalogSizeBucket::VeryWide
        );
    }

    #[test]
    fn bucket_labels_round_trip_and_reject_unknown_cohorts() {
        for bucket in [
            CatalogSizeBucket::Empty,
            CatalogSizeBucket::Tiny,
            CatalogSizeBucket::AtOrBelowCaps,
            CatalogSizeBucket::Wide,
            CatalogSizeBucket::VeryWide,
        ] {
            assert_eq!(
                CatalogSizeBucket::from_str_label(bucket.as_str()),
                Some(bucket)
            );
        }
        assert_eq!(CatalogSizeBucket::from_str_label("huge"), None);
    }

    #[test]
    fn reduction_is_none_when_there_was_nothing_to_reduce() {
        let metrics = ToolDisclosureCallMetrics::default();
        assert_eq!(metrics.schema_token_reduction_pct(), None);
    }

    #[test]
    fn reduction_reports_the_share_of_full_schema_tokens_avoided() {
        let metrics = ToolDisclosureCallMetrics {
            full_schema_tokens: 1_000,
            advertised_schema_tokens: 163,
            ..ToolDisclosureCallMetrics::default()
        };
        let reduction = metrics
            .schema_token_reduction_pct()
            .expect("nonzero full surface reports a reduction");
        assert!(
            (reduction - 83.7).abs() < 1e-9,
            "unexpected reduction {reduction}"
        );
    }
}
