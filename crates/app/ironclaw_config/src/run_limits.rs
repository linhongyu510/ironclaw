//! Deployment-level wall-clock ceiling for prepared (unbound) runs.
//!
//! `ResourceBudgetPolicy::max_wall_clock_seconds` is defined and enforced by
//! the loop's budget stage, but nothing in the tree ever sets it: the
//! interactive tier defaults to `None`, both `PreparedTurnDeclarations`
//! producers pass `TurnLimits::default()`, and the loop's own budget strategy
//! defaults to no wall-clock cap. A run therefore has no idea how long it is
//! allowed to take, which is exactly what a harness with an external timeout
//! needs it to know — a deadline the run cannot see is a deadline it cannot
//! plan against.
//!
//! This knob supplies one, for the prepared/OpenAI-compatible lane only. Set it
//! slightly BELOW the harness's own timeout so the run reaches its internal
//! deadline first and can still finish deliberately (writing an owed file, for
//! instance) instead of being killed mid-work from outside.
//!
//! Unset is the default and changes nothing. The value flows through
//! `TurnLimits`, which is narrowing-only, so it can only ever shorten a run.

use std::env;

/// Wall-clock ceiling in seconds for prepared/unbound runs. Unset or `0`
/// means no ceiling, which is the historical behavior.
pub const RUN_MAX_WALL_CLOCK_SECONDS_ENV: &str = "IRONCLAW_RUN_MAX_WALL_CLOCK_SECONDS";

/// Read the configured prepared-run wall-clock ceiling.
///
/// Fails open on every ambiguity — unset, empty, `0`, or unparseable all yield
/// `None`. A misread here must not invent a deadline that terminates real runs,
/// and the value is advisory configuration rather than a security boundary.
pub fn prepared_run_max_wall_clock_seconds() -> Option<u32> {
    parse_max_wall_clock_seconds(env::var(RUN_MAX_WALL_CLOCK_SECONDS_ENV).ok().as_deref())
}

fn parse_max_wall_clock_seconds(raw: Option<&str>) -> Option<u32> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    // Unparseable joins unset and `0` in meaning "no ceiling". This crate has
    // no logging dependency and is not worth one for a single line; the
    // fail-open direction is the safe one, because the alternative to ignoring
    // a malformed value is inventing a deadline that terminates real runs.
    match raw.parse::<u32>() {
        Ok(0) | Err(_) => None,
        Ok(seconds) => Some(seconds),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_positive_whole_number_of_seconds_is_a_ceiling() {
        assert_eq!(parse_max_wall_clock_seconds(Some("300")), Some(300));
        assert_eq!(parse_max_wall_clock_seconds(Some("  300  ")), Some(300));
        assert_eq!(parse_max_wall_clock_seconds(Some("1")), Some(1));
    }

    /// Every ambiguous form means "no ceiling". Inventing one would terminate
    /// runs that today have no deadline at all.
    #[test]
    fn everything_ambiguous_means_no_ceiling() {
        for raw in [
            None,
            Some(""),
            Some("   "),
            Some("0"),
            Some("-5"),
            Some("abc"),
            Some("30s"),
        ] {
            assert_eq!(
                parse_max_wall_clock_seconds(raw),
                None,
                "input {raw:?} must not produce a ceiling"
            );
        }
    }
}
