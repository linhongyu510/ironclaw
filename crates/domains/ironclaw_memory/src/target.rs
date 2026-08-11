//! Document target aliases — the reserved model-facing `target` values of the
//! shared memory write tool and their canonical relative document paths.
//!
//! This is the OPTIONAL conventional `ironclaw.memory.write` / `.read` tool
//! vocabulary, owned here beside their shared capability ids, request DTOs,
//! and wire helpers — never copied between providers. A provider may expose
//! different tools or none at all; a provider declaring this conventional
//! document-tool pair with the shared prompt/schema uses this table so the
//! same alias means the same canonical document across backend swaps (#7505).
//! The shared write prompt (`memory-native/prompts/memory-native/write.md`,
//! reused verbatim by mem0) teaches the model the aliases:
//!
//! | `target` alias        | canonical document                     |
//! |-----------------------|----------------------------------------|
//! | `memory`              | `MEMORY.md` (the standing durable fact doc) |
//! | `daily_log`           | `daily/<YYYY-MM-DD>.md` (today, timezone-aware) |
//! | `heartbeat`           | `HEARTBEAT.md` (the standing checklist) |
//! | `bootstrap`           | `BOOTSTRAP.md` (a write clears it)     |
//! | any other relative path | itself (unchanged)                   |
//!
//! Providers declaring the conventional document-tool pair with this shared
//! vocabulary route write/read path resolution through
//! [`resolve_document_target`] / [`same_document_target`] rather than
//! reimplementing the table. They opt into the separate
//! `crate::memory_document_tool_contract!` suite; lifecycle-only providers do
//! not.

use chrono::Utc;
use chrono_tz::Tz;

use crate::MemoryServiceError;

/// `target: "memory"` — the standing durable memory document ([`MEMORY_DOCUMENT_PATH`]).
pub const MEMORY_DOCUMENT_TARGET: &str = "memory";
/// `target: "daily_log"` — today's dated log (timezone-aware, `daily/<YYYY-MM-DD>.md`).
pub const DAILY_LOG_DOCUMENT_TARGET: &str = "daily_log";
/// `target: "heartbeat"` — the standing heartbeat checklist document ([`HEARTBEAT_DOCUMENT_PATH`]).
pub const HEARTBEAT_DOCUMENT_TARGET: &str = "heartbeat";
/// `target: "bootstrap"` — the standing bootstrap checklist document ([`BOOTSTRAP_DOCUMENT_PATH`]);
/// a write clears it.
pub const BOOTSTRAP_DOCUMENT_TARGET: &str = "bootstrap";

/// Canonical relative document path of the standing durable memory document.
pub const MEMORY_DOCUMENT_PATH: &str = "MEMORY.md";
/// Canonical relative document path of the standing heartbeat checklist document.
pub const HEARTBEAT_DOCUMENT_PATH: &str = "HEARTBEAT.md";
/// Canonical relative document path of the standing bootstrap checklist document.
pub const BOOTSTRAP_DOCUMENT_PATH: &str = "BOOTSTRAP.md";

/// Resolve a write `target` to its canonical relative document path.
///
/// Fixed aliases map to their canonical documents; `daily_log` maps to
/// today's date in the given IANA `timezone` (UTC when absent — an invalid
/// timezone is an input error, mirroring the pre-contract native behavior);
/// any other relative path passes through unchanged. For providers declaring
/// the conventional document tools, the resolved path is what the provider
/// stores/addresses — the alias itself is not the document identity (#7505).
pub fn resolve_document_target(
    target: &str,
    timezone: Option<&str>,
) -> Result<String, MemoryServiceError> {
    match target {
        MEMORY_DOCUMENT_TARGET => Ok(MEMORY_DOCUMENT_PATH.to_string()),
        HEARTBEAT_DOCUMENT_TARGET => Ok(HEARTBEAT_DOCUMENT_PATH.to_string()),
        BOOTSTRAP_DOCUMENT_TARGET => Ok(BOOTSTRAP_DOCUMENT_PATH.to_string()),
        DAILY_LOG_DOCUMENT_TARGET => {
            let timezone = match timezone {
                Some(value) => value
                    .parse::<Tz>()
                    .map_err(|_| MemoryServiceError::input())?,
                None => Tz::UTC,
            };
            let now = Utc::now().with_timezone(&timezone);
            Ok(format!("daily/{}.md", now.format("%Y-%m-%d")))
        }
        path => Ok(path.to_string()),
    }
}

/// The legacy aliases whose canonical document path is `path`.
///
/// Read-side compatibility (#7505): rows stored under a pre-resolution alias
/// (mem0 historically tagged `"memory"` verbatim) must stay reachable by
/// their canonical path (e.g. `MEMORY.md` — the path the host's always-on
/// prompt lane reads). `daily_log` has no fixed canonical path (its target
/// encodes the write date), so it has no entry here.
pub fn document_target_aliases(path: &str) -> &'static [&'static str] {
    match path {
        MEMORY_DOCUMENT_PATH => &[MEMORY_DOCUMENT_TARGET],
        HEARTBEAT_DOCUMENT_PATH => &[HEARTBEAT_DOCUMENT_TARGET],
        BOOTSTRAP_DOCUMENT_PATH => &[BOOTSTRAP_DOCUMENT_TARGET],
        _ => &[],
    }
}

/// Whether a stored document identity and a requested path name the same
/// document: exact equality, or the stored identity is a legacy alias of the
/// requested canonical path (see [`document_target_aliases`]).
///
/// Used by tag-based document stores (mem0 filters memories by their
/// `target` metadata tag) so reads find both canonically-tagged rows and
/// pre-fix alias-tagged rows.
pub fn same_document_target(stored: &str, requested: &str) -> bool {
    stored == requested || document_target_aliases(requested).contains(&stored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryServiceErrorKind;

    #[test]
    fn fixed_aliases_resolve_to_their_canonical_documents() {
        assert_eq!(
            resolve_document_target(MEMORY_DOCUMENT_TARGET, None).unwrap(),
            MEMORY_DOCUMENT_PATH
        );
        assert_eq!(
            resolve_document_target(HEARTBEAT_DOCUMENT_TARGET, None).unwrap(),
            HEARTBEAT_DOCUMENT_PATH
        );
        assert_eq!(
            resolve_document_target(BOOTSTRAP_DOCUMENT_TARGET, None).unwrap(),
            BOOTSTRAP_DOCUMENT_PATH
        );
    }

    #[test]
    fn daily_log_resolves_to_today_dated_path() {
        let resolved = resolve_document_target(DAILY_LOG_DOCUMENT_TARGET, None).unwrap();
        assert!(
            resolved.starts_with("daily/") && resolved.ends_with(".md"),
            "daily_log must resolve to today's dated document, got {resolved}"
        );
        let date = &resolved["daily/".len()..resolved.len() - ".md".len()];
        assert_eq!(
            date.len(),
            10,
            "date component must be YYYY-MM-DD, got {date}"
        );
        date.parse::<chrono::NaiveDate>()
            .expect("date component must parse");
    }

    #[test]
    fn daily_log_accepts_a_valid_timezone_and_rejects_an_invalid_one() {
        assert!(resolve_document_target(DAILY_LOG_DOCUMENT_TARGET, Some("Europe/Berlin")).is_ok());
        assert_eq!(
            resolve_document_target(DAILY_LOG_DOCUMENT_TARGET, Some("not/a-zone"))
                .unwrap_err()
                .kind(),
            MemoryServiceErrorKind::Input
        );
    }

    #[test]
    fn ordinary_paths_pass_through_unchanged() {
        assert_eq!(
            resolve_document_target("notes/alpha.md", None).unwrap(),
            "notes/alpha.md"
        );
    }

    #[test]
    fn alias_table_round_trips_canonical_paths() {
        assert_eq!(
            document_target_aliases(MEMORY_DOCUMENT_PATH),
            &[MEMORY_DOCUMENT_TARGET]
        );
        assert_eq!(
            document_target_aliases(HEARTBEAT_DOCUMENT_PATH),
            &[HEARTBEAT_DOCUMENT_TARGET]
        );
        assert_eq!(
            document_target_aliases(BOOTSTRAP_DOCUMENT_PATH),
            &[BOOTSTRAP_DOCUMENT_TARGET]
        );
        assert!(document_target_aliases("notes/a.md").is_empty());
        assert!(document_target_aliases(MEMORY_DOCUMENT_TARGET).is_empty());
    }

    #[test]
    fn same_document_target_tolerates_legacy_aliases() {
        assert!(same_document_target("MEMORY.md", "MEMORY.md"));
        assert!(same_document_target("memory", "MEMORY.md"));
        assert!(!same_document_target("HEARTBEAT.md", "MEMORY.md"));
        assert!(!same_document_target("daily_log", "daily/2026-08-11.md"));
        assert!(!same_document_target("MEMORY.md", "memory"));
    }
}
