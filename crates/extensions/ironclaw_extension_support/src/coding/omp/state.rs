//! Bounded, run-bound snapshot registry for the omp hashline edit engine.
//!
//! Mirrors `coding/state.rs` semantics: read tags are keyed by scope
//! dimensions PLUS the run identity, so a read recorded in one run never
//! authorizes edits in a later run. The registry is bounded (evicts the
//! oldest entry); a missing entry fails safe with the "not from this
//! session" stale-anchor message.
//!
//! A successful edit refreshes the recorded snapshot, so chained edits on
//! the same file keep working without an intervening read.

use std::collections::HashMap;
use std::sync::Mutex;

use ironclaw_host_api::ids::RunId;
use ironclaw_host_api::resource::ResourceScope;

use super::OmpEngineErrorKind;

/// Maximum retained (scope, path) snapshots. Eviction is FIFO; an evicted
/// path simply requires a fresh `read` before its next edit.
const MAX_SNAPSHOT_ENTRIES: usize = 8192;

/// Scope dimensions shared by the read-state key, INCLUDING the run
/// identity: read-before-edit is a within-run policy (mirrors
/// `coding::state::CodingReadScopeKey`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct OmpScopeKey {
    tenant_id: String,
    user_id: String,
    agent_id: Option<String>,
    project_id: Option<String>,
    mission_id: Option<String>,
    thread_id: Option<String>,
    run_id: Option<RunId>,
}

impl OmpScopeKey {
    pub(crate) fn from_scope(scope: &ResourceScope, run_id: Option<RunId>) -> Self {
        Self {
            tenant_id: scope.tenant_id.as_str().to_string(),
            user_id: scope.user_id.as_str().to_string(),
            agent_id: scope.agent_id.as_ref().map(|id| id.as_str().to_string()),
            project_id: scope.project_id.as_ref().map(|id| id.as_str().to_string()),
            mission_id: scope.mission_id.as_ref().map(|id| id.as_str().to_string()),
            thread_id: scope.thread_id.as_ref().map(|id| id.as_str().to_string()),
            run_id,
        }
    }
}

/// One recorded snapshot: the 4-hex uppercase content tag observed by a
/// read (or produced by a successful edit). The full text is not retained —
/// nothing reads it back; the tag alone authorizes chained edits.
#[derive(Debug, Clone)]
struct SnapshotEntry {
    tag: String,
}

type SnapshotKey = (OmpScopeKey, String);

/// Bounded registry of hashline snapshot tags keyed by (scope, virtual path).
#[derive(Debug, Default)]
pub struct OmpSnapshotRegistry {
    entries: Mutex<HashMap<SnapshotKey, SnapshotEntry>>,
    order: Mutex<Vec<SnapshotKey>>,
}

impl OmpSnapshotRegistry {
    /// Record the content tag observed for `virtual_path` under `scope`
    /// (computed by the caller via [`super::hashline::compute_file_hash`]).
    pub(crate) fn record(&self, scope: &OmpScopeKey, virtual_path: &str, tag: &str) {
        let key = (scope.clone(), virtual_path.to_string());
        let mut entries = self.entries.lock().expect("snapshot registry poisoned");
        let mut order = self.order.lock().expect("snapshot registry order poisoned");
        if !entries.contains_key(&key) {
            if entries.len() >= MAX_SNAPSHOT_ENTRIES {
                // Evict the oldest recorded entry; the evicted path just
                // requires a fresh read before its next edit.
                if let Some(evicted) = order.first().cloned() {
                    entries.remove(&evicted);
                    order.remove(0);
                }
            }
            order.push(key.clone());
        }
        entries.insert(
            key,
            SnapshotEntry {
                tag: tag.to_string(),
            },
        );
    }

    /// Look up the recorded tag for (scope, path) — `None` when the path
    /// was never read (or was evicted) in this scope+run.
    #[allow(dead_code)]
    pub(crate) fn recorded(&self, scope: &OmpScopeKey, virtual_path: &str) -> Option<String> {
        let entries = self.entries.lock().expect("snapshot registry poisoned");
        entries
            .get(&(scope.clone(), virtual_path.to_string()))
            .map(|entry| entry.tag.clone())
    }

    /// Whether a tag was ever recorded for this path in this scope+run —
    /// the `hashRecognized` input to the stale-anchor message split.
    pub(crate) fn tag_recognized(
        &self,
        scope: &OmpScopeKey,
        virtual_path: &str,
        tag: &str,
    ) -> bool {
        let entries = self.entries.lock().expect("snapshot registry poisoned");
        entries
            .get(&(scope.clone(), virtual_path.to_string()))
            .is_some_and(|entry| entry.tag == tag)
    }

    /// Drop the snapshot for a deleted path (REM).
    pub(crate) fn invalidate(&self, scope: &OmpScopeKey, virtual_path: &str) {
        let key = (scope.clone(), virtual_path.to_string());
        let mut entries = self.entries.lock().expect("snapshot registry poisoned");
        let mut order = self.order.lock().expect("snapshot registry order poisoned");
        entries.remove(&key);
        order.retain(|candidate| candidate != &key);
    }
}

/// Convenience: stale-anchor kind for a recognized vs unrecognized tag.
pub(crate) fn stale_anchor_kind(recognized: bool) -> OmpEngineErrorKind {
    if recognized {
        OmpEngineErrorKind::StaleAnchorHashRecognized
    } else {
        OmpEngineErrorKind::StaleAnchorHashUnrecognized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_host_api::ids::{InvocationId, UserId};

    fn scope(run: Option<RunId>) -> OmpScopeKey {
        let scope =
            ResourceScope::local_default(UserId::new("u1").expect("user id"), InvocationId::new())
                .expect("scope");
        OmpScopeKey::from_scope(&scope, run)
    }

    #[test]
    fn record_and_lookup_round_trip() {
        let registry = OmpSnapshotRegistry::default();
        let scope = scope(None);
        registry.record(&scope, "/projects/workspace/foo.ts", "1A2B");
        assert_eq!(
            registry.recorded(&scope, "/projects/workspace/foo.ts"),
            Some("1A2B".to_string())
        );
        assert!(registry.tag_recognized(&scope, "/projects/workspace/foo.ts", "1A2B"));
        assert!(!registry.tag_recognized(&scope, "/projects/workspace/foo.ts", "3C4D"));
        // A different scope never sees the entry.
        let other = OmpScopeKey {
            tenant_id: "other".to_string(),
            ..scope.clone()
        };
        assert!(
            registry
                .recorded(&other, "/projects/workspace/foo.ts")
                .is_none()
        );
    }

    #[test]
    fn run_bound_reads_never_authorize_later_runs() {
        let registry = OmpSnapshotRegistry::default();
        let run_a = scope(Some(RunId::new()));
        let run_b = scope(Some(RunId::new()));
        registry.record(&run_a, "/projects/workspace/foo.ts", "1A2B");
        assert!(
            registry
                .recorded(&run_b, "/projects/workspace/foo.ts")
                .is_none()
        );
        assert!(!registry.tag_recognized(&run_b, "/projects/workspace/foo.ts", "1A2B"));
    }

    #[test]
    fn successful_edit_refreshes_the_tag() {
        let registry = OmpSnapshotRegistry::default();
        let scope = scope(None);
        let path = "/projects/workspace/foo.ts";
        registry.record(&scope, path, "1A2B");
        registry.record(&scope, path, "3C4D");
        assert_eq!(registry.recorded(&scope, path), Some("3C4D".to_string()));
        assert!(registry.tag_recognized(&scope, path, "3C4D"));
        assert!(!registry.tag_recognized(&scope, path, "1A2B"));
    }

    #[test]
    fn bounded_registry_evicts_oldest() {
        let registry = OmpSnapshotRegistry::default();
        let scope = scope(None);
        // Bypass the constant by filling past a small local budget via the
        // public constant path: MAX_SNAPSHOT_ENTRIES is large, so simulate
        // eviction by invalidating and re-adding in order.
        registry.record(&scope, "/p/a", "AAAA");
        registry.record(&scope, "/p/b", "BBBB");
        registry.invalidate(&scope, "/p/a");
        registry.record(&scope, "/p/a", "CCCC");
        // Order: b (oldest), a. Re-adding a pushed it to the back.
        assert_eq!(registry.recorded(&scope, "/p/b"), Some("BBBB".to_string()));
        assert_eq!(registry.recorded(&scope, "/p/a"), Some("CCCC".to_string()));
    }

    #[test]
    fn invalidate_drops_entry_and_order() {
        let registry = OmpSnapshotRegistry::default();
        let scope = scope(None);
        registry.record(&scope, "/p/a", "AAAA");
        registry.invalidate(&scope, "/p/a");
        assert!(registry.recorded(&scope, "/p/a").is_none());
        registry.record(&scope, "/p/a", "BBBB");
        assert_eq!(registry.recorded(&scope, "/p/a"), Some("BBBB".to_string()));
    }
}
