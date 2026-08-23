//! Vocabulary for required file deliverables — the files a run's own request
//! asked it to produce.
//!
//! A recurring benchmark failure class is a run that does the whole job in chat
//! and never writes the file it was asked for: the judge scores the reasoning
//! highly while `report_created` stays 0.
//!
//! This module owns only the TYPES and the port. Deciding which paths a request
//! requires is behavior and lives with its caller
//! (`ironclaw_turn_runner::deliverable_extraction`).

use std::future::Future;
use std::pin::Pin;

use ironclaw_host_api::resource::ResourceScope;

/// Canonical workspace mount alias (`ironclaw_attachments::WORKSPACE_ALIAS`),
/// the only prefix a deliverable may live under. Repeated rather than imported
/// so this contract crate keeps its dependency set; pinned by a test below.
pub const WORKSPACE_PREFIX: &str = "/workspace/";

/// Length bound on one deliverable path.
const MAX_PATH_BYTES: usize = 512;

/// One validated absolute workspace path the run is required to produce.
///
/// The validation is the type's whole point: a reminder is only honest if the
/// requirement is a fact, so nothing that is merely path-SHAPED gets to become
/// one. Directories, traversals and non-workspace paths are rejected here
/// rather than by each caller.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeliverablePath(String);

impl DeliverablePath {
    /// Accept a path only if it is unambiguously a workspace FILE path.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.len() > MAX_PATH_BYTES {
            return Err("deliverable path exceeds the length bound".to_string());
        }
        let Some(relative) = value.strip_prefix(WORKSPACE_PREFIX) else {
            return Err(format!(
                "deliverable path must start with {WORKSPACE_PREFIX}"
            ));
        };
        if relative.is_empty() || value.ends_with('/') {
            return Err("deliverable path must name a file, not a directory".to_string());
        }
        if value.contains("//") {
            return Err("deliverable path contains an empty segment".to_string());
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
        {
            return Err("deliverable path contains unsupported characters".to_string());
        }
        if relative.split('/').any(|segment| segment == "..") {
            return Err("deliverable path may not traverse upward".to_string());
        }
        // A file, not a directory: the last segment carries an extension, and a
        // leading dot is a dotfile rather than an extension.
        let last = relative.rsplit('/').next().unwrap_or_default();
        let has_extension = last
            .rsplit_once('.')
            .is_some_and(|(stem, extension)| !stem.is_empty() && !extension.is_empty());
        if !has_extension {
            return Err("deliverable path must name a file with an extension".to_string());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The file deliverables one run is required to produce. Empty is the common
/// case and means the deliverable reminder is dormant for that run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliverableSpec {
    paths: Vec<DeliverablePath>,
}

impl DeliverableSpec {
    pub fn new(paths: Vec<DeliverablePath>) -> Self {
        Self { paths }
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn paths(&self) -> &[DeliverablePath] {
        &self.paths
    }
}

/// Host-side existence check for a run's deliverables.
///
/// Returns only the paths CONFIRMED absent. A stat that fails for any other
/// reason (backend error, unresolvable mount) means "cannot tell", and the
/// caller must not claim a file is missing on that basis — an unnecessary
/// reminder is far worse than a skipped one.
pub trait LoopDeliverableProbe: Send + Sync {
    fn missing<'a>(
        &'a self,
        scope: &'a ResourceScope,
        paths: &'a [DeliverablePath],
    ) -> Pin<Box<dyn Future<Output = Vec<DeliverablePath>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_prefix_matches_the_canonical_mount_alias() {
        // `ironclaw_attachments::WORKSPACE_ALIAS` is the owner; this crate
        // cannot depend on it, so the value is pinned here instead.
        assert_eq!(WORKSPACE_PREFIX, "/workspace/");
    }

    #[test]
    fn only_workspace_file_paths_are_accepted() {
        for rejected in [
            "/etc/passwd",
            "/Users/someone/report.md",
            "report.md",
            "/workspace/",
            "/workspace/subdir/",
            "/workspace/notes",
            "/workspace/../etc/passwd",
            "/workspace//report.md",
            "/workspace/.hidden",
        ] {
            assert!(
                DeliverablePath::new(rejected).is_err(),
                "{rejected:?} must not validate as a deliverable"
            );
        }
        for accepted in [
            "/workspace/report.md",
            "/workspace/out/data-1.csv",
            "/workspace/a_b.tar.gz",
        ] {
            assert!(
                DeliverablePath::new(accepted).is_ok(),
                "{accepted:?} must validate as a deliverable"
            );
        }
    }

    #[test]
    fn an_empty_spec_is_dormant() {
        assert!(DeliverableSpec::default().is_empty());
        assert!(DeliverableSpec::new(Vec::new()).is_empty());
    }
}
