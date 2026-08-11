//! Pinned omp-parity coding engines (issue #7392).
//!
//! These engines implement the model-visible contract of the five omp core
//! coding tools (`read`, `write`, `edit`, `glob`, `grep`) at upstream commit
//! `08819b279cf02ae2545e69dad7111ab48d91d35e` of `can1357/oh-my-pi`, backed by
//! [`RootFilesystem`] and the host's scoped artifact reader. The always-on
//! first-party package wires them through normal production dispatch. Contract
//! tests compare them with the pinned snapshot under
//! `tests/fixtures/omp_coding_contract/`.
//!
//! Exact strings (selector errors, stale-anchor messages, output formats,
//! success shapes) are copied verbatim from the pinned upstream sources;
//! never approximate them.
//!
//! Scope notes: `artifact://` reads are implemented. Archives, SQLite,
//! documents, URLs, SSH, ast_grep/ast_edit, networked tools, and the
//! multi-backend conformance suite remain later issue #7392 slices.

use std::sync::Arc;

use ironclaw_filesystem::RootFilesystem;
use ironclaw_host_api::{ids::RunId, mount::MountView, resource::ResourceScope};
use serde_json::{Value, json};

mod glob;
mod grep;
mod hashline;
/// Public surface for the pinned registration assets (issue #7392 slice 3):
/// the model-visible descriptions and input schemas, embedded in this crate
/// and exposed so downstream crates resolve them without cross-crate
/// `include_str!` reach-ins.
pub mod omp_assets;
mod read;
mod selector;
mod state;
mod write;

pub use state::OmpSnapshotRegistry;

/// Stable classification of an omp engine failure. The rendered message
/// ([`OmpEngineError::message`]) is the model-visible contract and is always
/// the exact pinned omp text; the kind is a stable tag for tests and
/// callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OmpEngineErrorKind {
    /// Input did not satisfy the pinned wire schema (required field/type).
    Input,
    /// `read`/`glob`/`grep` path did not exist.
    PathNotFound,
    /// `read` selector could not be parsed (invalid selector text).
    InvalidSelector,
    /// Multi-range selector on a directory listing.
    MultiRangeDirectory,
    /// `glob` refused the filesystem root (`/`).
    RootNotAllowed,
    /// `glob` path list contained no non-empty entry.
    EmptyPath,
    /// `grep` pattern failed to compile.
    InvalidRegex,
    /// `grep` pattern was blank.
    PatternEmpty,
    /// `grep` skip was negative or non-finite.
    SkipNegative,
    /// `grep` line-range selector applied to a glob (not a single file).
    LineRangeSelectorRequiresSingleFile,
    /// `grep` line-range selector path did not exist.
    LineRangePathNotFound,
    /// `grep` line-range selector named a directory.
    LineRangeTargetIsDirectory,
    /// `grep` multi-path input: every entry missing.
    PathNotFoundMulti,
    /// `write` target looked URI-like but was not a known scheme.
    UnknownUriLikeTarget,
    /// `edit`: the section tag was recorded this run but the live file no
    /// longer hashes to it (stale anchor, hash recognized).
    StaleAnchorHashRecognized,
    /// `edit`: the section tag was never recorded for this scope+run (not
    /// from this session).
    StaleAnchorHashUnrecognized,
    /// `edit`: a line reference was malformed.
    MalformedLineReference,
    /// `edit`: an anchor referenced a line past EOF.
    LineOutOfBounds,
    /// `edit`: an absolute range endpoint was invalid.
    InvalidAbsoluteRange,
    /// `edit`: parse/apply failure with a pinned hashline message.
    HashlineApply,
    /// `edit`: multi-section aggregate failure.
    MultiEntryAggregate,
    /// Path did not resolve inside an authorized mount (IronClaw-specific;
    /// the pinned omp tools run on the process filesystem and have no
    /// counterpart).
    PathResolution,
    /// The backing filesystem reported an error.
    Filesystem,
    /// Filesystem metadata or mount permissions denied access.
    FilesystemDenied,
    /// A bounded traversal or materialization limit was exceeded.
    ResourceLimit,
    /// Internal invariant violated (defensive; not a model-visible shape).
    Internal,
}

/// Failure of one omp-compatible engine call. `message` is the exact
/// rendered omp error text (pinned sources/fixtures); `kind` is a stable
/// classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmpEngineError {
    kind: OmpEngineErrorKind,
    message: String,
}

impl OmpEngineError {
    pub(crate) fn new(kind: OmpEngineErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> OmpEngineErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for OmpEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OmpEngineError {}

/// Shared engine context: the backing filesystem, the mount view that
/// authorizes scoped paths, the caller scope (mirrors `coding/state.rs`
/// scope dimensions), the loop run identity, and the bounded snapshot
/// registry that binds hashline edit tags to reads from the SAME run.
#[derive(Clone)]
pub struct OmpEngineContext {
    pub filesystem: Arc<dyn RootFilesystem>,
    pub artifact_reader: Option<Arc<dyn ironclaw_host_api::artifact::ScopedArtifactReader>>,
    pub mounts: MountView,
    pub scope: ResourceScope,
    pub run_id: Option<RunId>,
    pub snapshots: Arc<OmpSnapshotRegistry>,
}

/// A resolved engine target: the canonical virtual path on the backend and
/// the granting mount.
pub(crate) struct OmpResolvedPath {
    pub(crate) virtual_path: ironclaw_host_api::path::VirtualPath,
    pub(crate) grant: ironclaw_host_api::mount::MountGrant,
}

impl OmpResolvedPath {
    /// Whether this resolution IS its grant's mount root (mirrors
    /// `coding/types.rs::ResolvedPath::is_mount_root`): a mount root the
    /// caller is authorized for exists by definition, so reads of the root
    /// itself behave as an empty directory rather than `NotFound`.
    pub(crate) fn is_mount_root(&self) -> bool {
        self.virtual_path.as_str() == self.grant.target.as_str()
    }
}

/// The five omp engine entry points. Each returns the exact model-visible
/// omp output as JSON (`{"output": "<text>"}`) or the exact pinned error
/// text in [`OmpEngineError`].
pub async fn read(ctx: &OmpEngineContext, input: Value) -> Result<Value, OmpEngineError> {
    let output = read::read(ctx, input).await?;
    Ok(json!({ "output": output }))
}

pub async fn write(ctx: &OmpEngineContext, input: Value) -> Result<Value, OmpEngineError> {
    let output = write::write(ctx, input).await?;
    Ok(json!({ "output": output }))
}

pub async fn edit(ctx: &OmpEngineContext, input: Value) -> Result<Value, OmpEngineError> {
    let output = hashline::edit(ctx, input).await?;
    Ok(json!({ "output": output }))
}

pub async fn glob(ctx: &OmpEngineContext, input: Value) -> Result<Value, OmpEngineError> {
    let output = glob::glob(ctx, input).await?;
    Ok(json!({ "output": output }))
}

pub async fn grep(ctx: &OmpEngineContext, input: Value) -> Result<Value, OmpEngineError> {
    let output = grep::grep(ctx, input).await?;
    Ok(json!({ "output": output }))
}

/// Public test seam for the root harness bin (`tests/reborn_omp_coding_engines.rs`)
/// and the differential comparison factory: exposes the pinned selector
/// parser and error-template render functions without exposing engine
/// internals. Not part of any production surface.
#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub mod harness {
    use super::selector::{ParsedSelector, parse_sel, sel_to_offset_limit};
    use super::{OmpEngineErrorKind, hashline};
    use serde_json::{Value, json};

    /// Parse a read-tool selector and render the golden-shaped record
    /// `{"selector": …, "offset_limit": …}`, or return the exact pinned
    /// error text.
    pub fn parse_selector(sel: &str) -> Result<Value, String> {
        let parsed = parse_sel(Some(sel))?;
        let selector = match &parsed {
            ParsedSelector::None => json!({ "kind": "none" }),
            ParsedSelector::Raw => json!({ "kind": "raw" }),
            ParsedSelector::Conflicts => json!({ "kind": "conflicts" }),
            ParsedSelector::Lines { ranges, raw } => {
                let ranges: Vec<Value> = ranges
                    .iter()
                    .map(|range| {
                        let mut value = json!({ "startLine": range.start_line });
                        if let Some(end) = range.end_line {
                            value["endLine"] = json!(end);
                        }
                        value
                    })
                    .collect();
                let mut value = json!({ "kind": "lines", "ranges": ranges });
                if *raw {
                    value["raw"] = json!(true);
                }
                value
            }
        };
        let (offset, limit) = sel_to_offset_limit(&parsed);
        let offset_limit = match (offset, limit) {
            (Some(offset), Some(limit)) => json!({ "offset": offset, "limit": limit }),
            (Some(offset), None) => json!({ "offset": offset }),
            (None, _) => json!({}),
        };
        Ok(json!({ "selector": selector, "offset_limit": offset_limit }))
    }

    /// Render the stale-anchor rejection with the pinned recognized /
    /// not-from-session wording.
    pub fn render_stale_anchor(
        path: Option<&str>,
        expected: &str,
        actual: &str,
        file_lines: &[String],
        anchor_lines: &[u64],
        recognized: bool,
    ) -> String {
        hashline::render_mismatch_message(
            path,
            expected,
            actual,
            file_lines,
            anchor_lines,
            recognized,
        )
    }

    pub fn render_malformed_line_reference(raw: &str) -> String {
        hashline::malformed_line_reference(raw)
    }

    pub fn render_line_out_of_bounds(line: u64, line_count: usize) -> String {
        hashline::line_out_of_bounds(line, line_count)
    }

    /// Render the source-faithful invalid-absolute-range message (the
    /// fixture template pins the leading sentence; the engine extends it
    /// with the counted-range retry sentence, matching the pinned source).
    pub fn render_invalid_absolute_range(patch_line: u64, start: u64, end: u64) -> String {
        hashline::invalid_absolute_range_message(
            patch_line,
            start,
            end,
            hashline::AbsoluteRangeOp::Replace,
            None,
            None,
        )
    }

    pub fn render_per_file_failure(path: &str, error_text: &str) -> String {
        hashline::render_per_file_failure_aggregate(path, error_text)
    }

    pub fn render_files_not_applied(skipped_paths: &str) -> String {
        hashline::render_files_not_applied(skipped_paths)
    }

    pub fn render_auto_piped_warning() -> String {
        hashline::BARE_BODY_AUTO_PIPED_WARNING.to_string()
    }

    /// Compute the pinned hashline snapshot tag for `text` (xxHash32 low 16
    /// bits rendered as 4 uppercase hex digits, after the pinned
    /// normalization). The registration-seam integration test authors an
    /// `edit` payload with the tag of its seeded file BEFORE the scripted
    /// `read` result arrives, so it needs the same deterministic tag the
    /// engine will advertise.
    pub fn compute_file_hash(text: &str) -> String {
        hashline::format::compute_file_hash(text)
    }

    pub fn render_unknown_uri_like_target(trimmed: &str, suggestion: &str) -> String {
        super::write::render_unknown_uri_like_target(trimmed, suggestion)
    }

    /// Stable kind name for a rendered error (harness assertions).
    pub fn kind_name(kind: OmpEngineErrorKind) -> &'static str {
        match kind {
            OmpEngineErrorKind::Input => "Input",
            OmpEngineErrorKind::PathNotFound => "PathNotFound",
            OmpEngineErrorKind::InvalidSelector => "InvalidSelector",
            OmpEngineErrorKind::MultiRangeDirectory => "MultiRangeDirectory",
            OmpEngineErrorKind::RootNotAllowed => "RootNotAllowed",
            OmpEngineErrorKind::EmptyPath => "EmptyPath",
            OmpEngineErrorKind::InvalidRegex => "InvalidRegex",
            OmpEngineErrorKind::PatternEmpty => "PatternEmpty",
            OmpEngineErrorKind::SkipNegative => "SkipNegative",
            OmpEngineErrorKind::LineRangeSelectorRequiresSingleFile => {
                "LineRangeSelectorRequiresSingleFile"
            }
            OmpEngineErrorKind::LineRangePathNotFound => "LineRangePathNotFound",
            OmpEngineErrorKind::LineRangeTargetIsDirectory => "LineRangeTargetIsDirectory",
            OmpEngineErrorKind::PathNotFoundMulti => "PathNotFoundMulti",
            OmpEngineErrorKind::UnknownUriLikeTarget => "UnknownUriLikeTarget",
            OmpEngineErrorKind::StaleAnchorHashRecognized => "StaleAnchorHashRecognized",
            OmpEngineErrorKind::StaleAnchorHashUnrecognized => "StaleAnchorHashUnrecognized",
            OmpEngineErrorKind::MalformedLineReference => "MalformedLineReference",
            OmpEngineErrorKind::LineOutOfBounds => "LineOutOfBounds",
            OmpEngineErrorKind::InvalidAbsoluteRange => "InvalidAbsoluteRange",
            OmpEngineErrorKind::HashlineApply => "HashlineApply",
            OmpEngineErrorKind::MultiEntryAggregate => "MultiEntryAggregate",
            OmpEngineErrorKind::PathResolution => "PathResolution",
            OmpEngineErrorKind::Filesystem => "Filesystem",
            OmpEngineErrorKind::FilesystemDenied => "FilesystemDenied",
            OmpEngineErrorKind::ResourceLimit => "ResourceLimit",
            OmpEngineErrorKind::Internal => "Internal",
        }
    }
}

pub(crate) fn omp_error(kind: OmpEngineErrorKind, message: impl Into<String>) -> OmpEngineError {
    OmpEngineError::new(kind, message)
}

pub(crate) fn input_error(message: impl Into<String>) -> OmpEngineError {
    OmpEngineError::new(OmpEngineErrorKind::Input, message)
}

pub(crate) fn filesystem_denied() -> OmpEngineError {
    OmpEngineError::new(
        OmpEngineErrorKind::FilesystemDenied,
        "workspace file access denied",
    )
}

pub(crate) fn read_limit_exceeded() -> OmpEngineError {
    OmpEngineError::new(
        OmpEngineErrorKind::ResourceLimit,
        "workspace file exceeds the read limit",
    )
}

// ─── Path resolution ─────────────────────────────────────────────────────────
//
// Mirrors the sequence in `coding/paths.rs::resolve_path` (scoped-path
// normalization → mount resolution → sensitivity checks → permission gate),
// reusing its primitives where they are `pub(super)`-visible, but rendering
// failures as `OmpEngineError` instead of the dispatch-oriented
// `CodingCapabilityError`. The pinned omp tools resolve against the process
// cwd; the IronClaw equivalent root is the workspace mount root
// (`DEFAULT_SCOPED_ROOT` alias).

const DEFAULT_SCOPED_ROOT: &str = "/workspace";

fn scoped_path_input(path: &str) -> String {
    if path == "." || path.is_empty() {
        DEFAULT_SCOPED_ROOT.to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else if let Some(scoped_workspace_path) = workspace_scoped_alias(path) {
        scoped_workspace_path
    } else {
        let relative = path.trim_start_matches("./");
        format!("{DEFAULT_SCOPED_ROOT}/{relative}")
    }
}

fn workspace_scoped_alias(path: &str) -> Option<String> {
    let path = strip_leading_current_dir_segments(path);
    if path == "workspace" {
        return Some(DEFAULT_SCOPED_ROOT.to_string());
    }
    path.strip_prefix("workspace/")
        .map(|relative| relative.trim_start_matches('/'))
        .map(|relative| {
            if relative.is_empty() {
                DEFAULT_SCOPED_ROOT.to_string()
            } else {
                format!("{DEFAULT_SCOPED_ROOT}/{relative}")
            }
        })
}

fn strip_leading_current_dir_segments(mut path: &str) -> &str {
    while let Some(stripped) = path.strip_prefix("./") {
        path = stripped;
    }
    path
}

/// Resolve a caller-supplied path through the mount view, enforcing the same
/// sensitivity and permission gates as the production coding dispatch.
pub(crate) fn resolve_input_path(
    ctx: &OmpEngineContext,
    path: &str,
    operation: ironclaw_filesystem::FilesystemOperation,
) -> Result<OmpResolvedPath, OmpEngineError> {
    use ironclaw_safety::sensitive_paths::is_sensitive_path_str;

    let scoped_path = ctx
        .mounts
        .scoped_path(scoped_path_input(path))
        .map_err(|error| {
            tracing::debug!(%error, "omp scoped path resolution failed");
            omp_error(
                OmpEngineErrorKind::PathResolution,
                format!("{path} is not under an available scoped root"),
            )
        })?;
    if is_sensitive_path_str(scoped_path.as_str()) {
        return Err(omp_error(
            OmpEngineErrorKind::PathResolution,
            format!("{path} resolves to a sensitive path"),
        ));
    }
    let (virtual_path, grant) = ctx
        .mounts
        .resolve_with_grant(&scoped_path)
        .map_err(|error| {
            tracing::debug!(%error, "omp mount resolution failed");
            omp_error(
                OmpEngineErrorKind::PathResolution,
                format!("{path} does not resolve inside an available scoped root"),
            )
        })?;
    if is_sensitive_path_str(virtual_path.as_str()) {
        return Err(omp_error(
            OmpEngineErrorKind::PathResolution,
            format!("{path} resolves to a sensitive path"),
        ));
    }
    if !super::paths::operation_allowed(&grant.permissions, operation) {
        return Err(omp_error(
            OmpEngineErrorKind::PathResolution,
            format!("the mount for {path} does not permit this operation"),
        ));
    }
    Ok(OmpResolvedPath {
        virtual_path,
        grant: grant.clone(),
    })
}

/// Display path of `candidate` relative to the workspace mount root, matching
/// omp's `formatPathRelativeToCwd` shape (`.` for the root itself).
pub(crate) fn display_path(
    root: &ironclaw_host_api::path::VirtualPath,
    candidate: &ironclaw_host_api::path::VirtualPath,
) -> String {
    let target = root.as_str().trim_end_matches('/');
    let raw = candidate.as_str();
    if raw == target {
        return ".".to_string();
    }
    raw.strip_prefix(&format!("{target}/"))
        .unwrap_or(raw)
        .to_string()
}

/// The virtual mount root the workspace alias resolves to, when the mount
/// view authorizes it. Engines render display paths relative to this root;
/// callers propagate `None` as a path-resolution failure.
pub(crate) fn workspace_virtual_root(
    ctx: &OmpEngineContext,
) -> Option<ironclaw_host_api::path::VirtualPath> {
    let scoped = match ctx.mounts.scoped_path(DEFAULT_SCOPED_ROOT) {
        Ok(scoped) => scoped,
        Err(error) => {
            tracing::debug!(%error, "omp workspace mount root scoped-path lookup failed");
            return None;
        }
    };
    match ctx.mounts.resolve_with_grant(&scoped) {
        Ok((virtual_path, _)) => Some(virtual_path),
        Err(error) => {
            tracing::debug!(%error, "omp workspace mount root resolution failed");
            None
        }
    }
}
