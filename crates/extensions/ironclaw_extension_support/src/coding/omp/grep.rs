//! `grep` engine, ported from the pinned
//! `packages/coding-agent/src/tools/grep.ts`, `path-utils.ts`
//! (parseSearchPath / splitPathAndSel), and `match-line-format.ts` at commit
//! `08819b279cf02ae2545e69dad7111ab48d91d35e`.
//!
//! `pattern` (required), semicolon-delimited `path` (default workspace
//! root), `skip` pagination, `case`, single-file line-range selectors
//! (`<file>:N-M`), hashline-mode match rows (`*N:line`) and context rows
//! (` N:line`), per-file caps, and the exact pinned error texts. Archives
//! and internal URLs are later slices.
//!
//! Documented deviations: regexes compile with the Rust `regex` crate, so
//! `Invalid regex: ${message}` renders the Rust parser's message (the
//! template itself is pinned); the native `gitignore` walk is a no-op on
//! virtual backends (no `.gitignore` rules exist there); the delimited-path
//! expansion beyond semicolons is not ported.

use std::path::Path as FsPath;

use ironclaw_filesystem::{FileType, FilesystemError, FilesystemOperation};
use serde_json::Value;

use super::hashline::format::format_hashline_header;
use super::selector::{LineRange, parse_line_ranges};
use super::state::OmpScopeKey;
use super::{
    OmpEngineContext, OmpEngineError, OmpEngineErrorKind, display_path, input_error, omp_error,
    resolve_input_path, workspace_virtual_root,
};

const DEFAULT_FILE_LIMIT: usize = 20;
const MULTI_FILE_PER_FILE_MATCHES: usize = 20;
const SINGLE_FILE_MATCHES: usize = 200;
/// `grep.contextBefore` / `grep.contextAfter` defaults (settings-schema.ts).
const CONTEXT_BEFORE: usize = 1;
const CONTEXT_AFTER: usize = 3;

struct PathSpec {
    original: String,
    clean: String,
    ranges: Option<Vec<LineRange>>,
}

struct FileHits {
    display_path: String,
    virtual_path: ironclaw_host_api::path::VirtualPath,
    lines: Vec<(u64, String, bool)>, // (line number, text, is_match)
}

pub(crate) async fn grep(ctx: &OmpEngineContext, input: Value) -> Result<String, OmpEngineError> {
    let Some(pattern) = input.get("pattern").and_then(Value::as_str) else {
        return Err(input_error("grep requires a string `pattern`"));
    };
    let raw_path = input.get("path").and_then(Value::as_str);
    let skip = input.get("skip");
    let case_sensitive = input.get("case").and_then(Value::as_bool);

    if pattern.trim().is_empty() {
        return Err(omp_error(
            OmpEngineErrorKind::PatternEmpty,
            "Pattern must not be empty",
        ));
    }
    let normalized_skip = match skip {
        None | Some(Value::Null) => 0usize,
        Some(Value::Number(number)) => {
            let value = number.as_f64().unwrap_or(f64::NAN);
            if !value.is_finite() || value < 0.0 {
                return Err(omp_error(
                    OmpEngineErrorKind::SkipNegative,
                    "Skip must be a non-negative number",
                ));
            }
            value.floor() as usize
        }
        Some(_) => {
            return Err(omp_error(
                OmpEngineErrorKind::SkipNegative,
                "Skip must be a non-negative number",
            ));
        }
    };

    let compiled = regex::RegexBuilder::new(pattern)
        .case_insensitive(!case_sensitive.unwrap_or(true))
        .build()
        .map_err(|error| {
            omp_error(
                OmpEngineErrorKind::InvalidRegex,
                format!("Invalid regex: {error}"),
            )
        })?;

    let scoped_paths = to_path_list(raw_path);
    let effective_paths: Vec<String> = if scoped_paths.is_empty() {
        vec![".".to_string()]
    } else {
        scoped_paths
    };

    let workspace_root = workspace_virtual_root(ctx).ok_or_else(|| {
        omp_error(
            OmpEngineErrorKind::PathResolution,
            "no workspace mount root".to_string(),
        )
    })?;

    // Parse each entry: peel `:N-M` selectors, prefer literal filesystem
    // matches.
    let mut specs: Vec<PathSpec> = Vec::new();
    for entry in &effective_paths {
        let (path_part, sel) = split_path_and_sel(entry);
        let mut clean = path_part.to_string();
        let mut ranges: Option<Vec<LineRange>> = None;
        if let Some(sel) = sel {
            if literal_exists(ctx, entry).await? {
                clean = entry.clone();
            } else {
                let parsed = match parse_line_ranges(sel) {
                    Ok(Some(ranges)) => ranges,
                    Ok(None) => {
                        return Err(omp_error(
                            OmpEngineErrorKind::LineRangeSelectorRequiresSingleFile,
                            format!(
                                "path entry \"{entry}\" — only line-range selectors like \":50-100\" are supported (no \":raw\"/\":conflicts\")"
                            ),
                        ));
                    }
                    Err(message) => {
                        return Err(omp_error(OmpEngineErrorKind::InvalidSelector, message));
                    }
                };
                if has_glob_path_chars(path_part) {
                    return Err(omp_error(
                        OmpEngineErrorKind::LineRangeSelectorRequiresSingleFile,
                        format!("Line-range selector requires a single file, not a glob: {entry}"),
                    ));
                }
                clean = path_part.to_string();
                ranges = Some(parsed);
            }
        }
        specs.push(PathSpec {
            original: entry.clone(),
            clean,
            ranges,
        });
    }

    // Line-range selector targets must be single existing FILES (pinned
    // grep: the per-spec range check runs before generic path-missing
    // handling, so `gone.rs:1-5` reports the line-range message).
    for spec in &specs {
        if spec.ranges.is_none() {
            continue;
        }
        let Ok(resolved) = resolve_input_path(ctx, &spec.clean, FilesystemOperation::ReadFile)
        else {
            return Err(omp_error(
                OmpEngineErrorKind::LineRangePathNotFound,
                format!("Path not found for line-range selector: {}", spec.original),
            ));
        };
        let stat = stat_optional_omp(ctx, &resolved.virtual_path).await?;
        let Some(stat) = stat else {
            return Err(omp_error(
                OmpEngineErrorKind::LineRangePathNotFound,
                format!("Path not found for line-range selector: {}", spec.original),
            ));
        };
        if stat.file_type != FileType::File {
            return Err(omp_error(
                OmpEngineErrorKind::LineRangeTargetIsDirectory,
                format!(
                    "Line-range selector requires a single file: {} is a directory",
                    spec.original
                ),
            ));
        }
    }

    // Resolve the scope: single entry vs multi-target.
    let mut missing_paths: Vec<String> = Vec::new();
    let mut resolved_targets: Vec<(String, Option<String>)> = Vec::new(); // (virtual path, glob)
    let mut is_directory = false;
    if specs.len() == 1 {
        let spec = &specs[0];
        let (base_path, glob_filter, has_glob) = parse_search_path(&spec.clean);
        let Ok(resolved) = resolve_input_path(ctx, &base_path, FilesystemOperation::ReadFile)
        else {
            return Err(omp_error(
                OmpEngineErrorKind::PathNotFound,
                format!("Path not found: {base_path}"),
            ));
        };
        let stat = stat_optional_omp(ctx, &resolved.virtual_path).await?;
        let Some(stat) = stat else {
            let scope_path = display_path(&workspace_root, &resolved.virtual_path);
            return Err(omp_error(
                OmpEngineErrorKind::PathNotFound,
                format!("Path not found: {scope_path}"),
            ));
        };
        is_directory = stat.file_type == FileType::Directory;
        if !is_directory && !has_glob {
            resolved_targets.push((resolved.virtual_path.as_str().to_string(), None));
        } else {
            resolved_targets.push((
                resolved.virtual_path.as_str().to_string(),
                Some(glob_filter.unwrap_or_else(|| "**/*".to_string())),
            ));
        }
    } else {
        let mut valid: Vec<&PathSpec> = Vec::new();
        for spec in &specs {
            let (base_path, _, _) = parse_search_path(&spec.clean);
            if let Ok(resolved) = resolve_input_path(ctx, &base_path, FilesystemOperation::ReadFile)
                && stat_optional_omp(ctx, &resolved.virtual_path)
                    .await?
                    .is_some()
            {
                valid.push(spec);
                continue;
            }
            missing_paths.push(spec.original.clone());
        }
        if missing_paths.len() == specs.len() {
            return Err(omp_error(
                OmpEngineErrorKind::PathNotFoundMulti,
                format!(
                    "Path not found: {}; list each target in the semicolon-delimited `path`",
                    missing_paths.join(", ")
                ),
            ));
        }
        for spec in valid {
            let (base_path, glob_filter, has_glob) = parse_search_path(&spec.clean);
            let resolved = resolve_input_path(ctx, &base_path, FilesystemOperation::ReadFile)?;
            let stat = stat_optional_omp(ctx, &resolved.virtual_path).await?;
            let is_file = stat
                .as_ref()
                .is_some_and(|stat| stat.file_type == FileType::File);
            if is_file && !has_glob {
                resolved_targets.push((resolved.virtual_path.as_str().to_string(), None));
            } else {
                resolved_targets.push((resolved.virtual_path.as_str().to_string(), glob_filter));
            }
        }
    }

    // Line-range selector targets are validated above (before scope
    // resolution) so missing paths surface the pinned line-range message.

    let is_multi_scope = resolved_targets.len() > 1 || is_directory;
    let per_file_match_cap = if is_multi_scope {
        MULTI_FILE_PER_FILE_MATCHES
    } else {
        SINGLE_FILE_MATCHES
    };

    // Collect hits per target file.
    let mut all_hits: Vec<FileHits> = Vec::new();
    for (target, glob_filter) in &resolved_targets {
        let virtual_path = ironclaw_host_api::path::VirtualPath::new(target.clone())
            .map_err(|error| omp_error(OmpEngineErrorKind::PathResolution, error.to_string()))?;
        let stat = stat_optional_omp(ctx, &virtual_path).await?;
        let Some(stat) = stat else {
            continue;
        };
        if stat.file_type == FileType::File {
            let hits = search_file(ctx, &virtual_path, &workspace_root, &compiled, &specs).await?;
            all_hits.push(hits);
        } else if stat.file_type == FileType::Directory {
            let hits = search_directory(
                ctx,
                &virtual_path,
                glob_filter.as_deref().unwrap_or("**/*"),
                &workspace_root,
                &compiled,
                &specs,
            )
            .await?;
            all_hits.extend(hits);
        }
    }
    all_hits.sort_by(|a, b| a.display_path.cmp(&b.display_path));

    // Per-file match caps.
    for hits in &mut all_hits {
        if hits.lines.len() > per_file_match_cap {
            hits.lines.truncate(per_file_match_cap);
        }
    }

    let total_files = all_hits.len();
    let can_paginate = is_multi_scope;
    let skip_files = if can_paginate {
        normalized_skip.min(total_files)
    } else {
        0
    };
    let selected: Vec<&FileHits> = if can_paginate {
        all_hits
            .iter()
            .skip(skip_files)
            .take(DEFAULT_FILE_LIMIT)
            .collect()
    } else {
        all_hits.iter().collect()
    };
    let file_limit_reached = can_paginate && total_files > skip_files + DEFAULT_FILE_LIMIT;
    let next_skip = skip_files + selected.len();
    let limit_message = if file_limit_reached {
        format!(
            "Showing files {}-{next_skip} of {total_files}. Use skip={next_skip} for the next page, or narrow paths/pattern.",
            skip_files + 1
        )
    } else {
        String::new()
    };

    let missing_paths_note = if missing_paths.is_empty() {
        None
    } else {
        Some(format!(
            "Skipped missing paths: {}",
            missing_paths.join(", ")
        ))
    };

    if selected.is_empty() {
        let skip_past_end =
            can_paginate && normalized_skip > 0 && total_files > 0 && skip_files >= total_files;
        let no_match_text = if skip_past_end {
            format!(
                "No more results ({total_files} files total; skip={normalized_skip} is past the end)"
            )
        } else {
            "No matches found".to_string()
        };
        return Ok(match missing_paths_note {
            Some(note) => format!("{no_match_text}\n{note}"),
            None => no_match_text,
        });
    }

    let is_grouped = is_directory || is_multi_scope;
    let mut output_lines: Vec<String> = Vec::new();
    if is_grouped {
        // formatGroupedFiles (pinned grouped-file-output.ts): prefix-folded
        // headers, one `#` per depth; a blank line precedes every directory
        // header and every root-level file header.
        let mut sections: Vec<(String, String, Vec<String>)> = Vec::new();
        for hits in &selected {
            let tag = if hits.lines.is_empty() {
                None
            } else {
                record_snapshot_tag(ctx, &hits.virtual_path).await
            };
            let header_suffix = tag.map(|tag| format!("#{tag}")).unwrap_or_default();
            sections.push((hits.display_path.clone(), header_suffix, render_hits(hits)));
        }
        let mut tree_root = GrepTree::new();
        for (path, suffix, body) in &sections {
            tree_root.insert(path, suffix.clone(), body.clone());
        }
        let mut emitted = false;
        tree_root.walk(&mut |kind, depth, name, body| {
            let hashes = "#".repeat(depth + 1);
            let needs_separator = emitted && (depth == 0 || kind == GrepEventKind::Dir);
            if needs_separator {
                output_lines.push(String::new());
            }
            emitted = true;
            match kind {
                GrepEventKind::Dir => {
                    output_lines.push(format!("{hashes} {name}/"));
                }
                GrepEventKind::File => {
                    output_lines.push(format!("{hashes} {name}"));
                    output_lines.extend(body.iter().cloned());
                }
            }
        });
    } else {
        for hits in &selected {
            if !output_lines.is_empty() {
                output_lines.push(String::new());
            }
            let tag = record_snapshot_tag(ctx, &hits.virtual_path).await;
            if let Some(tag) = tag {
                output_lines.push(format_hashline_header(&hits.display_path, &tag));
            }
            output_lines.extend(render_hits(hits));
        }
    }

    if !limit_message.is_empty() {
        output_lines.push(String::new());
        output_lines.push(limit_message);
    }
    if let Some(note) = missing_paths_note {
        output_lines.push(String::new());
        output_lines.push(note);
    }
    Ok(output_lines.join("\n"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrepEventKind {
    Dir,
    File,
}

/// Prefix-folded path tree used by `formatGroupedFiles` (mirrors
/// `buildPathTree`/`walkPathTree` in the pinned `path-tree.ts`).
struct GrepTree {
    files: Vec<(String, String, Vec<String>)>, // (name, header suffix, body)
    subdirs: Vec<(String, GrepTree)>,
}

impl GrepTree {
    fn new() -> Self {
        Self {
            files: Vec::new(),
            subdirs: Vec::new(),
        }
    }

    fn insert(&mut self, path: &str, suffix: String, body: Vec<String>) {
        let trimmed = path.trim_end_matches('/');
        let mut segments: Vec<&str> = trimmed.split('/').collect();
        let name = segments.pop().unwrap_or_default().to_string();
        let mut node = self;
        for segment in segments {
            let idx = node
                .subdirs
                .iter()
                .position(|(existing, _)| *existing == segment);
            if let Some(idx) = idx {
                node = &mut node.subdirs[idx].1;
            } else {
                node.subdirs.push((segment.to_string(), GrepTree::new()));
                node = &mut node.subdirs.last_mut().expect("just pushed").1;
            }
        }
        node.files.push((name, suffix, body));
    }

    fn walk(&self, emit: &mut impl FnMut(GrepEventKind, usize, String, &Vec<String>)) {
        self.walk_at(0, emit);
    }

    fn walk_at(
        &self,
        depth: usize,
        emit: &mut impl FnMut(GrepEventKind, usize, String, &Vec<String>),
    ) {
        for (name, suffix, body) in &self.files {
            let header_name = format!("{name}{suffix}");
            emit(GrepEventKind::File, depth, header_name, body);
        }
        for (dir_name, subtree) in &self.subdirs {
            let mut parts: Vec<String> = vec![dir_name.clone()];
            let mut dir_node = subtree;
            while dir_node.files.is_empty() && dir_node.subdirs.len() == 1 {
                let (only_name, only_tree) = &dir_node.subdirs[0];
                parts.push(only_name.clone());
                dir_node = only_tree;
            }
            let folded = parts.join("/");
            emit(GrepEventKind::Dir, depth, folded, &Vec::new());
            dir_node.walk_at(depth + 1, emit);
        }
    }
}

fn to_path_list(input: Option<&str>) -> Vec<String> {
    let Some(input) = input else {
        return Vec::new();
    };
    if input.contains(';') {
        input.split(';').map(ToString::to_string).collect()
    } else {
        vec![input.to_string()]
    }
}

fn has_glob_path_chars(segment: &str) -> bool {
    segment.contains('*') || segment.contains('?') || segment.contains('[') || segment.contains('{')
}

/// `splitPathAndSel` (strict, no literal probe — the literal probe happens
/// in the caller via `literal_exists`).
fn split_path_and_sel(raw_path: &str) -> (&str, Option<&str>) {
    let Some(colon) = raw_path.rfind(':') else {
        return (raw_path, None);
    };
    if colon == 0 {
        return (raw_path, None);
    }
    let candidate = &raw_path[colon + 1..];
    if !selector_shaped(candidate) {
        return (raw_path, None);
    }
    let mut base_path = &raw_path[..colon];
    let mut sel = candidate;
    if let Some(inner_colon) = base_path.rfind(':')
        && inner_colon > 0
    {
        let inner_candidate = &base_path[inner_colon + 1..];
        let inner_is_raw = inner_candidate.eq_ignore_ascii_case("raw");
        let outer_is_raw = candidate.eq_ignore_ascii_case("raw");
        let inner_is_range = range_only(inner_candidate);
        let outer_is_range = range_only(candidate);
        if (inner_is_raw && outer_is_range) || (inner_is_range && outer_is_raw) {
            sel = &base_path[inner_colon + 1..];
            base_path = &base_path[..inner_colon];
        }
    }
    (base_path, Some(sel))
}

fn selector_shaped(candidate: &str) -> bool {
    if candidate.eq_ignore_ascii_case("raw") || candidate.eq_ignore_ascii_case("conflicts") {
        return true;
    }
    range_only(candidate)
}

fn range_only(candidate: &str) -> bool {
    if candidate.is_empty() {
        return false;
    }
    candidate.split(',').all(|chunk| {
        let mut rest = chunk;
        if rest.starts_with(['L', 'l']) {
            rest = &rest[1..];
        }
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return false;
        }
        rest = &rest[digits.len()..];
        if rest.is_empty() {
            return true;
        }
        if let Some(after) = rest.strip_prefix("..") {
            rest = after;
        } else if let Some(after) = rest.strip_prefix(['-', '+']) {
            rest = after;
        } else {
            return false;
        }
        if rest.is_empty() {
            return true;
        }
        if rest.starts_with(['L', 'l']) {
            rest = &rest[1..];
        }
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
    })
}

async fn literal_exists(ctx: &OmpEngineContext, raw_path: &str) -> Result<bool, OmpEngineError> {
    if let Ok(resolved) = resolve_input_path(ctx, raw_path, FilesystemOperation::ReadFile) {
        return Ok(stat_optional_omp(ctx, &resolved.virtual_path)
            .await?
            .is_some());
    }
    Ok(false)
}

/// `parseSearchPath` from the pinned `path-utils.ts`.
fn parse_search_path(file_path: &str) -> (String, Option<String>, bool) {
    let segments: Vec<&str> = file_path.split('/').collect();
    let mut first_glob_index = -1i64;
    for (index, segment) in segments.iter().enumerate() {
        if has_glob_path_chars(segment) {
            first_glob_index = index as i64;
            break;
        }
    }
    if first_glob_index == -1 {
        return (file_path.to_string(), None, false);
    }
    if first_glob_index == 0 {
        return (".".to_string(), Some(file_path.to_string()), true);
    }
    (
        segments[..first_glob_index as usize].join("/"),
        Some(segments[first_glob_index as usize..].join("/")),
        true,
    )
}

async fn stat_optional_omp(
    ctx: &OmpEngineContext,
    path: &ironclaw_host_api::path::VirtualPath,
) -> Result<Option<ironclaw_filesystem::FileStat>, OmpEngineError> {
    match ctx.filesystem.stat(path).await {
        Ok(stat) => Ok(Some(stat)),
        Err(FilesystemError::NotFound { .. }) => Ok(None),
        Err(error) => Err(omp_error(
            OmpEngineErrorKind::Filesystem,
            format!("filesystem error: {error}"),
        )),
    }
}

async fn read_file_text(
    ctx: &OmpEngineContext,
    virtual_path: &ironclaw_host_api::path::VirtualPath,
) -> Result<Option<String>, OmpEngineError> {
    let Some(versioned) = ctx.filesystem.get(virtual_path).await.map_err(|error| {
        omp_error(
            OmpEngineErrorKind::Filesystem,
            format!("filesystem error: {error}"),
        )
    })?
    else {
        return Ok(None);
    };
    match String::from_utf8(versioned.entry.body) {
        Ok(text) => Ok(Some(text)),
        Err(_) => Ok(None),
    }
}

async fn search_file(
    ctx: &OmpEngineContext,
    virtual_path: &ironclaw_host_api::path::VirtualPath,
    workspace_root: &ironclaw_host_api::path::VirtualPath,
    compiled: &regex::Regex,
    specs: &[PathSpec],
) -> Result<FileHits, OmpEngineError> {
    let display = display_path(workspace_root, virtual_path);
    let Some(text) = read_file_text(ctx, virtual_path).await? else {
        return Ok(FileHits {
            display_path: display,
            virtual_path: virtual_path.clone(),
            lines: Vec::new(),
        });
    };
    let ranges = specs
        .iter()
        .find(|spec| spec.clean == display)
        .and_then(|spec| spec.ranges.clone());
    let lines: Vec<&str> = text.split('\n').collect();
    // Precompute match positions so context detection is linear.
    let match_lines: Vec<u64> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| compiled.is_match(line))
        .map(|(index, _)| index as u64 + 1)
        .collect();
    let mut hits: Vec<(u64, String, bool)> = Vec::new();
    let mut last_emitted: Option<u64> = None;
    for (index, line) in lines.iter().enumerate() {
        let line_number = index as u64 + 1;
        if let Some(ranges) = &ranges
            && !line_in_ranges(line_number, ranges)
        {
            continue;
        }
        let is_match = compiled.is_match(line);
        if !is_match {
            // Per-direction context windows (pinned grep.contextBefore=1 /
            // contextAfter=3, settings-schema.ts): a non-match line is
            // emitted only inside the contextBefore window of a LATER match
            // or the contextAfter window of an EARLIER match. Lines are
            // visited in ascending order, so no line is ever repeated.
            let near_match = match_lines.iter().any(|other| {
                if *other == line_number {
                    return false;
                }
                if *other > line_number {
                    *other - line_number <= CONTEXT_BEFORE as u64
                } else {
                    line_number - *other <= CONTEXT_AFTER as u64
                }
            });
            if !near_match {
                continue;
            }
        }
        if let Some(last) = last_emitted
            && line_number > last + 1
        {
            hits.push((0, "...".to_string(), false));
        }
        hits.push((line_number, (*line).to_string(), is_match));
        last_emitted = Some(line_number);
    }
    Ok(FileHits {
        display_path: display,
        virtual_path: virtual_path.clone(),
        lines: hits,
    })
}

async fn search_directory(
    ctx: &OmpEngineContext,
    dir: &ironclaw_host_api::path::VirtualPath,
    glob_filter: &str,
    workspace_root: &ironclaw_host_api::path::VirtualPath,
    compiled: &regex::Regex,
    specs: &[PathSpec],
) -> Result<Vec<FileHits>, OmpEngineError> {
    let compiled_glob = glob::Pattern::new(glob_filter).map_err(|error| {
        omp_error(
            OmpEngineErrorKind::Input,
            format!("Invalid glob pattern: {error}"),
        )
    })?;
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    let mut hits: Vec<FileHits> = Vec::new();
    let mut stack: Vec<ironclaw_host_api::path::VirtualPath> = vec![dir.clone()];
    while let Some(current) = stack.pop() {
        let entries = match ctx.filesystem.list_dir(&current).await {
            Ok(entries) => entries,
            Err(FilesystemError::NotFound { .. }) => continue,
            Err(error) => {
                return Err(omp_error(
                    OmpEngineErrorKind::Filesystem,
                    format!("filesystem error: {error}"),
                ));
            }
        };
        for entry in entries {
            if entry.name == ".git" || entry.name == "node_modules" {
                continue;
            }
            // Match the pattern against the path relative to the walk base
            // (pinned: the native walker globs `pattern` under `searchPath`),
            // not the workspace-relative display path — `dir/*` must match
            // `a.ts` under `dir`, not `dir/a.ts`, with
            // `require_literal_separator`.
            let relative = display_path(dir, &entry.path);
            if entry.file_type == FileType::Directory {
                stack.push(entry.path.clone());
                continue;
            }
            if !compiled_glob.matches_path_with(FsPath::new(&relative), options) {
                continue;
            }
            let file_hits = search_file(ctx, &entry.path, workspace_root, compiled, specs).await?;
            if !file_hits.lines.is_empty() {
                hits.push(file_hits);
            }
        }
    }
    Ok(hits)
}

fn line_in_ranges(line_number: u64, ranges: &[LineRange]) -> bool {
    ranges.iter().any(|range| {
        line_number >= range.start_line && range.end_line.is_none_or(|end| line_number <= end)
    })
}

/// Record the whole-file snapshot tag for a hit file (hashline mode header).
async fn record_snapshot_tag(
    ctx: &OmpEngineContext,
    virtual_path: &ironclaw_host_api::path::VirtualPath,
) -> Option<String> {
    let text = read_file_text(ctx, virtual_path).await.ok()??;
    let normalized = super::hashline::normalize_to_lf(&text);
    Some(ctx.snapshots.record_and_return(
        &OmpScopeKey::from_scope(&ctx.scope, ctx.run_id),
        virtual_path.as_str(),
        &normalized,
    ))
}

/// `formatMatchLine` rows: `*N:line` matches, ` N:line` context, `...` gaps.
fn render_hits(hits: &FileHits) -> Vec<String> {
    let mut rows: Vec<String> = Vec::new();
    for (line_number, text, is_match) in &hits.lines {
        if *line_number == 0 {
            rows.push("...".to_string());
            continue;
        }
        let marker = if *is_match { "*" } else { " " };
        rows.push(format!("{marker}{line_number}:{text}"));
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_path_and_sel_grep_shapes() {
        assert_eq!(
            split_path_and_sel("src/foo.ts:50-100"),
            ("src/foo.ts", Some("50-100"))
        );
        assert_eq!(split_path_and_sel("src/foo.ts"), ("src/foo.ts", None));
        assert_eq!(
            split_path_and_sel("src/*.ts:50-100"),
            ("src/*.ts", Some("50-100"))
        );
    }

    #[test]
    fn parse_search_path_shapes() {
        assert_eq!(parse_search_path("src"), ("src".to_string(), None, false));
        assert_eq!(
            parse_search_path("src/*.ts"),
            ("src".to_string(), Some("*.ts".to_string()), true)
        );
        assert_eq!(
            parse_search_path("**/*.rs"),
            (".".to_string(), Some("**/*.rs".to_string()), true)
        );
    }

    #[test]
    fn line_in_ranges_checks() {
        let ranges = vec![LineRange {
            start_line: 50,
            end_line: Some(100),
        }];
        assert!(line_in_ranges(50, &ranges));
        assert!(line_in_ranges(100, &ranges));
        assert!(!line_in_ranges(101, &ranges));
        let open = vec![LineRange {
            start_line: 50,
            end_line: None,
        }];
        assert!(line_in_ranges(5000, &open));
    }

    #[test]
    fn match_rows_use_hashline_shapes() {
        let hits = FileHits {
            display_path: "a.ts".to_string(),
            virtual_path: ironclaw_host_api::path::VirtualPath::new("/projects/workspace/a.ts")
                .expect("path"),
            lines: vec![
                (1, "fn main() {}".to_string(), false),
                (2, "match x {".to_string(), true),
                (0, "...".to_string(), false),
                (10, "// tail".to_string(), true),
            ],
        };
        let rows = render_hits(&hits);
        assert_eq!(
            rows,
            vec![" 1:fn main() {}", "*2:match x {", "...", "*10:// tail"]
        );
    }
}
