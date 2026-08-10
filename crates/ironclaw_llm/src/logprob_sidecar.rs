//! Local sidecar for captured per-token log-probabilities.
//!
//! # Why this is not the event store
//!
//! Logprobs are the generating model's distributions, conditioned on the
//! *entire* context — including anything a later redaction pass would remove.
//! That makes them strictly more sensitive than the text they describe, and it
//! means they cannot be attached to anything that is submitted, because a
//! scrub applied after generation cannot scrub numbers produced before it.
//!
//! So capture writes here: an append-only file under the IronClaw base
//! directory, off by default, never read by the submission path, and never
//! merged into the trace event stream. Whatever consumes this data has to go
//! to the data; the data does not travel.
//!
//! See `docs/superpowers/specs/2026-08-10-captured-logits-design.md` in
//! trace-commons-server for the reasoning this implements.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Directory override for captured logprobs. Defaults to
/// `<ironclaw_base_dir>/logprobs`.
pub(crate) const LOGPROB_SIDECAR_DIR_ENV: &str = "IRONCLAW_NEARAI_LOGPROB_DIR";

/// Per-token log-probabilities for one choice, as returned by an
/// OpenAI-compatible backend.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct ChoiceLogprobs {
    #[serde(default)]
    pub(crate) content: Vec<TokenLogprob>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct TokenLogprob {
    pub(crate) token: String,
    pub(crate) logprob: f32,
    #[serde(default)]
    pub(crate) top_logprobs: Vec<TopLogprob>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct TopLogprob {
    pub(crate) token: String,
    pub(crate) logprob: f32,
}

/// One appended line: the distributions for a single completion, tagged with
/// enough identity to line it up against the turn that produced it.
#[derive(Debug, Serialize)]
struct LogprobRecord<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    run_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    turn_id: Option<&'a str>,
    model: &'a str,
    streamed: bool,
    captured_at: String,
    token_count: usize,
    tokens: &'a [TokenLogprob],
}

/// Resolve the sidecar directory.
pub(crate) fn sidecar_dir() -> PathBuf {
    match ironclaw_common::env_helpers::env_or_override(LOGPROB_SIDECAR_DIR_ENV) {
        Some(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => ironclaw_common::paths::ironclaw_base_dir().join("logprobs"),
    }
}

/// Turn a run identifier into a safe single filename component.
///
/// `run_id` reaches us through an opaque metadata map, so it is untrusted for
/// this purpose: anything that is not alphanumeric, dash or underscore is
/// replaced, which makes traversal (`../`) and absolute paths unrepresentable.
pub(crate) fn sidecar_file_name(run_id: Option<&str>) -> String {
    let raw = run_id.map(str::trim).filter(|s| !s.is_empty());
    let Some(raw) = raw else {
        return "unattributed.jsonl".to_string();
    };
    let mut safe: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(120)
        .collect();
    if safe.chars().all(|c| c == '_') {
        safe = "unattributed".to_string();
    }
    format!("{safe}.jsonl")
}

/// Append one record. Best-effort: capture is diagnostic, so a failure to
/// write is logged and swallowed rather than failing the user's turn.
pub(crate) fn append(
    dir: &Path,
    run_id: Option<&str>,
    turn_id: Option<&str>,
    model: &str,
    streamed: bool,
    tokens: &[TokenLogprob],
) {
    if tokens.is_empty() {
        return;
    }
    if let Err(error) = try_append(dir, run_id, turn_id, model, streamed, tokens) {
        tracing::warn!(
            "could not write captured logprobs to {}: {error}",
            dir.display()
        );
    }
}

fn try_append(
    dir: &Path,
    run_id: Option<&str>,
    turn_id: Option<&str>,
    model: &str,
    streamed: bool,
    tokens: &[TokenLogprob],
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let record = LogprobRecord {
        run_id,
        turn_id,
        model,
        streamed,
        captured_at: chrono::Utc::now().to_rfc3339(),
        token_count: tokens.len(),
        tokens,
    };
    let mut line = serde_json::to_string(&record)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');

    let path = dir.join(sidecar_file_name(run_id));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(line.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(text: &str, logprob: f32) -> TokenLogprob {
        TokenLogprob {
            token: text.to_string(),
            logprob,
            top_logprobs: vec![TopLogprob {
                token: text.to_string(),
                logprob,
            }],
        }
    }

    /// `run_id` arrives through an opaque metadata map. It must never be able
    /// to steer the write outside the sidecar directory.
    #[test]
    fn test_file_name_rejects_traversal() {
        assert_eq!(
            sidecar_file_name(Some("../../etc/passwd")),
            "______etc_passwd.jsonl"
        );
        assert_eq!(
            sidecar_file_name(Some("/absolute/path")),
            "_absolute_path.jsonl"
        );
        assert!(!sidecar_file_name(Some("a/b")).contains('/'));
        assert!(
            !sidecar_file_name(Some("..")).contains('.')
                || sidecar_file_name(Some("..")).ends_with(".jsonl")
        );
    }

    #[test]
    fn test_file_name_falls_back_when_unidentified() {
        assert_eq!(sidecar_file_name(None), "unattributed.jsonl");
        assert_eq!(sidecar_file_name(Some("")), "unattributed.jsonl");
        assert_eq!(sidecar_file_name(Some("   ")), "unattributed.jsonl");
        // A name that sanitises to nothing but separators is not a useful file
        // name either.
        assert_eq!(sidecar_file_name(Some("///")), "unattributed.jsonl");
    }

    #[test]
    fn test_file_name_preserves_ordinary_ids() {
        assert_eq!(
            sidecar_file_name(Some("run-01H8XYZ_abc")),
            "run-01H8XYZ_abc.jsonl"
        );
    }

    #[test]
    fn test_append_writes_one_json_line_per_call() {
        let dir =
            std::env::temp_dir().join(format!("ironclaw-logprob-test-{}", uuid::Uuid::new_v4()));
        append(
            &dir,
            Some("run-1"),
            Some("turn-1"),
            "qwen3-30b",
            true,
            &[token("ok", -0.25)],
        );
        append(
            &dir,
            Some("run-1"),
            Some("turn-2"),
            "qwen3-30b",
            true,
            &[token("sure", -1.5), token("!", -0.1)],
        );

        let path = dir.join("run-1.jsonl");
        let contents = std::fs::read_to_string(&path).expect("sidecar file written");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "one line per completion");

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["run_id"], "run-1");
        assert_eq!(first["turn_id"], "turn-1");
        assert_eq!(first["model"], "qwen3-30b");
        assert_eq!(first["streamed"], true);
        assert_eq!(first["token_count"], 1);
        assert_eq!(first["tokens"][0]["token"], "ok");
        assert_eq!(first["tokens"][0]["top_logprobs"][0]["token"], "ok");

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["token_count"], 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Nothing captured means nothing written — an empty file per turn would
    /// make the sidecar useless for spotting which turns actually carry data.
    #[test]
    fn test_append_skips_empty_token_lists() {
        let dir =
            std::env::temp_dir().join(format!("ironclaw-logprob-empty-{}", uuid::Uuid::new_v4()));
        append(&dir, Some("run-2"), None, "qwen3-30b", false, &[]);
        assert!(
            !dir.join("run-2.jsonl").exists(),
            "no file should be created for an empty capture"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A write failure must not propagate — capture is diagnostic and must
    /// never cost the user their turn.
    #[test]
    fn test_append_swallows_write_failure() {
        // A path whose parent is a file, not a directory: create_dir_all fails.
        let file =
            std::env::temp_dir().join(format!("ironclaw-logprob-blocker-{}", uuid::Uuid::new_v4()));
        std::fs::write(&file, b"not a directory").unwrap();
        let dir = file.join("nested");

        append(
            &dir,
            Some("run-3"),
            None,
            "qwen3-30b",
            false,
            &[token("x", -1.0)],
        );

        std::fs::remove_file(&file).ok();
    }
}
