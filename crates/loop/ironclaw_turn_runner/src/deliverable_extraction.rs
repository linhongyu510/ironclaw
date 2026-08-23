//! Deciding which file deliverables a run's request requires.
//!
//! Benchmark run 410dfedf ended `task_meeting_advisory_technical` on the
//! sentence "Now I'll write the report" with no file behind it. The remedy is a
//! reminder, and a reminder is only honest if the requirement is a FACT rather
//! than a guess. So extraction is deliberately narrow and deterministic — no
//! model call, no fuzzy inference:
//!
//! * the path must be written out in full by the user, under `/workspace/`;
//! * it must name a file (a final segment with an extension), not a directory;
//! * it must sit in a sentence that asks for something to be PRODUCED.
//!
//! Anything else extracts nothing, and a run with nothing extracted never sees
//! the feature at all. Missing a real deliverable is a non-event; inventing one
//! would put a false instruction in front of the model.

use ironclaw_loop_contracts::deliverable::{DeliverablePath, DeliverableSpec, WORKSPACE_PREFIX};

/// Upper bound on extracted deliverables. A request naming more paths than this
/// is not the failure class this targets, and a long reminder is a worse
/// reminder.
const MAX_DELIVERABLES: usize = 4;

/// Verb stems that mark a sentence as ASKING FOR OUTPUT. Stems rather than whole
/// words so tense and person do not matter (`creat` covers create/creates/
/// created/creating). Reading, loading, and inspecting verbs are deliberately
/// absent: "read /workspace/data.csv" names an input, not a deliverable.
const PRODUCE_VERB_STEMS: &[&str] = &[
    "writ", "sav", "creat", "produc", "output", "generat", "deliver", "export", "emit", "store",
];

/// Extract the required deliverables from the USER REQUEST text alone.
///
/// Split the request into sentences, keep only sentences that ask for output,
/// and take the fully written-out workspace file paths inside them.
pub(crate) fn extract_from_request(text: &str) -> DeliverableSpec {
    let mut paths: Vec<DeliverablePath> = Vec::new();
    for sentence in sentences(text) {
        if !asks_for_output(sentence) {
            continue;
        }
        for candidate in workspace_path_candidates(sentence) {
            let Ok(path) = DeliverablePath::new(candidate) else {
                continue;
            };
            if !paths.contains(&path) {
                paths.push(path);
            }
            if paths.len() == MAX_DELIVERABLES {
                return DeliverableSpec::new(paths);
            }
        }
    }
    DeliverableSpec::new(paths)
}

/// Split on line breaks and on sentence-ending punctuation followed by
/// whitespace. The trailing-whitespace condition is what keeps `report.md`
/// intact — a bare `.` split would cut every path at its extension.
fn sentences(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut sentences = Vec::new();
    let mut start = 0usize;
    for (index, byte) in bytes.iter().enumerate() {
        let ends_here = match byte {
            b'\n' | b'\r' => true,
            b'.' | b'!' | b'?' | b';' | b':' => bytes
                .get(index + 1)
                .is_none_or(|next| next.is_ascii_whitespace()),
            _ => false,
        };
        if ends_here {
            sentences.push(&text[start..index]);
            start = index + 1;
        }
    }
    if start < text.len() {
        sentences.push(&text[start..]);
    }
    sentences
}

fn asks_for_output(sentence: &str) -> bool {
    let lowered = sentence.to_ascii_lowercase();
    PRODUCE_VERB_STEMS.iter().any(|stem| lowered.contains(stem))
}

/// Collect every `/workspace/…` run of path characters in the sentence. Quoting,
/// backticks and trailing punctuation fall away because they are not path
/// characters, so `` `/workspace/report.md`. `` yields `/workspace/report.md`.
fn workspace_path_candidates(sentence: &str) -> Vec<&str> {
    let mut candidates = Vec::new();
    let mut search_from = 0usize;
    while let Some(offset) = sentence[search_from..].find(WORKSPACE_PREFIX) {
        let start = search_from + offset;
        let end = sentence[start..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/')))
            .map_or(sentence.len(), |length| start + length);
        // A sentence-final period belongs to the sentence, not the filename.
        let candidate = sentence[start..end].trim_end_matches('.');
        if !candidate.is_empty() {
            candidates.push(candidate);
        }
        search_from = end.max(start + WORKSPACE_PREFIX.len());
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extracted(request: &str) -> Vec<String> {
        extract_from_request(request)
            .paths()
            .iter()
            .map(|path| path.as_str().to_string())
            .collect()
    }

    #[test]
    fn an_explicit_save_instruction_yields_the_named_file() {
        assert_eq!(
            extracted("Review the notes and write a summary to /workspace/report.md"),
            vec!["/workspace/report.md".to_string()]
        );
    }

    /// Backticks, quotes and a sentence-final period are not part of the name.
    #[test]
    fn surrounding_punctuation_is_not_part_of_the_path() {
        for request in [
            "Save the output as `/workspace/out.json`.",
            "Save the output as \"/workspace/out.json\".",
            "Save the output as /workspace/out.json.",
            "Save the output as /workspace/out.json, then stop.",
        ] {
            assert_eq!(
                extracted(request),
                vec!["/workspace/out.json".to_string()],
                "request {request:?}"
            );
        }
    }

    #[test]
    fn several_deliverables_are_all_collected_once_each() {
        assert_eq!(
            extracted(
                "Write the findings to /workspace/findings.md.\n\
                 Also produce /workspace/data/table.csv and /workspace/findings.md again."
            ),
            vec![
                "/workspace/findings.md".to_string(),
                "/workspace/data/table.csv".to_string()
            ]
        );
    }

    /// The dormancy guarantee: no produce verb, no deliverable. A path that is
    /// an INPUT must never become a requirement.
    #[test]
    fn paths_without_a_produce_verb_are_not_deliverables() {
        for request in [
            "Read /workspace/data.csv and tell me what you find",
            "The transcript is at /workspace/meeting.txt — summarize it for me",
            "Compare /workspace/a.json with /workspace/b.json",
        ] {
            assert!(
                extracted(request).is_empty(),
                "request {request:?} extracted a deliverable"
            );
        }
    }

    /// Non-workspace paths are rejected even inside a perfectly good save
    /// sentence — the run can only be held to files in its own workspace.
    #[test]
    fn a_save_instruction_outside_the_workspace_extracts_nothing() {
        assert!(extracted("Write the report to /tmp/report.md please").is_empty());
    }

    #[test]
    fn extraction_is_bounded() {
        let request = (0..20)
            .map(|index| format!("Write /workspace/file{index}.md."))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(extracted(&request).len(), MAX_DELIVERABLES);
    }

    #[test]
    fn an_empty_request_is_dormant() {
        assert!(extracted("").is_empty());
    }
}
