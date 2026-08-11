use std::fmt;

/// Metadata source tag for threads created to record automation trigger runs.
pub const AUTOMATION_TRIGGER_THREAD_SOURCE_TAG: &str = "automation_trigger";

/// Metadata source tag for threads created to run suggestion-card generation
/// (#7038). Same hidden-thread mechanism as automation triggers: the run's
/// transcript is real, durable, and directly readable — only the WebUI
/// thread *listing* excludes it (spec §6/§7-item-5).
pub const SUGGESTION_GENERATION_THREAD_SOURCE_TAG: &str = "suggestion_generation";

/// Every source tag that makes a thread hidden from thread listing. Adding a
/// new hidden-thread source means adding one entry here, not a second
/// bespoke `thread_metadata_is_*` predicate (spec §7-item-5) — subagent
/// threads (`SubagentThreadMetadata`) are a distinct mechanism and
/// deliberately not folded in here.
const HIDDEN_THREAD_SOURCE_TAGS: &[&str] = &[
    AUTOMATION_TRIGGER_THREAD_SOURCE_TAG,
    SUGGESTION_GENERATION_THREAD_SOURCE_TAG,
];

pub fn automation_trigger_thread_metadata_json(trigger_id: impl fmt::Display) -> String {
    serde_json::json!({
        "source": AUTOMATION_TRIGGER_THREAD_SOURCE_TAG,
        "trigger_id": trigger_id.to_string(),
    })
    .to_string()
}

pub fn suggestion_generation_thread_metadata_json(job_id: impl fmt::Display) -> String {
    serde_json::json!({
        "source": SUGGESTION_GENERATION_THREAD_SOURCE_TAG,
        "job_id": job_id.to_string(),
    })
    .to_string()
}

/// Whether `metadata_json`'s `source` tag is the automation-trigger tag
/// specifically (used by the automation-run-thread scoping resolver, which
/// must not match suggestion-generation threads).
pub fn thread_metadata_is_automation_trigger(
    metadata_json: &str,
) -> Result<bool, serde_json::Error> {
    thread_metadata_source_matches(metadata_json, AUTOMATION_TRIGGER_THREAD_SOURCE_TAG)
}

/// Whether `metadata_json`'s `source` tag is any hidden-thread source tag
/// (spec §7-item-5's generalized listing-filter predicate).
pub fn thread_metadata_is_hidden(metadata_json: &str) -> Result<bool, serde_json::Error> {
    for tag in HIDDEN_THREAD_SOURCE_TAGS {
        if thread_metadata_source_matches(metadata_json, tag)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn thread_metadata_source_matches(
    metadata_json: &str,
    tag: &str,
) -> Result<bool, serde_json::Error> {
    if !metadata_json.contains(tag) {
        return Ok(false);
    }
    let metadata = serde_json::from_str::<serde_json::Value>(metadata_json)?;
    Ok(metadata.get("source").and_then(serde_json::Value::as_str) == Some(tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automation_trigger_tag_is_hidden_but_not_confused_with_suggestion_tag() {
        let automation_json = automation_trigger_thread_metadata_json("trigger-1");
        assert!(thread_metadata_is_automation_trigger(&automation_json).unwrap());
        assert!(thread_metadata_is_hidden(&automation_json).unwrap());

        let suggestion_json = suggestion_generation_thread_metadata_json("job-1");
        assert!(!thread_metadata_is_automation_trigger(&suggestion_json).unwrap());
        assert!(thread_metadata_is_hidden(&suggestion_json).unwrap());
    }

    #[test]
    fn ordinary_thread_metadata_is_not_hidden() {
        let ordinary = serde_json::json!({"source": "webui"}).to_string();
        assert!(!thread_metadata_is_hidden(&ordinary).unwrap());
        assert!(!thread_metadata_is_automation_trigger(&ordinary).unwrap());
    }

    #[test]
    fn absent_metadata_source_field_is_not_hidden() {
        assert!(!thread_metadata_is_hidden("{}").unwrap());
    }
}
