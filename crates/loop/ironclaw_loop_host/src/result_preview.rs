use ironclaw_host_api::{
    model_result_preview::{AUTOMATIC_MODEL_RESULT_PREVIEW_MAX_BYTES, ModelResultPreview},
    turn::LoopResultRef,
};
use ironclaw_loop_contracts::{
    MODEL_VISIBLE_TOOL_OBSERVATION_SCHEMA_VERSION, ModelVisibleArtifact,
    ModelVisibleToolObservation, ObservationTrust, ToolObservationDetail, ToolObservationStatus,
};

/// Build the model-visible observation for a completed capability result.
///
/// `serialized` is the exact durable representation, while `output` is used
/// only to derive a bounded structural preview and array cardinality. The
/// complete result remains behind `result_ref`; this function only constructs
/// the small model-facing first look.
pub fn result_reference_observation(
    result_ref: &LoopResultRef,
    byte_len: u64,
    output: &serde_json::Value,
    serialized: &[u8],
    producer_preview: Option<ModelResultPreview>,
) -> ModelVisibleToolObservation {
    let item_count = output.as_array().map(|items| items.len() as u64);
    let preview = first_look_result_preview(output, serialized, producer_preview);
    result_reference_observation_from_preview(result_ref, byte_len, preview, item_count)
}

struct FirstLookResultPreview {
    text: String,
    /// `None` when `text` already covers the entire payload.
    next_offset: Option<u64>,
}

fn first_look_result_preview(
    output: &serde_json::Value,
    serialized: &[u8],
    producer_preview: Option<ModelResultPreview>,
) -> Option<FirstLookResultPreview> {
    let full_text = std::str::from_utf8(serialized).ok()?;
    if let Some(preview) = producer_preview
        && let Some(text) = bounded_redacted_preview(preview.into_inner())
    {
        let next_offset = (text.as_bytes() != serialized).then_some(0);
        return Some(FirstLookResultPreview { text, next_offset });
    }
    if serialized.len() <= AUTOMATIC_MODEL_RESULT_PREVIEW_MAX_BYTES
        && let Some(text) = bounded_redacted_preview(full_text.to_string())
    {
        let next_offset = (text.as_bytes() != serialized).then_some(0);
        return Some(FirstLookResultPreview { text, next_offset });
    }

    let summary = oversized_json_summary(output, serialized.len());
    let text = bounded_redacted_preview(summary)
        .unwrap_or_else(|| r#"{"kind":"oversized_json","values_elided":true}"#.to_string());
    Some(FirstLookResultPreview {
        text,
        next_offset: Some(0),
    })
}

fn bounded_redacted_preview(value: String) -> Option<String> {
    let preview = ModelResultPreview::redacted(value).ok()?;
    (preview.as_str().len() <= AUTOMATIC_MODEL_RESULT_PREVIEW_MAX_BYTES)
        .then(|| preview.into_inner())
}

fn oversized_json_summary(output: &serde_json::Value, total_bytes: usize) -> String {
    let summary = match output {
        serde_json::Value::Object(fields) => {
            let omitted_key_count = fields.len().saturating_sub(16);
            let keys = fields
                .keys()
                .take(16)
                .map(|key| truncate_utf8(key, 128))
                .collect::<Vec<_>>();
            serde_json::json!({
                "kind": "object",
                "total_bytes": total_bytes,
                "keys": keys,
                "omitted_key_count": omitted_key_count,
                "values_elided": true,
            })
        }
        serde_json::Value::Array(items) => serde_json::json!({
            "kind": "array",
            "total_bytes": total_bytes,
            "item_count": items.len(),
            "values_elided": true,
        }),
        serde_json::Value::Null => scalar_summary("null", total_bytes),
        serde_json::Value::Bool(_) => scalar_summary("boolean", total_bytes),
        serde_json::Value::Number(_) => scalar_summary("number", total_bytes),
        serde_json::Value::String(_) => scalar_summary("string", total_bytes),
    };
    serde_json::to_string(&summary)
        .unwrap_or_else(|_| r#"{"kind":"oversized_json","values_elided":true}"#.to_string())
}

fn scalar_summary(kind: &str, total_bytes: usize) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "total_bytes": total_bytes,
        "values_elided": true,
    })
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    &value[..floor_char_boundary(value, max_bytes)]
}

fn floor_char_boundary(value: &str, index: usize) -> usize {
    if index >= value.len() {
        return value.len();
    }
    let mut index = index;
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn result_reference_observation_from_preview(
    result_ref: &LoopResultRef,
    byte_len: u64,
    preview: Option<FirstLookResultPreview>,
    item_count: Option<u64>,
) -> ModelVisibleToolObservation {
    let (summary, preview_text, total_bytes, next_offset, item_count) = match preview {
        Some(FirstLookResultPreview {
            text,
            next_offset: Some(next_offset),
        }) => (
            preview_continuation_summary(next_offset, item_count),
            Some(text),
            Some(byte_len),
            Some(next_offset),
            item_count,
        ),
        Some(FirstLookResultPreview {
            text,
            next_offset: None,
        }) => (
            "Tool completed; preview contains the full result.".to_string(),
            Some(text),
            Some(byte_len),
            None,
            None,
        ),
        None => (
            "Tool completed; use result_read with the result reference for more output."
                .to_string(),
            None,
            None,
            None,
            None,
        ),
    };
    ModelVisibleToolObservation {
        schema_version: MODEL_VISIBLE_TOOL_OBSERVATION_SCHEMA_VERSION,
        status: ToolObservationStatus::Success,
        summary,
        detail: ToolObservationDetail::ResultReference {
            result_ref: result_ref.as_str().to_string(),
            byte_len,
            preview: preview_text,
            total_bytes,
            next_offset,
            item_count,
        },
        artifacts: vec![ModelVisibleArtifact {
            artifact_ref: result_ref.as_str().to_string(),
            summary: "Stored tool result".to_string(),
        }],
        recovery: None,
        trust: ObservationTrust::UntrustedToolOutput,
    }
}

fn preview_continuation_summary(next_offset: u64, item_count: Option<u64>) -> String {
    let base = if next_offset == 0 {
        "Tool completed; preview is a projection of the full result. Use result_read with the result reference and offset 0 for more output."
            .to_string()
    } else {
        format!(
            "Tool completed; preview truncated, use result_read with the result reference and offset {next_offset} for more output."
        )
    };
    match item_count {
        Some(count) => format!("{base} Full result is a JSON array of {count} items."),
        None => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_outputs_use_bounded_structural_projections_for_every_json_shape() {
        let cases = [
            (
                serde_json::json!({"records": "x".repeat(8 * 1024), "status": "ok"}),
                "object",
            ),
            (serde_json::json!(["x".repeat(8 * 1024)]), "array"),
            (serde_json::json!("x".repeat(8 * 1024)), "string"),
        ];

        for (output, expected_kind) in cases {
            let serialized = serde_json::to_vec(&output).expect("fixture serializes");
            let preview = first_look_result_preview(&output, &serialized, None)
                .expect("JSON output always has a preview");
            let projected: serde_json::Value =
                serde_json::from_str(&preview.text).expect("projection is valid JSON");

            assert_eq!(projected["kind"], expected_kind);
            assert!(preview.text.len() <= AUTOMATIC_MODEL_RESULT_PREVIEW_MAX_BYTES);
            assert_eq!(preview.next_offset, Some(0));
            assert!(!preview.text.contains(&"x".repeat(1_024)));
        }
    }

    #[test]
    fn producer_preview_uses_the_same_budget_and_offset_contract() {
        let output = serde_json::json!({"transport": "x".repeat(8 * 1024)});
        let serialized = serde_json::to_vec(&output).expect("fixture serializes");
        let semantic = ModelResultPreview::new(r#"{"message":"readable"}"#)
            .expect("semantic preview is valid");

        let preview = first_look_result_preview(&output, &serialized, Some(semantic))
            .expect("producer preview is retained");

        assert_eq!(preview.text, r#"{"message":"readable"}"#);
        assert_eq!(preview.next_offset, Some(0));
    }

    #[test]
    fn oversized_producer_preview_falls_back_to_generic_projection() {
        let output = serde_json::json!({"records": "x".repeat(8 * 1024)});
        let serialized = serde_json::to_vec(&output).expect("fixture serializes");
        let oversized =
            ModelResultPreview::new("p".repeat(AUTOMATIC_MODEL_RESULT_PREVIEW_MAX_BYTES + 1))
                .expect("producer preview remains below the explicit page cap");

        let preview = first_look_result_preview(&output, &serialized, Some(oversized))
            .expect("generic projection is available");
        let projected: serde_json::Value =
            serde_json::from_str(&preview.text).expect("projection is valid JSON");

        assert_eq!(projected["kind"], "object");
        assert!(preview.text.len() <= AUTOMATIC_MODEL_RESULT_PREVIEW_MAX_BYTES);
        assert_eq!(preview.next_offset, Some(0));
    }

    #[test]
    fn offset_zero_summary_names_the_projection_and_read_origin() {
        let result_ref = LoopResultRef::new("result:test-run.id").expect("result ref");
        let output = serde_json::json!(["one", "two"]);
        let serialized = serde_json::to_vec(&output).expect("fixture serializes");
        let observation = result_reference_observation(
            &result_ref,
            serialized.len() as u64,
            &output,
            &serialized,
            Some(ModelResultPreview::new(r#"{"items":["one"]}"#).expect("preview")),
        );

        assert!(observation.summary.contains("preview is a projection"));
        assert!(observation.summary.contains("result_read"));
        assert!(observation.summary.contains("offset 0"));
        assert!(observation.summary.contains("2 items"));
    }

    #[test]
    fn positive_offset_summary_keeps_truncated_wording() {
        let result_ref = LoopResultRef::new("result:test-run.id").expect("result ref");
        let observation = result_reference_observation_from_preview(
            &result_ref,
            128,
            Some(FirstLookResultPreview {
                text: "prefix".to_string(),
                next_offset: Some(64),
            }),
            None,
        );

        assert!(observation.summary.contains("preview truncated"));
        assert!(observation.summary.contains("offset 64"));
        assert!(!observation.summary.contains("preview is a projection"));
    }
}
