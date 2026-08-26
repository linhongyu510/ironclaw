use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use ironclaw_host_api::{
    dispatch::RuntimeDispatchErrorKind,
    model_result_preview::{AUTOMATIC_MODEL_RESULT_PREVIEW_MAX_BYTES, ModelResultPreview},
};
use serde_json::{Value, json};

use super::GsuiteDispatchError;

pub(super) fn from_get_message_output(
    output: &Value,
) -> Result<ModelResultPreview, GsuiteDispatchError> {
    let message = output
        .get("body")
        .and_then(Value::as_object)
        .ok_or_else(|| GsuiteDispatchError::new(RuntimeDispatchErrorKind::OutputDecode))?;
    let payload = message
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| GsuiteDispatchError::new(RuntimeDispatchErrorKind::OutputDecode))?;
    let mut headers = serde_json::Map::new();
    if let Some(values) = payload.get("headers").and_then(Value::as_array) {
        for header in values {
            let Some(name) = header.get("name").and_then(Value::as_str) else {
                continue;
            };
            let key = match name.to_ascii_lowercase().as_str() {
                "from" => "from",
                "to" => "to",
                "subject" => "subject",
                "date" => "date",
                _ => continue,
            };
            if let Some(value) = header.get("value").and_then(Value::as_str) {
                headers.insert(
                    key.to_string(),
                    Value::String(truncate_owned_utf8(value, 512)),
                );
            }
        }
    }

    let body = plain_text_body(payload)?;
    bounded_preview(headers, &body)
}

fn plain_text_body(
    payload: &serde_json::Map<String, Value>,
) -> Result<String, GsuiteDispatchError> {
    if payload.get("mimeType").and_then(Value::as_str) == Some("text/plain")
        && let Some(data) = payload
            .get("body")
            .and_then(Value::as_object)
            .and_then(|body| body.get("data"))
            .and_then(Value::as_str)
    {
        let decoded = URL_SAFE_NO_PAD
            .decode(data)
            .or_else(|_| URL_SAFE.decode(data))
            .map_err(output_decode_error)?;
        return String::from_utf8(decoded).map_err(output_decode_error);
    }
    if let Some(parts) = payload.get("parts").and_then(Value::as_array) {
        for part in parts {
            let Some(part) = part.as_object() else {
                continue;
            };
            let body = plain_text_body(part)?;
            if !body.is_empty() {
                return Ok(body);
            }
        }
    }
    Ok(String::new())
}

fn bounded_preview(
    mut headers: serde_json::Map<String, Value>,
    body: &str,
) -> Result<ModelResultPreview, GsuiteDispatchError> {
    shrink_headers_to_preview_budget(&mut headers, !body.is_empty())?;
    let mut low = 0;
    let mut high = body.len();
    let mut best = None;
    while low <= high {
        let midpoint = low + (high - low) / 2;
        let end = floor_utf8_boundary(body, midpoint);
        let candidate = json!({
            "headers": headers,
            "body": &body[..end],
            "body_truncated": end < body.len(),
        });
        let serialized = serde_json::to_string(&candidate).map_err(output_decode_error)?;
        if serialized.len() > AUTOMATIC_MODEL_RESULT_PREVIEW_MAX_BYTES {
            if midpoint == 0 {
                break;
            }
            high = midpoint - 1;
            continue;
        }
        let preview = ModelResultPreview::redacted(serialized).map_err(output_decode_error)?;
        if preview.as_str().len() <= AUTOMATIC_MODEL_RESULT_PREVIEW_MAX_BYTES {
            best = Some(preview);
            low = midpoint.saturating_add(1);
        } else if midpoint == 0 {
            break;
        } else {
            high = midpoint - 1;
        }
    }
    best.ok_or_else(|| GsuiteDispatchError::new(RuntimeDispatchErrorKind::OutputDecode))
}

fn shrink_headers_to_preview_budget(
    headers: &mut serde_json::Map<String, Value>,
    body_truncated: bool,
) -> Result<(), GsuiteDispatchError> {
    let header_budget = AUTOMATIC_MODEL_RESULT_PREVIEW_MAX_BYTES / 2;
    loop {
        let envelope = json!({
            "headers": &*headers,
            "body": "",
            "body_truncated": body_truncated,
        });
        if serde_json::to_vec(&envelope)
            .map_err(output_decode_error)?
            .len()
            <= header_budget
        {
            return Ok(());
        }

        let Some((key, len)) = headers
            .iter()
            .filter_map(|(key, value)| value.as_str().map(|value| (key, value.len())))
            .filter(|(_, len)| *len > 0)
            .max_by_key(|(_, len)| *len)
            .map(|(key, len)| (key.clone(), len))
        else {
            return Err(GsuiteDispatchError::new(
                RuntimeDispatchErrorKind::OutputDecode,
            ));
        };
        if let Some(Value::String(value)) = headers.get_mut(&key) {
            *value = truncate_owned_utf8(value, len / 2);
        }
    }
}

fn output_decode_error(error: impl std::fmt::Display) -> GsuiteDispatchError {
    tracing::warn!(error = %error, "failed to construct Gmail semantic preview");
    GsuiteDispatchError::new(RuntimeDispatchErrorKind::OutputDecode)
}

fn truncate_owned_utf8(value: &str, max_bytes: usize) -> String {
    value[..floor_utf8_boundary(value, max_bytes)].to_string()
}

fn floor_utf8_boundary(value: &str, index: usize) -> usize {
    let mut index = index.min(value.len());
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_preview_terminates_at_multibyte_boundaries() {
        let body = "😀".repeat(5_000);

        let preview = bounded_preview(serde_json::Map::new(), &body)
            .expect("multibyte body has a bounded preview");
        let value: Value =
            serde_json::from_str(preview.as_str()).expect("preview remains valid JSON");

        assert!(preview.as_str().len() <= AUTOMATIC_MODEL_RESULT_PREVIEW_MAX_BYTES);
        assert_eq!(value["body_truncated"], true);
        assert!(value["body"].as_str().is_some_and(|body| !body.is_empty()));
    }

    #[test]
    fn bounded_preview_redacts_credentials_embedded_in_message_text() {
        let body = r#"{"access_token":"opaque-live-value","message":"safe"}"#;

        let preview = bounded_preview(serde_json::Map::new(), body)
            .expect("credential-bearing body has a redacted preview");

        assert!(!preview.as_str().contains("opaque-live-value"));
        assert!(preview.as_str().contains("[redacted]"));
        assert!(preview.as_str().contains("safe"));
    }

    #[test]
    fn bounded_preview_keeps_valid_escaped_headers_within_budget() {
        let escaped = "\\\"".repeat(256);
        let headers = ["from", "to", "subject", "date"]
            .into_iter()
            .map(|name| (name.to_string(), Value::String(escaped.clone())))
            .collect();

        let preview = bounded_preview(headers, "readable body")
            .expect("escaped headers still yield a semantic preview");

        assert!(preview.as_str().len() <= AUTOMATIC_MODEL_RESULT_PREVIEW_MAX_BYTES);
        assert!(preview.as_str().contains("readable body"));
    }
}
