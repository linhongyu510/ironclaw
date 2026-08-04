use serde_json::Value as JsonValue;

mod placeholder_stripping;

pub(crate) use placeholder_stripping::{PlaceholderStrippingMode, strip_unset_optional_fields};

/// Policy for shaping tool schemas at the provider boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolSchemaPolicy {
    /// Apply top-level flattening plus strict-mode object rewriting.
    StrictOpenAi,
    /// Apply top-level flattening plus provider-safe cleanup, but do not
    /// force optional fields into required-nullable strict mode.
    FlattenOnly,
    /// Reduce schemas to the subset accepted by Gemini function declarations.
    Gemini,
}

/// Shape a tool schema for the target provider contract.
///
/// `description` is mutable because flattening can append an advisory hint
/// containing the original top-level schema when the request path cannot send
/// that shape directly.
pub(crate) fn shape_tool_schema(
    policy: ToolSchemaPolicy,
    schema: &JsonValue,
    description: &mut String,
) -> JsonValue {
    match policy {
        ToolSchemaPolicy::StrictOpenAi => normalize_schema_strict(schema, description),
        ToolSchemaPolicy::FlattenOnly => normalize_schema_flatten_only(schema, description),
        ToolSchemaPolicy::Gemini => normalize_schema_gemini(schema, description),
    }
}

/// Normalize a JSON Schema for OpenAI strict tool-calling compatibility.
pub(crate) fn normalize_schema_strict(schema: &JsonValue, description: &mut String) -> JsonValue {
    normalize_schema(schema, description, true)
}

fn normalize_schema_flatten_only(schema: &JsonValue, description: &mut String) -> JsonValue {
    normalize_schema(schema, description, false)
}

fn normalize_schema_gemini(schema: &JsonValue, description: &mut String) -> JsonValue {
    let mut schema = normalize_schema(schema, description, false);
    normalize_gemini_schema_recursive(&mut schema);
    schema
}

fn normalize_gemini_schema_recursive(schema: &mut JsonValue) {
    let Some(object) = schema.as_object_mut() else {
        *schema = serde_json::json!({ "type": "string" });
        return;
    };

    let constant = object.remove("const");
    let mut all_of = take_schema_variants(object, "allOf");
    let mut union_variants = take_schema_variants(object, "oneOf");
    union_variants.extend(take_schema_variants(object, "anyOf"));

    for variant in all_of.iter_mut().chain(union_variants.iter_mut()) {
        normalize_gemini_schema_recursive(variant);
    }

    for keyword in [
        "if",
        "then",
        "else",
        "not",
        "$schema",
        "$ref",
        "$defs",
        "definitions",
        "dependentRequired",
        "dependentSchemas",
        "contains",
        "prefixItems",
        "unevaluatedItems",
        "unevaluatedProperties",
        "patternProperties",
        "propertyNames",
    ] {
        object.remove(keyword);
    }

    normalize_gemini_type(object, constant.as_ref(), &all_of, &union_variants);

    for variant in &all_of {
        merge_gemini_variant(object, variant, true);
    }
    if let Some(selected) = union_variants
        .iter()
        .max_by_key(|variant| gemini_schema_rank(variant))
    {
        merge_gemini_variant(object, selected, false);
    }
    for variant in &union_variants {
        merge_gemini_properties(object, variant);
    }

    if let Some(JsonValue::Object(properties)) = object.get_mut("properties") {
        for property in properties.values_mut() {
            normalize_gemini_schema_recursive(property);
        }
    }
    if let Some(items) = object.get_mut("items") {
        normalize_gemini_schema_recursive(items);
    }
    if let Some(additional) = object.get_mut("additionalProperties")
        && additional.is_object()
    {
        normalize_gemini_schema_recursive(additional);
    }

    if object.get("type").and_then(JsonValue::as_str) != Some("array") {
        object.remove("items");
    }
}

fn take_schema_variants(
    object: &mut serde_json::Map<String, JsonValue>,
    keyword: &str,
) -> Vec<JsonValue> {
    object
        .remove(keyword)
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default()
}

fn normalize_gemini_type(
    object: &mut serde_json::Map<String, JsonValue>,
    constant: Option<&JsonValue>,
    all_of: &[JsonValue],
    union_variants: &[JsonValue],
) {
    let explicit = match object.get("type") {
        Some(JsonValue::String(kind)) => Some(kind.clone()),
        Some(JsonValue::Array(kinds)) => kinds
            .iter()
            .filter_map(JsonValue::as_str)
            .filter(|kind| *kind != "null")
            .max_by_key(|kind| gemini_type_rank(kind))
            .map(str::to_string),
        _ => None,
    };
    let structural = if object.contains_key("properties") {
        Some("object".to_string())
    } else if object.contains_key("items") {
        Some("array".to_string())
    } else {
        None
    };
    let variant_type = all_of
        .iter()
        .chain(union_variants)
        .max_by_key(|variant| gemini_schema_rank(variant))
        .and_then(gemini_schema_type);
    object.insert(
        "type".to_string(),
        JsonValue::String(
            structural
                .or(explicit)
                .or(variant_type)
                .or_else(|| constant.and_then(gemini_value_type).map(str::to_string))
                .unwrap_or_else(|| "string".to_string()),
        ),
    );

    if let Some(JsonValue::String(value)) = constant
        && !object.contains_key("enum")
    {
        object.insert("enum".to_string(), serde_json::json!([value]));
    }
}

fn gemini_value_type(value: &JsonValue) -> Option<&'static str> {
    match value {
        JsonValue::String(_) => Some("string"),
        JsonValue::Bool(_) => Some("boolean"),
        JsonValue::Number(number) if number.is_i64() || number.is_u64() => Some("integer"),
        JsonValue::Number(_) => Some("number"),
        JsonValue::Array(_) => Some("array"),
        JsonValue::Object(_) => Some("object"),
        JsonValue::Null => None,
    }
}

fn gemini_type_rank(kind: &str) -> u8 {
    match kind {
        "object" => 6,
        "array" => 5,
        "integer" | "number" | "boolean" => 4,
        "string" => 3,
        "null" => 0,
        _ => 1,
    }
}

fn gemini_schema_type(schema: &JsonValue) -> Option<String> {
    let object = schema.as_object()?;
    if object.contains_key("properties") {
        return Some("object".to_string());
    }
    if object.contains_key("items") {
        return Some("array".to_string());
    }
    object
        .get("type")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
}

fn gemini_schema_rank(schema: &JsonValue) -> u8 {
    gemini_schema_type(schema)
        .as_deref()
        .map(gemini_type_rank)
        .unwrap_or(0)
}

fn merge_gemini_variant(
    target: &mut serde_json::Map<String, JsonValue>,
    variant: &JsonValue,
    merge_required: bool,
) {
    let Some(source) = variant.as_object() else {
        return;
    };
    for key in [
        "items",
        "enum",
        "format",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
    ] {
        if !target.contains_key(key)
            && let Some(value) = source.get(key)
        {
            target.insert(key.to_string(), value.clone());
        }
    }
    merge_gemini_properties(target, variant);
    if merge_required && let Some(JsonValue::Array(required)) = source.get("required") {
        let target_required = target
            .entry("required".to_string())
            .or_insert_with(|| JsonValue::Array(Vec::new()));
        if let JsonValue::Array(existing) = target_required {
            for field in required {
                if !existing.contains(field) {
                    existing.push(field.clone());
                }
            }
        }
    }
}

fn merge_gemini_properties(target: &mut serde_json::Map<String, JsonValue>, variant: &JsonValue) {
    let Some(source_properties) = variant.get("properties").and_then(JsonValue::as_object) else {
        return;
    };
    let target_properties = target
        .entry("properties".to_string())
        .or_insert_with(|| JsonValue::Object(serde_json::Map::new()));
    let Some(target_properties) = target_properties.as_object_mut() else {
        return;
    };
    for (name, property) in source_properties {
        target_properties
            .entry(name.clone())
            .or_insert_with(|| property.clone());
    }
}

fn normalize_schema(
    schema: &JsonValue,
    description: &mut String,
    strict_objects: bool,
) -> JsonValue {
    let mut schema = schema.clone();

    if needs_top_level_flatten(&schema) {
        flatten_top_level(&mut schema, description);
        if let Some(props) = schema.get_mut("properties").and_then(|v| v.as_object_mut()) {
            for (_key, prop_schema) in props.iter_mut() {
                normalize_schema_recursive(prop_schema, strict_objects);
            }
        }
        if strict_objects {
            return schema;
        }
    } else {
        normalize_schema_recursive(&mut schema, strict_objects);
    }

    // Diagnostic strict-mode validation lives in the main crate's
    // `tools::schema_validator` and is exercised in CI tests there. The
    // run-time `normalize_schema_strict` itself does not need it — invalid
    // schemas remain usable (the LLM provider may reject them at request
    // time) so the previous debug-log call has been intentionally dropped
    // during the LLM-crate extraction.
    schema
}

/// JSON Schema keywords that OpenAI's tool API rejects at the top level of a
/// tool's `parameters`.
const FORBIDDEN_TOP_LEVEL: &[&str] = &["oneOf", "anyOf", "allOf", "enum", "not"];

fn detect_forbidden_top_level(schema: &JsonValue) -> Option<&'static str> {
    let map = schema.as_object()?;
    FORBIDDEN_TOP_LEVEL
        .iter()
        .find(|keyword| map.contains_key(**keyword))
        .copied()
}

fn needs_top_level_flatten(schema: &JsonValue) -> bool {
    match schema {
        JsonValue::Object(map) => {
            let has_forbidden = FORBIDDEN_TOP_LEVEL.iter().any(|k| map.contains_key(*k));
            has_forbidden || !top_level_accepts_object_properties(map)
        }
        _ => true,
    }
}

fn schema_flatten_hint_intro(detected: Option<&'static str>) -> &'static str {
    match detected {
        Some("oneOf") | Some("anyOf") => {
            "\n\nUpstream JSON schema (advisory; the actual top-level union has been \
             flattened so the OpenAI tool API will accept the tool — pick ONE variant \
             and pass its fields as a flat object):\n"
        }
        Some("allOf") => {
            "\n\nUpstream JSON schema (advisory; the actual top-level intersection has \
             been flattened so the OpenAI tool API will accept the tool — pass fields \
             from ALL variants combined as a flat object):\n"
        }
        Some("enum") => {
            "\n\nUpstream JSON schema (advisory; the actual top-level was an enum, \
             which OpenAI's tool API doesn't allow at the top level — pass one of \
             the listed values as the parameters object):\n"
        }
        Some("not") => {
            "\n\nUpstream JSON schema (advisory; the actual top-level was a `not` \
             constraint, which OpenAI's tool API doesn't allow at the top level — \
             pass any object that does NOT match the constraint):\n"
        }
        _ => {
            "\n\nUpstream JSON schema (advisory; the original was not a top-level \
             object schema, so we flattened to a free-form object — see below for \
             the actual constraints the upstream server will enforce):\n"
        }
    }
}

fn merge_top_level_variant_properties(schema: &JsonValue) -> serde_json::Map<String, JsonValue> {
    let mut merged = serde_json::Map::new();
    let Some(obj) = schema.as_object() else {
        return merged;
    };
    if top_level_accepts_object_properties(obj)
        && let Some(props) = obj.get("properties").and_then(|v| v.as_object())
    {
        for (key, value) in props {
            merged.insert(key.clone(), value.clone());
        }
    }
    for keyword in &["oneOf", "anyOf", "allOf"] {
        let Some(JsonValue::Array(variants)) = obj.get(*keyword) else {
            continue;
        };
        for variant in variants {
            let Some(props) = variant.get("properties").and_then(|v| v.as_object()) else {
                continue;
            };
            for (key, value) in props {
                if !merged.contains_key(key) {
                    merged.insert(key.clone(), value.clone());
                }
            }
        }
    }
    merged
}

fn top_level_accepts_object_properties(map: &serde_json::Map<String, JsonValue>) -> bool {
    match map.get("type") {
        Some(JsonValue::String(s)) => s == "object",
        Some(JsonValue::Array(arr)) => arr
            .iter()
            .any(|v| matches!(v, JsonValue::String(s) if s == "object")),
        None => map.contains_key("properties"),
        _ => false,
    }
}

fn top_level_required_fields(
    schema: &JsonValue,
    properties: &serde_json::Map<String, JsonValue>,
) -> Vec<JsonValue> {
    schema
        .get("required")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .filter(|field| properties.contains_key(*field))
        .map(|field| JsonValue::String(field.to_string()))
        .collect()
}

pub(crate) struct CappedJson {
    pub(crate) text: String,
    pub(crate) was_truncated: bool,
}

pub(crate) fn serialize_json_capped(value: &JsonValue, max_bytes: usize) -> Result<CappedJson, ()> {
    use std::io::{Error, Write};

    const CAP_REACHED: &str = "json cap reached";

    struct CappedWriter {
        buf: Vec<u8>,
        max: usize,
        was_truncated: bool,
    }

    impl Write for CappedWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            let remaining = self.max.saturating_sub(self.buf.len());
            if remaining == 0 {
                self.was_truncated = true;
                return Err(Error::other(CAP_REACHED));
            }
            let to_write = data.len().min(remaining);
            self.buf.extend_from_slice(&data[..to_write]);
            if to_write < data.len() {
                self.was_truncated = true;
                return Err(Error::other(CAP_REACHED));
            }
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let writer = CappedWriter {
        buf: Vec::with_capacity(max_bytes.min(8192)),
        max: max_bytes,
        was_truncated: false,
    };
    let mut ser = serde_json::Serializer::new(writer);
    let serialize_result = serde::Serialize::serialize(value, &mut ser);
    let writer = ser.into_inner();
    let was_truncated = writer.was_truncated;
    let buf = writer.buf;

    match serialize_result {
        Ok(()) => {}
        Err(e) if was_truncated && e.to_string().contains(CAP_REACHED) => {}
        Err(_) => return Err(()),
    }

    let text = match String::from_utf8(buf) {
        Ok(s) => s,
        Err(e) => {
            let valid_len = e.utf8_error().valid_up_to();
            let mut buf = e.into_bytes();
            buf.truncate(valid_len);
            String::from_utf8(buf).map_err(|_| ())?
        }
    };

    Ok(CappedJson {
        text,
        was_truncated,
    })
}

fn flatten_top_level(parameters: &mut JsonValue, description: &mut String) {
    const SCHEMA_HINT_MAX_BYTES: usize = 1500;

    let detected = detect_forbidden_top_level(parameters);
    let merged_properties = merge_top_level_variant_properties(parameters);
    let required = top_level_required_fields(parameters, &merged_properties);

    if let Ok(capped) = serialize_json_capped(parameters, SCHEMA_HINT_MAX_BYTES)
        && !capped.text.is_empty()
    {
        let hint = if capped.was_truncated {
            format!("{} ... (truncated)", capped.text)
        } else {
            capped.text
        };
        description.push_str(schema_flatten_hint_intro(detected));
        description.push_str(&hint);
    }

    *parameters = serde_json::json!({
        "type": "object",
        "properties": JsonValue::Object(merged_properties),
        "additionalProperties": true,
        "required": required
    });
}

fn normalize_schema_recursive(schema: &mut JsonValue, strict_objects: bool) {
    let obj = match schema.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    for key in &["anyOf", "oneOf", "allOf"] {
        if let Some(JsonValue::Array(variants)) = obj.get_mut(*key) {
            for variant in variants.iter_mut() {
                normalize_schema_recursive(variant, strict_objects);
            }
        }
    }

    let is_array = obj
        .get("type")
        .map(|t| {
            t.as_str() == Some("array")
                || t.as_array()
                    .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("array")))
        })
        .unwrap_or(false);
    if is_array {
        let needs_fix = match obj.get("items") {
            None => true,
            Some(JsonValue::Object(_)) => false,
            _ => true,
        };
        if needs_fix {
            obj.insert("items".to_string(), serde_json::json!({}));
        }
    }
    if let Some(items) = obj.get_mut("items") {
        normalize_schema_recursive(items, strict_objects);
    }

    for key in &["not", "if", "then", "else"] {
        if let Some(sub) = obj.get_mut(*key) {
            normalize_schema_recursive(sub, strict_objects);
        }
    }

    if !strict_objects {
        if obj.contains_key("properties") && !obj.contains_key("type") {
            obj.insert("type".to_string(), JsonValue::String("object".to_string()));
        }
        if let Some(JsonValue::Object(props)) = obj.get_mut("properties") {
            for prop_schema in props.values_mut() {
                normalize_schema_recursive(prop_schema, false);
            }
        }
        return;
    }

    let is_object = obj
        .get("type")
        .and_then(|t| t.as_str())
        .map(|t| t == "object")
        .unwrap_or(false);
    let has_properties = obj.contains_key("properties");

    if !is_object && !has_properties {
        return;
    }

    if !obj.contains_key("type") && has_properties {
        obj.insert("type".to_string(), JsonValue::String("object".to_string()));
    }

    obj.insert("additionalProperties".to_string(), JsonValue::Bool(false));

    if !obj.contains_key("properties") {
        obj.insert(
            "properties".to_string(),
            JsonValue::Object(serde_json::Map::new()),
        );
    }

    let current_required: std::collections::HashSet<String> = obj
        .get("required")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let all_keys: Vec<String> = obj
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|props| {
            let mut keys: Vec<String> = props.keys().cloned().collect();
            keys.sort();
            keys
        })
        .unwrap_or_default();

    if let Some(JsonValue::Object(props)) = obj.get_mut("properties") {
        for key in &all_keys {
            if let Some(prop_schema) = props.get_mut(key) {
                normalize_schema_recursive(prop_schema, true);
                if !current_required.contains(key) {
                    make_nullable(prop_schema);
                }
            }
        }
    }

    let required_value: Vec<JsonValue> = all_keys.into_iter().map(JsonValue::String).collect();
    obj.insert("required".to_string(), JsonValue::Array(required_value));
}

fn make_nullable(schema: &mut JsonValue) {
    let obj = match schema.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    if let Some(type_val) = obj.get("type").cloned() {
        match type_val {
            JsonValue::String(ref t) if t != "null" => {
                obj.insert("type".to_string(), serde_json::json!([t, "null"]));
            }
            JsonValue::Array(ref arr) => {
                let has_null = arr.iter().any(|v| v.as_str() == Some("null"));
                if !has_null {
                    let mut new_arr = arr.clone();
                    new_arr.push(JsonValue::String("null".to_string()));
                    obj.insert("type".to_string(), JsonValue::Array(new_arr));
                }
            }
            _ => {}
        }
    } else {
        let existing = JsonValue::Object(obj.clone());
        obj.clear();
        obj.insert(
            "anyOf".to_string(),
            serde_json::json!([existing, {"type": "null"}]),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_gemini_schema_subset(value: &JsonValue) {
        match value {
            JsonValue::Object(object) => {
                for keyword in [
                    "if", "then", "else", "not", "const", "oneOf", "anyOf", "allOf",
                ] {
                    assert!(
                        !object.contains_key(keyword),
                        "Gemini schema still contains unsupported keyword {keyword}: {value}"
                    );
                }
                if let Some(schema_type) = object.get("type") {
                    assert!(
                        schema_type.is_string(),
                        "Gemini requires a scalar type: {value}"
                    );
                }
                for nested in object.values() {
                    assert_gemini_schema_subset(nested);
                }
            }
            JsonValue::Array(values) => {
                for nested in values {
                    assert_gemini_schema_subset(nested);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn test_gemini_policy_recursively_reduces_unsupported_schema_constructs() {
        let input = serde_json::json!({
            "type": "object",
            "properties": {
                "headers": {
                    "type": ["string", "object", "null"],
                    "additionalProperties": { "type": "string" }
                },
                "action": { "const": "replace" },
                "payload": {
                    "oneOf": [
                        { "type": "string" },
                        {
                            "type": "object",
                            "properties": { "value": { "type": "string" } }
                        }
                    ]
                }
            },
            "allOf": [{
                "if": { "properties": { "action": { "const": "replace" } } },
                "then": { "required": ["payload"] }
            }]
        });
        let mut description = "HTTP request".to_string();

        let result = shape_tool_schema(ToolSchemaPolicy::Gemini, &input, &mut description);

        assert_gemini_schema_subset(&result);
        assert_eq!(result["properties"]["headers"]["type"], "object");
        assert_eq!(result["properties"]["payload"]["type"], "object");
        assert_eq!(
            result["properties"]["payload"]["properties"]["value"]["type"],
            "string"
        );
        assert_eq!(result["properties"]["action"]["type"], "string");
        assert_eq!(
            result["properties"]["action"]["enum"],
            serde_json::json!(["replace"])
        );
    }

    #[test]
    fn test_flatten_only_preserves_optional_object_fields() {
        let input = serde_json::json!({
            "type": "object",
            "properties": {
                "content": { "type": "string" },
                "channel": { "type": "string" },
                "attachments": { "type": "array" }
            },
            "required": ["content"]
        });
        let mut description = "Message tool".to_string();

        let result = shape_tool_schema(ToolSchemaPolicy::FlattenOnly, &input, &mut description);

        assert_eq!(
            result,
            serde_json::json!({
                "type": "object",
                "properties": {
                    "content": { "type": "string" },
                    "channel": { "type": "string" },
                    "attachments": { "type": "array", "items": {} }
                },
                "required": ["content"]
            })
        );
        assert_eq!(description, "Message tool");
    }

    #[test]
    fn test_flatten_only_flattens_top_level_oneof_without_strict_nullability() {
        let input = serde_json::json!({
            "type": "object",
            "oneOf": [
                {
                    "properties": {
                        "mode": { "const": "by_name" },
                        "name": { "type": "string" }
                    },
                    "required": ["mode", "name"]
                },
                {
                    "properties": {
                        "mode": { "const": "by_id" },
                        "id": { "type": "string" }
                    },
                    "required": ["mode", "id"]
                }
            ]
        });
        let mut description = "Lookup tool".to_string();

        let result = shape_tool_schema(ToolSchemaPolicy::FlattenOnly, &input, &mut description);

        assert_eq!(result["type"], "object");
        assert!(result.get("oneOf").is_none());
        assert_eq!(result["additionalProperties"], true);
        assert_eq!(result["required"], serde_json::json!([]));
        assert_eq!(result["properties"]["mode"]["const"], "by_name");
        assert_eq!(result["properties"]["name"]["type"], "string");
        assert_eq!(result["properties"]["id"]["type"], "string");
        assert!(description.contains("Upstream JSON schema"));
    }

    #[test]
    fn test_flatten_top_level_anyof_preserves_parent_properties() {
        let input = serde_json::json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "capability_id": { "type": "string" },
                "detail": { "type": "string", "enum": ["names", "summary", "schema"] }
            },
            "anyOf": [
                { "required": ["name"] },
                { "required": ["capability_id"] }
            ]
        });
        let mut description = "Capability info".to_string();

        let result = shape_tool_schema(ToolSchemaPolicy::FlattenOnly, &input, &mut description);

        assert_eq!(result["type"], "object");
        assert!(result.get("anyOf").is_none());
        assert_eq!(result["additionalProperties"], true);
        assert_eq!(result["required"], serde_json::json!([]));
        assert_eq!(result["properties"]["name"]["type"], "string");
        assert_eq!(result["properties"]["capability_id"]["type"], "string");
        assert_eq!(
            result["properties"]["detail"]["enum"],
            serde_json::json!(["names", "summary", "schema"])
        );
        assert!(description.contains("Upstream JSON schema"));
    }

    #[test]
    fn test_flatten_top_level_preserves_parent_required_fields() {
        let input = serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" },
                "old_string": { "type": "string" },
                "new_string": { "type": "string" },
                "edits": { "type": "array", "items": {"type": "object"} }
            },
            "required": ["path"],
            "oneOf": [
                { "required": ["old_string", "new_string"] },
                { "required": ["edits"] }
            ]
        });
        let mut description = "Patch tool".to_string();

        let result = shape_tool_schema(ToolSchemaPolicy::FlattenOnly, &input, &mut description);

        assert_eq!(result["type"], "object");
        assert!(result.get("oneOf").is_none());
        assert_eq!(result["additionalProperties"], true);
        assert_eq!(result["required"], serde_json::json!(["path"]));
        assert_eq!(result["properties"]["path"]["type"], "string");
        assert_eq!(result["properties"]["edits"]["type"], "array");
        assert!(description.contains("Upstream JSON schema"));
    }

    #[test]
    fn test_flatten_only_preserves_properties_without_explicit_object_type() {
        let input = serde_json::json!({
            "properties": {
                "content": { "type": "string" },
                "channel": { "type": "string" }
            },
            "required": ["content"]
        });
        let mut description = "Message tool".to_string();

        let result = shape_tool_schema(ToolSchemaPolicy::FlattenOnly, &input, &mut description);

        assert_eq!(result["type"], "object");
        assert_eq!(result["properties"]["content"]["type"], "string");
        assert_eq!(result["properties"]["channel"]["type"], "string");
        assert_eq!(result["required"], serde_json::json!(["content"]));
        assert_eq!(description, "Message tool");
    }

    #[test]
    fn test_strict_openai_preserves_properties_without_explicit_object_type() {
        let input = serde_json::json!({
            "properties": {
                "content": { "type": "string" },
                "channel": { "type": "string" }
            },
            "required": ["content"]
        });
        let mut description = "Message tool".to_string();

        let result = shape_tool_schema(ToolSchemaPolicy::StrictOpenAi, &input, &mut description);

        assert_eq!(result["type"], "object");
        assert_eq!(result["properties"]["content"]["type"], "string");
        assert_eq!(
            result["properties"]["channel"]["type"],
            serde_json::json!(["string", "null"])
        );
        assert_eq!(
            result["required"],
            serde_json::json!(["channel", "content"])
        );
        assert_eq!(result["additionalProperties"], false);
        assert_eq!(description, "Message tool");
    }

    #[test]
    fn test_non_object_top_level_type_with_properties_still_flattens() {
        for policy in [
            ToolSchemaPolicy::FlattenOnly,
            ToolSchemaPolicy::StrictOpenAi,
        ] {
            let input = serde_json::json!({
                "type": "string",
                "properties": {
                    "content": { "type": "string" }
                },
                "required": ["content"]
            });
            let mut description = "Malformed tool".to_string();

            let result = shape_tool_schema(policy, &input, &mut description);

            assert_eq!(result["type"], "object");
            assert!(
                result["properties"]
                    .as_object()
                    .expect("properties")
                    .is_empty()
            );
            assert_eq!(result["additionalProperties"], true);
            assert_eq!(result["required"], serde_json::json!([]));
            assert!(description.contains("Upstream JSON schema"));
        }
    }
}
