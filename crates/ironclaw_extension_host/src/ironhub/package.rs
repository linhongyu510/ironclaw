use crate::{AvailableExtensionPackage, registry_extension_package};

use super::catalog::validate_hub_name;
use super::model::{
    GENERIC_TOOL_INPUT_SCHEMA, GENERIC_TOOL_OUTPUT_SCHEMA, IronHubCommandError, IronHubToolEntry,
};

pub(crate) fn ironhub_tool_package(
    entry: &IronHubToolEntry,
    wasm: Vec<u8>,
    capabilities: Vec<u8>,
    reserved_bundled_ids: &[String],
) -> Result<AvailableExtensionPackage, IronHubCommandError> {
    validate_hub_name(&entry.name)?;
    validate_hub_name(&entry.crate_name)?;
    let module_path = format!("wasm/{}_tool.wasm", entry.crate_name);
    let input_schema_path = format!("schemas/{}/invoke.input.v1.json", entry.name);
    let output_schema_path = format!("schemas/{}/raw_output.v1.json", entry.name);
    let manifest = generic_tool_manifest_with_credentials(
        entry,
        &module_path,
        &input_schema_path,
        &output_schema_path,
        &capabilities,
    )?;
    registry_extension_package(
        vec![
            ("manifest.toml".to_string(), manifest.into_bytes()),
            (module_path, wasm),
            ("legacy/capabilities.json".to_string(), capabilities),
            (input_schema_path, GENERIC_TOOL_INPUT_SCHEMA.to_vec()),
            (output_schema_path, GENERIC_TOOL_OUTPUT_SCHEMA.to_vec()),
        ],
        reserved_bundled_ids,
    )
    .map_err(IronHubCommandError::Product)
}

/// A credential the tool published in its signed capabilities artifact, mapped
/// onto the v3 injection contract.
struct MappedCredential {
    handle: String,
    host: String,
    header: String,
    /// `None` injects the raw secret as the header value: monday.com sends the
    /// token as the Authorization value with no scheme prefix, so inventing a
    /// "Bearer " prefix would break every request it makes.
    prefix: Option<String>,
}

/// Read `http.credentials` out of the signed capabilities artifact.
///
/// The artifact is already downloaded and digest-verified; before this it was
/// written into the package as `legacy/capabilities.json` and never read, so
/// every credential recipe a tool published was discarded and the generated
/// manifest claimed the tool needed no secrets. A credentialed tool therefore
/// installed "successfully" and could never authenticate.
///
/// Policy fields (trust, origin gates, default permission, visibility) stay
/// host-authored: a third-party package declares which credential it needs,
/// never what it is allowed to do.
fn mapped_credentials(
    entry: &IronHubToolEntry,
    capabilities: &[u8],
) -> Result<Vec<MappedCredential>, IronHubCommandError> {
    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(capabilities) else {
        // Policing the artifact's overall shape is not this function's contract;
        // a package with no readable credential block installs as before.
        return Ok(Vec::new());
    };
    let Some(declared) = parsed
        .get("http")
        .and_then(|http| http.get("credentials"))
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(Vec::new());
    };

    let mut mapped = Vec::new();
    for (handle, credential) in declared {
        let location = credential
            .get("location")
            .and_then(serde_json::Value::as_object);
        let kind = location
            .and_then(|location| location.get("type"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let (header, prefix) = match kind {
            "bearer" => ("authorization".to_string(), Some("Bearer ".to_string())),
            "header" => {
                let name = location
                    .and_then(|location| location.get("name"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("authorization");
                (name.to_ascii_lowercase(), None)
            }
            other => {
                // Fail closed. v3 injection models header, query param, path
                // placeholder and JSON pointer — not HTTP Basic. Installing
                // anyway would recreate the exact failure this function fixes:
                // a successful install that can never authenticate.
                return Err(IronHubCommandError::Catalog {
                    reason: format!(
                        "'{}' declares credential '{handle}' with unsupported location type \
                         '{other}'; the host cannot inject it, so the tool would install \
                         without working authentication",
                        entry.name
                    ),
                });
            }
        };
        let host = credential
            .get("host_patterns")
            .and_then(serde_json::Value::as_array)
            .and_then(|hosts| hosts.first())
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        if host.is_empty() {
            return Err(IronHubCommandError::Catalog {
                reason: format!(
                    "'{}' declares credential '{handle}' without a host pattern; the \
                     injection audience cannot be bounded",
                    entry.name
                ),
            });
        }
        mapped.push(MappedCredential {
            handle: handle.clone(),
            host,
            header,
            prefix,
        });
    }
    // Deterministic order: the manifest is content-addressed through the package.
    mapped.sort_by(|left, right| left.handle.cmp(&right.handle));
    Ok(mapped)
}

fn credential_blocks(entry: &IronHubToolEntry, credentials: &[MappedCredential]) -> String {
    credentials
        .iter()
        .map(|credential| {
            let prefix = credential
                .prefix
                .as_ref()
                .map(|prefix| format!(", prefix = {}", toml_string(prefix.clone())))
                .unwrap_or_default();
            format!(
                "\n[[tools.credentials]]\nhandle = {handle}\nvendor = {vendor}\naudience = {{ scheme = \"https\", host = {host} }}\ninjection = {{ type = \"header\", name = {name}{prefix} }}\n",
                handle = toml_string(credential.handle.clone()),
                vendor = toml_string(entry.name.clone()),
                host = toml_string(credential.host.clone()),
                name = toml_string(credential.header.clone()),
            )
        })
        .collect()
}

/// Emit the `[auth.<vendor>]` recipe every referenced vendor must declare.
///
/// v3 validation rejects a manifest whose credential names a vendor with no
/// recipe ("credential vendor `attio` has no [auth.attio] recipe"), so emitting
/// credentials without this makes the package uninstallable.
///
/// `method = "api_key"` is what maps to `RuntimeCredentialAccountSetup::ManualToken`,
/// which is the flow that renders the masked in-chat credential card. The label
/// and display name come from the tool's own published `setup`/`auth` blocks so
/// the user sees the vendor's wording rather than a synthesised placeholder.
/// `validation` is deliberately omitted: it is optional, and a probe URL the host
/// invents could fail against a tool it has never talked to.
fn auth_recipe_block(
    entry: &IronHubToolEntry,
    credentials: &[MappedCredential],
    capabilities: &[u8],
) -> String {
    if credentials.is_empty() {
        return String::new();
    }
    let parsed = serde_json::from_slice::<serde_json::Value>(capabilities).unwrap_or_default();
    let display_name = parsed
        .get("auth")
        .and_then(|auth| auth.get("display_name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(entry.name.as_str())
        .to_string();
    let prompts = parsed
        .get("setup")
        .and_then(|setup| setup.get("required_secrets"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    let fields = credentials
        .iter()
        .map(|credential| {
            let label = prompts
                .iter()
                .find(|secret| {
                    secret.get("name").and_then(serde_json::Value::as_str)
                        == Some(credential.handle.as_str())
                })
                .and_then(|secret| secret.get("prompt"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or(credential.handle.as_str())
                .to_string();
            format!(
                "{{ handle = {handle}, label = {label}, secret = true }}",
                handle = toml_string(credential.handle.clone()),
                label = toml_string(label),
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "\n[auth.{vendor}]\nmethod = \"api_key\"\ndisplay_name = {display_name}\nfields = [ {fields} ]\n",
        vendor = entry.name,
        display_name = toml_string(display_name),
    )
}

fn generic_tool_manifest_with_credentials(
    entry: &IronHubToolEntry,
    module_path: &str,
    input_schema_path: &str,
    output_schema_path: &str,
    capabilities: &[u8],
) -> Result<String, IronHubCommandError> {
    let credentials = mapped_credentials(entry, capabilities)?;
    let effects = if credentials.is_empty() {
        r#"["network"]"#
    } else {
        r#"["network", "use_secret"]"#
    };
    Ok(format!(
        "{}{}{}",
        generic_tool_manifest(
            entry,
            module_path,
            input_schema_path,
            output_schema_path,
            effects,
        ),
        credential_blocks(entry, &credentials),
        auth_recipe_block(entry, &credentials, capabilities),
    ))
}

fn generic_tool_manifest(
    entry: &IronHubToolEntry,
    module_path: &str,
    input_schema_path: &str,
    output_schema_path: &str,
    effects: &str,
) -> String {
    format!(
        r#"schema_version = "reborn.extension_manifest.v3"
id = {id}
name = {name}
version = {version}
description = {description}
trust = "third_party"

[runtime]
kind = "wasm"
module = {module}

[[tools]]
origin_gate_matrix = {{ loop_run = "gated_unless_granted", product = "forbidden", automation = "forbidden" }}
id = {capability_id}
description = {description}
effects = {effects}
default_permission = "ask"
visibility = "model"
input_schema_ref = {input_schema_ref}
output_schema_ref = {output_schema_ref}
"#,
        id = toml_string(&entry.name),
        name = toml_string(&entry.name),
        version = toml_string(&entry.version),
        description = toml_string(&entry.description),
        module = toml_string(module_path),
        capability_id = toml_string(format!("{}.invoke", entry.name)),
        input_schema_ref = toml_string(input_schema_path),
        output_schema_ref = toml_string(output_schema_path),
        effects = effects,
    )
}

fn toml_string(value: impl Into<String>) -> String {
    toml::Value::String(value.into()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ironhub::model::{IronHubArtifact, IronHubProvenance};

    fn caps(credentials: &str) -> Vec<u8> {
        format!(r#"{{"version":"0.1.0","http":{{"credentials":{credentials}}}}}"#).into_bytes()
    }

    fn entry_named(name: &str) -> IronHubToolEntry {
        IronHubToolEntry {
            name: name.to_string(),
            crate_name: name.replace('-', "_"),
            version: "0.1.0".to_string(),
            description: "test tool".to_string(),
            provenance: IronHubProvenance::Official,
            wasm: IronHubArtifact {
                url: "https://hub.ironclaw.com/t.wasm".to_string(),
                size_bytes: 1,
                sha256: "a".repeat(64),
            },
            capabilities: IronHubArtifact {
                url: "https://hub.ironclaw.com/t.json".to_string(),
                size_bytes: 1,
                sha256: "b".repeat(64),
            },
        }
    }

    /// A published credential recipe must reach the generated manifest.
    ///
    /// The catalog artifact already carries `http.credentials`, but
    /// `generic_tool_manifest` discarded it and emitted `effects = ["network"]`
    /// with no credential block — so every credentialed IronHub tool installed
    /// "successfully" and could never authenticate. Attio is the reported case.
    #[test]
    fn bearer_credentials_reach_the_generated_manifest() {
        let entry = entry_named("attio");
        let manifest = generic_tool_manifest_with_credentials(
            &entry,
            "wasm/attio_tool.wasm",
            "in.json",
            "out.json",
            &caps(
                r#"{"attio_api_key":{"secret_name":"attio_api_key","location":{"type":"bearer"},"host_patterns":["api.attio.com"]}}"#,
            ),
        )
        .expect("bearer credential maps");

        assert!(
            manifest.contains("use_secret"),
            "a tool needing a secret must declare the effect: {manifest}"
        );
        assert!(manifest.contains("[[tools.credentials]]"), "{manifest}");
        assert!(
            manifest.contains(r#"handle = "attio_api_key""#),
            "{manifest}"
        );
        assert!(manifest.contains(r#"host = "api.attio.com""#), "{manifest}");
        assert!(
            manifest.contains(r#"prefix = "Bearer ""#),
            "bearer maps to an Authorization header with a Bearer prefix: {manifest}"
        );
    }

    /// monday.com sends the raw token as the Authorization value with NO
    /// "Bearer " prefix; emitting one would silently break every request.
    #[test]
    fn raw_header_credentials_keep_no_prefix() {
        let entry = entry_named("monday");
        let manifest = generic_tool_manifest_with_credentials(
            &entry,
            "wasm/monday_tool.wasm",
            "in.json",
            "out.json",
            &caps(
                r#"{"monday_api_token":{"secret_name":"monday_api_token","location":{"type":"header","name":"Authorization"},"host_patterns":["api.monday.com"]}}"#,
            ),
        )
        .expect("raw header credential maps");

        assert!(
            manifest.contains(r#"handle = "monday_api_token""#),
            "{manifest}"
        );
        assert!(
            !manifest.contains("prefix"),
            "monday takes the raw Authorization value; a prefix must not be invented: {manifest}"
        );
    }

    /// v3 injection has no Basic variant. Installing a tool whose credential
    /// cannot be injected would repeat the failure this change fixes — a
    /// successful install that can never authenticate — so it fails closed.
    #[test]
    fn unsupported_credential_location_fails_the_install_loudly() {
        let entry = entry_named("wazuh");
        let error = generic_tool_manifest_with_credentials(
            &entry,
            "wasm/wazuh_tool.wasm",
            "in.json",
            "out.json",
            &caps(
                r#"{"wazuh_indexer_password":{"secret_name":"wazuh_indexer_password","location":{"type":"basic","username":"admin"},"host_patterns":["wazuh-indexer.local"]}}"#,
            ),
        )
        .expect_err("an unmappable credential must not install silently");
        let text = error.to_string();
        assert!(text.contains("wazuh"), "names the tool: {text}");
        assert!(
            text.contains("basic"),
            "names the unsupported shape: {text}"
        );
    }

    /// The generated manifest must satisfy the real v3 parser, not just contain
    /// the right substrings — a credential block that fails `parse_manifest_v3`
    /// would break activation at install time instead of at authentication time.
    #[test]
    fn generated_credential_manifest_parses_as_v3() {
        let entry = entry_named("attio");
        let manifest = generic_tool_manifest_with_credentials(
            &entry,
            "wasm/attio_tool.wasm",
            "schemas/attio/invoke.input.v1.json",
            "schemas/attio/raw_output.v1.json",
            &caps(
                r#"{"attio_api_key":{"secret_name":"attio_api_key","location":{"type":"bearer"},"host_patterns":["api.attio.com"]}}"#,
            ),
        )
        .expect("bearer credential maps");

        let parsed: toml::Value = toml::from_str(&manifest).expect("manifest is valid TOML");
        let credential = &parsed["tools"][0]["credentials"][0];
        assert_eq!(credential["handle"].as_str(), Some("attio_api_key"));
        assert_eq!(credential["vendor"].as_str(), Some("attio"));
        assert_eq!(
            credential["audience"]["host"].as_str(),
            Some("api.attio.com")
        );
        assert_eq!(credential["injection"]["type"].as_str(), Some("header"));
        assert_eq!(credential["injection"]["prefix"].as_str(), Some("Bearer "));
        let effects = parsed["tools"][0]["effects"]
            .as_array()
            .expect("effects array");
        assert!(
            effects
                .iter()
                .any(|effect| effect.as_str() == Some("use_secret")),
            "the tool must declare use_secret: {effects:?}"
        );
    }

    /// The REAL seam: the generated manifest must survive
    /// `registry_extension_package`, which runs the production v3 parser and
    /// package validation. The TOML-parse test above is not sufficient — it
    /// proved the string was well-formed TOML, not that the host accepts it.
    #[test]
    fn attio_package_builds_through_the_production_package_validator() {
        let entry = entry_named("attio");
        let capabilities = caps(
            r#"{"attio_api_key":{"secret_name":"attio_api_key","location":{"type":"bearer"},"host_patterns":["api.attio.com"]}}"#,
        );
        // A real WASI component: the validator rejects core modules, and a stub
        // would fail for that reason instead of exercising manifest validation.
        let module = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../ironclaw_first_party_extensions/assets/github/wasm/github_tool.wasm"),
        )
        .expect("bundled component fixture is readable");

        if let Err(error) = ironhub_tool_package(&entry, module, capabilities, &[]) {
            panic!("attio must install; production validator rejected it: {error}");
        }
    }

    /// A tool with no credentials keeps the previous shape exactly.
    #[test]
    fn credential_free_tools_are_unchanged() {
        let entry = entry_named("near-rpc");
        let manifest = generic_tool_manifest_with_credentials(
            &entry,
            "wasm/near_rpc_tool.wasm",
            "in.json",
            "out.json",
            br#"{"version":"0.1.0"}"#,
        )
        .expect("no credentials is valid");
        assert!(!manifest.contains("use_secret"), "{manifest}");
        assert!(!manifest.contains("[[tools.credentials]]"), "{manifest}");
        assert!(manifest.contains(r#"effects = ["network"]"#), "{manifest}");
    }

    #[test]
    fn generic_tool_manifest_uses_current_v3_extension_contract() {
        let entry = IronHubToolEntry {
            name: "quote_tool".to_string(),
            crate_name: "quote_tool".to_string(),
            version: "0.1.0".to_string(),
            description: "quote \" slash \\ newline\nok".to_string(),
            provenance: IronHubProvenance::Official,
            wasm: IronHubArtifact {
                url: "https://hub.ironclaw.com/quote_tool.wasm".to_string(),
                size_bytes: 1,
                sha256: "a".repeat(64),
            },
            capabilities: IronHubArtifact {
                url: "https://hub.ironclaw.com/quote_tool.capabilities.json".to_string(),
                size_bytes: 1,
                sha256: "b".repeat(64),
            },
        };

        let manifest = generic_tool_manifest(
            &entry,
            "wasm/quote_tool_tool.wasm",
            "schemas/quote_tool/invoke.input.v1.json",
            "schemas/quote_tool/raw_output.v1.json",
            r#"["network"]"#,
        );
        let parsed: toml::Value = toml::from_str(&manifest).expect("manifest TOML parses");
        assert_eq!(
            parsed["schema_version"].as_str(),
            Some("reborn.extension_manifest.v3")
        );
        assert_eq!(
            parsed["description"].as_str(),
            Some("quote \" slash \\ newline\nok")
        );
        assert_eq!(parsed["tools"][0]["id"].as_str(), Some("quote_tool.invoke"));
    }
}
