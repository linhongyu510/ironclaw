//! Exact omp coding surface for the always-on first-party package (issue #7392).
//!
//! Registers `read`, `write`, `edit`, `glob`, and `grep` with the pinned omp
//! schemas, prompts, provider names, and engine behavior. These capabilities
//! use the ordinary first-party dispatch path, so authorization, approvals,
//! resource accounting, mount scoping, and durable artifact handling remain
//! host-owned.

use std::sync::Arc;
use std::time::Instant;

use super::{
    GLOB_CAPABILITY_ID, GREP_CAPABILITY_ID, MAX_FIRST_PARTY_INPUT_BYTES,
    MAX_WRITE_FILE_INPUT_BYTES, builtin_first_party_package,
};
use crate::first_party::PendingFirstPartyArtifact;
use crate::{
    FirstPartyCapabilityError, FirstPartyCapabilityHandler, FirstPartyCapabilityRegistry,
    FirstPartyCapabilityRequest, FirstPartyCapabilityResult,
};
use async_trait::async_trait;
use ironclaw_extension_registry::{
    CapabilityManifest, CapabilityVisibility, ExtensionError, ExtensionPackage,
};
use ironclaw_extension_support::coding::omp::{
    OmpEngineContext, OmpEngineError, OmpEngineErrorKind, OmpSnapshotRegistry,
};
use ironclaw_host_api::{
    artifact::{
        ARTIFACT_INLINE_PREVIEW_MAX_BYTES, ArtifactOwnerScope, ArtifactRef, ArtifactWriteError,
        ArtifactWriteMetadata,
    },
    capability::{EffectKind, PermissionMode},
    capability_profile::CapabilityProfileSchemaRef,
    dispatch::RuntimeDispatchErrorKind,
    error::HostApiError,
    ids::{CapabilityId, ProviderToolName},
    path::VirtualPath,
    resource::ResourceUsage,
    result_meta::OutputDigest,
    runtime_policy::ProcessBackendKind,
};
use ironclaw_loop_contracts::ContentDigest;

/// Canonical capability id of the omp `read` engine.
pub const OMP_READ_CAPABILITY_ID: &str = "builtin.read";
/// Canonical capability id of the omp `write` engine.
pub const OMP_WRITE_CAPABILITY_ID: &str = "builtin.write";
/// Canonical capability id of the omp hashline `edit` engine.
pub const OMP_EDIT_CAPABILITY_ID: &str = "builtin.edit";
/// Canonical capability id of the omp `glob` engine.
pub const OMP_GLOB_CAPABILITY_ID: &str = GLOB_CAPABILITY_ID;
/// Canonical capability id of the omp `grep` engine.
pub const OMP_GREP_CAPABILITY_ID: &str = GREP_CAPABILITY_ID;

const OMP_ARTIFACT_PREVIEW_MAX_BYTES: usize = 8 * 1024;

/// Exact model-visible provider names (the pinned omp tool names).
const OMP_READ_PROVIDER_TOOL_NAME: &str = "read";
const OMP_WRITE_PROVIDER_TOOL_NAME: &str = "write";
const OMP_EDIT_PROVIDER_TOOL_NAME: &str = "edit";
const OMP_GLOB_PROVIDER_TOOL_NAME: &str = "glob";
const OMP_GREP_PROVIDER_TOOL_NAME: &str = "grep";

/// Pinned model-visible descriptions. `read` uses the RENDERED prompt for
/// the issue-target context (fixture `prompts/read.rendered.md`); the others
/// use the verbatim pinned prompt files (`write.md`, `hashline.md`,
/// `glob.md`, `grep.md` — upstream renders `write`/`edit` with an empty
/// context and the fixture pins the `glob`/`grep` templates raw).
const OMP_READ_DESCRIPTION: &str =
    ironclaw_extension_support::coding::omp::omp_assets::OMP_READ_DESCRIPTION;
const OMP_WRITE_DESCRIPTION: &str =
    ironclaw_extension_support::coding::omp::omp_assets::OMP_WRITE_DESCRIPTION;
const OMP_EDIT_DESCRIPTION: &str =
    ironclaw_extension_support::coding::omp::omp_assets::OMP_EDIT_DESCRIPTION;
const OMP_GLOB_DESCRIPTION: &str =
    ironclaw_extension_support::coding::omp::omp_assets::OMP_GLOB_DESCRIPTION;
const OMP_GREP_DESCRIPTION: &str =
    ironclaw_extension_support::coding::omp::omp_assets::OMP_GREP_DESCRIPTION;

/// Schema refs resolving through `super::schemas::resolve_builtin_input_schema_ref`
/// to the pinned fixture schema assets (byte-identical, verified by the
/// `omp_registration_assets_byte_match_pinned_fixtures` crate test).
const OMP_READ_SCHEMA_REF: &str = "schemas/builtin/omp.read.input.v1.json";
const OMP_WRITE_SCHEMA_REF: &str = "schemas/builtin/omp.write.input.v1.json";
const OMP_EDIT_SCHEMA_REF: &str = "schemas/builtin/omp.edit.input.v1.json";
const OMP_GLOB_SCHEMA_REF: &str = "schemas/builtin/omp.glob.input.v1.json";
const OMP_GREP_SCHEMA_REF: &str = "schemas/builtin/omp.grep.input.v1.json";

#[derive(Debug, Clone, Copy)]
struct OmpCapabilityMetadata {
    id: &'static str,
    provider_tool_name: &'static str,
    description: &'static str,
    effects: &'static [EffectKind],
    max_input_bytes: usize,
    schema_ref: &'static str,
}

const OMP_CAPABILITIES: &[OmpCapabilityMetadata] = &[
    OmpCapabilityMetadata {
        id: OMP_READ_CAPABILITY_ID,
        provider_tool_name: OMP_READ_PROVIDER_TOOL_NAME,
        description: OMP_READ_DESCRIPTION,
        effects: &[EffectKind::ReadFilesystem],
        max_input_bytes: MAX_FIRST_PARTY_INPUT_BYTES,
        schema_ref: OMP_READ_SCHEMA_REF,
    },
    OmpCapabilityMetadata {
        id: OMP_WRITE_CAPABILITY_ID,
        provider_tool_name: OMP_WRITE_PROVIDER_TOOL_NAME,
        description: OMP_WRITE_DESCRIPTION,
        effects: &[EffectKind::WriteFilesystem],
        max_input_bytes: MAX_WRITE_FILE_INPUT_BYTES,
        schema_ref: OMP_WRITE_SCHEMA_REF,
    },
    OmpCapabilityMetadata {
        id: OMP_EDIT_CAPABILITY_ID,
        provider_tool_name: OMP_EDIT_PROVIDER_TOOL_NAME,
        description: OMP_EDIT_DESCRIPTION,
        effects: &[
            EffectKind::ReadFilesystem,
            EffectKind::WriteFilesystem,
            EffectKind::DeleteFilesystem,
        ],
        max_input_bytes: MAX_WRITE_FILE_INPUT_BYTES,
        schema_ref: OMP_EDIT_SCHEMA_REF,
    },
    OmpCapabilityMetadata {
        id: GLOB_CAPABILITY_ID,
        provider_tool_name: OMP_GLOB_PROVIDER_TOOL_NAME,
        description: OMP_GLOB_DESCRIPTION,
        effects: &[EffectKind::ReadFilesystem],
        max_input_bytes: MAX_FIRST_PARTY_INPUT_BYTES,
        schema_ref: OMP_GLOB_SCHEMA_REF,
    },
    OmpCapabilityMetadata {
        id: GREP_CAPABILITY_ID,
        provider_tool_name: OMP_GREP_PROVIDER_TOOL_NAME,
        description: OMP_GREP_DESCRIPTION,
        effects: &[EffectKind::ReadFilesystem],
        max_input_bytes: MAX_FIRST_PARTY_INPUT_BYTES,
        schema_ref: OMP_GREP_SCHEMA_REF,
    },
];

/// The canonical always-on first-party package with the five omp coding
/// capabilities, restricted for the selected process backend.
pub fn omp_coding_package(
    process_backend: ProcessBackendKind,
) -> Result<ExtensionPackage, ExtensionError> {
    let mut package = builtin_first_party_package()?;
    super::restrict_package_for_process_backend(&mut package, process_backend)?;
    let manifest = package.manifest;
    ExtensionPackage::from_manifest(manifest, VirtualPath::new("/system/extensions/builtin")?)
}

pub(super) fn omp_coding_manifests() -> Result<Vec<CapabilityManifest>, ExtensionError> {
    OMP_CAPABILITIES
        .iter()
        .map(omp_capability_manifest)
        .collect()
}

fn omp_capability_manifest(
    metadata: &OmpCapabilityMetadata,
) -> Result<CapabilityManifest, ExtensionError> {
    Ok(CapabilityManifest {
        id: CapabilityId::new(metadata.id)?,
        description: metadata.description.to_string(),
        effects: metadata.effects.to_vec(),
        default_permission: PermissionMode::Allow,
        visibility: CapabilityVisibility::Model,
        standard_op: None,
        input_schema_ref: CapabilityProfileSchemaRef::new(metadata.schema_ref)?,
        output_schema_ref: None,
        prompt_doc_ref: None,
        required_host_ports: Vec::new(),
        runtime_credentials: Vec::new(),
        network_targets: Vec::new(),
        max_egress_bytes: None,
        resource_profile: super::resource_profile(),
        origin_gate_matrix: Some(super::first_party_origin_gate_matrix(metadata.id)),
        provider_tool_name: Some(ProviderToolName::new(metadata.provider_tool_name)?),
    })
}

/// Register handlers for the five canonical omp coding capabilities.
pub fn insert_omp_coding_handlers(
    registry: &mut FirstPartyCapabilityRegistry,
) -> Result<(), HostApiError> {
    let handler = Arc::new(OmpCodingTools::new(
        Arc::new(OmpSnapshotRegistry::default()),
    ));
    for metadata in OMP_CAPABILITIES {
        registry.insert_handler(CapabilityId::new(metadata.id)?, Arc::clone(&handler));
    }
    Ok(())
}

/// First-party handler adapter translating the five omp capability ids to the
/// `coding::omp` engines.
///
/// Mirrors the stock coding path's resource discipline: bounded input size,
/// bounded output bytes, wall-clock + output-byte accounting. The engine
/// context is built from the already-authorized request (filesystem, mount
/// view, caller scope, run identity) plus the shared snapshot registry that
/// binds hashline edit tags to reads from the SAME run.
pub struct OmpCodingTools {
    snapshots: Arc<OmpSnapshotRegistry>,
    post_edit_check_seen: crate::post_edit_check::PostEditCheckSeenLines,
}

impl OmpCodingTools {
    pub fn new(snapshots: Arc<OmpSnapshotRegistry>) -> Self {
        Self {
            snapshots,
            post_edit_check_seen: crate::post_edit_check::PostEditCheckSeenLines::default(),
        }
    }
}

#[async_trait]
impl FirstPartyCapabilityHandler for OmpCodingTools {
    async fn dispatch(
        &self,
        request: FirstPartyCapabilityRequest,
    ) -> Result<FirstPartyCapabilityResult, FirstPartyCapabilityError> {
        let Some(metadata) = omp_capability_metadata(request.capability_id.as_str()) else {
            return Err(FirstPartyCapabilityError::new(
                RuntimeDispatchErrorKind::UndeclaredCapability,
            ));
        };
        super::bounded_input_size_with_max(&request.input, metadata.max_input_bytes)?;
        let start = Instant::now();
        let mounts = request.mounts.clone().ok_or_else(|| {
            FirstPartyCapabilityError::new(RuntimeDispatchErrorKind::FilesystemDenied)
        })?;
        let context = OmpEngineContext {
            filesystem: Arc::clone(&request.services.filesystem),
            artifact_reader: request.services.artifact_reader.clone(),
            mounts,
            scope: request.scope.clone(),
            run_id: request.run_id,
            snapshots: Arc::clone(&self.snapshots),
        };
        let mut output = match request.capability_id.as_str() {
            OMP_READ_CAPABILITY_ID => {
                ironclaw_extension_support::coding::omp::read(&context, request.input.clone()).await
            }
            OMP_WRITE_CAPABILITY_ID => {
                ironclaw_extension_support::coding::omp::write(&context, request.input.clone())
                    .await
            }
            OMP_EDIT_CAPABILITY_ID => {
                ironclaw_extension_support::coding::omp::edit(&context, request.input.clone()).await
            }
            GLOB_CAPABILITY_ID => {
                ironclaw_extension_support::coding::omp::glob(&context, request.input.clone()).await
            }
            GREP_CAPABILITY_ID => {
                ironclaw_extension_support::coding::omp::grep(&context, request.input.clone()).await
            }
            _ => unreachable!("omp handler is registered only for the five omp ids"),
        }
        .map_err(omp_error)?;
        let mut process_count = 0;
        if matches!(
            request.capability_id.as_str(),
            OMP_WRITE_CAPABILITY_ID | OMP_EDIT_CAPABILITY_ID
        ) && let Some(service) = &request.services.post_edit_check
        {
            let edited_scoped_path = request
                .input
                .get("path")
                .and_then(serde_json::Value::as_str);
            if let Some(check) = crate::post_edit_check::run_post_edit_check(
                &self.post_edit_check_seen,
                service.process.as_ref(),
                &request.scope,
                request.mounts.as_ref(),
                edited_scoped_path,
                &service.config,
            )
            .await
            {
                if let Some(object) = output.as_object_mut() {
                    object.insert("post_edit_check".to_string(), check);
                }
                process_count = 1;
            }
        }
        let canonical_output_digest = canonical_output_digest(&output)?;
        let wall_clock_ms = start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        let (output, pending_artifact, output_bytes) = artifact_backed_output(&request, output)
            .await
            .map_err(|error| {
                error.with_usage(ResourceUsage::default().set_wall_clock_ms(wall_clock_ms))
            })?;
        let result = FirstPartyCapabilityResult::new(
            output,
            ResourceUsage::default()
                .set_wall_clock_ms(wall_clock_ms)
                .set_output_bytes(output_bytes)
                .set_process_count(process_count),
        )
        .with_canonical_output_digest(canonical_output_digest);
        Ok(match pending_artifact {
            Some(artifact) => result.with_pending_artifact(artifact),
            None => result,
        })
    }
}

fn canonical_output_digest(
    output: &serde_json::Value,
) -> Result<OutputDigest, FirstPartyCapabilityError> {
    ContentDigest::from_json_value(output)
        .map(|digest| OutputDigest::new(digest.0))
        .map_err(|_| FirstPartyCapabilityError::new(RuntimeDispatchErrorKind::OutputDecode))
}

async fn artifact_backed_output(
    request: &FirstPartyCapabilityRequest,
    output: serde_json::Value,
) -> Result<(serde_json::Value, Option<PendingFirstPartyArtifact>, u64), FirstPartyCapabilityError>
{
    let serde_json::Value::Object(mut object) = output else {
        let output_bytes =
            super::bounded_output_bytes(&output, super::FIRST_PARTY_MAX_OUTPUT_BYTES)?;
        return Ok((output, None, output_bytes));
    };
    let Some(serde_json::Value::String(raw_output)) = object.remove("output") else {
        let output = serde_json::Value::Object(object);
        let output_bytes =
            super::bounded_output_bytes(&output, super::FIRST_PARTY_MAX_OUTPUT_BYTES)?;
        return Ok((output, None, output_bytes));
    };
    if raw_output.len() <= ARTIFACT_INLINE_PREVIEW_MAX_BYTES {
        object.insert("output".to_string(), serde_json::Value::String(raw_output));
        let output = serde_json::Value::Object(object);
        let output_bytes =
            super::bounded_output_bytes(&output, super::FIRST_PARTY_MAX_OUTPUT_BYTES)?;
        return Ok((output, None, output_bytes));
    }

    let namespace = request
        .services
        .artifact_namespace
        .ok_or_else(|| FirstPartyCapabilityError::new(RuntimeDispatchErrorKind::Backend))?;
    let persistence = request
        .services
        .artifact_persistence
        .as_ref()
        .ok_or_else(|| FirstPartyCapabilityError::new(RuntimeDispatchErrorKind::MethodMissing))?;
    let raw_len = u64::try_from(raw_output.len())
        .map_err(|_| FirstPartyCapabilityError::new(RuntimeDispatchErrorKind::Resource))?;
    let handle = persistence
        .allocate(ArtifactWriteMetadata {
            write_key: Some(request.scope.invocation_id),
            owner_scope: ArtifactOwnerScope::from_resource_scope(&request.scope),
            namespace,
            producer_capability_id: request.capability_id.clone(),
            content_type: "text/plain; charset=utf-8".to_string(),
            expected_bytes: Some(raw_len),
        })
        .await
        .map_err(artifact_write_error)?;
    let artifact_ref = ArtifactRef::new(handle.artifact_id());
    let preview = artifact_preview(&raw_output, &artifact_ref);
    let output = serde_json::json!({
        "output": preview,
        "artifact_ref": artifact_ref.to_string(),
        "total_bytes": raw_len,
    });
    Ok((
        output,
        Some(PendingFirstPartyArtifact {
            handle,
            bytes: raw_output.into_bytes(),
        }),
        raw_len,
    ))
}

fn artifact_write_error(error: ArtifactWriteError) -> FirstPartyCapabilityError {
    let kind = match error {
        ArtifactWriteError::Budget => RuntimeDispatchErrorKind::Resource,
        ArtifactWriteError::InvalidHandle
        | ArtifactWriteError::DigestMismatch
        | ArtifactWriteError::Storage => RuntimeDispatchErrorKind::OperationFailed,
    };
    FirstPartyCapabilityError::new(kind)
}

fn artifact_preview(raw_output: &str, artifact_ref: &ArtifactRef) -> String {
    let footer = format!("\n[raw output: {artifact_ref}]");
    let marker = "\n\n... [artifact output elided] ...\n\n";
    let content_budget = OMP_ARTIFACT_PREVIEW_MAX_BYTES
        .saturating_sub(footer.len())
        .saturating_sub(marker.len());
    let head_budget = content_budget / 2;
    let tail_budget = content_budget.saturating_sub(head_budget);
    let head_end = floor_char_boundary(raw_output, head_budget);
    let tail_start = ceil_char_boundary(raw_output, raw_output.len().saturating_sub(tail_budget));
    format!(
        "{}{marker}{}{}",
        &raw_output[..head_end],
        &raw_output[tail_start..],
        footer
    )
}

fn floor_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while index < value.len() && !value.is_char_boundary(index) {
        index += 1;
    }
    index
}

fn omp_capability_metadata(capability_id: &str) -> Option<OmpCapabilityMetadata> {
    OMP_CAPABILITIES
        .iter()
        .copied()
        .find(|metadata| metadata.id == capability_id)
}

/// Map an omp engine failure onto the first-party capability error surface.
///
/// The pinned omp error text is the model-visible contract, but it is free
/// text (paths, newlines) that the strict `SafeSummary` validator rejects,
/// so it rides the untrusted diagnostic channel exactly like the stock shell
/// path routes raw failure causes.
fn omp_error(error: OmpEngineError) -> FirstPartyCapabilityError {
    let kind = match error.kind() {
        OmpEngineErrorKind::Input => RuntimeDispatchErrorKind::InputEncode,
        OmpEngineErrorKind::FilesystemDenied | OmpEngineErrorKind::PathResolution => {
            RuntimeDispatchErrorKind::FilesystemDenied
        }
        OmpEngineErrorKind::ResourceLimit => RuntimeDispatchErrorKind::Resource,
        _ => RuntimeDispatchErrorKind::OperationFailed,
    };
    FirstPartyCapabilityError::dispatch_with_diagnostic(
        kind,
        None,
        bounded_diagnostic(
            error.message(),
            super::FIRST_PARTY_MAX_OUTPUT_BYTES as usize,
        ),
    )
}

fn bounded_diagnostic(message: &str, max_bytes: usize) -> String {
    if message.len() <= max_bytes {
        return message.to_string();
    }
    const MARKER: &str = "\n[diagnostic truncated]";
    let content_limit = max_bytes.saturating_sub(MARKER.len());
    let mut end = content_limit.min(message.len());
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = message[..end].to_string();
    if MARKER.len() <= max_bytes {
        bounded.push_str(MARKER);
    }
    bounded
}

#[cfg(test)]
mod tests {
    use super::bounded_diagnostic;

    #[test]
    fn diagnostic_bound_preserves_utf8_and_never_exceeds_limit() {
        let bounded = bounded_diagnostic("é".repeat(100).as_str(), 31);

        assert!(bounded.is_char_boundary(bounded.len()));
        assert!(bounded.len() <= 31, "{} bytes", bounded.len());
        assert!(bounded.ends_with("[diagnostic truncated]"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_digest_covers_the_full_output_before_artifact_previewing() {
        let prefix = "a".repeat(8 * 1024);
        let suffix = "z".repeat(8 * 1024);
        let first = serde_json::json!({
            "output": format!("{prefix}{}{}", "m".repeat(32 * 1024), suffix),
        });
        let same = first.clone();
        let changed_middle = serde_json::json!({
            "output": format!("{prefix}{}{}", "n".repeat(32 * 1024), suffix),
        });

        assert_eq!(
            canonical_output_digest(&first).expect("first digest"),
            canonical_output_digest(&same).expect("same digest"),
        );
        assert_ne!(
            canonical_output_digest(&first).expect("first digest"),
            canonical_output_digest(&changed_middle).expect("changed digest"),
        );
    }
}
