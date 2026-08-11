//! Registration seam for the omp-parity coding engines (issue #7392 slice 3).
//!
//! Produces the built-in first-party package PLUS the five omp capabilities
//! (`builtin.read`, `builtin.write`, `builtin.edit`, `builtin.glob`,
//! `builtin.grep`) with exact provider-name overrides (`read`, `write`,
//! `edit`, `glob`, `grep`), the pinned fixture schemas and descriptions as
//! model-visible contract bytes, and a [`FirstPartyCapabilityHandler`]
//! adapter dispatching to `ironclaw_extension_support::coding::omp::*`
//! through the ordinary first-party capability path (CapabilityHost,
//! authorization, approvals, resource accounting, RootFilesystem/MountView,
//! durable tool results).
//!
//! Two canonical ids overlap with the stock builtins: `builtin.glob` and
//! `builtin.grep`. The temporary benchmark package replaces those entries
//! and removes the remaining legacy coding tools so the model sees only the
//! five exact omp names.
//!
//! ⚠️ TEMPORARY benchmark override (revert at cutover): the omp surface is
//! enabled in PRODUCTION builds for the /benchmark panel (issue #7392) — the
//! stock production package/handler builders now include the five omp
//! capabilities unconditionally. The atomic cutover removes the old tools;
//! the omp surface then becomes the only surface and this override (plus the
//! `// ⚠️ TEMPORARY benchmark override` markers at the wiring points in
//! `mod.rs`) goes away.
//!
//! Documented divergence from the stock coding path: the stock arm runs
//! `normalize_optional_null_sentinels` (keyed on its derived schema names)
//! before dispatch; the omp schemas are pinned fixture bytes under their own
//! refs, so that normalization does not apply here — optional fields
//! populated with the string `"null"` reach the omp engines verbatim and get
//! the pinned engine error rather than graceful absent-field handling. This
//! is the exact pinned contract; revisit only if the benchmark arm shows a
//! real model-behavior delta.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use ironclaw_extension_registry::{
    CapabilityManifest, CapabilityVisibility, ExtensionError, ExtensionPackage,
};
use ironclaw_extension_support::coding::omp::{
    OmpEngineContext, OmpEngineError, OmpEngineErrorKind, OmpSnapshotRegistry,
};
use ironclaw_host_api::{
    capability::{EffectKind, PermissionMode},
    capability_profile::CapabilityProfileSchemaRef,
    dispatch::RuntimeDispatchErrorKind,
    error::HostApiError,
    ids::{CapabilityId, ProviderToolName},
    path::VirtualPath,
    resource::ResourceUsage,
    runtime_policy::ProcessBackendKind,
};

use super::{
    APPLY_PATCH_CAPABILITY_ID, GLOB_CAPABILITY_ID, GREP_CAPABILITY_ID, LIST_DIR_CAPABILITY_ID,
    MAX_FIRST_PARTY_INPUT_BYTES, MAX_WRITE_FILE_INPUT_BYTES, READ_FILE_CAPABILITY_ID,
    WRITE_FILE_CAPABILITY_ID, builtin_first_party_package,
};
use crate::{
    FirstPartyCapabilityError, FirstPartyCapabilityHandler, FirstPartyCapabilityRegistry,
    FirstPartyCapabilityRequest, FirstPartyCapabilityResult,
};

/// Canonical capability id of the omp `read` engine (slice 2). New id —
/// no stock builtin shares it.
pub const OMP_READ_CAPABILITY_ID: &str = "builtin.read";
/// Canonical capability id of the omp `write` engine (slice 2). New id.
pub const OMP_WRITE_CAPABILITY_ID: &str = "builtin.write";
/// Canonical capability id of the omp hashline `edit` engine (slice 2).
/// New id.
pub const OMP_EDIT_CAPABILITY_ID: &str = "builtin.edit";
/// The omp `glob` engine rides the existing `builtin.glob` canonical id
/// (replacing the stock v1 glob capability in the omp-extended package).
/// See the module docs.
///
/// Canonical ids stay namespaced (`builtin.*`); only the model-visible names
/// are overridden to the exact unqualified omp names.
pub const OMP_GLOB_CAPABILITY_ID: &str = GLOB_CAPABILITY_ID;
/// The omp `grep` engine rides the existing `builtin.grep` canonical id
/// (replacing the stock v1 grep capability in the omp-extended package).
pub const OMP_GREP_CAPABILITY_ID: &str = GREP_CAPABILITY_ID;

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

/// The built-in first-party package extended with the five omp capabilities.
///
/// Starts from the ordinary builtin package, applies the process-backend
/// restriction, and swaps the two overlapping ids (`builtin.glob`/
/// `builtin.grep`) for their omp counterparts while appending the three new
/// ids (`builtin.read`/`builtin.write`/`builtin.edit`). The four old coding
/// tools (`read_file`, `write_file`, `list_dir`, `apply_patch`) are REMOVED
/// so the benchmark arm's model surface is omp-only for coding tools —
/// otherwise models keep calling the familiar old names and the A/B measures
/// tool preference instead of tool quality.
///
/// ⚠️ TEMPORARY benchmark override (issue #7392 bench arm): this removal is
/// part of the flip and is exactly the atomic cutover's end-state; revert the
/// whole override at cutover.
pub fn omp_coding_package(
    process_backend: ProcessBackendKind,
) -> Result<ExtensionPackage, ExtensionError> {
    let mut package = builtin_first_party_package()?;
    super::restrict_package_for_process_backend(&mut package, process_backend)?;
    let mut manifest = package.manifest;
    manifest.capabilities.retain(|capability| {
        let id = capability.id.as_str();
        id != GLOB_CAPABILITY_ID
            && id != GREP_CAPABILITY_ID
            && id != READ_FILE_CAPABILITY_ID
            && id != WRITE_FILE_CAPABILITY_ID
            && id != LIST_DIR_CAPABILITY_ID
            && id != APPLY_PATCH_CAPABILITY_ID
    });
    manifest.capabilities.extend(omp_coding_manifests()?);
    ExtensionPackage::from_manifest(manifest, VirtualPath::new("/system/extensions/builtin")?)
}

fn omp_coding_manifests() -> Result<Vec<CapabilityManifest>, ExtensionError> {
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

/// Register the omp handler adapter for the five omp capability ids.
///
/// Overwrites the stock builtin handler for `builtin.glob`/`builtin.grep`
/// (upsert semantics of [`FirstPartyCapabilityRegistry::insert_handler`]);
/// the other builtin ids keep their stock handlers.
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
        let wall_clock_ms = start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        let output_bytes =
            super::bounded_output_bytes(&output, super::FIRST_PARTY_MAX_OUTPUT_BYTES).map_err(
                |error| error.with_usage(ResourceUsage::default().set_wall_clock_ms(wall_clock_ms)),
            )?;
        Ok(FirstPartyCapabilityResult::new(
            output,
            ResourceUsage::default()
                .set_wall_clock_ms(wall_clock_ms)
                .set_output_bytes(output_bytes)
                .set_process_count(process_count),
        ))
    }
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
