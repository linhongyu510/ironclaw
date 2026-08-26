//! Memory tools ride the ordinary first-party capability registry.
//!
//! Tools are manifest-declared and registry-routed: composition registers the
//! BOUND memory package's declared capability ids to its provider's handler
//! ([`register_memory_tool_handler`]), so the host never enumerates memory
//! tool ids — the memory contract itself is lifecycle-only
//! (`ironclaw_memory::MemoryService`). This file owns:
//!
//! - [`MemoryToolProfile`] / [`memory_tool_profiles`]: the per-tool dispatch
//!   profile derived from the bound package's manifest (mount authority from
//!   declared effects, input schema for null-sentinel normalization) — shared
//!   by every provider's handler.
//! - [`NativeMemoryToolHandler`]: the NATIVE provider's handler — constructs
//!   the native service over each request's filesystem (fs-identity cache,
//!   audit-backed prompt-write-safety sink) and serves the conventional tools
//!   native declares. mem0's equivalent lives in composition (the one layer
//!   allowed to name the mem0 crate). The model-visible wire shapes come from
//!   `ironclaw_memory`'s shared output helpers, so backends cannot drift.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use ironclaw_event_log::AuditSink;
use ironclaw_extension_registry::ExtensionPackage;
use ironclaw_filesystem::RootFilesystem;
use ironclaw_host_api::{
    audit::{ActionResultSummary, ActionSummary, AuditEnvelope, AuditStage, DecisionSummary},
    capability::EffectKind,
    dispatch::RuntimeDispatchErrorKind,
    ids::{AuditEventId, CapabilityId, CorrelationId, ExtensionId},
    resource::ResourceUsage,
};
use ironclaw_memory::{
    AUTOMATION_LESSONS_SET_CAPABILITY_ID, AutomationOwner, MEMORY_READ_CAPABILITY_ID,
    MEMORY_SEARCH_CAPABILITY_ID, MEMORY_TREE_CAPABILITY_ID, MEMORY_WRITE_CAPABILITY_ID,
    MemoryEventSinkError, MemoryInvocation, MemoryServiceError, MemoryServiceErrorKind,
    MemoryServiceLessonsSetRequest, MemoryServiceProfileSetRequest, MemoryServiceReadRequest,
    MemoryServiceSearchRequest, MemoryServiceTreeRequest, MemoryServiceWriteRequest,
    PROFILE_SET_CAPABILITY_ID, PromptSafetyReasonCode, PromptWriteOperation,
    PromptWriteSafetyEvent, PromptWriteSafetyEventKind, PromptWriteSafetyEventSink,
    lessons_set_response_output, profile_set_response_output, read_response_output,
    search_response_output, tree_response_output, write_response_output,
};
use ironclaw_memory_native::NativeMemoryService;
use serde_json::Value;

use crate::{
    FirstPartyCapabilityError, FirstPartyCapabilityHandler, FirstPartyCapabilityRegistry,
    FirstPartyCapabilityRequest, FirstPartyCapabilityResult,
};

use super::{
    FIRST_PARTY_MAX_OUTPUT_BYTES, bounded_output_bytes, input_error,
    normalize_optional_null_sentinels_against_schema, operation_error,
    resolve_native_memory_input_schema_ref,
};

const MEMORY_PROMPT_SAFETY_EXTENSION_ID: &str = "memory.prompt_safety";

/// Per-tool dispatch profile derived from the BOUND package's manifest: the
/// mount authority the host enforces (from the tool's declared effects) and
/// the declared input schema the null-sentinel normalization consults. The
/// host derives this from manifest data — it never hardcodes per-tool policy.
#[derive(Clone)]
pub struct MemoryToolProfile {
    pub requires_write_mount: bool,
    pub input_schema: Option<Value>,
}

/// Derive the per-tool dispatch profiles from a memory package's manifest.
pub fn memory_tool_profiles(
    package: &ExtensionPackage,
) -> BTreeMap<CapabilityId, MemoryToolProfile> {
    package
        .manifest
        .capabilities
        .iter()
        .map(|capability| {
            (
                capability.id.clone(),
                MemoryToolProfile {
                    requires_write_mount: capability.effects.contains(&EffectKind::WriteFilesystem),
                    input_schema: resolve_native_memory_input_schema_ref(
                        capability.input_schema_ref.as_str(),
                    ),
                },
            )
        })
        .collect()
}

/// Register the bound provider's tool handler for every capability id its
/// package declares — wrapped in the host-owned [`MemoryToolGuard`], so the
/// mount check, input normalization, and output bounding are enforced ONCE
/// here for every provider, never re-implemented (or forgotten) per handler.
/// Registration is the only way a memory tool becomes dispatchable, which
/// makes the guard unforgeable; nothing is registered when no provider is
/// bound, so the tools are absent from dispatch exactly as they are absent
/// from the surface.
pub fn register_memory_tool_handler(
    registry: &mut FirstPartyCapabilityRegistry,
    package: &ExtensionPackage,
    handler: Arc<dyn FirstPartyCapabilityHandler>,
) {
    let guarded: Arc<dyn FirstPartyCapabilityHandler> = Arc::new(MemoryToolGuard {
        profiles: memory_tool_profiles(package),
        inner: handler,
    });
    for capability in &package.manifest.capabilities {
        registry.insert_handler_dyn(capability.id.clone(), Arc::clone(&guarded));
    }
}

/// Host-owned guard around every registered memory tool handler. Derives each
/// tool's authority and schema FROM THE MANIFEST and enforces, in order:
///
/// 1. the id is one the bound manifest declares (fail closed otherwise);
/// 2. the `/memory` mount check — write+delete authority exactly when the
///    tool's declared effects include a filesystem write;
/// 3. schema-driven null-sentinel input normalization;
/// 4. after the provider handler runs: the model-visible output byte bound
///    and usage stamping.
///
/// Provider handlers behind this guard implement pure tool BEHAVIOR only.
struct MemoryToolGuard {
    profiles: BTreeMap<CapabilityId, MemoryToolProfile>,
    inner: Arc<dyn FirstPartyCapabilityHandler>,
}

#[async_trait]
impl FirstPartyCapabilityHandler for MemoryToolGuard {
    async fn dispatch(
        &self,
        mut request: FirstPartyCapabilityRequest,
    ) -> Result<FirstPartyCapabilityResult, FirstPartyCapabilityError> {
        let start = std::time::Instant::now();
        let Some(profile) = self.profiles.get(&request.capability_id).cloned() else {
            return Err(FirstPartyCapabilityError::new(
                RuntimeDispatchErrorKind::UndeclaredCapability,
            ));
        };
        ensure_memory_mount(&request, profile.requires_write_mount)?;
        normalize_memory_tool_input(&mut request.input, &profile);
        let result = self.inner.dispatch(request).await?;
        finish_memory_tool_result(result.output, start)
    }
}

/// Convenience for local-testing/harness compositions that bind the default
/// native provider: build native's bundle + handler and register its declared
/// tools. Mirrors what production composition does with the resolved binding.
pub fn register_native_memory_tools(
    registry: &mut FirstPartyCapabilityRegistry,
) -> Result<(), ironclaw_extension_registry::ExtensionError> {
    let bundle = crate::memory_native_extension::native_memory_provider_bundle()?;
    let handler = Arc::new(NativeMemoryToolHandler::from_package(&bundle.package));
    register_memory_tool_handler(registry, &bundle.package, handler);
    Ok(())
}

struct CachedMemoryService {
    filesystem: Arc<dyn RootFilesystem>,
    audit_sink: Option<Arc<dyn AuditSink>>,
    service: Arc<NativeMemoryService>,
}

/// The native provider's tool handler: serves the conventional memory tools
/// over a per-request native service (constructed over the request's
/// filesystem, cached on filesystem identity, with the audit-backed
/// prompt-write-safety sink attached when the request carries an audit sink).
pub struct NativeMemoryToolHandler {
    profiles: BTreeMap<CapabilityId, MemoryToolProfile>,
    cached: Mutex<Option<CachedMemoryService>>,
}

impl std::fmt::Debug for NativeMemoryToolHandler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeMemoryToolHandler")
            .field("tools", &self.profiles.len())
            .finish()
    }
}

impl NativeMemoryToolHandler {
    /// Build the handler for native's (or a native-shaped) memory package.
    pub fn from_package(package: &ExtensionPackage) -> Self {
        Self {
            profiles: memory_tool_profiles(package),
            cached: Mutex::new(None),
        }
    }

    fn service_for(
        &self,
        request: &FirstPartyCapabilityRequest,
    ) -> Result<Arc<NativeMemoryService>, FirstPartyCapabilityError> {
        let mut cached = self.cached.lock().map_err(|_| operation_error())?;
        if let Some(cached) = cached.as_ref()
            && Arc::ptr_eq(&cached.filesystem, &request.services.filesystem)
            && audit_sinks_match(
                cached.audit_sink.as_ref(),
                request.services.audit_sink.as_ref(),
            )
        {
            return Ok(Arc::clone(&cached.service));
        }

        let filesystem = Arc::clone(&request.services.filesystem);
        let audit_sink = request.services.audit_sink.clone();
        let prompt_write_safety_event_sink = audit_sink.clone().map(|audit_sink| {
            Arc::new(AuditPromptWriteSafetyEventSink { audit_sink })
                as Arc<dyn PromptWriteSafetyEventSink>
        });
        let service = Arc::new(NativeMemoryService::from_filesystem(
            Arc::clone(&filesystem),
            prompt_write_safety_event_sink,
        ));
        *cached = Some(CachedMemoryService {
            filesystem,
            audit_sink,
            service: Arc::clone(&service),
        });
        Ok(service)
    }
}

#[async_trait]
impl FirstPartyCapabilityHandler for NativeMemoryToolHandler {
    async fn dispatch(
        &self,
        request: FirstPartyCapabilityRequest,
    ) -> Result<FirstPartyCapabilityResult, FirstPartyCapabilityError> {
        // Pure behavior: the host-owned MemoryToolGuard already enforced the
        // manifest-declared mount authority, normalized the input, and will
        // bound the output.
        let start = std::time::Instant::now();
        let output = serve_native_tool(self, &request).await?;
        finish_memory_tool_result(output, start)
    }
}

/// Serve one of native's conventional tools. A declared id native does not
/// implement fails closed as an operation error — never a silent fallback.
async fn serve_native_tool(
    handler: &NativeMemoryToolHandler,
    request: &FirstPartyCapabilityRequest,
) -> Result<Value, FirstPartyCapabilityError> {
    let service = handler.service_for(request)?;
    let invocation = invocation_for_request(request);
    match request.capability_id.as_str() {
        PROFILE_SET_CAPABILITY_ID => {
            let parsed = MemoryServiceProfileSetRequest::from_tool_input(&request.input)
                .map_err(map_memory_service_error)?;
            let response = service
                .profile_set(invocation, parsed)
                .await
                .map_err(map_memory_service_error)?;
            Ok(profile_set_response_output(response))
        }

        AUTOMATION_LESSONS_SET_CAPABILITY_ID => {
            // Origin gate: scheduled (automation-fire) runs only. The
            // matrix cannot express "scheduled-only" — interactive `LoopRun`
            // and trigger-fired `ScheduledLoopRun` share one column — so the
            // handler repeats the posture check host-side, exactly like the
            // trigger-mutation tools do.
            let owner = automation_owner_for_request(request)?;
            let parsed = MemoryServiceLessonsSetRequest::from_tool_input(&request.input)
                .map_err(map_memory_service_error)?;
            let response = service
                .automation_lessons_set(invocation, &owner, parsed)
                .await
                .map_err(map_memory_service_error)?;
            Ok(lessons_set_response_output(response))
        }
        MEMORY_SEARCH_CAPABILITY_ID => {
            let parsed = MemoryServiceSearchRequest::from_tool_input(&request.input)
                .map_err(map_memory_service_error)?;
            let response = service
                .search(invocation, parsed)
                .await
                .map_err(map_memory_service_error)?;
            Ok(search_response_output(response))
        }
        MEMORY_WRITE_CAPABILITY_ID => {
            let parsed = MemoryServiceWriteRequest::from_tool_input(&request.input)
                .map_err(map_memory_service_error)?;
            let response = service
                .write(invocation, parsed)
                .await
                .map_err(map_memory_service_error)?;
            Ok(write_response_output(response))
        }
        MEMORY_READ_CAPABILITY_ID => {
            let parsed = MemoryServiceReadRequest::from_tool_input(&request.input)
                .map_err(map_memory_service_error)?;
            let response = service
                .read(invocation, parsed)
                .await
                .map_err(map_memory_service_error)?;
            Ok(read_response_output(response))
        }
        MEMORY_TREE_CAPABILITY_ID => {
            let parsed = MemoryServiceTreeRequest::from_tool_input(&request.input)
                .map_err(map_memory_service_error)?;
            let response = service
                .tree(invocation, parsed)
                .await
                .map_err(map_memory_service_error)?;
            Ok(tree_response_output(response))
        }
        // Declared in the manifest but not implemented by this provider:
        // fail closed with the model-visible operation error.
        _ => Err(operation_error()),
    }
}

/// Bind the per-automation identity for `automation_lessons_set` from the
/// host-sealed execution context.
///
/// Two checks, both mandatory:
///
/// 1. the run's origin is a scheduled (trigger-fired) loop run — an
///    interactive `LoopRun`, a product call, or a non-model routine has no
///    automation to bind and is denied;
/// 2. the typed trigger identity is present. It arrives only through the
///    trusted-trigger submit → product-context → execution-context thread;
///    it is NEVER parsed out of `external_conversation_id` or any other
///    display string, so a model-supplied value can never influence it.
pub fn automation_owner_for_request(
    request: &FirstPartyCapabilityRequest,
) -> Result<AutomationOwner, FirstPartyCapabilityError> {
    fn denied() -> FirstPartyCapabilityError {
        FirstPartyCapabilityError::with_safe_summary(
            RuntimeDispatchErrorKind::PolicyDenied,
            "automation lessons are writable only by that automation's own scheduled runs",
        )
    }
    if !matches!(
        request.origin.as_ref(),
        Some(ironclaw_host_api::invocation::InvocationOrigin::ScheduledLoopRun(_))
    ) {
        return Err(denied());
    }
    let trigger_id = request.automation_trigger_id.as_ref().ok_or_else(denied)?;
    AutomationOwner::new(trigger_id.as_str()).map_err(|_| denied())
}

fn audit_sinks_match(
    left: Option<&Arc<dyn AuditSink>>,
    right: Option<&Arc<dyn AuditSink>>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        _ => false,
    }
}

struct AuditPromptWriteSafetyEventSink {
    audit_sink: Arc<dyn AuditSink>,
}

#[async_trait]
impl PromptWriteSafetyEventSink for AuditPromptWriteSafetyEventSink {
    async fn record_prompt_write_safety_event(
        &self,
        event: PromptWriteSafetyEvent,
    ) -> Result<(), MemoryEventSinkError> {
        let Some(audit_context) = event.audit_context.as_ref() else {
            return Err(MemoryEventSinkError::new(
                "prompt-write safety event missing audit context",
            ));
        };
        let resource_scope = audit_context.resource_scope.clone();
        let record = AuditEnvelope {
            event_id: AuditEventId::new(),
            correlation_id: audit_context.correlation_id,
            stage: match event.kind {
                PromptWriteSafetyEventKind::Rejected => AuditStage::Denied,
                _ => AuditStage::After,
            },
            timestamp: Utc::now(),
            tenant_id: resource_scope.tenant_id,
            user_id: resource_scope.user_id,
            agent_id: resource_scope.agent_id,
            project_id: resource_scope.project_id,
            mission_id: resource_scope.mission_id,
            thread_id: resource_scope.thread_id,
            invocation_id: resource_scope.invocation_id,
            process_id: None,
            approval_request_id: None,
            extension_id: Some(ExtensionId::new(MEMORY_PROMPT_SAFETY_EXTENSION_ID).map_err(
                |error| {
                    MemoryEventSinkError::new(format!(
                        "invalid memory prompt-safety extension id: {error}"
                    ))
                },
            )?),
            action: ActionSummary {
                kind: prompt_write_action_kind(event.operation).to_string(),
                target: None,
                effects: vec![EffectKind::WriteFilesystem],
            },
            decision: DecisionSummary {
                kind: event
                    .reason_code
                    .map(prompt_safety_reason_projection_kind)
                    .unwrap_or_else(|| prompt_safety_event_kind_label(event.kind))
                    .to_string(),
                reason: None,
                actor: None,
            },
            result: Some(ActionResultSummary {
                success: event.kind != PromptWriteSafetyEventKind::Rejected,
                status: Some(encode_prompt_safety_metadata(&event)),
                output_bytes: None,
            }),
        };
        self.audit_sink
            .emit_audit(record)
            .await
            // security: the audit-sink error may carry backend paths/details, so it
            // is not stringified into the cross-layer sink error. The upstream
            // `PromptWriteSafetyEventUnavailable` reason is the actionable signal.
            .map_err(|_error| MemoryEventSinkError::new("audit sink unavailable"))
    }
}

fn prompt_write_action_kind(operation: PromptWriteOperation) -> &'static str {
    match operation {
        PromptWriteOperation::Write => "write_file",
        PromptWriteOperation::Append => "append_file",
        PromptWriteOperation::Patch => "patch_file",
        PromptWriteOperation::Import => "memory_import",
        PromptWriteOperation::Seed => "memory_seed",
        PromptWriteOperation::ProfileUpdate => "profile_update",
        PromptWriteOperation::AdminSystemPromptUpdate => "admin_system_prompt_update",
    }
}

fn prompt_safety_reason_projection_kind(reason: PromptSafetyReasonCode) -> &'static str {
    match reason {
        PromptSafetyReasonCode::HighRiskPromptInjection => "prompt_high_risk",
        PromptSafetyReasonCode::CriticalPromptInjection => "prompt_critical",
        PromptSafetyReasonCode::PromptWritePolicyUnavailable => "prompt_policy_unavailable",
        PromptSafetyReasonCode::PromptWritePolicyMisconfigured => "prompt_policy_misconfigured",
        PromptSafetyReasonCode::ProtectedPathRegistryUnavailable => "protected_registry_missing",
        PromptSafetyReasonCode::PromptWriteBypassNotAllowed => "prompt_bypass_denied",
        PromptSafetyReasonCode::PromptWriteSafetyEventUnavailable => "prompt_event_unavailable",
    }
}

fn prompt_safety_event_kind_label(kind: PromptWriteSafetyEventKind) -> &'static str {
    match kind {
        PromptWriteSafetyEventKind::Checked => "prompt_write_safety_checked",
        PromptWriteSafetyEventKind::Warned => "prompt_write_safety_warned",
        PromptWriteSafetyEventKind::Rejected => "prompt_write_safety_rejected",
        PromptWriteSafetyEventKind::BypassAllowed => "prompt_write_safety_bypass_allowed",
    }
}

fn encode_prompt_safety_metadata(event: &PromptWriteSafetyEvent) -> String {
    let mut pairs = vec![format!(
        "status={}",
        match event.kind {
            PromptWriteSafetyEventKind::Checked => "checked",
            PromptWriteSafetyEventKind::Warned => "warned",
            PromptWriteSafetyEventKind::Rejected => "rejected",
            PromptWriteSafetyEventKind::BypassAllowed => "bypass_allowed",
        }
    )];
    if let Some(path_hash) = &event.relative_path_hash {
        pairs.push(format!("path_hash={path_hash}"));
    }
    if let Some(path_class) = &event.protected_path_class {
        pairs.push(format!("protected_path_class={}", path_class.as_str()));
    }
    if let Some(reason) = event.reason_code {
        pairs.push(format!("reason={}", reason.as_str()));
    }
    if let Some(severity) = event.severity {
        pairs.push(format!("severity={}", severity.as_str()));
    }
    if event.finding_count > 0 {
        pairs.push(format!("findings={}", event.finding_count));
    }
    format!("memory_prompt_safety:v1;{}", pairs.join(";"))
}

/// Authorize a memory-tool request against its `/memory` mount grant. Write
/// authority is required exactly when the tool's manifest declares a write
/// effect ([`MemoryToolProfile::requires_write_mount`]).
pub fn ensure_memory_mount(
    request: &FirstPartyCapabilityRequest,
    write: bool,
) -> Result<(), FirstPartyCapabilityError> {
    let Some(mounts) = &request.mounts else {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::FilesystemDenied,
        ));
    };
    let Some(grant) = mounts
        .mounts
        .iter()
        .find(|grant| grant.alias.as_str() == "/memory" && grant.target.as_str() == "/memory")
    else {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::FilesystemDenied,
        ));
    };
    let permissions = &grant.permissions;
    if !permissions.read
        || !permissions.list
        || (write && (!permissions.write || !permissions.delete))
    {
        return Err(FirstPartyCapabilityError::new(
            RuntimeDispatchErrorKind::FilesystemDenied,
        ));
    }
    Ok(())
}

/// Build the memory invocation for a tool request.
pub fn invocation_for_request(request: &FirstPartyCapabilityRequest) -> MemoryInvocation {
    MemoryInvocation {
        scope: request.scope.clone(),
        correlation_id: CorrelationId::new(),
    }
}

/// Bound + stamp a memory tool's output into a capability result (shared by
/// every provider's handler so usage accounting cannot drift).
pub fn finish_memory_tool_result(
    output: Value,
    started: std::time::Instant,
) -> Result<FirstPartyCapabilityResult, FirstPartyCapabilityError> {
    let output_bytes = bounded_output_bytes(&output, FIRST_PARTY_MAX_OUTPUT_BYTES)?;
    let wall_clock_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    Ok(FirstPartyCapabilityResult::new(
        output,
        ResourceUsage::default()
            .set_wall_clock_ms(wall_clock_ms)
            .set_output_bytes(output_bytes),
    ))
}

/// Schema-driven null-sentinel normalization for a memory tool input, using
/// the tool's manifest-declared schema (see [`MemoryToolProfile`]).
pub fn normalize_memory_tool_input(input: &mut Value, profile: &MemoryToolProfile) {
    normalize_optional_null_sentinels_against_schema(input, profile.input_schema.as_ref());
}

/// Map a provider error onto the sanitized model-visible capability error.
pub fn map_memory_service_error(error: MemoryServiceError) -> FirstPartyCapabilityError {
    match error.kind() {
        MemoryServiceErrorKind::Input => input_error(),
        MemoryServiceErrorKind::Operation | MemoryServiceErrorKind::Unavailable => {
            // Log only the sanitized error kind — the `Display`/`source` chain
            // can carry backend details or host paths.
            tracing::debug!(
                error_kind = ?error.kind(),
                "memory service operation failed"
            );
            operation_error()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ironclaw_filesystem::InMemoryBackend;
    use ironclaw_host_api::{
        ids::{CapabilityId, InvocationId, TenantId, ThreadId, UserId},
        mount::{MountGrant, MountPermissions, MountView},
        path::{MountAlias, VirtualPath},
        resource::ResourceScope,
    };
    use serde_json::{Value, json};

    use crate::{FirstPartyCapabilityRequest, HostProcessPort, InvocationServices};

    use super::*;

    fn handler() -> MemoryToolGuard {
        guard_with_extra_profile(None)
    }

    /// Build the production-shaped guard→native chain; `extra` injects an
    /// additional declared-tool profile (the declared-but-unserved case).
    fn guard_with_extra_profile(extra: Option<(&str, MemoryToolProfile)>) -> MemoryToolGuard {
        let bundle = crate::memory_native_extension::native_memory_provider_bundle()
            .expect("native bundle builds");
        let mut profiles = memory_tool_profiles(&bundle.package);
        if let Some((id, profile)) = extra {
            profiles.insert(CapabilityId::new(id).unwrap(), profile);
        }
        MemoryToolGuard {
            profiles,
            inner: Arc::new(NativeMemoryToolHandler::from_package(&bundle.package)),
        }
    }

    fn sample_scope() -> ResourceScope {
        ResourceScope {
            tenant_id: TenantId::new("tenant-memory-service").unwrap(),
            user_id: UserId::new("user-memory-service").unwrap(),
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: Some(ThreadId::new("thread-memory-service").unwrap()),
            invocation_id: InvocationId::new(),
        }
    }

    fn memory_mount() -> MountView {
        MountView::new(vec![MountGrant::new(
            MountAlias::new("/memory").unwrap(),
            VirtualPath::new("/memory").unwrap(),
            MountPermissions::read_write_list_delete(),
        )])
        .unwrap()
    }

    fn memory_request_over(
        filesystem: Arc<InMemoryBackend>,
        capability_id: &str,
        input: Value,
    ) -> FirstPartyCapabilityRequest {
        FirstPartyCapabilityRequest {
            automation_trigger_id: None,
            origin: None,
            run_id: None,
            capability_id: CapabilityId::new(capability_id).unwrap(),
            scope: sample_scope(),
            authenticated_actor_user_id: None,
            estimate: ironclaw_host_api::resource::ResourceEstimate::default(),
            mounts: Some(memory_mount()),
            services: InvocationServices {
                filesystem,
                runtime_http_egress: None,
                tool_call_http_egress: None,
                runtime_secret_material_stager: None,
                process: Arc::new(HostProcessPort::new()),
                secret_store: None,
                audit_sink: None,
                unsafe_raw_diagnostics_allowed: false,
                post_edit_check: None,
            },
            input,
        }
    }

    /// A scheduled (automation-fire) request: `ScheduledLoopRun` origin plus
    /// the typed trigger identity threaded from the trusted submit seam.
    fn scheduled_lessons_request(
        filesystem: Arc<InMemoryBackend>,
        input: Value,
        with_trigger_id: bool,
    ) -> FirstPartyCapabilityRequest {
        let mut request =
            memory_request_over(filesystem, AUTOMATION_LESSONS_SET_CAPABILITY_ID, input);
        let run_id = ironclaw_host_api::ids::RunId::new();
        request.run_id = Some(run_id);
        request.origin =
            Some(ironclaw_host_api::invocation::InvocationOrigin::ScheduledLoopRun(run_id));
        if with_trigger_id {
            request.automation_trigger_id = Some(
                ironclaw_host_api::ids::AutomationTriggerId::new("01J9Z8G7S4XK2WQ6P3N5R8TVCY")
                    .unwrap(),
            );
        }
        request
    }

    /// A scheduled run writes its lessons through the full guard→native
    /// chain; the file lands at the host-derived path
    /// `automations/<trigger-id>/lessons.md` and a second write fully
    /// supersedes the first.
    #[tokio::test]
    async fn scheduled_run_writes_host_derived_lessons_path_with_replace_semantics() {
        let handler = handler();
        let filesystem = Arc::new(InMemoryBackend::new());

        let first = handler
            .dispatch(scheduled_lessons_request(
                Arc::clone(&filesystem),
                json!({"content": "install fails at step 3; retry twice"}),
                true,
            ))
            .await
            .expect("first lessons write succeeds");
        assert_eq!(first.output["status"], "ok");

        let second = handler
            .dispatch(scheduled_lessons_request(
                Arc::clone(&filesystem),
                json!({"content": "skip section X"}),
                true,
            ))
            .await
            .expect("second lessons write succeeds");
        assert_eq!(second.output["status"], "ok");
        assert_eq!(
            second.output["content_length"],
            "skip section X".len() as u64
        );

        // The document lives at the host-derived path under the request's own
        // memory scope — the model never named it.
        let scope_prefix = format!(
            "/memory/tenants/{}/users/{}/agents/_none/projects/_none/automations/\
             01J9Z8G7S4XK2WQ6P3N5R8TVCY",
            sample_scope().tenant_id.as_str(),
            sample_scope().user_id.as_str(),
        );
        let lessons_path = ironclaw_memory::automation_lessons_document_path(
            ironclaw_memory::MemoryDocumentScope::new(
                sample_scope().tenant_id.as_str(),
                sample_scope().user_id.as_str(),
                None,
            )
            .unwrap(),
            &AutomationOwner::new("01J9Z8G7S4XK2WQ6P3N5R8TVCY").unwrap(),
        )
        .unwrap()
        .virtual_path()
        .unwrap();
        assert!(
            lessons_path.as_str().starts_with(&scope_prefix),
            "unexpected lessons path {lessons_path:?}"
        );
        let stored = filesystem
            .get(&lessons_path)
            .await
            .unwrap()
            .expect("lessons document exists");
        assert_eq!(stored.entry.body, b"skip section X");
    }

    /// Oversize content is a model-visible rejected outcome — the dispatch
    /// SUCCEEDS and the output carries `status=rejected` — never a host error.
    #[tokio::test]
    async fn oversize_lessons_content_is_a_model_visible_rejected_outcome() {
        let handler = handler();
        let filesystem = Arc::new(InMemoryBackend::new());
        let result = handler
            .dispatch(scheduled_lessons_request(
                filesystem,
                json!({"content": "x".repeat(2049)}),
                true,
            ))
            .await
            .expect("oversize write is an outcome, not an error");
        assert_eq!(result.output["status"], "rejected");
        assert!(
            result.output["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("limit")),
        );
    }

    /// An interactive loop-run caller is denied even though the capability is
    /// granted: only that automation's own scheduled runs may write lessons.
    #[tokio::test]
    async fn interactive_loop_run_caller_is_denied() {
        let handler = handler();
        let mut request = memory_request_over(
            Arc::new(InMemoryBackend::new()),
            AUTOMATION_LESSONS_SET_CAPABILITY_ID,
            json!({"content": "hi"}),
        );
        let run_id = ironclaw_host_api::ids::RunId::new();
        request.run_id = Some(run_id);
        request.origin = Some(ironclaw_host_api::invocation::InvocationOrigin::LoopRun(
            run_id,
        ));
        request.automation_trigger_id = None;
        let error = handler
            .dispatch(request)
            .await
            .expect_err("interactive caller must be denied");
        assert_eq!(error.kind(), Some(RuntimeDispatchErrorKind::PolicyDenied));
    }

    /// Even a scheduled origin cannot write lessons when the typed trigger
    /// identity is absent — there is nothing host-bound to derive the path
    /// from, so the handler fails closed instead of guessing.
    #[tokio::test]
    async fn scheduled_origin_without_typed_trigger_id_fails_closed() {
        let handler = handler();
        let request = scheduled_lessons_request(
            Arc::new(InMemoryBackend::new()),
            json!({"content": "hi"}),
            false,
        );
        let error = handler
            .dispatch(request)
            .await
            .expect_err("missing trigger id must fail closed");
        assert_eq!(error.kind(), Some(RuntimeDispatchErrorKind::PolicyDenied));
    }

    /// The registry-routed handler serves the conventional tools end to end
    /// over the real native service: a write dispatched through the handler is
    /// visible to a search dispatched through the handler on the same request
    /// filesystem.
    #[tokio::test]
    async fn handler_serves_write_then_search_over_the_request_filesystem() {
        let handler = handler();
        let filesystem = Arc::new(InMemoryBackend::new());
        const QUERY: &str = "handler marker heron";
        const RESULT_BOUND: usize = 8 * 1024;
        let position = RESULT_BOUND + 512;
        let oversized = format!(
            "{} {QUERY} {}",
            "a".repeat(position),
            "a".repeat(RESULT_BOUND),
        );

        let write = handler
            .dispatch(memory_request_over(
                Arc::clone(&filesystem),
                MEMORY_WRITE_CAPABILITY_ID,
                json!({
                    "target": "notes/alpha.md",
                    "content": oversized,
                    "append": false
                }),
            ))
            .await
            .expect("write dispatches through the handler");
        assert_eq!(write.output["path"], "notes/alpha.md");

        let search = handler
            .dispatch(memory_request_over(
                filesystem,
                MEMORY_SEARCH_CAPABILITY_ID,
                json!({"query": QUERY, "limit": 3}),
            ))
            .await
            .expect("search dispatches through the handler");
        assert_eq!(
            search.output["search_scope"],
            "reborn_internal_persistent_memory"
        );
        assert_eq!(search.output["external_services_searched"], false);
        assert_eq!(search.output["result_count"], 1);
        let result_content = search.output["results"][0]["content"]
            .as_str()
            .expect("search result includes content");
        assert!(result_content.len() <= RESULT_BOUND);
        assert!(result_content.contains(QUERY));
    }

    /// An id the bound manifest never declared is refused even if something
    /// mis-registered it to this handler.
    #[tokio::test]
    async fn undeclared_capability_id_fails_closed() {
        let handler = handler();
        let err = handler
            .dispatch(memory_request_over(
                Arc::new(InMemoryBackend::new()),
                "ironclaw.memory.never_declared",
                json!({}),
            ))
            .await
            .expect_err("an undeclared id must fail closed");
        assert_eq!(
            err.kind(),
            Some(RuntimeDispatchErrorKind::UndeclaredCapability)
        );
    }

    /// A manifest-declared tool this provider does not implement fails closed
    /// with the model-visible operation error (never a silent fallback).
    #[tokio::test]
    async fn declared_but_unserved_tool_fails_closed() {
        let handler = guard_with_extra_profile(Some((
            "ironclaw.memory.push",
            MemoryToolProfile {
                requires_write_mount: false,
                input_schema: None,
            },
        )));
        let err = handler
            .dispatch(memory_request_over(
                Arc::new(InMemoryBackend::new()),
                "ironclaw.memory.push",
                json!({}),
            ))
            .await
            .expect_err("a declared-but-unserved tool must fail closed");
        assert_eq!(err.kind(), Some(RuntimeDispatchErrorKind::OperationFailed));
    }

    /// The write tool requires write+delete mount authority (derived from its
    /// manifest effects, not a hardcoded id list).
    #[tokio::test]
    async fn write_tool_requires_write_mount_authority() {
        let handler = handler();
        let mut request = memory_request_over(
            Arc::new(InMemoryBackend::new()),
            MEMORY_WRITE_CAPABILITY_ID,
            json!({"target": "notes/alpha.md", "content": "x", "append": false}),
        );
        request.mounts = Some(
            MountView::new(vec![MountGrant::new(
                MountAlias::new("/memory").unwrap(),
                VirtualPath::new("/memory").unwrap(),
                MountPermissions::read_only(),
            )])
            .unwrap(),
        );
        let err = handler
            .dispatch(request)
            .await
            .expect_err("a read-only mount must not authorize the write tool");
        assert_eq!(err.kind(), Some(RuntimeDispatchErrorKind::FilesystemDenied));
    }

    /// profile_set rejects an unknown field before any memory-service side
    /// effect, and round-trips through the real native service.
    #[tokio::test]
    async fn profile_set_validates_fields_then_writes() {
        let handler = handler();
        let filesystem = Arc::new(InMemoryBackend::new());

        let err = handler
            .dispatch(memory_request_over(
                Arc::clone(&filesystem),
                PROFILE_SET_CAPABILITY_ID,
                json!({"always_approve": true}),
            ))
            .await
            .expect_err("unknown profile field must be rejected");
        assert_eq!(err.kind(), Some(RuntimeDispatchErrorKind::InputEncode));

        let ok = handler
            .dispatch(memory_request_over(
                Arc::clone(&filesystem),
                PROFILE_SET_CAPABILITY_ID,
                json!({"timezone": "Asia/Tokyo"}),
            ))
            .await
            .expect("valid profile_set dispatches");
        assert_eq!(ok.output["status"], "ok");

        let read = handler
            .dispatch(memory_request_over(
                filesystem,
                MEMORY_READ_CAPABILITY_ID,
                json!({"path": "context/profile.json"}),
            ))
            .await
            .expect("profile document reads back through the handler");
        assert!(
            read.output["content"]
                .as_str()
                .unwrap_or_default()
                .contains("Asia/Tokyo")
        );
    }
}
