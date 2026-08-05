//! Authorized first-party mutations for operator configuration.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use ironclaw_approvals::{
    AutoApproveSettingInput, PersistentApprovalAction, PersistentApprovalPolicyError,
    PersistentApprovalPolicyInput, PersistentApprovalPolicyKey, ToolPermissionOverride,
    ToolPermissionOverrideInput, ToolPermissionOverrideKey, ToolPermissionState,
};
use ironclaw_extensions::{
    CapabilityManifest, CapabilityVisibility, ExtensionError, ExtensionPackage,
};
use ironclaw_host_api::{
    capability::{EffectKind, GrantConstraints, OriginGateMatrix, PermissionMode},
    capability_profile::CapabilityProfileSchemaRef,
    dispatch::RuntimeDispatchErrorKind,
    error::HostApiError,
    ids::{CapabilityId, UserId},
    resource::{ResourceEstimate, ResourceProfile, ResourceScope, ResourceUsage},
    scope::Principal,
};
use ironclaw_host_runtime::{
    FirstPartyCapabilityError, FirstPartyCapabilityHandler, FirstPartyCapabilityRegistry,
    FirstPartyCapabilityRequest, FirstPartyCapabilityResult, SandboxCredentialRuntime,
};
use ironclaw_product::{
    OPERATOR_CONFIG_SET_AUTO_APPROVE_CAPABILITY_ID,
    OPERATOR_CONFIG_SET_TOOL_PERMISSION_CAPABILITY_ID,
    SANDBOX_CREDENTIAL_PLACEHOLDER_CAPABILITY_ID,
};
use ironclaw_product_contracts::operator_tools::{
    RebornOperatorToolCatalog, RebornOperatorToolInfo,
};
use ironclaw_secrets::{CredentialAccountStatus, CredentialAccountStore};

pub fn extend_builtin_first_party_package(
    mut package: ExtensionPackage,
    include_sandbox: bool,
) -> Result<ExtensionPackage, ExtensionError> {
    package.manifest.capabilities.push(manifest()?);
    package
        .manifest
        .capabilities
        .push(tool_permission_manifest()?);
    if include_sandbox {
        package
            .manifest
            .capabilities
            .push(sandbox_placeholder_manifest()?);
    }
    let root = package
        .materialized_root()
        .map_err(|error| ExtensionError::InvalidManifest {
            reason: format!("built-in package requires a materialized root: {error}"),
        })?
        .clone();
    ExtensionPackage::from_manifest(package.manifest, root)
}

pub fn insert_sandbox_handlers(
    registry: &mut FirstPartyCapabilityRegistry,
    credential_runtime: SandboxCredentialRuntime,
    credential_accounts: Arc<dyn CredentialAccountStore>,
) -> Result<(), HostApiError> {
    registry.insert_handler(
        CapabilityId::new(SANDBOX_CREDENTIAL_PLACEHOLDER_CAPABILITY_ID)?,
        Arc::new(SandboxCredentialPlaceholderHandler {
            credential_runtime,
            credential_accounts,
        }),
    );
    Ok(())
}

pub fn insert_handler(
    registry: &mut FirstPartyCapabilityRegistry,
    auto_approve: Arc<dyn ironclaw_approvals::AutoApproveSettingStorePort>,
    overrides: Arc<dyn ironclaw_approvals::ToolPermissionOverrideStorePort>,
    persistent_policies: Arc<dyn ironclaw_approvals::PersistentApprovalPolicyStorePort>,
    tool_catalog: Arc<dyn RebornOperatorToolCatalog>,
) -> Result<(), HostApiError> {
    registry.insert_handler(
        CapabilityId::new(OPERATOR_CONFIG_SET_AUTO_APPROVE_CAPABILITY_ID)?,
        Arc::new(SetAutoApproveHandler { auto_approve }),
    );
    registry.insert_handler(
        CapabilityId::new(OPERATOR_CONFIG_SET_TOOL_PERMISSION_CAPABILITY_ID)?,
        Arc::new(SetToolPermissionHandler {
            overrides,
            persistent_policies,
            tool_catalog,
        }),
    );
    Ok(())
}

fn manifest() -> Result<CapabilityManifest, ExtensionError> {
    Ok(CapabilityManifest {
        id: CapabilityId::new(OPERATOR_CONFIG_SET_AUTO_APPROVE_CAPABILITY_ID)?,
        description: "Set the authenticated operator's global auto-approve-tools setting."
            .to_string(),
        effects: vec![EffectKind::ModifyApproval],
        default_permission: PermissionMode::Allow,
        visibility: CapabilityVisibility::Api,
        input_schema_ref: CapabilityProfileSchemaRef::new(
            "schemas/builtin/operator_config_set_auto_approve.input.v1.json",
        )?,
        output_schema_ref: Some(CapabilityProfileSchemaRef::new(
            "schemas/builtin/operator_config_set_auto_approve.output.v1.json",
        )?),
        prompt_doc_ref: None,
        required_host_ports: Vec::new(),
        runtime_credentials: Vec::new(),
        network_targets: Vec::new(),
        max_egress_bytes: None,
        resource_profile: Some(ResourceProfile {
            default_estimate: ResourceEstimate::default()
                .set_wall_clock_ms(500)
                .set_output_bytes(1024),
            hard_ceiling: None,
        }),
        origin_gate_matrix: Some(OriginGateMatrix::product_consent_only()),
    })
}

fn tool_permission_manifest() -> Result<CapabilityManifest, ExtensionError> {
    Ok(CapabilityManifest {
        id: CapabilityId::new(OPERATOR_CONFIG_SET_TOOL_PERMISSION_CAPABILITY_ID)?,
        description: "Set the authenticated operator's permission for one tool.".to_string(),
        effects: vec![EffectKind::ModifyApproval],
        default_permission: PermissionMode::Allow,
        visibility: CapabilityVisibility::Api,
        input_schema_ref: CapabilityProfileSchemaRef::new(
            "schemas/builtin/operator_config_set_tool_permission.input.v1.json",
        )?,
        output_schema_ref: Some(CapabilityProfileSchemaRef::new(
            "schemas/builtin/operator_config_set_tool_permission.output.v1.json",
        )?),
        prompt_doc_ref: None,
        required_host_ports: Vec::new(),
        runtime_credentials: Vec::new(),
        network_targets: Vec::new(),
        max_egress_bytes: None,
        resource_profile: Some(ResourceProfile {
            default_estimate: ResourceEstimate::default()
                .set_wall_clock_ms(500)
                .set_output_bytes(1024),
            hard_ceiling: None,
        }),
        origin_gate_matrix: Some(OriginGateMatrix::product_consent_only()),
    })
}

fn sandbox_placeholder_manifest() -> Result<CapabilityManifest, ExtensionError> {
    Ok(CapabilityManifest {
        id: CapabilityId::new(SANDBOX_CREDENTIAL_PLACEHOLDER_CAPABILITY_ID)?,
        description:
            "Return an inert sandbox placeholder for an eligible configured credential provider."
                .to_string(),
        effects: Vec::new(),
        default_permission: PermissionMode::Allow,
        visibility: CapabilityVisibility::Model,
        input_schema_ref: CapabilityProfileSchemaRef::new(
            "schemas/builtin/sandbox_credential_placeholder.input.v1.json",
        )?,
        output_schema_ref: Some(CapabilityProfileSchemaRef::new(
            "schemas/builtin/sandbox_credential_placeholder.output.v1.json",
        )?),
        prompt_doc_ref: None,
        required_host_ports: Vec::new(),
        runtime_credentials: Vec::new(),
        network_targets: Vec::new(),
        max_egress_bytes: None,
        resource_profile: Some(ResourceProfile {
            default_estimate: ResourceEstimate::default()
                .set_wall_clock_ms(500)
                .set_output_bytes(1024),
            hard_ceiling: None,
        }),
        origin_gate_matrix: Some(OriginGateMatrix::builtin_loop_run_seed(
            SANDBOX_CREDENTIAL_PLACEHOLDER_CAPABILITY_ID,
        )),
    })
}

struct SetAutoApproveHandler {
    auto_approve: Arc<dyn ironclaw_approvals::AutoApproveSettingStorePort>,
}

#[async_trait]
impl FirstPartyCapabilityHandler for SetAutoApproveHandler {
    async fn dispatch(
        &self,
        request: FirstPartyCapabilityRequest,
    ) -> Result<FirstPartyCapabilityResult, FirstPartyCapabilityError> {
        let started = Instant::now();
        ensure_declared(&request, started)?;
        let actor = authenticated_actor(&request, started)?;
        let enabled = parse_enabled(request.input, started)?;
        let scope = request.scope.tenant_user_settings_scope();
        let record = self
            .auto_approve
            .set(AutoApproveSettingInput {
                scope,
                enabled,
                updated_by: Principal::User(actor),
            })
            .await
            .map_err(|error| {
                tracing::debug!(%error, "operator auto-approve setting mutation failed");
                dispatch_error(RuntimeDispatchErrorKind::Backend, started)
            })?;
        Ok(dispatch_result(
            serde_json::json!({
                "key": "agent.auto_approve_tools",
                "enabled": record.enabled,
                "tenant_id": record.key.tenant_id.as_str(),
                "user_id": record.key.user_id.as_str(),
            }),
            started,
        ))
    }
}

struct SetToolPermissionHandler {
    overrides: Arc<dyn ironclaw_approvals::ToolPermissionOverrideStorePort>,
    persistent_policies: Arc<dyn ironclaw_approvals::PersistentApprovalPolicyStorePort>,
    tool_catalog: Arc<dyn RebornOperatorToolCatalog>,
}

struct SandboxCredentialPlaceholderHandler {
    credential_runtime: SandboxCredentialRuntime,
    credential_accounts: Arc<dyn CredentialAccountStore>,
}

#[async_trait]
impl FirstPartyCapabilityHandler for SandboxCredentialPlaceholderHandler {
    async fn dispatch(
        &self,
        request: FirstPartyCapabilityRequest,
    ) -> Result<FirstPartyCapabilityResult, FirstPartyCapabilityError> {
        let started = Instant::now();
        ensure_sandbox_placeholder_declared(&request, started)?;
        authenticated_actor(&request, started)?;
        let provider = parse_provider_id(request.input, started)?;
        let accounts = self
            .credential_accounts
            .accounts_for_scope(&request.scope)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "sandbox credential account lookup failed");
                dispatch_error(RuntimeDispatchErrorKind::Backend, started)
            })?;
        let mut eligible = accounts.into_iter().filter(|account| {
            account.provider_or_extension_id == provider
                && account.status == CredentialAccountStatus::Active
                && account.secret_handles.len() == 1
                && !account.allowed_targets.is_empty()
                && same_credential_owner(&account.scope, &request.scope)
        });
        if eligible.next().is_none() {
            return Err(safe_dispatch_error(
                RuntimeDispatchErrorKind::OperationFailed,
                "no eligible sandbox credential is configured for this provider",
                started,
            ));
        }
        if eligible.next().is_some() {
            return Err(safe_dispatch_error(
                RuntimeDispatchErrorKind::OperationFailed,
                "multiple eligible sandbox credentials match this provider",
                started,
            ));
        }
        let placeholder = self
            .credential_runtime
            .placeholder_for(&request.scope, &provider)
            .map_err(|error| {
                tracing::warn!(%error, "sandbox credential placeholder allocation failed");
                dispatch_error(RuntimeDispatchErrorKind::Backend, started)
            })?;
        Ok(dispatch_result(
            serde_json::json!({
                "provider_id": provider.as_str(),
                "placeholder": placeholder.as_str(),
                "authorization_schemes": ["basic", "bearer"],
            }),
            started,
        ))
    }
}

#[async_trait]
impl FirstPartyCapabilityHandler for SetToolPermissionHandler {
    async fn dispatch(
        &self,
        request: FirstPartyCapabilityRequest,
    ) -> Result<FirstPartyCapabilityResult, FirstPartyCapabilityError> {
        let started = Instant::now();
        ensure_tool_permission_declared(&request, started)?;
        let actor = authenticated_actor(&request, started)?;
        let input = parse_tool_permission_input(request.input, started)?;
        let tool = find_operator_tool(
            self.tool_catalog.as_ref(),
            &input.capability_id,
            &request.scope.user_id,
            started,
        )
        .await?;
        if tool_permission_locked(&tool) {
            return Err(dispatch_error(
                RuntimeDispatchErrorKind::PolicyDenied,
                started,
            ));
        }
        apply_tool_permission_state(
            self.overrides.as_ref(),
            self.persistent_policies.as_ref(),
            &request.scope,
            &actor,
            &tool,
            input.state,
            started,
        )
        .await?;
        Ok(dispatch_result(
            serde_json::json!({
                "key": format!("tool.{}", input.capability_id.as_str()),
                "capability_id": input.capability_id.as_str(),
                "state": tool_permission_state_wire(input.state),
                "tenant_id": request.scope.tenant_id.as_str(),
                "user_id": request.scope.user_id.as_str(),
            }),
            started,
        ))
    }
}

fn ensure_declared(
    request: &FirstPartyCapabilityRequest,
    started: Instant,
) -> Result<(), FirstPartyCapabilityError> {
    if request.capability_id.as_str() == OPERATOR_CONFIG_SET_AUTO_APPROVE_CAPABILITY_ID {
        Ok(())
    } else {
        Err(dispatch_error(
            RuntimeDispatchErrorKind::UndeclaredCapability,
            started,
        ))
    }
}

fn ensure_tool_permission_declared(
    request: &FirstPartyCapabilityRequest,
    started: Instant,
) -> Result<(), FirstPartyCapabilityError> {
    if request.capability_id.as_str() == OPERATOR_CONFIG_SET_TOOL_PERMISSION_CAPABILITY_ID {
        Ok(())
    } else {
        Err(dispatch_error(
            RuntimeDispatchErrorKind::UndeclaredCapability,
            started,
        ))
    }
}

fn ensure_sandbox_placeholder_declared(
    request: &FirstPartyCapabilityRequest,
    started: Instant,
) -> Result<(), FirstPartyCapabilityError> {
    if request.capability_id.as_str() == SANDBOX_CREDENTIAL_PLACEHOLDER_CAPABILITY_ID {
        Ok(())
    } else {
        Err(dispatch_error(
            RuntimeDispatchErrorKind::UndeclaredCapability,
            started,
        ))
    }
}

fn authenticated_actor(
    request: &FirstPartyCapabilityRequest,
    started: Instant,
) -> Result<UserId, FirstPartyCapabilityError> {
    match request.authenticated_actor_user_id.as_ref() {
        Some(actor) if actor == &request.scope.user_id => Ok(actor.clone()),
        _ => Err(dispatch_error(
            RuntimeDispatchErrorKind::PolicyDenied,
            started,
        )),
    }
}

fn parse_enabled(
    input: serde_json::Value,
    started: Instant,
) -> Result<bool, FirstPartyCapabilityError> {
    let object = input
        .as_object()
        .ok_or_else(|| dispatch_error(RuntimeDispatchErrorKind::InputEncode, started))?;
    let enabled = object
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| dispatch_error(RuntimeDispatchErrorKind::InputEncode, started))?;
    if object.len() == 1 {
        Ok(enabled)
    } else {
        Err(dispatch_error(
            RuntimeDispatchErrorKind::InputEncode,
            started,
        ))
    }
}

fn parse_provider_id(
    input: serde_json::Value,
    started: Instant,
) -> Result<ironclaw_host_api::ids::ExtensionId, FirstPartyCapabilityError> {
    let object = input
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or_else(|| dispatch_error(RuntimeDispatchErrorKind::InputEncode, started))?;
    object
        .get("provider_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| dispatch_error(RuntimeDispatchErrorKind::InputEncode, started))
        .and_then(|provider| {
            ironclaw_host_api::ids::ExtensionId::new(provider)
                .map_err(|_| dispatch_error(RuntimeDispatchErrorKind::InputEncode, started))
        })
}

fn same_credential_owner(left: &ResourceScope, right: &ResourceScope) -> bool {
    left.tenant_id == right.tenant_id
        && left.user_id == right.user_id
        && left.agent_id == right.agent_id
        && left.project_id == right.project_id
}

struct ToolPermissionInput {
    capability_id: CapabilityId,
    state: ToolPermissionUpdate,
}

#[derive(Clone, Copy)]
enum ToolPermissionUpdate {
    Default,
    State(ToolPermissionState),
}

fn parse_tool_permission_input(
    input: serde_json::Value,
    started: Instant,
) -> Result<ToolPermissionInput, FirstPartyCapabilityError> {
    let object = input
        .as_object()
        .ok_or_else(|| dispatch_error(RuntimeDispatchErrorKind::InputEncode, started))?;
    if object.len() != 2 {
        return Err(dispatch_error(
            RuntimeDispatchErrorKind::InputEncode,
            started,
        ));
    }
    let capability_id = object
        .get("capability_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| dispatch_error(RuntimeDispatchErrorKind::InputEncode, started))
        .and_then(|value| {
            CapabilityId::new(value)
                .map_err(|_| dispatch_error(RuntimeDispatchErrorKind::InputEncode, started))
        })?;
    let state = object
        .get("state")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| dispatch_error(RuntimeDispatchErrorKind::InputEncode, started))
        .and_then(|value| match value {
            "default" => Ok(ToolPermissionUpdate::Default),
            "always_allow" => Ok(ToolPermissionUpdate::State(
                ToolPermissionState::AlwaysAllow,
            )),
            "ask_each_time" | "ask" => Ok(ToolPermissionUpdate::State(
                ToolPermissionState::AskEachTime,
            )),
            "disabled" => Ok(ToolPermissionUpdate::State(ToolPermissionState::Disabled)),
            _ => Err(dispatch_error(
                RuntimeDispatchErrorKind::InputEncode,
                started,
            )),
        })?;
    Ok(ToolPermissionInput {
        capability_id,
        state,
    })
}

async fn find_operator_tool(
    catalog: &dyn RebornOperatorToolCatalog,
    capability_id: &CapabilityId,
    caller: &UserId,
    started: Instant,
) -> Result<RebornOperatorToolInfo, FirstPartyCapabilityError> {
    catalog
        .list_operator_tools(caller)
        .await
        .into_iter()
        .find(|tool| tool.capability_id == *capability_id)
        .ok_or_else(|| dispatch_error(RuntimeDispatchErrorKind::PolicyDenied, started))
}

async fn apply_tool_permission_state(
    overrides: &dyn ironclaw_approvals::ToolPermissionOverrideStorePort,
    persistent_policies: &dyn ironclaw_approvals::PersistentApprovalPolicyStorePort,
    scope: &ResourceScope,
    actor: &UserId,
    tool: &RebornOperatorToolInfo,
    update: ToolPermissionUpdate,
    started: Instant,
) -> Result<(), FirstPartyCapabilityError> {
    let operator_scope = operator_tool_permission_scope(scope);
    match update {
        ToolPermissionUpdate::Default => {
            revoke_persistent_policy(persistent_policies, &operator_scope, tool, started).await?;
            overrides
                .clear(&ToolPermissionOverrideKey::new(
                    &operator_scope,
                    tool.capability_id.clone(),
                ))
                .await
                .map_err(|error| {
                    tracing::debug!(%error, "operator tool permission override clear failed");
                    dispatch_error(RuntimeDispatchErrorKind::Backend, started)
                })?;
        }
        ToolPermissionUpdate::State(ToolPermissionState::AlwaysAllow) => {
            // Clear the contradicting override BEFORE minting the grant. These are
            // two stores and the pair is not atomic, so the order decides what a
            // partial failure leaves behind. Granting first and failing to clear
            // would persist a live `Dispatch` grant underneath a stale
            // `ToolPermissionOverride::Disabled`: the gate honours the explicit
            // override, so the tool reads as disabled while carrying auto-approval
            // authority that takes effect the moment anything else clears the
            // override. Clearing first can only ever leave *less* authority than
            // the operator asked for (the tool falls back to its default), which is
            // the fail-closed direction.
            overrides
                .clear(&ToolPermissionOverrideKey::new(
                    &operator_scope,
                    tool.capability_id.clone(),
                ))
                .await
                .map_err(|error| {
                    tracing::debug!(%error, "operator tool permission override clear failed");
                    dispatch_error(RuntimeDispatchErrorKind::Backend, started)
                })?;
            persistent_policies
                .allow(PersistentApprovalPolicyInput {
                    scope: operator_scope.clone(),
                    action: PersistentApprovalAction::Dispatch,
                    capability_id: tool.capability_id.clone(),
                    grantee: Principal::Extension(tool.provider.clone()),
                    approved_by: Principal::User(actor.clone()),
                    constraints: GrantConstraints {
                        allowed_effects: tool.effects.as_ref().to_vec(),
                        mounts: Default::default(),
                        network: Default::default(),
                        secrets: Vec::new(),
                        resource_ceiling: None,
                        expires_at: None,
                        max_invocations: None,
                    },
                    source_approval_request_id: None,
                })
                .await
                .map_err(|error| {
                    tracing::debug!(%error, "operator persistent approval policy write failed");
                    dispatch_error(RuntimeDispatchErrorKind::Backend, started)
                })?;
        }
        ToolPermissionUpdate::State(state @ ToolPermissionState::AskEachTime)
        | ToolPermissionUpdate::State(state @ ToolPermissionState::Disabled) => {
            revoke_persistent_policy(persistent_policies, &operator_scope, tool, started).await?;
            let override_state = match state {
                ToolPermissionState::AskEachTime => ToolPermissionOverride::AskEachTime,
                ToolPermissionState::Disabled => ToolPermissionOverride::Disabled,
                ToolPermissionState::AlwaysAllow => {
                    return Err(dispatch_error(
                        RuntimeDispatchErrorKind::InputEncode,
                        started,
                    ));
                }
            };
            overrides
                .set(ToolPermissionOverrideInput {
                    scope: operator_scope,
                    capability_id: tool.capability_id.clone(),
                    state: override_state,
                    updated_by: Principal::User(actor.clone()),
                })
                .await
                .map_err(|error| {
                    tracing::debug!(%error, "operator tool permission override write failed");
                    dispatch_error(RuntimeDispatchErrorKind::Backend, started)
                })?;
        }
    }
    Ok(())
}

async fn revoke_persistent_policy(
    persistent_policies: &dyn ironclaw_approvals::PersistentApprovalPolicyStorePort,
    operator_scope: &ResourceScope,
    tool: &RebornOperatorToolInfo,
    started: Instant,
) -> Result<(), FirstPartyCapabilityError> {
    match persistent_policies
        .revoke(&persistent_user_policy_key(operator_scope, tool))
        .await
    {
        Ok(_) | Err(PersistentApprovalPolicyError::UnknownPolicy) => Ok(()),
        Err(error) => {
            tracing::debug!(%error, "operator persistent approval policy revoke failed");
            Err(dispatch_error(RuntimeDispatchErrorKind::Backend, started))
        }
    }
}

fn persistent_user_policy_key(
    scope: &ResourceScope,
    tool: &RebornOperatorToolInfo,
) -> PersistentApprovalPolicyKey {
    PersistentApprovalPolicyKey::new(
        scope,
        PersistentApprovalAction::Dispatch,
        tool.capability_id.clone(),
        Principal::Extension(tool.provider.clone()),
    )
}

fn operator_tool_permission_scope(scope: &ResourceScope) -> ResourceScope {
    scope.tenant_user_settings_scope()
}

fn tool_permission_locked(tool: &RebornOperatorToolInfo) -> bool {
    tool.default_permission == PermissionMode::Deny || hard_floor_tool(tool)
}

fn hard_floor_tool(tool: &RebornOperatorToolInfo) -> bool {
    tool.effects.iter().any(|effect| {
        matches!(
            effect,
            EffectKind::Financial | EffectKind::ModifyApproval | EffectKind::ModifyBudget
        )
    })
}

fn tool_permission_state_wire(update: ToolPermissionUpdate) -> &'static str {
    match update {
        ToolPermissionUpdate::Default => "default",
        ToolPermissionUpdate::State(ToolPermissionState::AlwaysAllow) => "always_allow",
        ToolPermissionUpdate::State(ToolPermissionState::AskEachTime) => "ask_each_time",
        ToolPermissionUpdate::State(ToolPermissionState::Disabled) => "disabled",
    }
}

fn dispatch_error(kind: RuntimeDispatchErrorKind, started: Instant) -> FirstPartyCapabilityError {
    FirstPartyCapabilityError::new(kind).with_usage(resource_usage(started))
}

fn safe_dispatch_error(
    kind: RuntimeDispatchErrorKind,
    summary: &'static str,
    started: Instant,
) -> FirstPartyCapabilityError {
    FirstPartyCapabilityError::with_safe_summary(kind, summary).with_usage(resource_usage(started))
}

fn dispatch_result(output: serde_json::Value, started: Instant) -> FirstPartyCapabilityResult {
    FirstPartyCapabilityResult::new(output, resource_usage(started))
}

fn resource_usage(started: Instant) -> ResourceUsage {
    ResourceUsage::default()
        .set_wall_clock_ms(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use ironclaw_approvals::{
        AutoApproveSettingStore, PersistentApprovalPolicyStore, ToolPermissionOverrideStore,
    };
    use ironclaw_filesystem::InMemoryBackend;
    use ironclaw_host_api::{
        action::NetworkMethod,
        ids::{AgentId, ExtensionId, InvocationId, ProjectId, SecretHandle, TenantId},
        resource::ResourceScope,
    };
    use ironclaw_secrets::{
        CredentialAccount, CredentialAccountId, CredentialPathPolicy, CredentialTargetPolicy,
        InMemoryCredentialBroker, RedactedJson,
    };

    use super::*;

    #[test]
    fn capabilities_are_api_only_modify_approval() {
        for manifest in [
            manifest().expect("auto-approve manifest"),
            tool_permission_manifest().expect("tool-permission manifest"),
        ] {
            assert_eq!(manifest.visibility, CapabilityVisibility::Api);
            assert_eq!(manifest.effects, vec![EffectKind::ModifyApproval]);
            assert_eq!(manifest.default_permission, PermissionMode::Allow);
        }
    }

    #[test]
    fn authenticated_actor_must_match_resource_user() {
        let operator = UserId::new("operator").expect("operator");
        let member = UserId::new("member").expect("member");
        let scope = ResourceScope {
            tenant_id: TenantId::new("tenant").expect("tenant"),
            user_id: operator.clone(),
            agent_id: Some(AgentId::new("agent").expect("agent")),
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        };
        let mut request = FirstPartyCapabilityRequest::request_for_test(
            CapabilityId::new(OPERATOR_CONFIG_SET_AUTO_APPROVE_CAPABILITY_ID)
                .expect("capability id"),
            scope,
            serde_json::json!({ "enabled": true }),
            None,
        );
        request.authenticated_actor_user_id = Some(member);
        assert!(authenticated_actor(&request, Instant::now()).is_err());
        request.authenticated_actor_user_id = Some(operator.clone());
        assert_eq!(
            authenticated_actor(&request, Instant::now()).expect("actor"),
            operator
        );
    }

    #[tokio::test]
    async fn sandbox_placeholder_requires_exactly_one_eligible_credential() {
        let broker = Arc::new(InMemoryCredentialBroker::new());
        let mut registry = FirstPartyCapabilityRegistry::new();
        insert_sandbox_handlers(
            &mut registry,
            SandboxCredentialRuntime::new(),
            broker.clone(),
        )
        .expect("insert sandbox handlers");

        let scope = ResourceScope {
            tenant_id: TenantId::new("tenant").expect("tenant"),
            user_id: UserId::new("alice").expect("user"),
            agent_id: Some(AgentId::new("agent").expect("agent")),
            project_id: Some(ProjectId::new("project").expect("project")),
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        };
        let placeholder_handler = registry
            .get(&CapabilityId::new(SANDBOX_CREDENTIAL_PLACEHOLDER_CAPABILITY_ID).expect("id"))
            .expect("placeholder handler");

        broker
            .put_account(eligible_account(
                scope.clone(),
                "github-main",
                "github-token",
            ))
            .expect("put account");

        let first = placeholder_handler
            .dispatch(sandbox_request(
                SANDBOX_CREDENTIAL_PLACEHOLDER_CAPABILITY_ID,
                scope.clone(),
                serde_json::json!({"provider_id": "github"}),
            ))
            .await
            .expect("first placeholder");
        let second = placeholder_handler
            .dispatch(sandbox_request(
                SANDBOX_CREDENTIAL_PLACEHOLDER_CAPABILITY_ID,
                scope.clone(),
                serde_json::json!({"provider_id": "github"}),
            ))
            .await
            .expect("second placeholder");
        assert_eq!(first.output["placeholder"], second.output["placeholder"]);
        assert!(
            first.output["placeholder"]
                .as_str()
                .is_some_and(|token| token.starts_with("icsbx_") && token.len() == 38)
        );
        assert_eq!(
            first.output["authorization_schemes"],
            serde_json::json!(["basic", "bearer"])
        );

        broker
            .put_account(eligible_account(
                scope.clone(),
                "github-secondary",
                "github-token-2",
            ))
            .expect("put second account");
        let ambiguous = placeholder_handler
            .dispatch(sandbox_request(
                SANDBOX_CREDENTIAL_PLACEHOLDER_CAPABILITY_ID,
                scope,
                serde_json::json!({"provider_id": "github"}),
            ))
            .await
            .expect_err("ambiguous accounts must fail");
        assert_eq!(
            ambiguous.safe_summary(),
            Some("multiple eligible sandbox credentials match this provider")
        );
    }

    fn sandbox_request(
        capability_id: &str,
        scope: ResourceScope,
        input: serde_json::Value,
    ) -> FirstPartyCapabilityRequest {
        let actor = scope.user_id.clone();
        let mut request = FirstPartyCapabilityRequest::request_for_test(
            CapabilityId::new(capability_id).expect("capability id"),
            scope,
            input,
            None,
        );
        request.authenticated_actor_user_id = Some(actor);
        request
    }

    fn eligible_account(scope: ResourceScope, id: &str, handle: &str) -> CredentialAccount {
        CredentialAccount {
            scope,
            id: CredentialAccountId::new(id).expect("account"),
            provider_or_extension_id: ExtensionId::new("github").expect("provider"),
            label: "GitHub".to_string(),
            status: CredentialAccountStatus::Active,
            secret_handles: vec![SecretHandle::new(handle).expect("handle")],
            allowed_targets: vec![CredentialTargetPolicy {
                scheme: "https".to_string(),
                host: "api.github.com".to_string(),
                port: Some(443),
                path: CredentialPathPolicy::Prefix("/".to_string()),
                methods: vec![NetworkMethod::Get],
            }],
            redacted_metadata: RedactedJson::new(serde_json::json!({})),
            updated_at: Utc::now(),
        }
    }

    /// The approvals stores plus the tool-permission handler, wired over one
    /// in-memory filesystem so a test can assert on what the handler actually
    /// persisted.
    #[allow(clippy::type_complexity)]
    fn tool_permission_fixture(
        tools: Vec<RebornOperatorToolInfo>,
    ) -> (
        Arc<dyn ironclaw_approvals::ToolPermissionOverrideStorePort>,
        Arc<dyn ironclaw_approvals::PersistentApprovalPolicyStorePort>,
        Arc<dyn FirstPartyCapabilityHandler>,
    ) {
        let scoped = Arc::new(ironclaw_filesystem::ScopedFilesystem::with_fixed_view(
            Arc::new(InMemoryBackend::new()),
            ironclaw_host_api::mount::MountView::new(vec![
                ironclaw_host_api::mount::MountGrant::new(
                    ironclaw_host_api::path::MountAlias::new("/approvals")
                        .expect("test approvals mount alias"),
                    ironclaw_host_api::path::VirtualPath::new("/projects/approvals")
                        .expect("test approvals mount target"),
                    ironclaw_host_api::mount::MountPermissions::read_write_list_delete(),
                ),
            ])
            .expect("test mount view"),
        ));
        let overrides: Arc<dyn ironclaw_approvals::ToolPermissionOverrideStorePort> =
            Arc::new(ToolPermissionOverrideStore::new(Arc::clone(&scoped)));
        let persistent_policies: Arc<dyn ironclaw_approvals::PersistentApprovalPolicyStorePort> =
            Arc::new(PersistentApprovalPolicyStore::new(Arc::clone(&scoped)));
        let auto_approve = Arc::new(AutoApproveSettingStore::new(scoped));
        let tool_catalog: Arc<dyn RebornOperatorToolCatalog> = Arc::new(StaticToolCatalog(tools));
        let mut registry = FirstPartyCapabilityRegistry::new();
        insert_handler(
            &mut registry,
            auto_approve,
            overrides.clone(),
            persistent_policies.clone(),
            tool_catalog,
        )
        .expect("insert handlers");
        let handler = registry
            .get(&CapabilityId::new(OPERATOR_CONFIG_SET_TOOL_PERMISSION_CAPABILITY_ID).expect("id"))
            .expect("tool permission handler");
        (overrides, persistent_policies, handler)
    }

    #[tokio::test]
    async fn tool_permission_handler_writes_persistent_policy_and_override() {
        let capability_id = CapabilityId::new("ext.search").expect("capability id");
        let provider = ExtensionId::new("ext").expect("provider id");
        let (overrides, persistent_policies, handler) =
            tool_permission_fixture(vec![RebornOperatorToolInfo {
                capability_id: capability_id.clone(),
                provider: provider.clone(),
                description: Arc::from("Search"),
                default_permission: PermissionMode::Ask,
                effects: Arc::<[EffectKind]>::from(vec![EffectKind::Network]),
            }]);
        let user = UserId::new("operator").expect("user id");
        let scope = ResourceScope::local_default(user.clone(), InvocationId::new())
            .expect("resource scope");

        let mut request = FirstPartyCapabilityRequest::request_for_test(
            CapabilityId::new(OPERATOR_CONFIG_SET_TOOL_PERMISSION_CAPABILITY_ID)
                .expect("capability id"),
            scope.clone(),
            serde_json::json!({
                "capability_id": capability_id.as_str(),
                "state": "always_allow",
            }),
            None,
        );
        request.authenticated_actor_user_id = Some(user.clone());
        let result = handler.dispatch(request).await.expect("dispatch");
        assert_eq!(result.output["state"], "always_allow");
        let operator_scope = scope.tenant_user_settings_scope();
        let policy_key = PersistentApprovalPolicyKey::new(
            &operator_scope,
            PersistentApprovalAction::Dispatch,
            capability_id.clone(),
            Principal::Extension(provider),
        );
        assert!(
            persistent_policies
                .lookup(&policy_key)
                .await
                .expect("policy lookup")
                .and_then(|policy| policy.active_grant())
                .is_some()
        );
        assert!(
            overrides
                .get(&ToolPermissionOverrideKey::new(
                    &operator_scope,
                    capability_id.clone()
                ))
                .await
                .expect("override lookup")
                .is_none()
        );

        let mut request = FirstPartyCapabilityRequest::request_for_test(
            CapabilityId::new(OPERATOR_CONFIG_SET_TOOL_PERMISSION_CAPABILITY_ID)
                .expect("capability id"),
            scope.clone(),
            serde_json::json!({
                "capability_id": capability_id.as_str(),
                "state": "disabled",
            }),
            None,
        );
        request.authenticated_actor_user_id = Some(user);
        let result = handler.dispatch(request).await.expect("dispatch");
        assert_eq!(result.output["state"], "disabled");
        assert!(
            persistent_policies
                .lookup(&policy_key)
                .await
                .expect("policy lookup")
                .and_then(|policy| policy.active_grant())
                .is_none()
        );
        assert_eq!(
            overrides
                .get(&ToolPermissionOverrideKey::new(
                    &operator_scope,
                    capability_id
                ))
                .await
                .expect("override lookup")
                .map(|record| record.state),
            Some(ToolPermissionOverride::Disabled)
        );
    }

    /// The hard floor, driven through `handler.dispatch` rather than through
    /// `hard_floor_tool`/`tool_permission_locked` directly.
    ///
    /// Those predicates gate a persistent authority write, and a wrapper plus a
    /// catalog lookup sit between them and that write — so a unit test on the
    /// predicate alone would not catch a wrong `matches!` arm or an inverted
    /// `==` in the caller (`.claude/rules/testing.md`, "Test through the
    /// caller"). Every locked shape must be refused *and* leave both stores
    /// untouched: a refusal that still wrote would be the dangerous outcome.
    #[tokio::test]
    async fn locked_tools_are_refused_and_write_nothing() {
        let user = UserId::new("operator").expect("user id");
        let provider = ExtensionId::new("ext").expect("provider id");

        // One case per reason a tool is locked: the three hard-floor effects,
        // and a `Deny` default with an otherwise innocuous effect.
        let cases: Vec<(&str, PermissionMode, EffectKind)> = vec![
            ("ext.pay", PermissionMode::Ask, EffectKind::Financial),
            (
                "ext.approve",
                PermissionMode::Ask,
                EffectKind::ModifyApproval,
            ),
            ("ext.budget", PermissionMode::Ask, EffectKind::ModifyBudget),
            ("ext.denied", PermissionMode::Deny, EffectKind::Network),
        ];

        for (tool_id, default_permission, effect) in cases {
            let capability_id = CapabilityId::new(tool_id).expect("capability id");
            let (overrides, persistent_policies, handler) =
                tool_permission_fixture(vec![RebornOperatorToolInfo {
                    capability_id: capability_id.clone(),
                    provider: provider.clone(),
                    description: Arc::from("Locked"),
                    default_permission,
                    effects: Arc::<[EffectKind]>::from(vec![effect]),
                }]);
            let scope = ResourceScope::local_default(user.clone(), InvocationId::new())
                .expect("resource scope");

            for state in ["always_allow", "ask_each_time", "disabled", "default"] {
                let mut request = FirstPartyCapabilityRequest::request_for_test(
                    CapabilityId::new(OPERATOR_CONFIG_SET_TOOL_PERMISSION_CAPABILITY_ID)
                        .expect("capability id"),
                    scope.clone(),
                    serde_json::json!({
                        "capability_id": capability_id.as_str(),
                        "state": state,
                    }),
                    None,
                );
                request.authenticated_actor_user_id = Some(user.clone());
                let error = handler
                    .dispatch(request)
                    .await
                    .expect_err(&format!("{tool_id} -> {state} must be refused"));
                assert_eq!(
                    error.kind(),
                    Some(RuntimeDispatchErrorKind::PolicyDenied),
                    "{tool_id} -> {state} must be refused as a policy denial, not another kind"
                );
            }

            let operator_scope = ResourceScope::local_default(user.clone(), InvocationId::new())
                .expect("resource scope")
                .tenant_user_settings_scope();
            let policy_key = PersistentApprovalPolicyKey::new(
                &operator_scope,
                PersistentApprovalAction::Dispatch,
                capability_id.clone(),
                Principal::Extension(provider.clone()),
            );
            assert!(
                persistent_policies
                    .lookup(&policy_key)
                    .await
                    .expect("policy lookup")
                    .and_then(|policy| policy.active_grant())
                    .is_none(),
                "{tool_id}: a refused request must not mint a persistent grant"
            );
            assert!(
                overrides
                    .get(&ToolPermissionOverrideKey::new(
                        &operator_scope,
                        capability_id
                    ))
                    .await
                    .expect("override lookup")
                    .is_none(),
                "{tool_id}: a refused request must not write an override"
            );
        }
    }

    /// An override store whose `clear` always fails, so a test can observe what
    /// a partial failure of the two-store `always_allow` write leaves behind.
    struct ClearFailsOverrideStore {
        inner: Arc<dyn ironclaw_approvals::ToolPermissionOverrideStorePort>,
    }

    #[async_trait]
    impl ironclaw_approvals::CapabilityPermissionOverrideStorePort for ClearFailsOverrideStore {
        async fn set(
            &self,
            input: ironclaw_approvals::CapabilityPermissionOverrideInput,
        ) -> Result<
            ironclaw_approvals::CapabilityPermissionOverrideRecord,
            ironclaw_approvals::CapabilityPermissionStoreError,
        > {
            self.inner.set(input).await
        }

        async fn get(
            &self,
            key: &ironclaw_approvals::CapabilityPermissionOverrideKey,
        ) -> Result<
            Option<ironclaw_approvals::CapabilityPermissionOverrideRecord>,
            ironclaw_approvals::CapabilityPermissionStoreError,
        > {
            self.inner.get(key).await
        }

        async fn clear(
            &self,
            _key: &ironclaw_approvals::CapabilityPermissionOverrideKey,
        ) -> Result<(), ironclaw_approvals::CapabilityPermissionStoreError> {
            Err(
                ironclaw_approvals::CapabilityPermissionStoreError::Filesystem(
                    "injected clear failure".to_string(),
                ),
            )
        }
    }

    /// `always_allow` writes two stores and the pair is not atomic, so the
    /// order decides what a partial failure leaves behind.
    ///
    /// Granting first and then failing to clear would persist a live `Dispatch`
    /// grant underneath the operator's earlier `Disabled` override — auto-approval
    /// authority the operator never sees, waiting for anything else to clear the
    /// override. Clearing first can only ever leave *less* authority than was
    /// asked for. This pins the fail-closed direction: after a failed
    /// `always_allow`, there must be no persistent grant.
    #[tokio::test]
    async fn a_failed_always_allow_never_leaves_a_grant_behind() {
        let capability_id = CapabilityId::new("ext.search").expect("capability id");
        let provider = ExtensionId::new("ext").expect("provider id");
        let tool = RebornOperatorToolInfo {
            capability_id: capability_id.clone(),
            provider: provider.clone(),
            description: Arc::from("Search"),
            default_permission: PermissionMode::Ask,
            effects: Arc::<[EffectKind]>::from(vec![EffectKind::Network]),
        };
        let (overrides, persistent_policies, _) = tool_permission_fixture(vec![tool.clone()]);
        let failing_overrides: Arc<dyn ironclaw_approvals::ToolPermissionOverrideStorePort> =
            Arc::new(ClearFailsOverrideStore {
                inner: Arc::clone(&overrides),
            });
        let user = UserId::new("operator").expect("user id");
        let scope = ResourceScope::local_default(user.clone(), InvocationId::new())
            .expect("resource scope");
        let operator_scope = scope.tenant_user_settings_scope();

        // The operator had previously disabled the tool.
        overrides
            .set(ToolPermissionOverrideInput {
                scope: operator_scope.clone(),
                capability_id: capability_id.clone(),
                state: ToolPermissionOverride::Disabled,
                updated_by: Principal::User(user.clone()),
            })
            .await
            .expect("seed disabled override");

        let error = apply_tool_permission_state(
            failing_overrides.as_ref(),
            persistent_policies.as_ref(),
            &scope,
            &user,
            &tool,
            ToolPermissionUpdate::State(ToolPermissionState::AlwaysAllow),
            Instant::now(),
        )
        .await
        .expect_err("the failing override clear must surface");
        assert_eq!(error.kind(), Some(RuntimeDispatchErrorKind::Backend));

        let policy_key = PersistentApprovalPolicyKey::new(
            &operator_scope,
            PersistentApprovalAction::Dispatch,
            capability_id,
            Principal::Extension(provider),
        );
        assert!(
            persistent_policies
                .lookup(&policy_key)
                .await
                .expect("policy lookup")
                .and_then(|policy| policy.active_grant())
                .is_none(),
            "a failed always_allow must not leave a live Dispatch grant under the stale \
             Disabled override"
        );
    }

    struct StaticToolCatalog(Vec<RebornOperatorToolInfo>);

    #[async_trait]
    impl RebornOperatorToolCatalog for StaticToolCatalog {
        async fn list_operator_tools(&self, _caller: &UserId) -> Vec<RebornOperatorToolInfo> {
            self.0.clone()
        }
    }
}
