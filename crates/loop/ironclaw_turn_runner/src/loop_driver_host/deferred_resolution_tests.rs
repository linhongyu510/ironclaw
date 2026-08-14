//! Production host-build coverage for deferred provider-call resolution.
#![cfg(test)]

use super::*;

use ironclaw_host_api::ids::{AgentId, CapabilityId, ProjectId, TenantId, ThreadId};
use ironclaw_host_api::turn::{TurnId, TurnLeaseToken, TurnRunId, TurnScope};
use ironclaw_loop_contracts::{
    CapabilitySurfaceVersion, InMemoryLoopHostMilestoneSink, InMemoryRunProfileResolver,
    ProviderToolCallCapabilityIds, RunProfileResolutionRequest, RunProfileResolver,
};
use ironclaw_threads::{EnsureThreadRequest, InMemorySessionThreadService};
use ironclaw_turns::test_support::{in_memory_agent_turn_runtime, in_memory_loop_checkpoint_store};

struct UnusedGateway;

#[async_trait]
impl HostManagedModelGateway for UnusedGateway {
    async fn stream_model(
        &self,
        _request: ironclaw_loop_host::HostManagedModelRequest,
    ) -> Result<
        ironclaw_loop_host::HostManagedModelResponse,
        ironclaw_loop_host::HostManagedModelError,
    > {
        panic!("this test never dispatches a model call"); // safety: test-only unreachable sentinel.
    }
}

struct DeferredResolverPort {
    capability_id: CapabilityId,
    definition: ProviderToolDefinition,
}

#[async_trait]
impl LoopCapabilityPort for DeferredResolverPort {
    fn tool_definitions(&self) -> Result<Vec<ProviderToolDefinition>, AgentLoopHostError> {
        Ok(Vec::new())
    }

    fn deferred_tool_definitions(&self) -> Result<Vec<ProviderToolDefinition>, AgentLoopHostError> {
        Ok(vec![self.definition.clone()])
    }

    fn provider_tool_call_capability_ids(
        &self,
        tool_call: &ProviderToolCall,
    ) -> Result<ProviderToolCallCapabilityIds, AgentLoopHostError> {
        assert_eq!(tool_call.name, self.definition.name);
        Ok(ProviderToolCallCapabilityIds::single(
            self.capability_id.clone(),
        ))
    }

    async fn invoke_capability(
        &self,
        _request: LoopRequest,
    ) -> Result<ironclaw_host_api::resolution::Resolution, AgentLoopHostError> {
        unreachable!("this test only resolves provider tool calls")
    }

    async fn invoke_capability_batch(
        &self,
        _request: LoopRequestBatch,
    ) -> Result<ironclaw_host_api::resolution::ResolutionBatch, AgentLoopHostError> {
        unreachable!("this test only resolves provider tool calls")
    }

    async fn visible_capabilities(
        &self,
        _request: VisibleCapabilityRequest,
    ) -> Result<VisibleCapabilitySurface, AgentLoopHostError> {
        Ok(VisibleCapabilitySurface {
            version: CapabilitySurfaceVersion::new("deferred-resolution-surface")
                .expect("valid surface version"),
            descriptors: Vec::new(),
            callable_capability_ids: None,
        })
    }
}

#[tokio::test]
async fn production_host_delegates_deferred_provider_call_resolution() {
    let thread_service = Arc::new(InMemorySessionThreadService::default());
    let tenant_id = TenantId::new("tenant-deferred-resolution").unwrap();
    let agent_id = AgentId::new("agent-deferred-resolution").unwrap();
    let project_id = ProjectId::new("project-deferred-resolution").unwrap();
    let thread_id = ThreadId::new("thread-deferred-resolution").unwrap();
    let thread_scope = ThreadScope {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        project_id: Some(project_id.clone()),
        owner_user_id: None,
        mission_id: None,
    };
    thread_service
        .ensure_thread(EnsureThreadRequest {
            scope: thread_scope.clone(),
            thread_id: Some(thread_id.clone()),
            created_by_actor_id: "user-deferred-resolution".to_string(),
            title: None,
            metadata_json: None,
        })
        .await
        .unwrap();

    let turn_scope = TurnScope::new(tenant_id, Some(agent_id), Some(project_id), thread_id);
    let resolved = InMemoryRunProfileResolver::default()
        .resolve_run_profile(RunProfileResolutionRequest::interactive_default())
        .await
        .unwrap();
    let run_context = LoopRunContext::new(
        turn_scope.clone(),
        TurnId::new(),
        TurnRunId::new(),
        resolved.clone(),
    );
    let claimed_run = claimed_run_matching(&run_context, &turn_scope);
    let capability_id = CapabilityId::new("demo.deferred").unwrap();
    let definition = ProviderToolDefinition::from_typed_parts(
        capability_id.clone(),
        ProviderToolDefinition::validate_name("demo__deferred").unwrap(),
        "Deferred capability",
        serde_json::json!({"type": "object"}),
    );
    let capabilities = Arc::new(DeferredResolverPort {
        capability_id: capability_id.clone(),
        definition,
    });
    let factory = RebornLoopDriverHostFactory::new(
        thread_service,
        thread_scope,
        Arc::new(UnusedGateway),
        Arc::new(in_memory_agent_turn_runtime()) as Arc<dyn AgentTurnSpawnTreeRuntimePort>,
        Arc::new(in_memory_loop_checkpoint_store()) as Arc<dyn LoopCheckpointStore>,
        Arc::new(InMemoryLoopHostMilestoneSink::default()) as Arc<dyn LoopHostMilestoneSink>,
        TextOnlyLoopHostConfig {
            max_messages: 8,
            require_model_route_snapshot: false,
        },
        InstructionSafetyContext::non_production_noop(),
    );
    let host = factory
        .build_text_only_host_with_capabilities(
            RebornLoopDriverHostRequest {
                claimed_run,
                loop_run_context: run_context,
            },
            capabilities,
        )
        .await
        .expect("host builds");
    let tool_call = ProviderToolCall::from_parts(
        "fixture-provider",
        "fixture-model",
        None,
        "call-1",
        "demo__deferred",
        serde_json::json!({}),
    )
    .expect("provider tool call");

    let resolved = host
        .provider_tool_call_capability_ids(&tool_call)
        .expect("deferred call reaches inner resolver");
    assert_eq!(resolved.provider_capability_id, capability_id);
}

fn claimed_run_matching(
    run_context: &LoopRunContext,
    scope: &TurnScope,
) -> ironclaw_turns::runner::ClaimedTurnRun {
    use ironclaw_turns::{
        AcceptedMessageRef, ReplyTargetBindingRef, SourceBindingRef, TurnRunnerId, TurnStatus,
    };

    ironclaw_turns::runner::ClaimedTurnRun {
        state: ironclaw_turns::TurnRunState {
            scope: scope.clone(),
            actor: None,
            turn_id: run_context.turn_id,
            run_id: run_context.run_id,
            status: TurnStatus::Running,
            accepted_message_ref: AcceptedMessageRef::new("msg:accepted").expect("valid"),
            source_binding_ref: SourceBindingRef::new("source-web").expect("valid"),
            reply_target_binding_ref: ReplyTargetBindingRef::new("reply-web").expect("valid"),
            resolved_run_profile_id: persisted_profile_id(
                &run_context.resolved_run_profile.profile_id,
            ),
            resolved_run_profile_version: run_context.resolved_run_profile.profile_version,
            allow_steering: true,
            resolved_model_route: None,
            model_usage: None,
            received_at: chrono::Utc::now(),
            checkpoint_id: None,
            gate_ref: None,
            blocked_activity_id: None,
            credential_requirements: Vec::new(),
            failure: None,
            event_cursor: ironclaw_turns::EventCursor(0),
            product_context: None,
            resume_disposition: None,
        },
        resolved_run_profile: run_context.resolved_run_profile.clone(),
        subagent_depth: 0,
        spawn_tree_descendant_cap: None,
        runner_id: TurnRunnerId::new(),
        lease_token: TurnLeaseToken::new(),
    }
}
