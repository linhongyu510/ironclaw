//! Integration test: a production-shaped `RebornRuntime` actually composes the
//! attested-signing graph.
//!
//! Regression for a total-inertness gap. Every piece of the attested-signing
//! path shipped and was unit-tested, but the shipping runtime constructed none
//! of it — `build_backend_production` hardcoded `attested_signing: None` and
//! `intent_store: None`, and no `AttestedRaiseHook` was ever handed to the host
//! runtime. The consequences compounded across four seams:
//!
//! 1. `product_surface.rs` registers the attested continuation only when BOTH
//!    `attested_signing()` and `intent_store()` are `Some`, so the resolve-gate
//!    ingress had nothing to dispatch to and refused every attested resolution.
//! 2. `production_turn_state_store` received `attested_resume_port: None`, so
//!    the turn store never admitted an attested resume.
//! 3. With no `AttestedRaiseHook` registered, `request_signature` fell through
//!    to the deliberately fail-closed handler in
//!    `first_party_tools/request_signature.rs` — whose own doc comment says it
//!    is "only reachable when no [`AttestedRaiseHook`] is" set.
//!
//! Net effect: no gate could be raised, and no gate could be resolved. The
//! behaviour of each piece was covered (see `attested_request_signature_raise`
//! and the driver's own suites); what was missing was that anything ever built
//! them. This test asserts the composition, which is the only thing those
//! suites cannot see.
//!
//! Lives in its own integration-test binary (mirroring
//! `production_runtime_identity.rs`) so the CPU-heavy production build does not
//! starve the lib unit tests' timeout budgets, and needs the libSQL substrate
//! the production-runtime path requires.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ironclaw_host_api::runtime_policy::{
    ApprovalPolicy, AuditMode, DeploymentMode, EffectiveRuntimePolicy, FilesystemBackendKind,
    NetworkMode, ProcessBackendKind, RuntimeProfile, SecretMode,
};
use ironclaw_host_api::{
    CapabilityId, CapabilitySet, CorrelationId, ExecutionContext, ExtensionId, FailureKind,
    InvocationId, InvocationOrigin, MountView, ProjectId, ResourceEstimate, ResourceScope, RunId,
    RuntimeKind, TenantId, TrustClass, UserId,
};
use ironclaw_host_runtime::{
    CommandExecutionOutput, CommandExecutionRequest, RuntimeCapabilityOutcome, RuntimeProcessError,
    SandboxCommandTransport, TenantSandboxProcessPort,
};
use ironclaw_reborn_composition::{
    RebornCompositionProfile, RebornHostBindings, RebornRuntimeIdentity, RebornRuntimeInput,
    RebornRuntimeProcessBinding, build_reborn_runtime,
};
use serde_json::json;

#[path = "support/first_party.rs"]
mod first_party_support;

#[derive(Debug)]
struct RecordingSandboxTransport;

#[async_trait]
impl SandboxCommandTransport for RecordingSandboxTransport {
    async fn run_command(
        &self,
        _request: CommandExecutionRequest,
    ) -> Result<CommandExecutionOutput, RuntimeProcessError> {
        Ok(CommandExecutionOutput {
            output: String::new(),
            saved_output: None,
            exit_code: 0,
            sandboxed: true,
            duration: Duration::ZERO,
        })
    }
}

/// The production build composes the attested-signing graph and the intent
/// store, so the gate ingress has something to dispatch to and
/// `request_signature` reaches the raise hook rather than the fail-closed
/// handler.
#[tokio::test]
async fn production_runtime_composes_the_attested_signing_graph() {
    // The custodial keystore is minted through `ironclaw_secrets`; without this
    // the build reaches for the OS keychain under test.
    unsafe { std::env::set_var("IRONCLAW_DISABLE_OS_KEYCHAIN", "1") };

    let dir = tempfile::tempdir().expect("tempdir");
    let db = Arc::new(
        libsql::Builder::new_local(dir.path().join("reborn.db"))
            .build()
            .await
            .expect("libsql db"),
    );

    let input = RebornRuntimeInput::from_build_input(
        RebornHostBindings::libsql(
            RebornCompositionProfile::Production,
            "prod-attested-owner",
            db,
            dir.path().join("events.db").to_string_lossy(),
            None,
            ironclaw_secrets::SecretMaterial::from("01234567890123456789012345678901"),
        )
        .with_first_party_bundles(first_party_support::test_first_party_bundles())
        .with_runtime_policy(EffectiveRuntimePolicy {
            deployment: DeploymentMode::HostedMultiTenant,
            requested_profile: RuntimeProfile::SecureDefault,
            resolved_profile: RuntimeProfile::SecureDefault,
            filesystem_backend: FilesystemBackendKind::ScopedVirtual,
            process_backend: ProcessBackendKind::TenantSandbox,
            network_mode: NetworkMode::Deny,
            secret_mode: SecretMode::BrokeredHandles,
            approval_policy: ApprovalPolicy::AskAlways,
            audit_mode: AuditMode::Standard,
        })
        .with_runtime_process_binding(RebornRuntimeProcessBinding::tenant_sandbox(Arc::new(
            TenantSandboxProcessPort::new(Arc::new(RecordingSandboxTransport)),
        ))),
    )
    .with_identity(RebornRuntimeIdentity {
        tenant_id: "prod-attested-runtime-tenant".to_string(),
        agent_id: "prod-attested-runtime-agent".to_string(),
        source_binding_id: "prod-attested-source".to_string(),
        reply_target_binding_id: "prod-attested-reply".to_string(),
    });

    let runtime = build_reborn_runtime(input)
        .await
        .expect("production runtime builds");

    // (1) THE ATTESTED GRAPH. `product_surface.rs` gates the whole attested
    // continuation on this being `Some`; `None` here means every attested gate
    // resolution is refused no matter how correct the ingress is.
    assert!(
        runtime.attested_signing().is_some(),
        "the production build must compose an attested-signing graph — without \
         it the resolve-gate ingress has nothing to dispatch to and refuses \
         every attested resolution"
    );

    // (2) THE INTENT STORE. The other half of that same `if let (Some, Some)`.
    // A composed graph with no intent store still yields no attested surface,
    // and no review link is ever minted for a raised gate.
    assert!(
        runtime.intent_store().is_some(),
        "the production build must compose an intent store — the attested \
         continuation is registered only when both it and the signing graph \
         are present"
    );

    // (3) THE RAISE HOOK, asserted through the capability path the agent loop
    // actually takes rather than through an accessor.
    //
    // `DefaultHostRuntime` intercepts `request_signature` and routes it to the
    // hook BEFORE the kernel authorization fold; with no hook the invocation
    // falls through into that fold instead. Deliberately malformed input
    // separates the two without needing a provisioned chain key: only the hook
    // can produce `InputEncode`. Verified by mutation — dropping
    // `with_attested_raise_hook` in the factory fails this assertion with
    // `Authorization` (the fold rejecting the empty grant set, having never
    // reached the fail-closed first-party handler behind it).
    let host_runtime = runtime
        .host_runtime_for_test()
        .expect("production runtime exposes its host runtime");
    let capability_id = CapabilityId::new("builtin.request_signature").expect("capability id");
    let outcome = host_runtime
        .invoke_capability((
            execution_context(owner_scope()),
            capability_id.clone(),
            ResourceEstimate::default(),
            json!({ "provider_hint": "custodial" }),
        ))
        .await
        .expect("invocation reaches the runtime");

    match outcome {
        RuntimeCapabilityOutcome::Failed(failure) => assert_eq!(
            failure.kind,
            FailureKind::InputEncode,
            "malformed input must be rejected BY THE RAISE HOOK; \
             `UnsupportedRunner` here means no hook is wired and every \
             `request_signature` refuses, making the attested path unreachable \
             from the agent loop"
        ),
        other => panic!("expected the raise hook to reject malformed input, got {other:?}"),
    }

    runtime.shutdown().await.expect("runtime shutdown");
}

fn owner_scope() -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new("default").expect("tenant"),
        user_id: UserId::new("alice").expect("user"),
        agent_id: None,
        project_id: Some(ProjectId::new("bootstrap").expect("project")),
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

/// The host execution context a raise reads identities from. A
/// `request_signature` only ever originates inside an agent-loop turn-run —
/// that is the origin whose gate the ceremony later resumes.
fn execution_context(scope: ResourceScope) -> ExecutionContext {
    let run_id = RunId::new();
    ExecutionContext {
        invocation_id: scope.invocation_id,
        correlation_id: CorrelationId::new(),
        process_id: None,
        parent_process_id: None,
        tenant_id: scope.tenant_id.clone(),
        user_id: scope.user_id.clone(),
        agent_id: scope.agent_id.clone(),
        project_id: scope.project_id.clone(),
        mission_id: None,
        thread_id: None,
        extension_id: ExtensionId::new("builtin").expect("extension"),
        runtime: RuntimeKind::Wasm,
        trust: TrustClass::UserTrusted,
        grants: CapabilitySet { grants: vec![] },
        mounts: MountView::default(),
        resource_scope: scope,
        authenticated_actor_user_id: None,
        origin: Some(InvocationOrigin::LoopRun(run_id)),
        run_id: Some(run_id),
    }
}
