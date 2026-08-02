//! API-visible first-party mutations for skill activation settings.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use async_trait::async_trait;
use ironclaw_extensions::{
    CapabilityManifest, CapabilityVisibility, ExtensionError, ExtensionPackage,
};
use ironclaw_host_api::{
    capability::{EffectKind, OriginGateMatrix, PermissionMode},
    capability_profile::CapabilityProfileSchemaRef,
    dispatch::RuntimeDispatchErrorKind,
    error::HostApiError,
    ids::{CapabilityId, TenantId, UserId},
    resource::{ResourceEstimate, ResourceProfile, ResourceUsage},
};
use ironclaw_host_runtime::{
    FirstPartyCapabilityError, FirstPartyCapabilityHandler, FirstPartyCapabilityRegistry,
    FirstPartyCapabilityRequest, FirstPartyCapabilityResult,
};
use ironclaw_product::{RebornSkillActionResponse, SKILL_AUTO_ACTIVATE_LEARNED_SET_CAPABILITY_ID};

pub fn extend_builtin_first_party_package(
    mut package: ExtensionPackage,
) -> Result<ExtensionPackage, ExtensionError> {
    package.manifest.capabilities.push(manifest()?);
    let root = package
        .materialized_root()
        .map_err(|error| ExtensionError::InvalidManifest {
            reason: format!("built-in package requires a materialized root: {error}"),
        })?
        .clone();
    ExtensionPackage::from_manifest(package.manifest, root)
}

pub fn insert_handler(
    registry: &mut FirstPartyCapabilityRegistry,
    auto_activate_learned: Arc<AtomicBool>,
) -> Result<(), HostApiError> {
    registry.insert_handler(
        CapabilityId::new(SKILL_AUTO_ACTIVATE_LEARNED_SET_CAPABILITY_ID)?,
        Arc::new(SetSkillAutoActivateLearnedHandler {
            auto_activate_learned,
            switch_owner: OnceLock::new(),
        }),
    );
    Ok(())
}

fn manifest() -> Result<CapabilityManifest, ExtensionError> {
    Ok(CapabilityManifest {
        id: CapabilityId::new(SKILL_AUTO_ACTIVATE_LEARNED_SET_CAPABILITY_ID)?,
        description: "Set the learned-skill auto-activation default for this deployment."
            .to_string(),
        // A settings write. `EffectKind` has no settings variant, and the
        // per-user design this switch is waiting on (a durable per-user
        // record, read per turn by the activation source) *is* a filesystem
        // write, so the manifest keeps the stricter declaration rather than
        // under-declaring the effect. Over-declaring only tightens gating.
        effects: vec![EffectKind::WriteFilesystem],
        default_permission: PermissionMode::Allow,
        visibility: CapabilityVisibility::Api,
        input_schema_ref: CapabilityProfileSchemaRef::new(
            "schemas/builtin/skill_auto_activate_learned_set.input.v1.json",
        )?,
        output_schema_ref: Some(CapabilityProfileSchemaRef::new(
            "schemas/builtin/skill_auto_activate_learned_set.output.v1.json",
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

/// The identity a call to this capability writes on behalf of.
///
/// Only the tenant/user axes: `agent_id` and `project_id` vary between two
/// calls by the same person, and this switch is not scoped to either.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SwitchCaller {
    tenant_id: TenantId,
    user_id: UserId,
}

/// Writes the learned-skill auto-activation default.
///
/// **The switch is process-global, not per-user.** What the skill-activation
/// source reads (`ironclaw_first_party_extension_ports::activation`) is this
/// one `AtomicBool`, shared by every turn of every user in the process; there
/// is no durable per-user record behind it and the read site takes no user.
/// So this handler does not pretend the setting is per-user: it binds the
/// switch to the first authenticated caller that sets it and denies every
/// other caller, rather than letting one user silently re-configure another
/// user's turns. The deny is deliberately the fail-closed direction — the
/// alternative is a cross-user write with no signal at either end.
///
/// Making the setting genuinely per-user is a change to the *read* side and
/// its wiring (a durable per-user record plus a per-turn lookup at the
/// activation source), neither of which this crate owns; the guard here is
/// what keeps the gap from being a silent one until then.
struct SetSkillAutoActivateLearnedHandler {
    auto_activate_learned: Arc<AtomicBool>,
    switch_owner: OnceLock<SwitchCaller>,
}

impl SetSkillAutoActivateLearnedHandler {
    /// Claim the process-global switch for `caller`, or reject a caller that
    /// is not the one holding it.
    fn claim_switch(
        &self,
        caller: SwitchCaller,
        started: Instant,
    ) -> Result<(), FirstPartyCapabilityError> {
        if self.switch_owner.get_or_init(|| caller.clone()) == &caller {
            return Ok(());
        }
        tracing::debug!(
            "denied a learned-skill auto-activation write from a caller that does not \
             hold the process-global switch"
        );
        Err(dispatch_error(
            RuntimeDispatchErrorKind::PolicyDenied,
            started,
        ))
    }
}

#[async_trait]
impl FirstPartyCapabilityHandler for SetSkillAutoActivateLearnedHandler {
    async fn dispatch(
        &self,
        request: FirstPartyCapabilityRequest,
    ) -> Result<FirstPartyCapabilityResult, FirstPartyCapabilityError> {
        let started = Instant::now();
        ensure_declared(&request, started)?;
        let caller = authenticated_caller(&request, started)?;
        // Parse before claiming: a malformed payload must not take the switch
        // away from the caller that can actually use it.
        let enabled = parse_enabled(request.input, started)?;
        self.claim_switch(caller, started)?;
        self.auto_activate_learned.store(enabled, Ordering::Relaxed);
        let response = RebornSkillActionResponse {
            success: true,
            message: format!(
                "Default skill auto-activation {}",
                if enabled { "enabled" } else { "disabled" }
            ),
        };
        let output = serde_json::to_value(response)
            .map_err(|_| dispatch_error(RuntimeDispatchErrorKind::InvalidResult, started))?;
        Ok(FirstPartyCapabilityResult::new(
            output,
            resource_usage(started),
        ))
    }
}

fn authenticated_caller(
    request: &FirstPartyCapabilityRequest,
    started: Instant,
) -> Result<SwitchCaller, FirstPartyCapabilityError> {
    if request.authenticated_actor_user_id.as_ref() != Some(&request.scope.user_id) {
        return Err(dispatch_error(
            RuntimeDispatchErrorKind::PolicyDenied,
            started,
        ));
    }
    Ok(SwitchCaller {
        tenant_id: request.scope.tenant_id.clone(),
        user_id: request.scope.user_id.clone(),
    })
}

fn ensure_declared(
    request: &FirstPartyCapabilityRequest,
    started: Instant,
) -> Result<(), FirstPartyCapabilityError> {
    if request.capability_id.as_str() == SKILL_AUTO_ACTIVATE_LEARNED_SET_CAPABILITY_ID {
        Ok(())
    } else {
        Err(dispatch_error(
            RuntimeDispatchErrorKind::UndeclaredCapability,
            started,
        ))
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

fn dispatch_error(kind: RuntimeDispatchErrorKind, started: Instant) -> FirstPartyCapabilityError {
    FirstPartyCapabilityError::new(kind).with_usage(resource_usage(started))
}

fn resource_usage(started: Instant) -> ResourceUsage {
    ResourceUsage::default()
        .set_wall_clock_ms(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use ironclaw_host_api::{
        ids::{InvocationId, UserId},
        resource::ResourceScope,
    };

    use super::*;

    fn handler(
        auto_activate_learned: Arc<AtomicBool>,
    ) -> Arc<dyn FirstPartyCapabilityHandler + 'static> {
        let mut registry = FirstPartyCapabilityRegistry::new();
        insert_handler(&mut registry, auto_activate_learned).expect("handler wiring");
        registry
            .get(
                &CapabilityId::new(SKILL_AUTO_ACTIVATE_LEARNED_SET_CAPABILITY_ID)
                    .expect("capability id"),
            )
            .expect("handler registered under its declared capability id")
    }

    /// One authenticated WebUI call, shaped the way the product surface
    /// stamps it: the scope's user is the verified actor.
    fn set_request(user: &str, enabled: bool) -> FirstPartyCapabilityRequest {
        let user_id = UserId::new(user).expect("user id");
        let mut request = FirstPartyCapabilityRequest::request_for_test(
            CapabilityId::new(SKILL_AUTO_ACTIVATE_LEARNED_SET_CAPABILITY_ID)
                .expect("capability id"),
            ResourceScope::local_default(user_id.clone(), InvocationId::new())
                .expect("resource scope"),
            serde_json::json!({ "enabled": enabled }),
            None,
        );
        request.authenticated_actor_user_id = Some(user_id);
        request
    }

    #[test]
    fn capability_is_api_only_filesystem_write() {
        let manifest = manifest().expect("manifest");
        assert_eq!(manifest.visibility, CapabilityVisibility::Api);
        assert_eq!(manifest.default_permission, PermissionMode::Allow);
        assert_eq!(manifest.effects, vec![EffectKind::WriteFilesystem]);
    }

    /// The switch this capability writes is one process-wide flag, so a
    /// second user's call must be denied rather than silently re-configuring
    /// the first user's turns.
    ///
    /// Driven through the registry the way composition wires it, because the
    /// registration is what binds the handler to the id the product surface
    /// dispatches; a direct call on the struct would not prove that the
    /// authenticated caller ever reaches this handler.
    #[tokio::test]
    async fn a_second_user_cannot_move_the_process_global_default() {
        let auto_activate_learned = Arc::new(AtomicBool::new(true));
        let handler = handler(Arc::clone(&auto_activate_learned));

        handler
            .dispatch(set_request("alice", false))
            .await
            .expect("the owning caller sets the default");
        assert!(
            !auto_activate_learned.load(Ordering::Relaxed),
            "the owning caller's write lands"
        );

        let error = handler
            .dispatch(set_request("mallory", true))
            .await
            .expect_err("a different user must not write the process-global switch");
        assert_eq!(
            error.kind(),
            Some(RuntimeDispatchErrorKind::PolicyDenied),
            "the denial is a policy decision, not a malformed input"
        );
        assert!(
            !auto_activate_learned.load(Ordering::Relaxed),
            "the first caller's default survives another user's attempt"
        );
    }

    /// The fail-closed guard binds the switch to a caller, not to a single
    /// call: the owning caller keeps toggling it, including back to the value
    /// it started at.
    #[tokio::test]
    async fn the_owning_caller_keeps_writing_the_default() {
        let auto_activate_learned = Arc::new(AtomicBool::new(true));
        let handler = handler(Arc::clone(&auto_activate_learned));

        for enabled in [false, true, false] {
            handler
                .dispatch(set_request("alice", enabled))
                .await
                .expect("the owning caller keeps its write authority");
            assert_eq!(auto_activate_learned.load(Ordering::Relaxed), enabled);
        }
    }

    /// A caller whose verified actor does not match the scope it claims is
    /// denied before it can claim the switch — otherwise a spoofed scope
    /// would lock the real owner out of a setting it never set.
    #[tokio::test]
    async fn an_unverified_caller_neither_writes_nor_claims_the_switch() {
        let auto_activate_learned = Arc::new(AtomicBool::new(true));
        let handler = handler(Arc::clone(&auto_activate_learned));

        let mut spoofed = set_request("alice", false);
        spoofed.authenticated_actor_user_id = Some(UserId::new("mallory").expect("user id"));
        let error = handler
            .dispatch(spoofed)
            .await
            .expect_err("the verified actor must match the scope it writes");
        assert_eq!(error.kind(), Some(RuntimeDispatchErrorKind::PolicyDenied));
        assert!(auto_activate_learned.load(Ordering::Relaxed));

        handler
            .dispatch(set_request("alice", false))
            .await
            .expect("the real owner still claims the switch afterwards");
        assert!(!auto_activate_learned.load(Ordering::Relaxed));
    }
}
