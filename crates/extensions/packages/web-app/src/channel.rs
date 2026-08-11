//! The Web Push `ChannelAdapter`: render one envelope into one notification,
//! encrypt it per enrolled browser, and POST through restricted egress.

use async_trait::async_trait;
use ironclaw_extension_contracts::auth_prompt::render_channel_auth_prompt;
use ironclaw_extension_contracts::channel_adapter::{
    ChannelAdapter, ChannelContext, ChannelError, DeliveryReport, InboundOutcome,
    MAX_NOTIFICATION_SETUP_PAYLOAD_BYTES, NotificationSetupScope, NotificationSetupStatus,
    OutboundEnvelope, OutboundPart, PartDeliveryOutcome, VerifiedInbound,
};
use ironclaw_extension_contracts::tool_adapter::{
    RestrictedEgress, RestrictedEgressError, RestrictedEgressRequest,
};
use ironclaw_host_api::action::NetworkMethod;
use ironclaw_host_api::ids::{InvocationId, SecretHandle};
use ironclaw_host_api::resource::ResourceScope;
use ironclaw_web_app::{
    DEFAULT_TTL_SECONDS, PushEndpoint, PushSubscriptionKeys, PushSubscriptionRecord,
    PushSubscriptionUpsertOutcome, PushUrgency, WEB_APP_VAPID_CREDENTIAL_HANDLE, WebAppError,
    WebAppNotificationPayload, WebAppRuntimeSlot, build_push_request, decode_web_app_target_ref,
};

/// Deep link a notification opens; the service worker resolves it against
/// the app origin.
const NOTIFICATION_URL: &str = "/automations";
const NOTIFICATION_TITLE: &str = "IronClaw";

/// Per-subscription send outcomes, folded into one part outcome.
#[derive(Default)]
struct FanOutTally {
    accepted: usize,
    pruned: usize,
    retryable: Option<String>,
    permanent: Option<String>,
    unauthorized: Option<String>,
}

pub struct WebAppChannelAdapter {
    runtime: WebAppRuntimeSlot,
}

impl WebAppChannelAdapter {
    pub fn new(runtime: WebAppRuntimeSlot) -> Self {
        Self { runtime }
    }
}

#[async_trait]
impl ChannelAdapter for WebAppChannelAdapter {
    /// The web app's inbound entrypoint is the authenticated session (the
    /// generic session-inbound route), whose wire shape is host-owned and
    /// whose actor authority is the authenticated caller — by the trust
    /// rules, an adapter can never mint that identity from a payload. Session
    /// normalization therefore lives at the host session door, and this
    /// adapter's webhook-shaped `inbound` stays unsupported: no webhook mount
    /// exists for this channel and a vendor-style parse would have nothing to
    /// parse. Replies stream over the durable projection pipeline (the
    /// channel declares `reply_mode = "streaming"`); this adapter's delivery
    /// half carries only notification-class sends (browser push).
    fn inbound(&self, _request: VerifiedInbound<'_>) -> Result<InboundOutcome, ChannelError> {
        Err(ChannelError::Unsupported)
    }

    async fn notification_setup_status(
        &self,
        _context: &ChannelContext<'_>,
        scope: &NotificationSetupScope,
    ) -> Result<NotificationSetupStatus, ChannelError> {
        let runtime = self.runtime.get().map_err(setup_error)?;
        setup_status(&runtime, scope).await
    }

    async fn enable_notifications(
        &self,
        _context: &ChannelContext<'_>,
        scope: &NotificationSetupScope,
        payload: &str,
    ) -> Result<NotificationSetupStatus, ChannelError> {
        let runtime = self.runtime.get().map_err(setup_error)?;
        if payload.len() > MAX_NOTIFICATION_SETUP_PAYLOAD_BYTES {
            return Err(ChannelError::Parse {
                reason: "enrollment payload exceeds the setup payload bound".to_string(),
            });
        }
        // The payload is the browser's PushSubscription: untrusted input,
        // validated and bounded before any storage — endpoint shape, the
        // push-service host allowlist, and the key material lengths.
        let request: EnrollmentPayload =
            serde_json::from_str(payload).map_err(|_| ChannelError::Parse {
                reason: "enrollment payload is not a valid subscription document".to_string(),
            })?;
        let endpoint = PushEndpoint::new(request.endpoint).map_err(setup_input_error)?;
        endpoint
            .validate_against_push_services(&runtime.allowed_push_hosts)
            .map_err(setup_input_error)?;
        let keys = PushSubscriptionKeys::new(request.keys.p256dh, request.keys.auth)
            .map_err(setup_input_error)?;
        let record = PushSubscriptionRecord::new(
            endpoint,
            keys,
            request.user_agent,
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
        let resource_scope = enrollment_scope(scope);
        let outcome = runtime
            .subscriptions
            .upsert_subscription(&resource_scope, record)
            .await
            .map_err(setup_error)?;
        let mut status = setup_status(&runtime, scope).await?;
        status.detail = with_enrollment_outcome(status.detail, outcome)?;
        Ok(status)
    }

    async fn disable_notifications(
        &self,
        _context: &ChannelContext<'_>,
        scope: &NotificationSetupScope,
        payload: &str,
    ) -> Result<NotificationSetupStatus, ChannelError> {
        let runtime = self.runtime.get().map_err(setup_error)?;
        if payload.len() > MAX_NOTIFICATION_SETUP_PAYLOAD_BYTES {
            return Err(ChannelError::Parse {
                reason: "unenrollment payload exceeds the setup payload bound".to_string(),
            });
        }
        let request: UnenrollmentPayload =
            serde_json::from_str(payload).map_err(|_| ChannelError::Parse {
                reason: "unenrollment payload is not a valid document".to_string(),
            })?;
        let endpoint = PushEndpoint::new(request.endpoint).map_err(setup_input_error)?;
        let resource_scope = enrollment_scope(scope);
        let removed = runtime
            .subscriptions
            .remove_subscription(&resource_scope, &endpoint)
            .await
            .map_err(setup_error)?;
        let mut status = setup_status(&runtime, scope).await?;
        status.detail = with_removal_outcome(status.detail, removed)?;
        Ok(status)
    }

    async fn deliver(
        &self,
        envelope: OutboundEnvelope,
        egress: &dyn RestrictedEgress,
    ) -> Result<DeliveryReport, ChannelError> {
        let conversation_id = envelope.target.conversation.conversation_id();
        let Some((tenant_id, user_id)) = decode_web_app_target_ref(conversation_id) else {
            return Err(ChannelError::Render {
                reason: "delivery target is not a web-app conversation".to_string(),
            });
        };
        let runtime = self
            .runtime
            .get()
            .map_err(|_| ChannelError::Configuration {
                reason: "web push runtime is not wired yet".to_string(),
            })?;
        let scope = ResourceScope {
            tenant_id,
            user_id,
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        };
        let subscriptions = runtime
            .subscriptions
            .list_subscriptions(&scope)
            .await
            .map_err(|error| ChannelError::Configuration {
                reason: format!("push subscription lookup failed: {error}"),
            })?;

        // Render every deliverable part into one notification body; push is
        // a coalesced surface, not a message stream.
        let mut lines: Vec<String> = Vec::new();
        let mut urgency = PushUrgency::Normal;
        let mut part_supported: Vec<Result<(), &'static str>> = Vec::new();
        for part in &envelope.parts {
            match part {
                OutboundPart::Text(text) => {
                    lines.push(text.clone());
                    part_supported.push(Ok(()));
                }
                OutboundPart::AuthPrompt {
                    view,
                    direct_message,
                } => {
                    lines.push(render_channel_auth_prompt(view, *direct_message));
                    urgency = PushUrgency::High;
                    part_supported.push(Ok(()));
                }
                OutboundPart::File(_) => {
                    part_supported.push(Err("attachments are not supported by browser push"));
                }
                OutboundPart::Retract { .. } => {
                    part_supported.push(Err("retraction is not supported by browser push"));
                }
            }
        }

        let has_deliverable = part_supported.iter().any(Result::is_ok);
        if !has_deliverable {
            return Ok(DeliveryReport {
                parts: part_supported
                    .into_iter()
                    .map(|supported| match supported {
                        Ok(()) => PartDeliveryOutcome::Permanent {
                            reason: "nothing to deliver".to_string(),
                        },
                        Err(reason) => PartDeliveryOutcome::Permanent {
                            reason: reason.to_string(),
                        },
                    })
                    .collect(),
            });
        }

        let deliverable_outcome = if subscriptions.is_empty() {
            PartDeliveryOutcome::Permanent {
                reason: "no browsers are enrolled for web push".to_string(),
            }
        } else {
            let payload = WebAppNotificationPayload::new(
                NOTIFICATION_TITLE,
                lines.join("\n\n"),
                NOTIFICATION_URL,
                None,
            );
            let tally = self
                .fan_out(&runtime, &scope, &subscriptions, &payload, urgency, egress)
                .await?;
            fold_tally(tally)
        };

        Ok(DeliveryReport {
            parts: part_supported
                .into_iter()
                .map(|supported| match supported {
                    Ok(()) => deliverable_outcome.clone(),
                    Err(reason) => PartDeliveryOutcome::Permanent {
                        reason: reason.to_string(),
                    },
                })
                .collect(),
        })
    }
}

impl WebAppChannelAdapter {
    async fn fan_out(
        &self,
        runtime: &ironclaw_web_app::WebAppRuntime,
        scope: &ResourceScope,
        subscriptions: &[PushSubscriptionRecord],
        payload: &WebAppNotificationPayload,
        urgency: PushUrgency,
        egress: &dyn RestrictedEgress,
    ) -> Result<FanOutTally, ChannelError> {
        let credential_handle =
            SecretHandle::new(WEB_APP_VAPID_CREDENTIAL_HANDLE).map_err(|_| {
                ChannelError::Configuration {
                    reason: "VAPID credential handle is invalid".to_string(),
                }
            })?;
        let mut tally = FanOutTally::default();
        for subscription in subscriptions {
            let plan = match build_push_request(subscription, payload, DEFAULT_TTL_SECONDS, urgency)
            {
                Ok(plan) => plan,
                Err(error) => {
                    tally.permanent = Some(format!("push request planning failed: {error}"));
                    continue;
                }
            };
            let request = RestrictedEgressRequest {
                method: NetworkMethod::Post,
                url: subscription.endpoint.as_str().to_string(),
                headers: plan
                    .headers
                    .iter()
                    .map(|(name, value)| ((*name).to_string(), value.clone()))
                    .collect(),
                body: Some(plan.body),
                credential: Some(credential_handle.clone()),
                body_credentials: Vec::new(),
            };
            match egress.send(request).await {
                Ok(response) => match response.status {
                    200..=299 => tally.accepted += 1,
                    404 | 410 => {
                        // The push service says this subscription no longer
                        // exists — prune it so future sends stop trying.
                        // Prune failure must not fail the delivery.
                        if let Err(error) = runtime
                            .subscriptions
                            .remove_subscription(scope, &subscription.endpoint)
                            .await
                        {
                            tracing::debug!(
                                target: "ironclaw::web_app",
                                error = %error,
                                "failed to prune an expired push subscription"
                            );
                        }
                        tally.pruned += 1;
                    }
                    401 | 403 => {
                        tally.unauthorized = Some(format!(
                            "push service rejected VAPID authorization (status {})",
                            response.status
                        ));
                    }
                    413 => {
                        tally.permanent =
                            Some("push payload exceeds the push service limit".to_string());
                    }
                    429 => {
                        tally.retryable = Some("push service rate limited the send".to_string());
                    }
                    500..=599 => {
                        tally.retryable = Some(format!(
                            "push service unavailable (status {})",
                            response.status
                        ));
                    }
                    other => {
                        tally.permanent = Some(format!(
                            "push service rejected the request (status {other})"
                        ));
                    }
                },
                Err(RestrictedEgressError::AuthRequired { .. }) => {
                    tally.unauthorized = Some("VAPID key material is not available".to_string());
                }
                Err(error @ RestrictedEgressError::Transport { .. }) => {
                    tally.retryable = Some(error.to_string());
                }
                Err(error) => {
                    tally.permanent = Some(error.to_string());
                }
            }
        }
        Ok(tally)
    }
}

fn fold_tally(tally: FanOutTally) -> PartDeliveryOutcome {
    if tally.accepted > 0 {
        // Push services return 201/202 with no durable message reference the
        // adapter is allowed to read (response headers are host-withheld),
        // so the honest evidence is Sent-without-ref: acceptance by the push
        // service, not device receipt.
        return PartDeliveryOutcome::Sent {
            vendor_message_ref: None,
        };
    }
    if let Some(reason) = tally.unauthorized {
        return PartDeliveryOutcome::Unauthorized { reason };
    }
    if let Some(reason) = tally.retryable {
        return PartDeliveryOutcome::Retryable { reason };
    }
    if let Some(reason) = tally.permanent {
        return PartDeliveryOutcome::Permanent { reason };
    }
    if tally.pruned > 0 {
        return PartDeliveryOutcome::Permanent {
            reason: "every enrolled browser subscription has expired".to_string(),
        };
    }
    PartDeliveryOutcome::Permanent {
        reason: "no push delivery was attempted".to_string(),
    }
}

/// The browser's enrollment document (a `PushSubscription` projection).
#[derive(serde::Deserialize)]
struct EnrollmentPayload {
    endpoint: String,
    keys: EnrollmentKeys,
    #[serde(default)]
    user_agent: Option<String>,
}

#[derive(serde::Deserialize)]
struct EnrollmentKeys {
    p256dh: String,
    auth: String,
}

#[derive(serde::Deserialize)]
struct UnenrollmentPayload {
    endpoint: String,
}

/// The enrollment storage scope. Byte-identical to the scope the retired
/// `/web-app/*` product service derived from the authenticated caller, so
/// existing per-user subscription documents keep resolving.
fn enrollment_scope(scope: &NotificationSetupScope) -> ResourceScope {
    ResourceScope {
        tenant_id: scope.tenant_id.clone(),
        user_id: scope.user_id.clone(),
        agent_id: None,
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

async fn setup_status(
    runtime: &ironclaw_web_app::WebAppRuntime,
    scope: &NotificationSetupScope,
) -> Result<NotificationSetupStatus, ChannelError> {
    let resource_scope = enrollment_scope(scope);
    let subscriptions = runtime
        .subscriptions
        .list_subscriptions(&resource_scope)
        .await
        .map_err(setup_error)?;
    let mut enrolled = Vec::with_capacity(subscriptions.len());
    for record in &subscriptions {
        enrolled.push(serde_json::json!({
            "subscription_id": record.subscription_id,
            "endpoint_host": record.endpoint.host().map_err(setup_error)?,
            "endpoint_digest": record.endpoint.digest(),
            "user_agent": record.user_agent,
            "created_at": record.created_at,
        }));
    }
    let detail = serde_json::json!({
        "vapid_public_key": runtime.vapid_public_key,
        "subscription_count": subscriptions.len(),
        "subscriptions": enrolled,
    });
    Ok(NotificationSetupStatus {
        enabled: !subscriptions.is_empty(),
        detail: detail.to_string(),
    })
}

fn with_enrollment_outcome(
    detail: String,
    outcome: PushSubscriptionUpsertOutcome,
) -> Result<String, ChannelError> {
    amend_detail(detail, |value| {
        value["outcome"] = serde_json::json!(match outcome {
            PushSubscriptionUpsertOutcome::Enrolled => "enrolled",
            PushSubscriptionUpsertOutcome::Refreshed => "refreshed",
        });
    })
}

fn with_removal_outcome(detail: String, removed: bool) -> Result<String, ChannelError> {
    amend_detail(detail, |value| {
        value["removed"] = serde_json::json!(removed);
    })
}

fn amend_detail(
    detail: String,
    amend: impl FnOnce(&mut serde_json::Value),
) -> Result<String, ChannelError> {
    let mut value: serde_json::Value =
        serde_json::from_str(&detail).map_err(|_| ChannelError::Render {
            reason: "setup detail document is not valid JSON".to_string(),
        })?;
    amend(&mut value);
    Ok(value.to_string())
}

/// Caller-correctable input problems (endpoint shape, unsupported push
/// service, key material, per-user limit) surface as parse errors; anything
/// else is channel configuration trouble. Endpoint URLs never enter reasons.
fn setup_input_error(error: WebAppError) -> ChannelError {
    match &error {
        WebAppError::InvalidSubscription { .. }
        | WebAppError::UnsupportedPushService { .. }
        | WebAppError::SubscriptionLimitReached { .. } => ChannelError::Parse {
            reason: error.to_string(),
        },
        _ => setup_error(error),
    }
}

fn setup_error(error: WebAppError) -> ChannelError {
    ChannelError::Configuration {
        reason: error.to_string(),
    }
}
