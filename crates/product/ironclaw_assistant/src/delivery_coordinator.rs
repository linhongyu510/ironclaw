//! The generic outbound delivery coordinator (extension-runtime §5.4,
//! OUT-1..7).
//!
//! Sending a message decomposes into two halves: **semantics and
//! reliability** (target resolution, authorization, attempt persistence,
//! retry, crash recovery — identical for every channel, owned here,
//! once) and **vendor mechanics** (rendering, splitting, API selection,
//! error mapping — owned by each extension's
//! [`ChannelAdapter::deliver`](ironclaw_extension_contracts::channel_adapter::ChannelDelivery)).
//!
//! Rules this module owns:
//! - Every user-visible channel output is a semantic [`DeliveryIntent`];
//!   emitters never know what channel the user is on (OUT-1).
//! - An attempt is persisted (`Prepared`→`Sending`) **before** any vendor
//!   egress (OUT-3); the coordinator is the sole delivery-state writer —
//!   adapters get no store and cannot mark anything delivered (OUT-4).
//! - A crash after possible vendor success leaves `Sending`; recovery marks
//!   it `Unknown` and never blindly resends (OUT-6).
//! - Once any part of a multipart delivery is sent, a later retryable part
//!   failure is terminal — a whole-envelope retry would duplicate the parts
//!   the vendor already accepted (OUT-7).

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use ironclaw_attachments::DEFAULT_ATTACHMENT_BUDGETS;
use ironclaw_extension_contracts::channel_adapter::{
    OutboundEnvelope, OutboundPart, OutboundTarget, PartDeliveryOutcome,
};
use ironclaw_extension_contracts::external::ExternalConversationRef;
use ironclaw_host_api::ids::ExtensionId;
use ironclaw_host_api::path::ScopedPath;
use ironclaw_host_api::product_adapter::AdapterInstallationId;
use ironclaw_outbound::{
    ClaimDeliveryAttemptForSendRequest, DeliveryFailureKind, OutboundDeliveryAttempt,
    OutboundDeliveryDecision, OutboundDeliveryStatus, OutboundPolicyService, OutboundPushCandidate,
    OutboundPushKind, OutboundStateStorePort, PrepareCommunicationDeliveryRequest,
    ReplyAttachmentIntent, UpdateDeliveryStatusRequest, ValidatedReplyTargetBinding,
};
use ironclaw_product_contracts::delivery::{
    ChannelDeliveryResolver, DeliveryRegistrationService, DeliveryReplyContextSource,
    ResolvedChannelDelivery,
};
use ironclaw_threads::{AttachmentRef, ThreadScope};
use ironclaw_turns::{TurnRunId, TurnScope};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::debug;

use crate::ProductSurfaceFailure;
use crate::outbound_delivery::{
    ProductOutboundTargetResolver, VerifiedProductOutboundTargetMetadata,
};
use crate::{ProjectFilesystemReader, ProjectFsEntryKind, ProjectFsError};

/// The semantic intents (§5.4). Emitters express *what* is being
/// communicated; the coordinator decides targeting, persistence, and retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryIntent {
    /// The assistant's final reply for a run.
    FinalReply,
    /// An approval gate needs the user.
    GatePrompt,
    /// An auth gate needs the user (authorization URL — DM-only).
    AuthPrompt,
    /// The run failed, timed out, or a message was dropped.
    FailureNotice,
    /// The user must connect an account before the channel works.
    ConnectRequired,
    /// Pairing or account-connection status feedback.
    ConnectionStatus,
    /// Immediate result or user-correctable rejection of a product command.
    CommandFeedback,
    /// A transient "working on it" indicator.
    Working,
    /// Remove an earlier delivery (e.g. delete the working indicator).
    Cleanup,
    /// Add or clear a run-lifecycle reaction on the triggering message
    /// (👀 while working, ✅/⚠️ at the end). Best-effort, source-routed.
    Reaction,
    /// A background (routine) run needs the user's attention on a
    /// notification channel: it failed, or it is parked on an auth gate whose
    /// authorization URL cannot be shown on this channel. Fanned out over the
    /// creator's notification-channel set, so unlike [`Self::FailureNotice`]
    /// (source-routed to an interactive conversation) it is policy-class.
    BackgroundRunNotice,
    /// A model-initiated explicit delivery via builtin.outbound_deliver.
    ModelDelivery,
}

impl DeliveryIntent {
    /// Policy-class intents run the outbound-policy pipeline (validated
    /// reply-target bindings + preference targets). Notice-class intents are
    /// source-routed system notices on the originating conversation.
    pub fn runs_outbound_policy(self) -> bool {
        matches!(
            self,
            Self::FinalReply
                | Self::GatePrompt
                | Self::AuthPrompt
                | Self::BackgroundRunNotice
                | Self::ModelDelivery
        )
    }

    /// Notice-class intents (`deliver_notice`): still persisted and driven by
    /// the coordinator, but targeted at the originating conversation instead
    /// of a policy-resolved binding.
    pub fn is_notice_class(self) -> bool {
        !self.runs_outbound_policy()
    }

    /// Conversation-scoped reply/interaction traffic — everything except the
    /// notification-class sends (`BackgroundRunNotice`, `ModelDelivery`). A
    /// `streaming` channel's conversation replies ride the durable projection
    /// stream, so these intents never route through the batched delivery
    /// path for such a channel; notification-class sends flow regardless.
    pub fn is_conversation_reply(self) -> bool {
        !matches!(self, Self::BackgroundRunNotice | Self::ModelDelivery)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::FinalReply => "final-reply",
            Self::GatePrompt => "gate-prompt",
            Self::AuthPrompt => "auth-prompt",
            Self::FailureNotice => "failure-notice",
            Self::ConnectRequired => "connect-required",
            Self::ConnectionStatus => "connection-status",
            Self::CommandFeedback => "command-feedback",
            Self::Working => "working",
            Self::Cleanup => "cleanup",
            Self::Reaction => "reaction",
            Self::BackgroundRunNotice => "background-run-notice",
            Self::ModelDelivery => "model-delivery",
        }
    }
}

/// Where an outbound thing is going — **the axis, decided once, by the
/// router**.
///
/// Reply and delivery are orthogonal, not alternatives. Reply answers the
/// run's input and is *source-routed*; delivery reaches someone out of band
/// and is *target-resolved*, and may exist with no run at all. One run can do
/// both: the answer streams into an open tab (reply) *and* a push fires
/// because nobody is looking (delivery).
///
/// **This type exists because dispatching on [`DeliveryIntent`] instead of on
/// the axis already shipped a defect.** A gate prompt is a reply when a human
/// is sitting in the thread and a delivery when a 3am routine is blocked and
/// nobody is there — same intent, same content, different axis. Keying the
/// streaming decision on the intent silently dropped the second case and
/// blocked-routine pushes vanished. Naming the axis makes that class of bug
/// unexpressible: content never implies routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundRoute {
    /// Back to the conversation or session the run came from.
    Reply { kind: ReplyKind },
    /// To a resolved target, with no assumption that a run exists.
    Delivery { origin: DeliveryOrigin },
}

/// What shape of reply this is. Content vocabulary only — it never decides
/// routing, which is the whole point of the split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    /// The run's answer.
    Answer,
    /// Something the user must act on before the run continues.
    Prompt,
    /// A transient "working on it" marker.
    Indicator,
    /// A run-lifecycle reaction on an existing message.
    Reaction,
    /// Removal of an earlier delivery.
    Retraction,
}

/// Who chose the delivery target — the authorization distinction, explicit.
///
/// Transport and the attempt record are unified; target *authorization* stays
/// a distinct stage with two entry points. Collapsing these would let a
/// model-chosen target inherit the trust of a user-configured one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOrigin {
    /// The host resolved the user's configured notification channels.
    UserConfigured,
    /// `builtin.outbound_deliver` — the model named a target, so it must be
    /// validated against what the user actually authorized.
    ModelRequested,
}

impl OutboundRoute {
    /// Decide the axis for a policy-class send, **once**, from the resolved
    /// routing decision rather than from what is being said.
    ///
    /// A run notification that resolved to the live source route is a reply:
    /// a human is in the thread. One that resolved to a preference target
    /// is a delivery, whatever its content happens to be.
    fn for_policy(
        intent: DeliveryIntent,
        resolution: &ironclaw_outbound::CommunicationDeliveryIntent,
    ) -> Self {
        if matches!(intent, DeliveryIntent::ModelDelivery) {
            return Self::Delivery {
                origin: DeliveryOrigin::ModelRequested,
            };
        }
        let target_resolved = matches!(
            resolution,
            ironclaw_outbound::CommunicationDeliveryIntent::RunNotification(context)
                if !matches!(
                    context.origin,
                    ironclaw_outbound::RunNotificationOrigin::LiveSourceRoute { .. }
                )
        ) && !matches!(intent, DeliveryIntent::FinalReply);
        if target_resolved {
            Self::Delivery {
                origin: DeliveryOrigin::UserConfigured,
            }
        } else {
            Self::Reply {
                kind: ReplyKind::for_intent(intent),
            }
        }
    }

    /// Notice-class sends are source-routed by construction — the target IS
    /// the originating conversation — so they are always the reply axis.
    fn for_notice(intent: DeliveryIntent) -> Self {
        Self::Reply {
            kind: ReplyKind::for_intent(intent),
        }
    }

    fn is_reply(self) -> bool {
        matches!(self, Self::Reply { .. })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Reply { .. } => "reply",
            Self::Delivery { .. } => "delivery",
        }
    }
}

impl ReplyKind {
    fn for_intent(intent: DeliveryIntent) -> Self {
        match intent {
            DeliveryIntent::Working => Self::Indicator,
            DeliveryIntent::Cleanup => Self::Retraction,
            DeliveryIntent::Reaction => Self::Reaction,
            DeliveryIntent::GatePrompt
            | DeliveryIntent::AuthPrompt
            | DeliveryIntent::ConnectRequired => Self::Prompt,
            DeliveryIntent::FinalReply
            | DeliveryIntent::FailureNotice
            | DeliveryIntent::ConnectionStatus
            | DeliveryIntent::CommandFeedback
            | DeliveryIntent::BackgroundRunNotice
            | DeliveryIntent::ModelDelivery => Self::Answer,
        }
    }
}

/// The registration scope for one delivery: the run's scope owner, which is
/// the user whose channels were resolved. `None` for a run with no explicit
/// owner — an ownerless run has no enrolled client set to reach, which the
/// caller reads as "no registrations" rather than as an error.
fn registration_scope_for(
    attempt: &OutboundDeliveryAttempt,
    channel: &ResolvedChannelDelivery,
) -> Option<ironclaw_product_contracts::delivery::DeliveryRegistrationScope> {
    let ironclaw_host_api::turn::TurnThreadOwner::ExplicitUser { owner_user_id } =
        &attempt.scope.thread_owner
    else {
        return None;
    };
    Some(
        ironclaw_product_contracts::delivery::DeliveryRegistrationScope {
            tenant_id: attempt.scope.tenant_id.clone(),
            user_id: owner_user_id.clone(),
            extension_id: channel.extension_id.clone(),
        },
    )
}

/// A no-registration source for deployments and tests with no
/// enrollment-requiring channel. Deliberately not a `None` dependency: a
/// coordinator that cannot answer "is this user enrolled?" must still answer
/// it, and "nobody is" is a real answer.
pub struct NoDeliveryRegistrations;

#[async_trait]
impl ironclaw_product_contracts::delivery::DeliveryRegistrationService for NoDeliveryRegistrations {
    async fn list(
        &self,
        _scope: &ironclaw_product_contracts::delivery::DeliveryRegistrationScope,
    ) -> Result<
        Vec<ironclaw_extension_contracts::channel_adapter::DeliveryRegistration>,
        ironclaw_product_contracts::delivery::DeliveryRegistrationError,
    > {
        Ok(Vec::new())
    }

    async fn enroll(
        &self,
        _scope: &ironclaw_product_contracts::delivery::DeliveryRegistrationScope,
        _request: ironclaw_product_contracts::delivery::DeliveryRegistrationRequest,
    ) -> Result<
        ironclaw_extension_contracts::channel_adapter::DeliveryRegistration,
        ironclaw_product_contracts::delivery::DeliveryRegistrationError,
    > {
        Err(
            ironclaw_product_contracts::delivery::DeliveryRegistrationError::Rejected {
                reason: "this deployment stores no delivery registrations".to_string(),
            },
        )
    }

    async fn remove(
        &self,
        _scope: &ironclaw_product_contracts::delivery::DeliveryRegistrationScope,
        _endpoint: &str,
    ) -> Result<bool, ironclaw_product_contracts::delivery::DeliveryRegistrationError> {
        Ok(false)
    }

    async fn prune(
        &self,
        _scope: &ironclaw_product_contracts::delivery::DeliveryRegistrationScope,
        _registration_ids: &[String],
    ) -> Result<usize, ironclaw_product_contracts::delivery::DeliveryRegistrationError> {
        Ok(0)
    }
}

/// A no-context source for channels/tests without stored contexts.
pub struct NoReplyContext;

#[async_trait]
impl DeliveryReplyContextSource for NoReplyContext {
    async fn reply_context(
        &self,
        _: &ExtensionId,
        _: &AdapterInstallationId,
        _: &str,
    ) -> Option<Vec<u8>> {
        None
    }
}

/// One coordinated delivery request: a policy-approved attempt driven
/// through a channel adapter.
pub struct CoordinatedDeliveryRequest<'a> {
    pub intent: DeliveryIntent,
    /// Policy inputs (resolution request, run id, projection ref).
    pub delivery: PrepareCommunicationDeliveryRequest,
    /// Channel-neutral content parts; the adapter owns rendering.
    pub parts: Vec<OutboundPart>,
    /// Ordered durable references from the finalized assistant message.
    /// Bytes are loaded only after policy authorization and immediately before
    /// adapter dispatch.
    pub attachments: Vec<AttachmentRef>,
    /// Optional vendor thread anchor (e.g. a thread timestamp).
    pub thread_anchor: Option<String>,
    /// AuthPrompt-style payloads must never land in shared conversations.
    pub require_direct_message_target: bool,
    /// The extension whose channel carries this delivery.
    pub extension_id: &'a str,
    /// Canonical project-filesystem authority scope for resolving transient
    /// `/workspace/...` references in final/triggered assistant text.
    pub thread_scope: &'a ThreadScope,
}

struct AuthorizedDeliveryTarget {
    binding: ValidatedReplyTargetBinding,
    require_direct_message: bool,
    /// Optional threading anchor within the resolved target conversation.
    thread_anchor: Option<String>,
}

/// Inputs for resolving transient `/workspace/...` references in final or
/// triggered assistant text into materialized [`OutboundPart::File`] parts.
struct WorkspaceMaterialization<'a> {
    intent: DeliveryIntent,
    project_filesystem: &'a dyn ProjectFilesystemReader,
    thread_scope: &'a ThreadScope,
    attachments: Vec<AttachmentRef>,
}

/// One notice-class delivery request (§5.4: `Working`, `Cleanup`,
/// `FailureNotice`, `ConnectRequired`, `ConnectionStatus`): a source-routed
/// system notice on the originating conversation. There is no policy
/// resolution — the target IS the conversation the triggering inbound event
/// arrived on — but the attempt is persisted and driven under the same
/// sole-writer rules.
pub struct NoticeDeliveryRequest<'a> {
    pub intent: DeliveryIntent,
    pub scope: TurnScope,
    pub turn_run_id: Option<TurnRunId>,
    /// The originating conversation (the source route). Requests without a
    /// source conversation cannot be constructed — that is the fail-closed
    /// rule for notices.
    pub conversation: ExternalConversationRef,
    pub thread_anchor: Option<String>,
    pub parts: Vec<OutboundPart>,
    pub extension_id: &'a str,
    /// Audit discriminator recorded in the attempt's projection ref
    /// (e.g. a run id or event id), so repeated notices stay distinguishable.
    pub notice_ref: String,
}

/// Coordinator outcome for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatedDeliveryOutcome {
    /// No target resolved (policy said no delivery) — nothing sent.
    NoDelivery,
    /// Policy rejected the candidate; the attempt records the rejection.
    Rejected { attempt: OutboundDeliveryAttempt },
    /// The adapter reported every part sent.
    Delivered {
        attempt: OutboundDeliveryAttempt,
        /// The resolved target conversation, so emitters can record follow-up
        /// state (gate routes, cleanup targets) without vendor knowledge.
        conversation: ExternalConversationRef,
        vendor_message_refs: Vec<String>,
    },
    /// Every part was sent — the provider refs are real — but the durable
    /// `Delivered` confirmation write failed, so the attempt row still reads
    /// as in-flight. The explicit weaker evidence type `tool-evidence.md`
    /// requires instead of fabricating `Delivered` (theredspoon's #7157 flag;
    /// #7029 fixes the same swallow on main). Deliberately not an error:
    /// an error invites a resend, and the message already reached the
    /// provider. Recovery reconciles the row as terminal-ambiguous.
    DeliveredUnconfirmed {
        attempt: OutboundDeliveryAttempt,
        conversation: ExternalConversationRef,
        vendor_message_refs: Vec<String>,
    },
    /// The same durable delivery fact was already confirmed delivered. The
    /// coordinator suppressed replay before provider egress. Provider refs
    /// are intentionally absent because attempt persistence does not retain
    /// them; callers may claim durable prior delivery, but not invent refs.
    AlreadyDelivered { attempt: OutboundDeliveryAttempt },
    /// Delivered by the durable projection pipeline rather than a vendor
    /// call — a `stream` reply. `cursor` is the projection ref at which the
    /// reply is visible to the subscribed client: durable proof the user can
    /// see it, which is what makes this evidence rather than an assumption.
    StreamDelivered {
        attempt: OutboundDeliveryAttempt,
        cursor: String,
    },
    /// The stream reply is visible, but the durable `Delivered` write failed.
    /// The weaker evidence type, for the same reason
    /// [`Self::DeliveredUnconfirmed`] exists on the vendor path.
    StreamDeliveredUnconfirmed {
        attempt: OutboundDeliveryAttempt,
        cursor: String,
    },
    /// Terminal failure (permanent, retries exhausted, or partial-multipart).
    Failed {
        attempt: OutboundDeliveryAttempt,
        failure_kind: DeliveryFailureKind,
    },
}

/// Coordinator-level failures raised before or around the adapter call.
#[derive(Debug, Error)]
pub enum CoordinatedDeliveryError {
    #[error("outbound policy failed: {0}")]
    Outbound(#[from] ironclaw_outbound::OutboundError),
    #[error("product workflow failed: {0}")]
    Workflow(#[from] ProductSurfaceFailure),
    #[error("no active channel for extension `{extension_id}`")]
    ChannelUnavailable { extension_id: String },
    #[error("delivery is already in flight for this attempt")]
    AlreadyInFlight,
    #[error("intent {intent:?} does not belong to this delivery path")]
    IntentClassMismatch { intent: DeliveryIntent },
    #[error("notice request is invalid: {reason}")]
    InvalidNotice { reason: String },
    #[error("workspace attachment could not be read")]
    WorkspaceAttachmentRead(#[source] ProjectFsError),
    #[error("workspace attachments exceed the delivery budget")]
    WorkspaceAttachmentBudgetExceeded,
    #[error("workspace attachment reference is invalid: {reason}")]
    WorkspaceAttachmentRefInvalid { reason: &'static str },
    #[error("caller-supplied materialized workspace attachments are not accepted")]
    PreMaterializedWorkspaceAttachment,
}

fn workspace_materialization_failure_kind(error: &CoordinatedDeliveryError) -> DeliveryFailureKind {
    match error {
        CoordinatedDeliveryError::WorkspaceAttachmentRead(ProjectFsError::Unavailable) => {
            DeliveryFailureKind::TransportUnavailable
        }
        _ => DeliveryFailureKind::Rejected,
    }
}

/// Retry policy for retryable per-part outcomes (bounded, jitter-free by
/// default — tests inject zero delays).
#[derive(Debug, Clone)]
pub struct DeliveryRetryPolicy {
    pub max_attempts: u32,
    pub backoff: Duration,
}

impl Default for DeliveryRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            backoff: Duration::from_millis(500),
        }
    }
}

/// The delivery coordinator. Sole writer of delivery state; one instance per
/// composition (§5.4: "no direct product send path").
pub struct DeliveryCoordinator {
    store: Arc<dyn OutboundStateStorePort>,
    resolver: Arc<dyn ChannelDeliveryResolver>,
    reply_context: Arc<dyn DeliveryReplyContextSource>,
    registrations: Arc<dyn DeliveryRegistrationService>,
    retry: DeliveryRetryPolicy,
    /// Per-delivery single-flight: a delivery id enters once.
    in_flight: Mutex<HashSet<ironclaw_outbound::OutboundDeliveryId>>,
    /// Scopes whose interrupted (`Sending`) attempts from prior lifetimes
    /// have been reconciled this lifetime. The store enumerates attempts per
    /// scope only, so recovery runs lazily before a scope's first delivery.
    recovered_scopes: Mutex<HashSet<TurnScope>>,
}

impl DeliveryCoordinator {
    /// Production construction requires a real store, resolver, and reply
    /// context source — there is deliberately no no-op-sink constructor
    /// (OUT-4): a composition that cannot persist attempts must not deliver.
    pub fn new(
        store: Arc<dyn OutboundStateStorePort>,
        resolver: Arc<dyn ChannelDeliveryResolver>,
        reply_context: Arc<dyn DeliveryReplyContextSource>,
        registrations: Arc<dyn DeliveryRegistrationService>,
        retry: DeliveryRetryPolicy,
    ) -> Self {
        Self {
            store,
            resolver,
            reply_context,
            registrations,
            retry,
            in_flight: Mutex::new(HashSet::new()),
            recovered_scopes: Mutex::new(HashSet::new()),
        }
    }

    /// Run crash recovery for `scope` exactly once per coordinator lifetime,
    /// before the scope's first delivery. Recovery failures are logged and
    /// do not block the new delivery: the stray attempt stays `Sending` and
    /// the next lifetime reconciles it.
    async fn ensure_scope_recovered(&self, scope: &TurnScope) {
        {
            let mut recovered = self
                .recovered_scopes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !recovered.insert(scope.clone()) {
                return;
            }
        }
        if let Err(error) = self.recover_interrupted_deliveries(scope.clone()).await {
            debug!(
                error = %error,
                "delivery coordinator: lazy interrupted-delivery recovery failed"
            );
        }
    }

    /// Crash recovery (OUT-6): every attempt still `Sending` in this scope
    /// crashed between vendor egress and the result write. Mark each
    /// `Unknown`; never blindly resend.
    pub async fn recover_interrupted_deliveries(
        &self,
        scope: ironclaw_turns::TurnScope,
    ) -> Result<usize, ironclaw_outbound::OutboundError> {
        let attempts = self.store.list_delivery_attempts(scope.clone()).await?;
        let mut recovered = 0usize;
        for attempt in attempts {
            if attempt.status != OutboundDeliveryStatus::Sending {
                continue;
            }
            self.store
                .update_delivery_status(UpdateDeliveryStatusRequest {
                    delivery_id: attempt.delivery_id,
                    scope: scope.clone(),
                    status: OutboundDeliveryStatus::Unknown,
                    updated_at: chrono::Utc::now(),
                    failure_kind: None,
                })
                .await?;
            recovered += 1;
        }
        if recovered > 0 {
            debug!(
                recovered,
                "delivery coordinator: interrupted deliveries marked Unknown (never resent)"
            );
        }
        Ok(recovered)
    }

    /// Deliver one policy-class intent end to end.
    ///
    /// `outbound_policy` stays borrow-based per call (it wraps this
    /// coordinator's store plus the caller's validators); the coordinator
    /// owns everything after the policy decision.
    pub async fn deliver(
        &self,
        outbound_policy: &OutboundPolicyService<'_>,
        target_resolver: &dyn ProductOutboundTargetResolver,
        project_filesystem: &dyn ProjectFilesystemReader,
        request: CoordinatedDeliveryRequest<'_>,
    ) -> Result<CoordinatedDeliveryOutcome, CoordinatedDeliveryError> {
        if !request.intent.runs_outbound_policy() {
            return Err(CoordinatedDeliveryError::IntentClassMismatch {
                intent: request.intent,
            });
        }
        reject_caller_supplied_files(&request.parts)?;
        // §7a classification, decided before the request is consumed by the
        // policy step: a run-notification that is NOT source-routed (i.e. it
        // targets a notification channel rather than the originating
        // conversation) and is not an explicitly routed final answer rides
        // the adapter's notification send.
        // The axis, decided ONCE, from the resolved routing decision — not
        // from what is being said. Everything downstream is handed this
        // instead of re-deriving "is this a notification?" from the intent.
        let route =
            OutboundRoute::for_policy(request.intent, &request.delivery.resolution_request.intent);
        self.ensure_scope_recovered(&request.delivery.resolution_request.scope)
            .await;
        // A stream reply is delivered by the projection pipeline, so the
        // batched adapter path must not also send it. It is still a real
        // delivery with real evidence — see `record_stream_reply` for why the
        // old silent `NoDelivery` was a hole rather than a shortcut.
        if self.stream_reply_rides_the_projection(route, request.extension_id) {
            return self
                .record_stream_reply(
                    &request.delivery.resolution_request.scope,
                    request.intent,
                    request.delivery.projection_ref.clone(),
                    request.delivery.turn_run_id,
                )
                .await;
        }

        // 1. Policy: authorize the candidate and persist the attempt.
        let Some(decision) = outbound_policy
            .prepare_communication_delivery_attempt(request.delivery)
            .await?
        else {
            return Ok(CoordinatedDeliveryOutcome::NoDelivery);
        };
        let (attempt, target) = match decision {
            OutboundDeliveryDecision::Authorized { attempt, target } => (attempt, target),
            OutboundDeliveryDecision::Rejected { attempt } => {
                return Ok(CoordinatedDeliveryOutcome::Rejected { attempt });
            }
        };

        // Reserve provider egress before target resolution, channel lookup,
        // or workspace materialization. A replay of a terminal delivery must
        // not depend on the target still being configured, and it must never
        // let a later resolution failure overwrite the terminal row.
        if !self.claim_delivery_attempt(&attempt).await? {
            return self.outcome_for_claimed_delivery(&attempt).await;
        }

        // Single-flight per delivery id.
        let delivery_id = attempt.delivery_id;
        {
            let mut in_flight = self
                .in_flight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !in_flight.insert(delivery_id) {
                return Err(CoordinatedDeliveryError::AlreadyInFlight);
            }
        }
        let result = self
            .drive_authorized(
                target_resolver,
                attempt,
                AuthorizedDeliveryTarget {
                    binding: target,
                    require_direct_message: request.require_direct_message_target,
                    thread_anchor: request.thread_anchor,
                },
                request.parts,
                request.extension_id,
                WorkspaceMaterialization {
                    intent: request.intent,
                    project_filesystem,
                    thread_scope: request.thread_scope,
                    attachments: request.attachments,
                },
                route,
            )
            .await;
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&delivery_id);
        result
    }

    /// Deliver one notice-class intent to its source conversation, under the
    /// same persistence and sole-writer rules as the policy path. The attempt
    /// is recorded `Prepared` before the channel resolves and moves to
    /// `Sending` before any vendor egress.
    pub async fn deliver_notice(
        &self,
        request: NoticeDeliveryRequest<'_>,
    ) -> Result<CoordinatedDeliveryOutcome, CoordinatedDeliveryError> {
        if !request.intent.is_notice_class() {
            return Err(CoordinatedDeliveryError::IntentClassMismatch {
                intent: request.intent,
            });
        }
        reject_caller_supplied_files(&request.parts)?;
        self.ensure_scope_recovered(&request.scope).await;
        // Unlike `deliver`, this guard is unconditional — and deliberately so.
        // Notice-class intents are SOURCE-routed: they target the originating
        // conversation, never a policy-resolved notification target, so none
        // of them is ever notification-routed and the `as_notification`
        // carve-out `deliver` needs cannot apply here. For a streaming
        // channel the originating conversation IS the durable projection
        // stream the client already renders from, which carries run status
        // and failure transitions; and the vendor-message operations in this
        // class (`Retract`, `React`) have no counterpart there — the web-app
        // adapter reports both as unsupported parts, so delivering them would
        // only persist a failed attempt. Background-run notices, the sends
        // that must reach a closed tab, are policy-class and flow through
        // `deliver`'s notification path instead. Pinned by
        // `streaming_channel_skips_source_routed_notices_but_not_notifications`.
        let route = OutboundRoute::for_notice(request.intent);
        if self.stream_reply_rides_the_projection(route, request.extension_id) {
            return self
                .record_stream_reply(
                    &request.scope,
                    request.intent,
                    ironclaw_outbound::ProjectionUpdateRef::new(format!(
                        "system-notice:{}:{}",
                        request.intent.as_str(),
                        request.notice_ref
                    ))
                    .map_err(|reason| CoordinatedDeliveryError::InvalidNotice { reason })?,
                    request.turn_run_id,
                )
                .await;
        }

        // Persist the attempt before anything else. The synthetic reply
        // target names the source conversation (hashed: fingerprints can
        // exceed the ref bound); `requires_reply_target_revalidation` is
        // false because there is no policy binding to revalidate — the
        // source conversation is the target by construction.
        let target = notice_target_ref(&request.conversation)
            .map_err(|reason| CoordinatedDeliveryError::InvalidNotice { reason })?;
        let projection_ref = ironclaw_outbound::ProjectionUpdateRef::new(format!(
            "system-notice:{}:{}",
            request.intent.as_str(),
            request.notice_ref
        ))
        .map_err(|reason| CoordinatedDeliveryError::InvalidNotice { reason })?;
        let attempt = OutboundDeliveryAttempt {
            delivery_id: ironclaw_outbound::OutboundDeliveryId::new(),
            scope: request.scope.clone(),
            candidate: OutboundPushCandidate {
                tenant_id: request.scope.tenant_id.clone(),
                agent_id: request.scope.agent_id.clone(),
                project_id: request.scope.project_id.clone(),
                thread_id: request.scope.thread_id.clone(),
                turn_run_id: request.turn_run_id,
                target,
                kind: OutboundPushKind::DeliveryStatus,
                projection_ref,
                requires_reply_target_revalidation: false,
            },
            status: OutboundDeliveryStatus::Prepared,
            attempted_at: chrono::Utc::now(),
            failure_kind: None,
        };
        self.store.record_delivery_attempt(attempt.clone()).await?;

        if !self.claim_delivery_attempt(&attempt).await? {
            return self.outcome_for_claimed_delivery(&attempt).await;
        }

        // Single-flight per delivery id (uniform with the policy path).
        let delivery_id = attempt.delivery_id;
        {
            let mut in_flight = self
                .in_flight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !in_flight.insert(delivery_id) {
                return Err(CoordinatedDeliveryError::AlreadyInFlight);
            }
        }
        let result = self
            .drive_resolved(
                attempt,
                request.extension_id,
                request.conversation,
                request.thread_anchor,
                request.parts,
                route,
            )
            .await;
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&delivery_id);
        result
    }

    // arch-exempt: too_many_args, delivery drive wants a PreparedDriveContext bundle, plan docs/internal/design/2026-08-10-unified-channel-model.md
    #[allow(clippy::too_many_arguments)]
    async fn drive_authorized(
        &self,
        target_resolver: &dyn ProductOutboundTargetResolver,
        attempt: OutboundDeliveryAttempt,
        target: AuthorizedDeliveryTarget,
        parts: Vec<OutboundPart>,
        extension_id: &str,
        materialization: WorkspaceMaterialization<'_>,
        route: OutboundRoute,
    ) -> Result<CoordinatedDeliveryOutcome, CoordinatedDeliveryError> {
        // 2. Resolve the trusted conversation metadata for the sealed target.
        let metadata: VerifiedProductOutboundTargetMetadata = match target_resolver
            .resolve_product_outbound_target_metadata(
                &target.binding,
                target.require_direct_message,
            )
            .await
        {
            Ok(metadata) => metadata,
            Err(error) => {
                let kind =
                    crate::outbound_delivery::delivery_failure_kind_for_surface_error(&error);
                self.mark_terminal(&attempt, OutboundDeliveryStatus::Failed, Some(kind))
                    .await;
                return Err(CoordinatedDeliveryError::Workflow(error));
            }
        };

        // Resolve the generation-pinned adapter and stored reply context
        // before touching workspace bytes. A missing channel or failed
        // context lookup must not cause file materialization as a side effect.
        let (channel, reply_context) = self
            .resolve_channel_context(&attempt, extension_id, &metadata.external_conversation_ref)
            .await?;

        let parts = match materialize_workspace_file_parts(materialization, parts).await {
            Ok(parts) => parts,
            Err(error) => {
                let failure_kind = workspace_materialization_failure_kind(&error);
                self.mark_terminal(&attempt, OutboundDeliveryStatus::Failed, Some(failure_kind))
                    .await;
                return Err(error);
            }
        };

        self.drive_prepared(
            attempt,
            channel,
            metadata.external_conversation_ref,
            target.thread_anchor,
            parts,
            reply_context,
            route,
        )
        .await
    }

    /// Shared delivery drive: channel resolution (generation-pinned), reply
    /// context, `Sending` persisted before egress (OUT-3), bounded retries,
    /// and the partial-multipart terminal rule (OUT-7).
    // arch-exempt: too_many_args, delivery drive wants a PreparedDriveContext bundle, plan docs/internal/design/2026-08-10-unified-channel-model.md
    #[allow(clippy::too_many_arguments)]
    async fn drive_resolved(
        &self,
        attempt: OutboundDeliveryAttempt,
        extension_id: &str,
        conversation: ExternalConversationRef,
        thread_anchor: Option<String>,
        parts: Vec<OutboundPart>,
        route: OutboundRoute,
    ) -> Result<CoordinatedDeliveryOutcome, CoordinatedDeliveryError> {
        let (channel, reply_context) = self
            .resolve_channel_context(&attempt, extension_id, &conversation)
            .await?;
        self.drive_prepared(
            attempt,
            channel,
            conversation,
            thread_anchor,
            parts,
            reply_context,
            route,
        )
        .await
    }

    /// Streaming-channel gate, keyed on the **route**.
    ///
    /// A `stream` channel's replies ride the durable projection stream, so the
    /// batched adapter path must never also send them. Deliveries flow
    /// regardless — that is the whole asymmetry, and reading it off the axis
    /// rather than off the intent is what makes the blocked-routine-push
    /// defect unexpressible. Unresolvable channels pass through: the delivery
    /// path's own resolution-failure handling stays authoritative.
    fn stream_reply_rides_the_projection(&self, route: OutboundRoute, extension_id: &str) -> bool {
        route.is_reply()
            && self.resolver.channel_reply_transport(extension_id)
                == Some(ironclaw_extension_contracts::channel::ReplyTransport::Stream)
    }

    /// Record a stream reply as a **delivered** attempt.
    ///
    /// This is the hole design §4 exists to close. A `stream` channel's reply
    /// is published by the projection pipeline rather than sent by an
    /// adapter, and the coordinator used to answer that with `NoDelivery` —
    /// so a browser reply produced **no delivery record at all**, "was the
    /// user's answer delivered?" had no uniform answer, and the whole channel
    /// was invisible in delivery audits.
    ///
    /// It is a full attempt row, not a lighter marker (§10.4): uniform beats
    /// cheap, and a per-transport audit shape is exactly the kind of split
    /// that makes two queries necessary where one should do. Revisit only on
    /// a measurement.
    ///
    /// The evidence is the **projection ref the turn already wrote** — §4.4's
    /// *verify*, not *own*. Moving the assistant-message append out of the
    /// turn pipeline would buy symmetry with push at the cost of surgery on
    /// replay; the interface here does not change if that write ever moves.
    async fn record_stream_reply(
        &self,
        scope: &TurnScope,
        intent: DeliveryIntent,
        projection_ref: ironclaw_outbound::ProjectionUpdateRef,
        turn_run_id: Option<TurnRunId>,
    ) -> Result<CoordinatedDeliveryOutcome, CoordinatedDeliveryError> {
        let cursor = projection_ref.as_str().to_string();
        let target = ironclaw_turns::ReplyTargetBindingRef::new(format!("projection:{cursor}"))
            .map_err(|reason| CoordinatedDeliveryError::InvalidNotice { reason })?;
        let attempt = OutboundDeliveryAttempt {
            delivery_id: ironclaw_outbound::OutboundDeliveryId::new(),
            scope: scope.clone(),
            candidate: OutboundPushCandidate {
                tenant_id: scope.tenant_id.clone(),
                agent_id: scope.agent_id.clone(),
                project_id: scope.project_id.clone(),
                thread_id: scope.thread_id.clone(),
                turn_run_id,
                target,
                kind: OutboundPushKind::DeliveryStatus,
                projection_ref,
                requires_reply_target_revalidation: false,
            },
            status: OutboundDeliveryStatus::Prepared,
            attempted_at: chrono::Utc::now(),
            failure_kind: None,
        };
        self.store.record_delivery_attempt(attempt.clone()).await?;
        let confirmed = self
            .mark_terminal(&attempt, OutboundDeliveryStatus::Delivered, None)
            .await;
        debug!(
            target: "ironclaw::reborn::delivery",
            intent = intent.as_str(),
            cursor = %cursor,
            confirmed,
            "stream reply delivered by the projection pipeline"
        );
        if !confirmed {
            // Same rule as a vendor send whose terminal write failed: the
            // user can see the reply, but we cannot durably claim it.
            return Ok(CoordinatedDeliveryOutcome::StreamDeliveredUnconfirmed { attempt, cursor });
        }
        Ok(CoordinatedDeliveryOutcome::StreamDelivered { attempt, cursor })
    }

    async fn resolve_channel_context(
        &self,
        attempt: &OutboundDeliveryAttempt,
        extension_id: &str,
        conversation: &ExternalConversationRef,
    ) -> Result<(ResolvedChannelDelivery, Option<Vec<u8>>), CoordinatedDeliveryError> {
        // Resolve the channel from ONE snapshot read (generation-pinned).
        let Some(channel) = self.resolver.resolve_channel_delivery(extension_id) else {
            self.mark_terminal(
                attempt,
                OutboundDeliveryStatus::Failed,
                Some(DeliveryFailureKind::TransportUnavailable),
            )
            .await;
            return Err(CoordinatedDeliveryError::ChannelUnavailable {
                extension_id: extension_id.to_string(),
            });
        };

        // Stored reply context for source-route replies (ING-11).
        let reply_context = self
            .reply_context
            .reply_context(
                &channel.extension_id,
                &channel.installation_id,
                &conversation.conversation_fingerprint(),
            )
            .await;

        Ok((channel, reply_context))
    }

    // arch-exempt: too_many_args, delivery drive wants a PreparedDriveContext bundle, plan docs/internal/design/2026-08-10-unified-channel-model.md
    #[allow(clippy::too_many_arguments)]
    async fn drive_prepared(
        &self,
        attempt: OutboundDeliveryAttempt,
        channel: ResolvedChannelDelivery,
        conversation: ExternalConversationRef,
        thread_anchor: Option<String>,
        parts: Vec<OutboundPart>,
        reply_context: Option<Vec<u8>>,
        route: OutboundRoute,
    ) -> Result<CoordinatedDeliveryOutcome, CoordinatedDeliveryError> {
        // Per-user delivery registrations (design §8). Resolved on the
        // DELIVERY axis only — a reply is source-routed and has no enrolled
        // client set — and BEFORE the adapter call, so a channel with zero
        // registrations is a resolvable "no target" rather than a failure
        // discovered inside the vendor path.
        let registration_scope = match route {
            OutboundRoute::Delivery { .. } => registration_scope_for(&attempt, &channel),
            OutboundRoute::Reply { .. } => None,
        };
        let registrations = match &registration_scope {
            Some(scope) => match self.registrations.list(scope).await {
                Ok(registrations) => registrations,
                Err(error) => {
                    debug!(
                        extension_id = %channel.extension_id,
                        error = %error,
                        "delivery coordinator: registration lookup failed"
                    );
                    let kind = DeliveryFailureKind::TransportUnavailable;
                    self.mark_terminal(&attempt, OutboundDeliveryStatus::Failed, Some(kind))
                        .await;
                    return Ok(CoordinatedDeliveryOutcome::Failed {
                        attempt,
                        failure_kind: kind,
                    });
                }
            },
            None => Vec::new(),
        };
        if registration_scope.is_some()
            && registrations.is_empty()
            && self
                .resolver
                .requires_enrollment(channel.extension_id.as_str())
                .unwrap_or(false)
        {
            // The guardrail the host could not have before §8: no enrolled
            // client is a resolved absence of target, not a vendor failure.
            debug!(
                extension_id = %channel.extension_id,
                "delivery coordinator: channel requires enrollment and has no registrations"
            );
            self.mark_terminal(&attempt, OutboundDeliveryStatus::Delivered, None)
                .await;
            return Ok(CoordinatedDeliveryOutcome::NoDelivery);
        }

        let envelope = OutboundEnvelope {
            extension_id: channel.extension_id.as_str().to_string(),
            installation_id: channel.installation_id.as_str().to_string(),
            delivery_attempt_id: attempt.delivery_id.to_string(),
            target: OutboundTarget {
                conversation: conversation.clone(),
                thread_anchor,
            },
            parts,
            reply_context,
            registrations,
        };

        // Resolve the half ONCE, by axis, before the retry loop. A channel
        // that declares an axis binds its half or fails activation, so a
        // missing half here means the coordinator routed to a channel that
        // never claimed the route.
        let half = match route {
            OutboundRoute::Reply { .. } => channel.surfaces.reply.clone().map(OutboundHalf::Reply),
            OutboundRoute::Delivery { .. } => channel
                .surfaces
                .delivery
                .clone()
                .map(OutboundHalf::Delivery),
        };
        let Some(half) = half else {
            let kind = DeliveryFailureKind::Rejected;
            self.mark_terminal(&attempt, OutboundDeliveryStatus::Failed, Some(kind))
                .await;
            debug!(
                extension_id = %channel.extension_id,
                route = route.as_str(),
                "delivery coordinator: channel implements no half for this route"
            );
            return Ok(CoordinatedDeliveryOutcome::Failed {
                attempt,
                failure_kind: kind,
            });
        };

        // Drive the adapter with bounded retries. Once any part has been
        //    sent, a later retryable failure is terminal (OUT-7).
        let mut attempts_used = 0u32;
        loop {
            attempts_used += 1;
            let report = half.send(envelope.clone(), channel.egress.as_ref()).await;
            match report {
                Ok(report) => {
                    // The adapter describes; the host writes. Pruning failure
                    // never fails the delivery that discovered it.
                    if let Some(scope) = &registration_scope
                        && !report.prune_registrations.is_empty()
                        && let Err(error) = self
                            .registrations
                            .prune(scope, &report.prune_registrations)
                            .await
                    {
                        debug!(
                            extension_id = %channel.extension_id,
                            error = %error,
                            "delivery coordinator: registration prune failed"
                        );
                    }
                    let mut sent_refs = Vec::new();
                    let mut retryable = false;
                    let mut permanent = false;
                    let mut unauthorized = false;
                    for part in &report.parts {
                        match part {
                            PartDeliveryOutcome::Sent { vendor_message_ref } => {
                                if let Some(reference) = vendor_message_ref {
                                    sent_refs.push(reference.clone());
                                }
                            }
                            PartDeliveryOutcome::Retryable { .. } => retryable = true,
                            PartDeliveryOutcome::Permanent { .. } => permanent = true,
                            PartDeliveryOutcome::Unauthorized { .. } => unauthorized = true,
                        }
                    }
                    let any_sent = report
                        .parts
                        .iter()
                        .any(|part| matches!(part, PartDeliveryOutcome::Sent { .. }));
                    let all_sent = report
                        .parts
                        .iter()
                        .all(|part| matches!(part, PartDeliveryOutcome::Sent { .. }));

                    if all_sent && !report.parts.is_empty() {
                        let confirmed = self
                            .mark_terminal(&attempt, OutboundDeliveryStatus::Delivered, None)
                            .await;
                        if !confirmed {
                            return Ok(CoordinatedDeliveryOutcome::DeliveredUnconfirmed {
                                attempt,
                                conversation,
                                vendor_message_refs: sent_refs,
                            });
                        }
                        return Ok(CoordinatedDeliveryOutcome::Delivered {
                            attempt,
                            conversation,
                            vendor_message_refs: sent_refs,
                        });
                    }
                    if unauthorized {
                        let kind = DeliveryFailureKind::AuthorizationRevoked;
                        self.mark_terminal(&attempt, OutboundDeliveryStatus::Failed, Some(kind))
                            .await;
                        return Ok(CoordinatedDeliveryOutcome::Failed {
                            attempt,
                            failure_kind: kind,
                        });
                    }
                    if permanent || (retryable && any_sent) {
                        // Partial multipart (OUT-7): retrying the whole
                        // envelope would duplicate already-accepted parts.
                        let kind = DeliveryFailureKind::Rejected;
                        self.mark_terminal(&attempt, OutboundDeliveryStatus::Failed, Some(kind))
                            .await;
                        return Ok(CoordinatedDeliveryOutcome::Failed {
                            attempt,
                            failure_kind: kind,
                        });
                    }
                    // Fully-retryable report (nothing sent).
                    if attempts_used >= self.retry.max_attempts {
                        let kind = DeliveryFailureKind::TransportUnavailable;
                        self.mark_terminal(&attempt, OutboundDeliveryStatus::Failed, Some(kind))
                            .await;
                        return Ok(CoordinatedDeliveryOutcome::Failed {
                            attempt,
                            failure_kind: kind,
                        });
                    }
                    tokio::time::sleep(self.retry.backoff).await;
                }
                Err(error) => {
                    debug!(
                        extension_id = %channel.extension_id,
                        error = %error,
                        "delivery coordinator: adapter deliver failed"
                    );
                    if attempts_used >= self.retry.max_attempts {
                        let kind = DeliveryFailureKind::TransportUnavailable;
                        self.mark_terminal(&attempt, OutboundDeliveryStatus::Failed, Some(kind))
                            .await;
                        return Ok(CoordinatedDeliveryOutcome::Failed {
                            attempt,
                            failure_kind: kind,
                        });
                    }
                    tokio::time::sleep(self.retry.backoff).await;
                }
            }
        }
    }

    /// Atomically reserve the sole provider-egress drive for this durable
    /// identity. Policy preparation is idempotent and may return a fresh
    /// `Prepared` value for an already-terminal row; only the store's guarded
    /// transition decides whether this invocation owns the send.
    async fn claim_delivery_attempt(
        &self,
        attempt: &OutboundDeliveryAttempt,
    ) -> Result<bool, CoordinatedDeliveryError> {
        self.store
            .claim_delivery_attempt_for_send(ClaimDeliveryAttemptForSendRequest {
                delivery_id: attempt.delivery_id,
                scope: attempt.scope.clone(),
            })
            .await
            .map_err(CoordinatedDeliveryError::Outbound)
    }

    /// Classify an atomic-claim miss from the authoritative persisted row.
    /// This preserves terminal failure semantics and distinguishes confirmed
    /// prior delivery from an in-flight or ambiguous attempt without ever
    /// reopening provider egress.
    async fn outcome_for_claimed_delivery(
        &self,
        requested: &OutboundDeliveryAttempt,
    ) -> Result<CoordinatedDeliveryOutcome, CoordinatedDeliveryError> {
        let existing = self
            .store
            .load_delivery_attempt(requested.scope.clone(), requested.delivery_id)
            .await
            .map_err(CoordinatedDeliveryError::Outbound)?
            .ok_or(CoordinatedDeliveryError::Outbound(
                ironclaw_outbound::OutboundError::DeliveryNotFound,
            ))?;
        match existing.status {
            OutboundDeliveryStatus::Delivered => {
                Ok(CoordinatedDeliveryOutcome::AlreadyDelivered { attempt: existing })
            }
            OutboundDeliveryStatus::Failed | OutboundDeliveryStatus::DeadLettered => {
                let failure_kind = existing
                    .failure_kind
                    .unwrap_or(DeliveryFailureKind::Unknown);
                Ok(CoordinatedDeliveryOutcome::Failed {
                    attempt: existing,
                    failure_kind,
                })
            }
            OutboundDeliveryStatus::Unknown | OutboundDeliveryStatus::Pending => {
                Ok(CoordinatedDeliveryOutcome::Failed {
                    attempt: existing,
                    failure_kind: DeliveryFailureKind::Unknown,
                })
            }
            OutboundDeliveryStatus::Prepared | OutboundDeliveryStatus::Sending => {
                Err(CoordinatedDeliveryError::AlreadyInFlight)
            }
        }
    }

    /// Persist the terminal status; `true` only when the durable write
    /// committed. Failure-path callers proceed regardless (the reported
    /// outcome is already non-success and recovery reconciles the row), but
    /// the `Delivered` caller must downgrade to
    /// [`CoordinatedDeliveryOutcome::DeliveredUnconfirmed`] — a success it
    /// cannot durably confirm is not a success it may claim.
    async fn mark_terminal(
        &self,
        attempt: &OutboundDeliveryAttempt,
        status: OutboundDeliveryStatus,
        failure_kind: Option<DeliveryFailureKind>,
    ) -> bool {
        match self
            .store
            .update_delivery_status(UpdateDeliveryStatusRequest {
                delivery_id: attempt.delivery_id,
                scope: attempt.scope.clone(),
                status,
                updated_at: chrono::Utc::now(),
                failure_kind,
            })
            .await
        {
            Ok(()) => true,
            Err(error) => {
                debug!(
                    delivery_id = %attempt.delivery_id,
                    error = %error,
                    "delivery coordinator: terminal status write failed"
                );
                false
            }
        }
    }
}

/// The outbound half one route resolves to. Resolved once per delivery so
/// the retry loop cannot drift onto the other axis between attempts.
enum OutboundHalf {
    Reply(Arc<dyn ironclaw_extension_contracts::channel_adapter::ChannelReply>),
    Delivery(Arc<dyn ironclaw_extension_contracts::channel_adapter::ChannelDelivery>),
}

impl OutboundHalf {
    async fn send(
        &self,
        envelope: OutboundEnvelope,
        egress: &dyn ironclaw_extension_contracts::tool_adapter::RestrictedEgress,
    ) -> Result<
        ironclaw_extension_contracts::channel_adapter::DeliveryReport,
        ironclaw_extension_contracts::channel_adapter::ChannelError,
    > {
        match self {
            Self::Reply(reply) => reply.send_reply(envelope, egress).await,
            Self::Delivery(delivery) => delivery.deliver(envelope, egress).await,
        }
    }
}

async fn materialize_workspace_file_parts(
    materialization: WorkspaceMaterialization<'_>,
    mut parts: Vec<OutboundPart>,
) -> Result<Vec<OutboundPart>, CoordinatedDeliveryError> {
    let WorkspaceMaterialization {
        intent,
        project_filesystem,
        thread_scope,
        attachments,
    } = materialization;
    reject_caller_supplied_files(&parts)?;
    if !matches!(intent, DeliveryIntent::FinalReply) {
        return if attachments.is_empty() {
            Ok(parts)
        } else {
            Err(CoordinatedDeliveryError::WorkspaceAttachmentRefInvalid {
                reason: "delivery intent does not accept attachments",
            })
        };
    }

    if attachments.is_empty() {
        return Ok(parts);
    }
    if attachments.len() > DEFAULT_ATTACHMENT_BUDGETS.max_count {
        return Err(CoordinatedDeliveryError::WorkspaceAttachmentBudgetExceeded);
    }

    let mut refs = Vec::with_capacity(attachments.len());
    let mut seen_ids = HashSet::with_capacity(attachments.len());
    let mut seen_paths = HashSet::with_capacity(attachments.len());
    for attachment in attachments {
        if !seen_ids.insert(attachment.id.clone()) {
            return Err(CoordinatedDeliveryError::WorkspaceAttachmentRefInvalid {
                reason: "duplicate attachment id",
            });
        }
        let path = attachment
            .storage_key
            .as_deref()
            .ok_or(CoordinatedDeliveryError::WorkspaceAttachmentRefInvalid {
                reason: "missing storage key",
            })
            .and_then(|path| {
                ScopedPath::new(path).map_err(|_| {
                    CoordinatedDeliveryError::WorkspaceAttachmentRefInvalid {
                        reason: "malformed storage key",
                    }
                })
            })?;
        if !seen_paths.insert(path.clone()) {
            return Err(CoordinatedDeliveryError::WorkspaceAttachmentRefInvalid {
                reason: "duplicate storage key",
            });
        }
        let intent = ReplyAttachmentIntent {
            path,
            filename: attachment.filename.ok_or(
                CoordinatedDeliveryError::WorkspaceAttachmentRefInvalid {
                    reason: "missing filename",
                },
            )?,
            mime_type: attachment.mime_type,
            size_bytes: attachment.size_bytes.ok_or(
                CoordinatedDeliveryError::WorkspaceAttachmentRefInvalid {
                    reason: "missing size",
                },
            )?,
        };
        intent.validate().map_err(|error| match error {
            ironclaw_outbound::OutboundError::ReplyAttachmentIntentLimitExceeded => {
                CoordinatedDeliveryError::WorkspaceAttachmentBudgetExceeded
            }
            _ => CoordinatedDeliveryError::WorkspaceAttachmentRefInvalid {
                reason: "invalid attachment metadata",
            },
        })?;
        refs.push(intent);
    }
    // Preflight every file before reading any bytes. The production delivery
    // reader is independently capped at max_file_bytes, while this metadata
    // pass avoids even bounded allocations when the declared set already
    // violates per-file or aggregate budgets.
    let mut declared_total_bytes = 0u64;
    for attachment in &refs {
        let stat = project_filesystem
            .stat(thread_scope, attachment.path.as_str())
            .await
            .map_err(CoordinatedDeliveryError::WorkspaceAttachmentRead)?;
        if stat.path != attachment.path.as_str() {
            return Err(CoordinatedDeliveryError::WorkspaceAttachmentRead(
                ProjectFsError::Internal,
            ));
        }
        if stat.kind != ProjectFsEntryKind::File {
            return Err(CoordinatedDeliveryError::WorkspaceAttachmentRead(
                ProjectFsError::NotAFile,
            ));
        }
        if stat.size_bytes != attachment.size_bytes
            || stat.size_bytes > DEFAULT_ATTACHMENT_BUDGETS.max_file_bytes as u64
        {
            return Err(CoordinatedDeliveryError::WorkspaceAttachmentBudgetExceeded);
        }
        declared_total_bytes = declared_total_bytes
            .checked_add(stat.size_bytes)
            .ok_or(CoordinatedDeliveryError::WorkspaceAttachmentBudgetExceeded)?;
        if declared_total_bytes > DEFAULT_ATTACHMENT_BUDGETS.max_total_bytes as u64 {
            return Err(CoordinatedDeliveryError::WorkspaceAttachmentBudgetExceeded);
        }
    }

    let mut total_bytes = 0usize;
    let mut files = Vec::with_capacity(refs.len());
    for attachment in refs {
        let mut file = project_filesystem
            .read_file(thread_scope, attachment.path.as_str())
            .await
            .map_err(CoordinatedDeliveryError::WorkspaceAttachmentRead)?;
        if file.path != attachment.path {
            return Err(CoordinatedDeliveryError::WorkspaceAttachmentRead(
                ProjectFsError::Internal,
            ));
        }
        let file_bytes = file.bytes.len();
        if u64::try_from(file_bytes).ok() != Some(attachment.size_bytes)
            || file_bytes > DEFAULT_ATTACHMENT_BUDGETS.max_file_bytes
        {
            return Err(CoordinatedDeliveryError::WorkspaceAttachmentBudgetExceeded);
        }
        total_bytes = total_bytes
            .checked_add(file_bytes)
            .ok_or(CoordinatedDeliveryError::WorkspaceAttachmentBudgetExceeded)?;
        if total_bytes > DEFAULT_ATTACHMENT_BUDGETS.max_total_bytes {
            return Err(CoordinatedDeliveryError::WorkspaceAttachmentBudgetExceeded);
        }
        file.filename = Some(attachment.filename);
        file.mime_type = attachment.mime_type;
        files.push(OutboundPart::File(file));
    }
    parts.extend(files);
    validate_final_workspace_files(&parts)?;
    Ok(parts)
}

fn reject_caller_supplied_files(parts: &[OutboundPart]) -> Result<(), CoordinatedDeliveryError> {
    if parts
        .iter()
        .any(|part| matches!(part, OutboundPart::File(_)))
    {
        return Err(CoordinatedDeliveryError::PreMaterializedWorkspaceAttachment);
    }
    Ok(())
}

fn validate_final_workspace_files(parts: &[OutboundPart]) -> Result<(), CoordinatedDeliveryError> {
    let mut count = 0usize;
    let mut total_bytes = 0usize;
    for file in parts.iter().filter_map(|part| match part {
        OutboundPart::File(file) => Some(file),
        OutboundPart::Text(_)
        | OutboundPart::AuthPrompt { .. }
        | OutboundPart::Retract { .. }
        | OutboundPart::React { .. } => None,
    }) {
        count = count
            .checked_add(1)
            .ok_or(CoordinatedDeliveryError::WorkspaceAttachmentBudgetExceeded)?;
        if count > DEFAULT_ATTACHMENT_BUDGETS.max_count
            || file.bytes.len() > DEFAULT_ATTACHMENT_BUDGETS.max_file_bytes
        {
            return Err(CoordinatedDeliveryError::WorkspaceAttachmentBudgetExceeded);
        }
        total_bytes = total_bytes
            .checked_add(file.bytes.len())
            .ok_or(CoordinatedDeliveryError::WorkspaceAttachmentBudgetExceeded)?;
        if total_bytes > DEFAULT_ATTACHMENT_BUDGETS.max_total_bytes {
            return Err(CoordinatedDeliveryError::WorkspaceAttachmentBudgetExceeded);
        }
    }
    Ok(())
}

/// Synthetic reply-target ref naming a notice's source conversation. Hashed:
/// conversation fingerprints embed raw ids and can exceed the 256-byte ref
/// bound.
fn notice_target_ref(
    conversation: &ExternalConversationRef,
) -> Result<ironclaw_turns::ReplyTargetBindingRef, String> {
    let digest = Sha256::digest(conversation.conversation_fingerprint().as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    ironclaw_turns::ReplyTargetBindingRef::new(format!("system-notice:{hex}"))
}
