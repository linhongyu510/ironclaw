use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use ironclaw_host_api::ingress::{
    AllowedEffectPath, AuditTraceClass, BodyLimitPolicy, CorsPolicy, IngressAuthPolicy,
    IngressAuthScheme, IngressPolicy, IngressPolicyParts, IngressRouteDescriptor,
    IngressScopeSource, ListenerClass, RateLimitPolicy, RateLimitScope, StreamingMode,
    WebSocketOriginPolicy,
};
use ironclaw_host_api::{action::NetworkMethod, host_port::HostPortId};
use ironclaw_host_ingress::PublicRouteMount;
use ironclaw_product::{IronhubLinkError, IronhubLinkService, IronhubRegisterRequest};

use crate::RebornBuildError;

pub const IRONHUB_REGISTER_PATH: &str = "/api/ironhub/register";
const IRONHUB_REGISTER_ROUTE_ID: &str = "ironhub.register";

#[derive(Clone)]
pub struct IronhubRegisterRouteState {
    link: Arc<dyn IronhubLinkService>,
}

impl IronhubRegisterRouteState {
    pub fn new(link: Arc<dyn IronhubLinkService>) -> Self {
        Self { link }
    }
}

impl std::fmt::Debug for IronhubRegisterRouteState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("IronhubRegisterRouteState").finish()
    }
}

pub fn ironhub_register_route_mount(
    state: IronhubRegisterRouteState,
) -> Result<PublicRouteMount, RebornBuildError> {
    Ok(PublicRouteMount::new(
        Router::new()
            .route(IRONHUB_REGISTER_PATH, post(ironhub_register_handler))
            .with_state(state),
        vec![ironhub_register_route_descriptor()?],
    ))
}

fn ironhub_register_route_descriptor() -> Result<IngressRouteDescriptor, RebornBuildError> {
    Ok(IngressRouteDescriptor::new(
        IRONHUB_REGISTER_ROUTE_ID,
        NetworkMethod::Post,
        IRONHUB_REGISTER_PATH,
        ironhub_register_policy()?,
    )?)
}

fn ironhub_register_policy() -> Result<IngressPolicy, RebornBuildError> {
    let max_bytes = NonZeroU64::new(8 * 1024).ok_or_else(|| RebornBuildError::InvalidConfig {
        reason: "IronHub register body limit must be non-zero".to_string(),
    })?;
    let max_requests = NonZeroU32::new(600).ok_or_else(|| RebornBuildError::InvalidConfig {
        reason: "IronHub register rate limit must be non-zero".to_string(),
    })?;
    let window_seconds = NonZeroU32::new(60).ok_or_else(|| RebornBuildError::InvalidConfig {
        reason: "IronHub register rate window must be non-zero".to_string(),
    })?;
    Ok(IngressPolicy::new(IngressPolicyParts {
        listener_class: ListenerClass::PublicWebhook,
        auth: IngressAuthPolicy::Required {
            schemes: vec![IngressAuthScheme::WebhookSignature],
        },
        scope_source: IngressScopeSource::HostResolved,
        body_limit: BodyLimitPolicy::Limited { max_bytes },
        rate_limit: RateLimitPolicy::Limited {
            scope: RateLimitScope::Global,
            max_requests,
            window_seconds,
        },
        cors: CorsPolicy::NotApplicable,
        websocket_origin: WebSocketOriginPolicy::NotApplicable,
        streaming: StreamingMode::None,
        audit: AuditTraceClass::PublicCallback,
        effect_path: AllowedEffectPath::HostPort {
            id: HostPortId::new("host.ironhub.agent_link")?,
        },
    })?)
}

async fn ironhub_register_handler(
    State(state): State<IronhubRegisterRouteState>,
    body: Bytes,
) -> Response {
    let request: IronhubRegisterRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    match state.link.register(request).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => ironhub_link_status(error).into_response(),
    }
}

fn ironhub_link_status(error: IronhubLinkError) -> StatusCode {
    match error {
        IronhubLinkError::InvalidSignature
        | IronhubLinkError::StaleTimestamp
        | IronhubLinkError::Replay => StatusCode::FORBIDDEN,
        IronhubLinkError::InvalidInput { .. } => StatusCode::BAD_REQUEST,
        IronhubLinkError::Install { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        IronhubLinkError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}
