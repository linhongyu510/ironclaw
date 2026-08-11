//! Generic notification-setup product surface (§7b of the unified channel
//! model): status/enable/disable by `extension_id`, dispatched to the
//! channel's own adapter. This is the surface that replaced the web app's
//! bespoke, now-retired per-channel enrollment routes — generic code
//! here knows
//! nothing about push endpoints, subscriptions, or VAPID; it resolves the
//! adapter, forwards the channel-opaque payload, and projects the sanitized
//! status back onto the wire.

use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_extension_contracts::channel_adapter::{
    ChannelContext, ChannelError, MAX_NOTIFICATION_SETUP_DETAIL_BYTES,
    MAX_NOTIFICATION_SETUP_PAYLOAD_BYTES, NotificationSetupScope, NotificationSetupStatus,
};
use ironclaw_product_contracts::delivery::ChannelDeliveryResolver;

use super::{
    ProductSurfaceCaller, ProductSurfaceError, RebornNotificationSetupMutationRequest,
    RebornNotificationSetupRequest, RebornNotificationSetupStatusResponse,
};

/// Per-channel notification-setup operations for the authenticated caller.
#[async_trait]
pub trait ChannelNotificationSetupService: Send + Sync {
    async fn status(
        &self,
        caller: ProductSurfaceCaller,
        request: RebornNotificationSetupRequest,
    ) -> Result<RebornNotificationSetupStatusResponse, ProductSurfaceError>;

    async fn enable(
        &self,
        caller: ProductSurfaceCaller,
        request: RebornNotificationSetupMutationRequest,
    ) -> Result<RebornNotificationSetupStatusResponse, ProductSurfaceError>;

    async fn disable(
        &self,
        caller: ProductSurfaceCaller,
        request: RebornNotificationSetupMutationRequest,
    ) -> Result<RebornNotificationSetupStatusResponse, ProductSurfaceError>;
}

/// Fail-closed default until composition wires the adapter-backed service.
pub struct UnsupportedChannelNotificationSetupService;

#[async_trait]
impl ChannelNotificationSetupService for UnsupportedChannelNotificationSetupService {
    async fn status(
        &self,
        _caller: ProductSurfaceCaller,
        _request: RebornNotificationSetupRequest,
    ) -> Result<RebornNotificationSetupStatusResponse, ProductSurfaceError> {
        Err(notification_setup_unavailable())
    }

    async fn enable(
        &self,
        _caller: ProductSurfaceCaller,
        _request: RebornNotificationSetupMutationRequest,
    ) -> Result<RebornNotificationSetupStatusResponse, ProductSurfaceError> {
        Err(notification_setup_unavailable())
    }

    async fn disable(
        &self,
        _caller: ProductSurfaceCaller,
        _request: RebornNotificationSetupMutationRequest,
    ) -> Result<RebornNotificationSetupStatusResponse, ProductSurfaceError> {
        Err(notification_setup_unavailable())
    }
}

/// Production service: resolve the channel from the same registry delivery
/// uses, then dispatch to the adapter's setup operations.
pub struct AdapterChannelNotificationSetupService {
    resolver: Arc<dyn ChannelDeliveryResolver>,
}

impl AdapterChannelNotificationSetupService {
    pub fn new(resolver: Arc<dyn ChannelDeliveryResolver>) -> Self {
        Self { resolver }
    }

    /// The channel's declared setup requirement, failing closed as NotFound
    /// for extensions the deployment does not know: the generic surface must
    /// not be an oracle for which channels exist.
    fn requires_setup(&self, extension_id: &str) -> Result<bool, ProductSurfaceError> {
        self.resolver
            .requires_enrollment(extension_id)
            .ok_or_else(ProductSurfaceError::not_found)
    }

    async fn dispatch(
        &self,
        caller: &ProductSurfaceCaller,
        extension_id: &str,
        operation: SetupOperation,
        payload: serde_json::Value,
    ) -> Result<RebornNotificationSetupStatusResponse, ProductSurfaceError> {
        let requires_setup = self.requires_setup(extension_id)?;
        if !requires_setup {
            return match operation {
                // A channel without per-user setup is deliverable as-is.
                SetupOperation::Status => Ok(RebornNotificationSetupStatusResponse {
                    extension_id: extension_id.to_string(),
                    requires_setup: false,
                    enabled: true,
                    detail: serde_json::Value::Null,
                }),
                SetupOperation::Enable | SetupOperation::Disable => {
                    Err(ProductSurfaceError::validation(
                        "extension_id",
                        super::ProductSurfaceValidationCode::InvalidValue,
                    ))
                }
            };
        }
        let Some(channel) = self.resolver.resolve_channel_delivery(extension_id) else {
            return Err(ProductSurfaceError::not_found());
        };
        let scope = NotificationSetupScope {
            tenant_id: caller.tenant_id.clone(),
            user_id: caller.user_id.clone(),
        };
        let context = ChannelContext {
            extension_id: channel.extension_id.as_str(),
            installation_id: channel.installation_id.as_str(),
            config: &[],
        };
        let payload_text = if payload.is_null() {
            String::from("{}")
        } else {
            payload.to_string()
        };
        if payload_text.len() > MAX_NOTIFICATION_SETUP_PAYLOAD_BYTES {
            return Err(ProductSurfaceError::validation(
                "payload",
                super::ProductSurfaceValidationCode::TooLong,
            ));
        }
        let status = match operation {
            SetupOperation::Status => {
                channel
                    .adapter
                    .notification_setup_status(&context, &scope)
                    .await
            }
            SetupOperation::Enable => {
                channel
                    .adapter
                    .enable_notifications(&context, &scope, &payload_text)
                    .await
            }
            SetupOperation::Disable => {
                channel
                    .adapter
                    .disable_notifications(&context, &scope, &payload_text)
                    .await
            }
        }
        .map_err(map_setup_channel_error)?;
        project_status(extension_id, status)
    }
}

#[derive(Clone, Copy)]
enum SetupOperation {
    Status,
    Enable,
    Disable,
}

#[async_trait]
impl ChannelNotificationSetupService for AdapterChannelNotificationSetupService {
    async fn status(
        &self,
        caller: ProductSurfaceCaller,
        request: RebornNotificationSetupRequest,
    ) -> Result<RebornNotificationSetupStatusResponse, ProductSurfaceError> {
        self.dispatch(
            &caller,
            &request.extension_id,
            SetupOperation::Status,
            serde_json::Value::Null,
        )
        .await
    }

    async fn enable(
        &self,
        caller: ProductSurfaceCaller,
        request: RebornNotificationSetupMutationRequest,
    ) -> Result<RebornNotificationSetupStatusResponse, ProductSurfaceError> {
        self.dispatch(
            &caller,
            &request.extension_id,
            SetupOperation::Enable,
            request.payload,
        )
        .await
    }

    async fn disable(
        &self,
        caller: ProductSurfaceCaller,
        request: RebornNotificationSetupMutationRequest,
    ) -> Result<RebornNotificationSetupStatusResponse, ProductSurfaceError> {
        self.dispatch(
            &caller,
            &request.extension_id,
            SetupOperation::Disable,
            request.payload,
        )
        .await
    }
}

fn project_status(
    extension_id: &str,
    status: NotificationSetupStatus,
) -> Result<RebornNotificationSetupStatusResponse, ProductSurfaceError> {
    if status.detail.len() > MAX_NOTIFICATION_SETUP_DETAIL_BYTES {
        tracing::error!(
            extension_id,
            "channel setup detail exceeded its bound; refusing to project"
        );
        return Err(ProductSurfaceError::internal());
    }
    let detail: serde_json::Value = serde_json::from_str(&status.detail).map_err(|error| {
        tracing::error!(
            extension_id,
            %error,
            "channel setup detail is not valid JSON"
        );
        ProductSurfaceError::internal()
    })?;
    Ok(RebornNotificationSetupStatusResponse {
        extension_id: extension_id.to_string(),
        requires_setup: true,
        enabled: status.enabled,
        detail,
    })
}

pub(super) fn notification_setup_unavailable() -> ProductSurfaceError {
    ProductSurfaceError::service_unavailable(false)
}

/// Map adapter setup failures onto the sanitized product taxonomy:
/// caller-correctable payload problems are validation errors; configuration
/// and store trouble is a retryable service failure; an adapter without
/// setup operations is not-found-shaped (the surface is not an oracle).
fn map_setup_channel_error(error: ChannelError) -> ProductSurfaceError {
    match &error {
        ChannelError::Parse { .. } => ProductSurfaceError::validation(
            "payload",
            super::ProductSurfaceValidationCode::InvalidValue,
        ),
        ChannelError::Configuration { .. } => {
            tracing::warn!(%error, "channel notification setup unavailable");
            ProductSurfaceError::service_unavailable(true)
        }
        ChannelError::Unsupported => ProductSurfaceError::not_found(),
        ChannelError::Render { .. }
        | ChannelError::VendorWiring { .. }
        | ChannelError::AttachmentTransfer { .. } => {
            tracing::error!(%error, "unexpected channel setup failure");
            ProductSurfaceError::internal()
        }
    }
}
