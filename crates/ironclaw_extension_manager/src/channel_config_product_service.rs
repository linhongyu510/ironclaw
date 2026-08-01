//! The `[channel.config]` product service — the manager-side face of
//! [`ironclaw_extension_host::ChannelConfigService`].
//!
//! The host owns the *service core*: validation against the installed
//! manifest, the durable/secret write split, and the §6.5 reactivate cycle.
//! What lives here is only the product port over it — the projection the
//! WebUI setup service and the lifecycle configure action see, and the
//! `ChannelConfigError` → `ProductSurfaceError` status table that decides
//! what those callers are told. Splitting them is the point of §6.8.3: the
//! host keeps the authority, the manager keeps the UX semantics.

use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_extension_host::{ChannelConfigError, ChannelConfigService};
use ironclaw_host_api::ids::ExtensionId;
use ironclaw_product_contracts::channel_config::ChannelConfigProductService;
use ironclaw_product_contracts::package_lifecycle::ChannelConfigField;
use ironclaw_product_contracts::surface::{
    ProductSurfaceError, ProductSurfaceErrorCode, ProductSurfaceErrorKind,
};

/// The production [`ChannelConfigProductService`] port
/// over [`ChannelConfigService`] — the surface the WebUI setup service and
/// the lifecycle configure action route through.
pub struct RebornChannelConfigProductService {
    service: Arc<ChannelConfigService>,
}

impl RebornChannelConfigProductService {
    pub fn new(service: Arc<ChannelConfigService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl ChannelConfigProductService for RebornChannelConfigProductService {
    async fn field_status(
        &self,
        extension_id: &ExtensionId,
    ) -> Result<Vec<ChannelConfigField>, ProductSurfaceError> {
        if let Ok(manifest) = self.service.resolved_manifest(extension_id).await
            && !manifest.admin_configuration.is_empty()
        {
            return Ok(Vec::new());
        }
        match self.service.status(extension_id).await {
            Ok(statuses) => Ok(statuses
                .into_iter()
                .map(|status| ChannelConfigField {
                    name: status.handle,
                    label: status.label,
                    secret: status.secret,
                    provided: status.provided,
                })
                .collect()),
            // A not-yet-installed extension has nothing to configure; the
            // setup view renders for it, so this projection stays empty
            // rather than erroring.
            Err(ChannelConfigError::NotInstalled { .. }) => Ok(Vec::new()),
            Err(error) => Err(map_channel_config_error(error)),
        }
    }

    async fn save_values(
        &self,
        extension_id: &ExtensionId,
        values: Vec<(String, String)>,
    ) -> Result<(), ProductSurfaceError> {
        self.service
            .save(extension_id, values)
            .await
            .map_err(map_channel_config_error)
    }
}

fn map_channel_config_error(error: ChannelConfigError) -> ProductSurfaceError {
    match error {
        ChannelConfigError::NotInstalled { .. } => ProductSurfaceError {
            code: ProductSurfaceErrorCode::NotFound,
            kind: ProductSurfaceErrorKind::NotFound,
            status_code: 404,
            retryable: false,
            field: None,
            validation_code: None,
        },
        ChannelConfigError::UnknownField { .. } => ProductSurfaceError {
            code: ProductSurfaceErrorCode::InvalidRequest,
            kind: ProductSurfaceErrorKind::Validation,
            status_code: 400,
            retryable: false,
            field: None,
            validation_code: None,
        },
        ChannelConfigError::Storage { .. } => ProductSurfaceError {
            code: ProductSurfaceErrorCode::Unavailable,
            kind: ProductSurfaceErrorKind::ServiceUnavailable,
            status_code: 503,
            retryable: true,
            field: None,
            validation_code: None,
        },
        // The save persisted but the §6.5 reactivate cycle failed: the host
        // record is left per §6.1 with the typed reason; the operator fixes
        // the value and saves again.
        ChannelConfigError::Reactivation { .. } => ProductSurfaceError {
            code: ProductSurfaceErrorCode::Conflict,
            kind: ProductSurfaceErrorKind::Conflict,
            status_code: 409,
            retryable: false,
            field: None,
            validation_code: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every arm of the status table, in one table-driven case.
    ///
    /// The projection is the only thing that decides what a WebUI caller is
    /// told when a channel-config write fails, and the four answers are
    /// deliberately different: a missing extension is a 404, a bad field name
    /// blames the caller with a 400, a storage fault is a *retryable* 503, and
    /// a failed reactivation is a 409 — the save landed, the §6.5 cycle did
    /// not, so retrying the same request would not help and the operator has
    /// to fix the value. Collapsing any pair would tell an operator to retry
    /// something that cannot succeed, or to give up on something that can.
    #[test]
    fn the_status_table_answers_each_failure_with_its_own_code() {
        let cases = [
            (
                ChannelConfigError::NotInstalled {
                    extension_id: "acme".to_string(),
                },
                ProductSurfaceErrorCode::NotFound,
                ProductSurfaceErrorKind::NotFound,
                404,
                false,
            ),
            (
                ChannelConfigError::UnknownField {
                    handle: "nope".to_string(),
                },
                ProductSurfaceErrorCode::InvalidRequest,
                ProductSurfaceErrorKind::Validation,
                400,
                false,
            ),
            (
                ChannelConfigError::Storage {
                    reason: "disk".to_string(),
                },
                ProductSurfaceErrorCode::Unavailable,
                ProductSurfaceErrorKind::ServiceUnavailable,
                503,
                true,
            ),
            (
                ChannelConfigError::Reactivation {
                    reason: "adapter refused".to_string(),
                },
                ProductSurfaceErrorCode::Conflict,
                ProductSurfaceErrorKind::Conflict,
                409,
                false,
            ),
        ];

        for (error, code, kind, status, retryable) in cases {
            let projected = map_channel_config_error(error.clone());
            assert_eq!(projected.code, code, "code for {error:?}");
            assert_eq!(projected.kind, kind, "kind for {error:?}");
            assert_eq!(projected.status_code, status, "status for {error:?}");
            assert_eq!(projected.retryable, retryable, "retryable for {error:?}");
            assert!(
                projected.field.is_none() && projected.validation_code.is_none(),
                "the projection must not leak a field name or a validation code \
                 out of the host's error text for {error:?}"
            );
        }
    }

    /// Storage is the only retryable answer. Pinned separately because
    /// "retryable" is what a WebUI client loops on: marking `Reactivation`
    /// retryable would spin a client against a value only a human can fix.
    #[test]
    fn only_a_storage_fault_is_retryable() {
        let retryable = [
            ChannelConfigError::NotInstalled {
                extension_id: "acme".to_string(),
            },
            ChannelConfigError::UnknownField {
                handle: "nope".to_string(),
            },
            ChannelConfigError::Storage {
                reason: "disk".to_string(),
            },
            ChannelConfigError::Reactivation {
                reason: "adapter refused".to_string(),
            },
        ]
        .into_iter()
        .filter(|error| map_channel_config_error(error.clone()).retryable)
        .count();
        assert_eq!(retryable, 1, "exactly one arm may tell a client to retry");
    }

    /// Composition holds this as `Arc<dyn ChannelConfigProductService>`.
    ///
    /// The coercion is the assertion — it is what fails to compile if the
    /// impl is dropped or the trait stops being object-safe, and it is the
    /// exact shape the wiring site uses. Nothing is constructed: taking the
    /// `Arc` by value and returning it as the trait object exercises the
    /// unsize coercion without needing a real `ChannelConfigService`, whose
    /// filesystem and secret-store substrates belong to the host's own tests.
    #[test]
    fn the_concrete_service_coerces_to_the_port_composition_stores() {
        fn coerce(
            service: Arc<RebornChannelConfigProductService>,
        ) -> Arc<dyn ChannelConfigProductService> {
            service
        }
        let _ = coerce;
    }
}
