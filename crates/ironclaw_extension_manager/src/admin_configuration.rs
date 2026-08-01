//! Manifest-driven tenant administrator configuration adapters.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use ironclaw_extension_host::{AdminConfigurationGroupState, AdminConfigurationService};
use ironclaw_filesystem::RootFilesystem;
use ironclaw_host_api::{ids::InvocationId, resource::ResourceScope};
use ironclaw_product::{
    ADMIN_CONFIGURATION_VIEW, RebornAdminConfigurationField, RebornAdminConfigurationGroup,
    RebornAdminConfigurationListResponse, RebornAdminConfigurationUse,
};
use ironclaw_product_contracts::surface::{
    ProductSurfaceCaller, ProductSurfaceError, ProductSurfaceErrorCode, ProductSurfaceErrorKind,
};
use ironclaw_product_contracts::views::{RebornViewDescriptor, RebornViewPage, RebornViewProvider};

use ironclaw_extension_host::AdminConfigurationCatalogUse;

pub type ComposedAdminConfigurationService =
    AdminConfigurationService<dyn RootFilesystem, dyn ironclaw_secrets::SecretStorePort>;
pub type ComposedExtensionAdminConfigurationResolver =
    ironclaw_extension_host::ChannelConfigService;

#[derive(Clone, Default)]
pub struct AdminConfigurationViewProvider {
    parts: Option<Arc<AdminConfigurationViewParts>>,
}

struct AdminConfigurationViewParts {
    service: Arc<ComposedAdminConfigurationService>,
    uses: Arc<Vec<AdminConfigurationCatalogUse>>,
    installation_store: Arc<dyn ironclaw_extensions::ExtensionInstallationStorePort>,
}

impl AdminConfigurationViewProvider {
    pub fn new(
        service: Arc<ComposedAdminConfigurationService>,
        uses: Vec<AdminConfigurationCatalogUse>,
        installation_store: Arc<dyn ironclaw_extensions::ExtensionInstallationStorePort>,
    ) -> Self {
        Self {
            parts: Some(Arc::new(AdminConfigurationViewParts {
                service,
                uses: Arc::new(uses),
                installation_store,
            })),
        }
    }
}

#[async_trait]
impl RebornViewProvider for AdminConfigurationViewProvider {
    fn descriptor(&self) -> RebornViewDescriptor {
        ADMIN_CONFIGURATION_VIEW
    }

    async fn query(
        &self,
        caller: ProductSurfaceCaller,
        params: serde_json::Value,
        cursor: Option<String>,
    ) -> Result<RebornViewPage, ProductSurfaceError> {
        if !caller.operator_config {
            return Err(forbidden());
        }
        if params != serde_json::json!({}) || cursor.is_some() {
            return Err(invalid_request());
        }
        let Some(parts) = &self.parts else {
            return Err(service_error(
                ProductSurfaceErrorCode::Unavailable,
                ProductSurfaceErrorKind::ServiceUnavailable,
                503,
            ));
        };
        let scope = caller_scope(&caller);
        let states = parts
            .service
            .list(&scope)
            .await
            .map_err(map_admin_configuration_error)?;
        let installed = parts
            .installation_store
            .list_installations()
            .await
            .map_err(|error| ProductSurfaceError::internal_from(error.to_string()))?
            .into_iter()
            .map(|installation| installation.extension_id().as_str().to_string())
            .collect::<BTreeSet<_>>();
        let groups = states
            .into_iter()
            .map(|state| render_group(state, &parts.uses, &installed))
            .collect();
        let payload = serde_json::to_value(RebornAdminConfigurationListResponse { groups })
            .map_err(ProductSurfaceError::internal_from)?;
        Ok(RebornViewPage {
            payload,
            next_cursor: None,
        })
    }
}

fn render_group(
    state: AdminConfigurationGroupState,
    uses: &[AdminConfigurationCatalogUse],
    installed: &BTreeSet<String>,
) -> RebornAdminConfigurationGroup {
    let group_id = state.group_id.as_str().to_string();
    RebornAdminConfigurationGroup {
        used_by: uses
            .iter()
            .filter(|usage| usage.descriptor.group_id == state.group_id)
            .map(|usage| RebornAdminConfigurationUse {
                package_id: usage.package_id.clone(),
                display_name: usage.display_name.clone(),
                installed: installed.contains(&usage.package_id),
            })
            .collect(),
        group_id,
        display_name: state.display_name,
        description: state.description,
        revision: state.revision,
        complete: state.complete,
        fields: state
            .fields
            .into_iter()
            .map(|field| RebornAdminConfigurationField {
                handle: field.handle.as_str().to_string(),
                label: field.label,
                secret: field.secret,
                required: field.required,
                provided: field.provided,
                value: field.value,
            })
            .collect(),
    }
}

pub fn caller_scope(caller: &ProductSurfaceCaller) -> ResourceScope {
    ResourceScope {
        tenant_id: caller.tenant_id.clone(),
        user_id: caller.user_id.clone(),
        agent_id: caller.agent_id.clone(),
        project_id: caller.project_id.clone(),
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

fn map_admin_configuration_error(
    error: ironclaw_extension_host::AdminConfigurationServiceError,
) -> ProductSurfaceError {
    use ironclaw_extension_host::AdminConfigurationServiceError;
    let source = error.to_string();
    match error {
        AdminConfigurationServiceError::UnknownGroup => ProductSurfaceError::not_found(),
        AdminConfigurationServiceError::RevisionConflict { .. }
        | AdminConfigurationServiceError::IdempotencyConflict => service_error(
            ProductSurfaceErrorCode::Conflict,
            ProductSurfaceErrorKind::Conflict,
            409,
        ),
        AdminConfigurationServiceError::UnknownField
        | AdminConfigurationServiceError::DuplicateField
        | AdminConfigurationServiceError::MissingRequiredField
        | AdminConfigurationServiceError::ValueTooLarge => invalid_request(),
        AdminConfigurationServiceError::InvalidDescriptor
        | AdminConfigurationServiceError::DescriptorConflict => {
            tracing::error!(error = %source, "admin-configuration descriptor projection failed");
            ProductSurfaceError::internal_from("admin configuration descriptor is invalid")
        }
        AdminConfigurationServiceError::Unavailable => {
            tracing::warn!(error = %source, "admin-configuration query service unavailable");
            ProductSurfaceError {
                code: ProductSurfaceErrorCode::Unavailable,
                kind: ProductSurfaceErrorKind::ServiceUnavailable,
                status_code: 503,
                retryable: true,
                field: None,
                validation_code: None,
            }
        }
    }
}

fn invalid_request() -> ProductSurfaceError {
    service_error(
        ProductSurfaceErrorCode::InvalidRequest,
        ProductSurfaceErrorKind::Validation,
        400,
    )
}

fn forbidden() -> ProductSurfaceError {
    service_error(
        ProductSurfaceErrorCode::Forbidden,
        ProductSurfaceErrorKind::ParticipantDenied,
        403,
    )
}

fn service_error(
    code: ProductSurfaceErrorCode,
    kind: ProductSurfaceErrorKind,
    status_code: u16,
) -> ProductSurfaceError {
    ProductSurfaceError {
        code,
        kind,
        status_code,
        retryable: false,
        field: None,
        validation_code: None,
    }
}

#[cfg(test)]
mod tests {
    use ironclaw_host_api::ids::{TenantId, UserId};

    use super::*;

    fn caller(operator_config: bool) -> ProductSurfaceCaller {
        let mut caller = ProductSurfaceCaller::new(
            TenantId::new("tenant").expect("tenant id"),
            UserId::new("user").expect("user id"),
            None,
            None,
        );
        caller.operator_config = operator_config;
        caller
    }

    /// The fail-closed gate, checked *before* anything else.
    ///
    /// The ordering is the point, not just the 403. The provider's other early
    /// exit is a 503 for an unwired provider, and an unwired provider is
    /// exactly what this drives — the profile default that ships whenever
    /// administrator configuration is not deployed. So the test asserts the
    /// answer **differs by the flag on the same provider**: `false` gets 403,
    /// `true` gets 503. Asserting only the 403 would pass just as happily
    /// against a provider that refused every caller, and asserting it against
    /// a wired provider would not exercise the ordering at all. If the wiring
    /// check ran first, both callers would see 503 and an ungranted caller
    /// would learn whether the service is deployed.
    #[tokio::test]
    async fn the_operator_config_grant_is_checked_before_the_wiring_is_consulted() {
        let provider = AdminConfigurationViewProvider::default();

        let denied = provider
            .query(caller(false), serde_json::json!({}), None)
            .await
            .expect_err("a caller without operator_config must be refused");
        assert_eq!(denied.code, ProductSurfaceErrorCode::Forbidden);
        assert_eq!(denied.kind, ProductSurfaceErrorKind::ParticipantDenied);
        assert_eq!(denied.status_code, 403);
        assert!(
            !denied.retryable,
            "a denied caller must not be told to retry"
        );

        let granted = provider
            .query(caller(true), serde_json::json!({}), None)
            .await
            .expect_err("the same provider is unwired, so a granted caller gets 503");
        assert_eq!(
            granted.status_code, 503,
            "the same provider must answer differently for a granted caller, or the 403 \
             above proves nothing about the grant"
        );
        assert_ne!(
            denied.status_code, granted.status_code,
            "the grant, not the wiring, decides the 403"
        );
    }

    /// The view takes no parameters and is not paginated. Accepting either
    /// silently would let a caller believe a filter or a page was applied.
    #[tokio::test]
    async fn unsupported_params_or_a_cursor_are_rejected_rather_than_ignored() {
        let provider = AdminConfigurationViewProvider::default();
        for (params, cursor) in [
            (serde_json::json!({ "group_id": "smtp" }), None),
            (serde_json::json!({}), Some("page-2".to_string())),
        ] {
            let Err(error) = provider
                .query(caller(true), params.clone(), cursor.clone())
                .await
            else {
                panic!("unsupported query shape must be refused: params={params} cursor={cursor:?}")
            };
            assert_eq!(error.status_code, 400, "params={params} cursor={cursor:?}");
            assert_eq!(error.kind, ProductSurfaceErrorKind::Validation);
        }
    }

    /// An unwired provider is the profile default, so this arm runs in
    /// production whenever administrator configuration is not deployed. It
    /// must answer "unavailable, retryable" rather than an internal error —
    /// the capability may appear once the service is wired.
    #[tokio::test]
    async fn an_unwired_provider_reports_unavailable_rather_than_failing_internally() {
        let provider = AdminConfigurationViewProvider::default();
        let error = provider
            .query(caller(true), serde_json::json!({}), None)
            .await
            .expect_err("an unwired provider has nothing to list");
        assert_eq!(error.code, ProductSurfaceErrorCode::Unavailable);
        assert_eq!(error.status_code, 503);
    }

    #[test]
    fn the_provider_answers_for_the_administrator_configuration_view() {
        assert_eq!(
            AdminConfigurationViewProvider::default().descriptor().id,
            ADMIN_CONFIGURATION_VIEW.id,
            "the view id is the routing key; changing it silently reroutes the WebUI"
        );
    }

    /// Every service-error arm, with the answer each gives.
    ///
    /// Three distinctions are load-bearing and would be invisible if this were
    /// spot-checked: a revision/idempotency conflict is a 409 the caller can
    /// resolve by re-reading, a malformed *descriptor* is an internal 500
    /// (nothing the caller did), and `Unavailable` is the only retryable one.
    #[test]
    fn the_service_error_table_gives_each_failure_its_own_answer() {
        use ironclaw_extension_host::AdminConfigurationServiceError as E;

        let cases = [
            (E::UnknownGroup, 404, false),
            (
                E::RevisionConflict {
                    expected: 1,
                    actual: 2,
                },
                409,
                false,
            ),
            (E::IdempotencyConflict, 409, false),
            (E::UnknownField, 400, false),
            (E::DuplicateField, 400, false),
            (E::MissingRequiredField, 400, false),
            (E::ValueTooLarge, 400, false),
            (E::InvalidDescriptor, 500, false),
            (E::DescriptorConflict, 500, false),
            (E::Unavailable, 503, true),
        ];

        for (error, status, retryable) in cases {
            let label = error.to_string();
            let projected = map_admin_configuration_error(error);
            assert_eq!(projected.status_code, status, "status for {label}");
            assert_eq!(projected.retryable, retryable, "retryable for {label}");
        }
    }

    /// No arm of the table hands the caller a field name or a validation code.
    ///
    /// `ProductSurfaceError` carries `field` and `validation_code` precisely so
    /// a *validated form submission* can point at the offending input. This is
    /// a read-only list view: there is no submitted field to blame, and
    /// `AdminConfigurationServiceError`'s own `Display` names internals
    /// (`RevisionConflict { expected, actual }`) that a caller has no business
    /// seeing. So every arm must leave both slots empty — including the two
    /// that log the source before answering.
    #[test]
    fn no_arm_of_the_table_hands_the_caller_a_field_or_a_validation_code() {
        use ironclaw_extension_host::AdminConfigurationServiceError as E;

        for error in [
            E::UnknownGroup,
            E::RevisionConflict {
                expected: 1,
                actual: 2,
            },
            E::IdempotencyConflict,
            E::UnknownField,
            E::DuplicateField,
            E::MissingRequiredField,
            E::ValueTooLarge,
            E::InvalidDescriptor,
            E::DescriptorConflict,
            E::Unavailable,
        ] {
            let label = error.to_string();
            let projected = map_admin_configuration_error(error);
            assert!(
                projected.field.is_none(),
                "{label} leaked a field name to the caller"
            );
            assert!(
                projected.validation_code.is_none(),
                "{label} leaked a validation code to the caller"
            );
        }
    }
}
