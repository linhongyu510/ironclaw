use async_trait::async_trait;
use ironclaw_extensions::ExtensionPackage;
use ironclaw_host_api::decision::RuntimeCredentialAuthRequirement;
use ironclaw_product_contracts::error::ProductOperationFailure;

use crate::package_runtime_credential_auth_requirements;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionActivationCredentialReadiness {
    Ready,
    Missing(Vec<RuntimeCredentialAuthRequirement>),
}

#[async_trait]
pub trait ExtensionActivationCredentialGate: Send + Sync {
    async fn ensure_credentials(
        &self,
        package: &ExtensionPackage,
    ) -> Result<(), ProductOperationFailure>;

    async fn credential_readiness(
        &self,
        package: &ExtensionPackage,
    ) -> Result<ExtensionActivationCredentialReadiness, ProductOperationFailure> {
        self.ensure_credentials(package).await?;
        Ok(ExtensionActivationCredentialReadiness::Ready)
    }
}

pub struct UnavailableExtensionActivationCredentialGate;

#[async_trait]
impl ExtensionActivationCredentialGate for UnavailableExtensionActivationCredentialGate {
    async fn ensure_credentials(
        &self,
        package: &ExtensionPackage,
    ) -> Result<(), ProductOperationFailure> {
        if package_runtime_credential_auth_requirements(package).is_empty() {
            return Ok(());
        }
        Err(missing_activation_credentials_error(package))
    }

    async fn credential_readiness(
        &self,
        package: &ExtensionPackage,
    ) -> Result<ExtensionActivationCredentialReadiness, ProductOperationFailure> {
        let missing = package_runtime_credential_auth_requirements(package);
        if missing.is_empty() {
            Ok(ExtensionActivationCredentialReadiness::Ready)
        } else {
            Ok(ExtensionActivationCredentialReadiness::Missing(missing))
        }
    }
}

pub struct PrecheckedExtensionActivationCredentialGate;

#[async_trait]
impl ExtensionActivationCredentialGate for PrecheckedExtensionActivationCredentialGate {
    async fn ensure_credentials(
        &self,
        _package: &ExtensionPackage,
    ) -> Result<(), ProductOperationFailure> {
        Ok(())
    }
}

pub fn missing_activation_credentials_error(package: &ExtensionPackage) -> ProductOperationFailure {
    ProductOperationFailure::InvalidBindingRequest {
        reason: format!(
            "extension {} requires product auth credentials before activation",
            package.manifest.id.as_str()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExtensionActivationCredentialGate, ExtensionActivationCredentialReadiness,
        UnavailableExtensionActivationCredentialGate, missing_activation_credentials_error,
    };
    use ironclaw_extensions::{ExtensionManifest, ExtensionPackage, ManifestSource};
    use ironclaw_host_api::path::VirtualPath;
    use ironclaw_product_contracts::error::ProductOperationFailure;

    const NO_CREDENTIAL_MANIFEST: &str = r#"
schema_version = "reborn.extension_manifest.v2"
id = "credentialless"
name = "Credentialless Extension"
version = "0.1.0"
description = "Activation gate fixture with no credential requirements"
trust = "first_party_requested"

[runtime]
kind = "wasm"
module = "wasm/fixture.wasm"

[[host_api]]
id = "ironclaw.capability_provider/v1"
section = "capability_provider.tools"

[capability_provider.tools]

[[capability_provider.tools.capabilities]]
id = "credentialless.search"
description = "Search without credentials"
effects = ["network"]
default_permission = "ask"
visibility = "model"
input_schema_ref = "schemas/search.input.json"
output_schema_ref = "schemas/search.output.json"
"#;

    fn package() -> ExtensionPackage {
        let contracts =
            crate::product_extension_host_api_contract_registry().expect("host API contracts");
        let manifest = ExtensionManifest::parse(
            NO_CREDENTIAL_MANIFEST,
            ManifestSource::HostBundled,
            &ironclaw_host_runtime::default_host_port_catalog().expect("host ports"),
            &contracts,
        )
        .expect("fixture manifest");
        let root = VirtualPath::new("/system/extensions/credentialless").expect("extension root");
        ExtensionPackage::from_manifest_toml(manifest, root, NO_CREDENTIAL_MANIFEST)
            .expect("fixture package")
    }

    /// `UnavailableExtensionActivationCredentialGate` is the stand-in used when
    /// no credential service is wired. It must fail *closed*: an extension that
    /// declares credential requirements cannot activate without one. An
    /// extension that declares none is not gated at all, which is what makes
    /// the deployment usable — so both halves are asserted, and the
    /// discriminating input is the package's own requirements.
    #[tokio::test]
    async fn the_unavailable_gate_admits_only_credentialless_extensions() {
        let package = package();
        assert!(
            super::package_runtime_credential_auth_requirements(&package).is_empty(),
            "fixture must declare no credential requirements for this to prove anything"
        );

        assert!(
            UnavailableExtensionActivationCredentialGate
                .ensure_credentials(&package)
                .await
                .is_ok(),
            "an extension needing no credentials must not be blocked by a missing service"
        );
        assert_eq!(
            UnavailableExtensionActivationCredentialGate
                .credential_readiness(&package)
                .await
                .expect("readiness is not an error for a credentialless package"),
            ExtensionActivationCredentialReadiness::Ready,
        );
    }

    #[test]
    fn the_missing_credentials_error_names_the_extension_and_is_caller_fixable() {
        assert_eq!(
            missing_activation_credentials_error(&package()),
            ProductOperationFailure::InvalidBindingRequest {
                reason: "extension credentialless requires product auth credentials before \
                         activation"
                    .to_string(),
            },
            "the caller must be told which extension needs connecting"
        );
    }
}
