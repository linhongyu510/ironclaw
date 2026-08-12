//! Narrow initialization seam for binary-linked first-party channels.
//!
//! Composition supplies shared credential storage and collects the resulting
//! non-secret client bootstrap document. The binding owns every
//! extension-specific decision: credential handles, material shape, and
//! bootstrap shape never enter generic composition.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use ironclaw_host_api::{
    ids::{ExtensionId, SecretHandle},
    resource::ResourceScope,
};
use ironclaw_secrets::{SecretMaterial, SecretStorePort};

use crate::input::ChannelExtensionBinding;

/// Shared host resources available to a binary-linked channel initializer.
#[derive(Clone)]
pub struct FirstPartyChannelInitializationContext {
    secret_store: Arc<dyn SecretStorePort>,
    credential_scope: ResourceScope,
}

impl FirstPartyChannelInitializationContext {
    pub(crate) fn new(
        secret_store: Arc<dyn SecretStorePort>,
        credential_scope: ResourceScope,
    ) -> Self {
        Self {
            secret_store,
            credential_scope,
        }
    }

    /// Store extension-owned credential material only when the handle is
    /// absent. The secret store arbitrates concurrent replica initialization.
    pub async fn store_credential_if_absent(
        &self,
        handle: SecretHandle,
        material: String,
    ) -> Result<bool, FirstPartyChannelInitializationError> {
        self.secret_store
            .put_if_absent(
                self.credential_scope.clone(),
                handle,
                SecretMaterial::from(material),
                None,
            )
            .await
            .map_err(|error| {
                FirstPartyChannelInitializationError::failed(format!(
                    "credential storage failed: {}",
                    error.stable_reason()
                ))
            })
    }

    /// Read extension-owned credential material through the one-shot lease
    /// protocol. The caller must keep the returned value secret.
    pub async fn read_credential_once(
        &self,
        handle: &SecretHandle,
    ) -> Result<secrecy::SecretString, FirstPartyChannelInitializationError> {
        let lease = self
            .secret_store
            .lease_once(&self.credential_scope, handle)
            .await
            .map_err(|error| {
                FirstPartyChannelInitializationError::failed(format!(
                    "credential lease failed: {}",
                    error.stable_reason()
                ))
            })?;
        self.secret_store
            .consume(&self.credential_scope, lease.id)
            .await
            .map_err(|error| {
                FirstPartyChannelInitializationError::failed(format!(
                    "credential read failed: {}",
                    error.stable_reason()
                ))
            })
    }
}

/// One binary-linked channel's optional startup initialization.
#[async_trait]
pub trait FirstPartyChannelInitializer: Send + Sync {
    /// Initialize extension-owned state and return the optional non-secret
    /// client bootstrap document published by notification setup.
    async fn initialize(
        &self,
        context: &FirstPartyChannelInitializationContext,
    ) -> Result<Option<serde_json::Value>, FirstPartyChannelInitializationError>;
}

/// Sanitized startup failure from a first-party channel initializer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("first-party channel initialization failed: {reason}")]
pub struct FirstPartyChannelInitializationError {
    reason: String,
}

impl FirstPartyChannelInitializationError {
    pub fn failed(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Bootstrap documents produced by successfully initialized channel bindings.
#[derive(Debug, Default)]
pub(crate) struct InitializedChannelBootstraps {
    documents: BTreeMap<ExtensionId, serde_json::Value>,
}

impl ironclaw_assistant::DeliveryClientBootstrap for InitializedChannelBootstraps {
    fn bootstrap(
        &self,
        extension_id: &str,
    ) -> Result<Option<serde_json::Value>, ironclaw_assistant::DeliveryClientBootstrapError> {
        let extension_id = ExtensionId::new(extension_id)
            .map_err(|_| ironclaw_assistant::DeliveryClientBootstrapError)?;
        Ok(self.documents.get(&extension_id).cloned())
    }
}

pub(crate) async fn initialize_first_party_channels(
    bindings: &[ChannelExtensionBinding],
    secret_store: Arc<dyn SecretStorePort>,
    credential_scope: ResourceScope,
) -> Result<InitializedChannelBootstraps, FirstPartyChannelInitializationError> {
    let context = FirstPartyChannelInitializationContext::new(secret_store, credential_scope);
    let mut documents = BTreeMap::new();
    for binding in bindings {
        let Some(initializer) = binding.first_party_initializer.as_ref() else {
            continue;
        };
        let bootstrap = initializer.initialize(&context).await.map_err(|error| {
            FirstPartyChannelInitializationError::failed(format!(
                "initializer for extension `{}` failed: {error}",
                binding.extension_id
            ))
        })?;
        if let Some(bootstrap) = bootstrap {
            documents.insert(binding.extension_id.clone(), bootstrap);
        }
    }
    Ok(InitializedChannelBootstraps { documents })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use ironclaw_assistant::DeliveryClientBootstrap as _;
    use ironclaw_extension_contracts::channel_adapter::ChannelSurfaces;
    use ironclaw_filesystem::InMemoryBackend;
    use ironclaw_host_api::{
        ids::{ExtensionId, InvocationId, SecretHandle, TenantId, UserId},
        resource::ResourceScope,
    };
    use ironclaw_secrets::{SecretStore, SecretStorePort};
    use secrecy::ExposeSecret as _;

    use crate::{
        ChannelExtensionBinding, FirstPartyChannelInitializationContext,
        FirstPartyChannelInitializationError, FirstPartyChannelInitializer,
    };

    struct StaticInitializer {
        result: Result<Option<serde_json::Value>, FirstPartyChannelInitializationError>,
    }

    struct GeneratedInitializer;

    #[async_trait]
    impl FirstPartyChannelInitializer for GeneratedInitializer {
        async fn initialize(
            &self,
            context: &FirstPartyChannelInitializationContext,
        ) -> Result<Option<serde_json::Value>, FirstPartyChannelInitializationError> {
            let handle = SecretHandle::new("replica_safe_generated_key")
                .map_err(|error| FirstPartyChannelInitializationError::failed(error.to_string()))?;
            context
                .store_credential_if_absent(handle.clone(), uuid::Uuid::new_v4().to_string())
                .await?;
            let winner = context.read_credential_once(&handle).await?;
            Ok(Some(
                serde_json::json!({ "winner": winner.expose_secret() }),
            ))
        }
    }

    #[async_trait]
    impl FirstPartyChannelInitializer for StaticInitializer {
        async fn initialize(
            &self,
            _context: &FirstPartyChannelInitializationContext,
        ) -> Result<Option<serde_json::Value>, FirstPartyChannelInitializationError> {
            self.result.clone()
        }
    }

    fn scope() -> ResourceScope {
        ResourceScope {
            tenant_id: TenantId::new("tenant-alpha").expect("tenant"),
            user_id: UserId::new("operator").expect("user"),
            agent_id: None,
            project_id: None,
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        }
    }

    fn binding(
        extension_id: &str,
        initializer: Arc<dyn FirstPartyChannelInitializer>,
    ) -> ChannelExtensionBinding {
        ChannelExtensionBinding {
            extension_id: ExtensionId::new(extension_id).expect("extension id"),
            surfaces: ChannelSurfaces::default(),
            preference_target_codec: None,
            outbound_target_provider: None,
            first_party_initializer: Some(initializer),
            registration_document_path: None,
        }
    }

    #[tokio::test]
    async fn binding_initializer_publishes_bootstrap_by_typed_extension_id() {
        let store: Arc<dyn SecretStorePort> = Arc::new(SecretStore::ephemeral_over(Arc::new(
            InMemoryBackend::new(),
        )));
        let bindings = vec![binding(
            "channel-a",
            Arc::new(StaticInitializer {
                result: Ok(Some(serde_json::json!({ "public_key": "pk-a" }))),
            }),
        )];

        let bootstraps = super::initialize_first_party_channels(&bindings, store, scope())
            .await
            .expect("initializer succeeds");

        assert_eq!(
            bootstraps
                .bootstrap("channel-a")
                .expect("bootstrap lookup succeeds"),
            Some(serde_json::json!({ "public_key": "pk-a" }))
        );
        assert_eq!(
            bootstraps
                .bootstrap("channel-b")
                .expect("unknown lookup succeeds"),
            None
        );
    }

    #[tokio::test]
    async fn binding_initializer_failure_aborts_bootstrap_assembly() {
        let store: Arc<dyn SecretStorePort> = Arc::new(SecretStore::ephemeral_over(Arc::new(
            InMemoryBackend::new(),
        )));
        let bindings = vec![binding(
            "channel-a",
            Arc::new(StaticInitializer {
                result: Err(FirstPartyChannelInitializationError::failed(
                    "bootstrap unavailable",
                )),
            }),
        )];

        let error = super::initialize_first_party_channels(&bindings, store, scope())
            .await
            .expect_err("initializer failure must fail assembly");

        assert!(error.to_string().contains("channel-a"));
    }

    #[tokio::test]
    async fn concurrent_initializers_publish_the_same_generated_credential() {
        let store: Arc<dyn SecretStorePort> = Arc::new(SecretStore::ephemeral_over(Arc::new(
            InMemoryBackend::new(),
        )));
        let first_bindings = vec![binding("channel-a", Arc::new(GeneratedInitializer))];
        let second_bindings = vec![binding("channel-a", Arc::new(GeneratedInitializer))];
        let first =
            super::initialize_first_party_channels(&first_bindings, Arc::clone(&store), scope());
        let second = super::initialize_first_party_channels(&second_bindings, store, scope());
        let (first, second) = tokio::join!(first, second);

        assert_eq!(
            first.expect("first initializer").bootstrap("channel-a"),
            second.expect("second initializer").bootstrap("channel-a"),
            "every replica must publish bootstrap data from the one winning secret",
        );
    }
}
