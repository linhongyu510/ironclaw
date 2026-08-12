use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ironclaw_product_contracts::ironhub::{IronhubLinkAdminService, IronhubLinkError};
use ironclaw_product_contracts::product_wire::RebornIronhubLinkResponse;
use ironclaw_product_contracts::surface::ProductSurfaceCaller;
use ironclaw_secrets::SecretStorePort;
use secrecy::{ExposeSecret, SecretString};

use super::agent_link::IronhubSharedKey;
use super::shared_key_store::IronhubSharedKeyStore;

pub struct RebornIronhubLinkAdminService {
    register_url: Option<String>,
    booted_with_key: bool,
    stored_since_boot: AtomicBool,
    keys: IronhubSharedKeyStore,
}

impl RebornIronhubLinkAdminService {
    pub fn new(
        register_url: Option<String>,
        booted_with_key: bool,
        secret_store: Arc<dyn SecretStorePort>,
    ) -> Self {
        Self {
            register_url,
            booted_with_key,
            stored_since_boot: AtomicBool::new(false),
            keys: IronhubSharedKeyStore::new(secret_store),
        }
    }

    async fn snapshot(&self) -> Result<RebornIronhubLinkResponse, IronhubLinkError> {
        let key_stored = match self.keys.exists().await {
            Ok(stored) => stored,
            Err(error) => {
                tracing::debug!(%error, "failed to probe the stored IronHub shared key");
                return Err(IronhubLinkError::Unavailable);
            }
        };
        Ok(RebornIronhubLinkResponse {
            register_url: self.register_url.clone(),
            key_stored,
            // The gateway validates with the key it booted with, so a key
            // stored since then is not in use until the next restart.
            key_active: self.booted_with_key && !self.stored_since_boot.load(Ordering::Relaxed),
        })
    }
}

#[async_trait::async_trait]
impl IronhubLinkAdminService for RebornIronhubLinkAdminService {
    async fn status(&self) -> Result<RebornIronhubLinkResponse, IronhubLinkError> {
        self.snapshot().await
    }

    async fn set_shared_key(
        &self,
        caller: ProductSurfaceCaller,
        shared_key: SecretString,
    ) -> Result<RebornIronhubLinkResponse, IronhubLinkError> {
        let accepted = shared_key.expose_secret().trim().to_string();
        IronhubSharedKey::new(accepted.as_str()).map_err(|error| {
            IronhubLinkError::InvalidInput {
                reason: error.to_string(),
            }
        })?;
        if let Err(error) = self.keys.put_plaintext(accepted).await {
            tracing::debug!(
                user = %caller.user_id,
                %error,
                "failed to store the IronHub shared key"
            );
            return Err(IronhubLinkError::Unavailable);
        }
        self.stored_since_boot.store(true, Ordering::Relaxed);
        tracing::debug!(
            tenant = %caller.tenant_id,
            user = %caller.user_id,
            "IronHub shared key stored; the gateway uses it after the next restart"
        );
        self.snapshot().await
    }

    async fn clear_shared_key(
        &self,
        caller: ProductSurfaceCaller,
    ) -> Result<RebornIronhubLinkResponse, IronhubLinkError> {
        if let Err(error) = self.keys.delete().await {
            tracing::debug!(
                user = %caller.user_id,
                %error,
                "failed to clear the IronHub shared key"
            );
            return Err(IronhubLinkError::Unavailable);
        }
        // Nothing is stored now, so no stored key differs from the boot key.
        self.stored_since_boot.store(false, Ordering::Relaxed);
        tracing::debug!(
            tenant = %caller.tenant_id,
            user = %caller.user_id,
            "IronHub shared key cleared; a running gateway keeps its boot key"
        );
        self.snapshot().await
    }
}

#[cfg(test)]
mod tests {
    use ironclaw_host_api::ids::{TenantId, UserId};
    use ironclaw_secrets::{SecretMaterial, SecretStore};

    use super::*;

    const KEY: &str = "ihub_sk_TestSharedKey00000000000000000000000";
    const URL: &str = "https://agent.example.com/api/ironhub/register";

    fn service(
        register_url: Option<&str>,
        booted_with_key: bool,
    ) -> (RebornIronhubLinkAdminService, Arc<dyn SecretStorePort>) {
        let store: Arc<dyn SecretStorePort> = Arc::new(SecretStore::ephemeral());
        let service = RebornIronhubLinkAdminService::new(
            register_url.map(str::to_string),
            booted_with_key,
            Arc::clone(&store),
        );
        (service, store)
    }

    fn caller() -> ProductSurfaceCaller {
        ProductSurfaceCaller {
            tenant_id: TenantId::new("tenant").expect("tenant"),
            user_id: UserId::new("user").expect("user"),
            agent_id: None,
            project_id: None,
            operator_config: false,
        }
    }

    #[tokio::test]
    async fn unconfigured_reports_no_url_and_no_key() {
        let (service, _store) = service(None, false);
        let status = service.status().await.expect("status");
        assert_eq!(status.register_url, None);
        assert!(!status.key_stored);
        assert!(!status.key_active);
    }

    #[tokio::test]
    async fn a_stored_key_reads_as_pending_restart_until_the_next_boot() {
        let (service, store) = service(Some(URL), false);
        IronhubSharedKeyStore::new(store)
            .put(SecretMaterial::from(KEY))
            .await
            .expect("store");

        let status = service.status().await.expect("status");
        assert!(status.key_stored);
        assert!(!status.key_active);
    }

    #[tokio::test]
    async fn an_env_key_reads_as_active_without_being_stored() {
        let (service, _store) = service(Some(URL), true);
        let status = service.status().await.expect("status");
        assert!(!status.key_stored);
        assert!(status.key_active);
    }

    #[tokio::test]
    async fn an_accepted_key_is_stored_and_reads_as_pending_restart() {
        let (service, _store) = service(Some(URL), false);

        let status = service
            .set_shared_key(caller(), SecretString::from(KEY))
            .await
            .expect("accepted");

        assert!(status.key_stored);
        assert!(!status.key_active);
    }

    #[tokio::test]
    async fn replacing_the_key_of_a_running_gateway_reads_as_pending_restart() {
        let (service, _store) = service(Some(URL), true);
        assert!(service.status().await.expect("status").key_active);

        let status = service
            .set_shared_key(caller(), SecretString::from(KEY))
            .await
            .expect("accepted");

        assert!(status.key_stored);
        assert!(
            !status.key_active,
            "the gateway still validates with its boot key until the next restart"
        );
    }

    #[tokio::test]
    async fn clearing_forgets_the_stored_key() {
        let (service, _store) = service(Some(URL), false);
        service
            .set_shared_key(caller(), SecretString::from(KEY))
            .await
            .expect("accepted");

        let status = service.clear_shared_key(caller()).await.expect("cleared");
        assert!(!status.key_stored);
    }

    #[tokio::test]
    async fn clearing_a_replacement_restores_the_running_gateway_reading() {
        let (service, _store) = service(Some(URL), true);
        service
            .set_shared_key(caller(), SecretString::from(KEY))
            .await
            .expect("accepted");
        assert!(!service.status().await.expect("status").key_active);

        let status = service.clear_shared_key(caller()).await.expect("cleared");
        assert!(!status.key_stored);
        assert!(
            status.key_active,
            "nothing is stored now, so the gateway's boot key is the only key in play"
        );
    }

    #[tokio::test]
    async fn clearing_an_absent_key_is_not_an_error() {
        let (service, _store) = service(None, false);
        let status = service.clear_shared_key(caller()).await.expect("cleared");
        assert!(!status.key_stored);
    }

    #[tokio::test]
    async fn clearing_leaves_the_running_gateway_active_until_restart() {
        let (service, store) = service(Some(URL), true);
        IronhubSharedKeyStore::new(store)
            .put(SecretMaterial::from(KEY))
            .await
            .expect("store");

        let status = service.clear_shared_key(caller()).await.expect("cleared");
        assert!(!status.key_stored);
        assert!(
            status.key_active,
            "the gateway keeps the key it booted with until the next restart"
        );
    }

    #[tokio::test]
    async fn a_short_key_is_rejected_before_it_reaches_the_store() {
        let (service, store) = service(None, false);

        let error = service
            .set_shared_key(caller(), SecretString::from("ihub_sk_tooshort"))
            .await
            .expect_err("must reject");
        assert!(matches!(error, IronhubLinkError::InvalidInput { .. }));

        assert!(
            !IronhubSharedKeyStore::new(store)
                .exists()
                .await
                .expect("exists"),
            "a rejected key must not be written"
        );
    }

    #[tokio::test]
    async fn surrounding_whitespace_is_trimmed_before_storage() {
        let (service, store) = service(None, false);
        service
            .set_shared_key(caller(), SecretString::from(format!("  {KEY}\n")))
            .await
            .expect("accepted");

        let stored = IronhubSharedKeyStore::new(store)
            .read()
            .await
            .expect("read")
            .expect("some");
        assert_eq!(secrecy::ExposeSecret::expose_secret(&stored), KEY);
    }

    #[tokio::test]
    async fn status_never_carries_key_material() {
        let (service, store) = service(None, true);
        IronhubSharedKeyStore::new(store)
            .put(SecretMaterial::from(KEY))
            .await
            .expect("store");

        let status = service.status().await.expect("status");
        assert!(!format!("{status:?}").contains(KEY));
    }
}
