use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ironclaw_filesystem::{CasExpectation, Entry, FilesystemError, RootFilesystem};
#[cfg(test)]
use ironclaw_host_api::RuntimeHttpEgress;
use ironclaw_host_api::{
    CapabilityId, InvocationId, ProductSurfaceCaller, ResourceScope, VirtualPath,
};
use ironclaw_product::{
    IronhubInstallDeliveryRequest, IronhubInstallDeliveryResult, IronhubLinkError,
    IronhubLinkService, IronhubRegisterRequest,
};
use ironclaw_skills::ScopedSkillManagementPort;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ironclaw_extension_host::ExtensionLifecycleManager;

use super::agent_link::{InstallDelivery, IronhubSharedKey, RegisterChallenge, verify_signature};
use super::model::{IronHubCommand, IronHubCommandError, IronHubInstallOptions, IronHubPhase};
use super::service::IronHubService;

const IRONHUB_STATE_ROOT: &str = "/system/settings/ironhub";
const MAX_LINK_ID_BYTES: usize = 256;
const MAX_NONCE_BYTES: usize = 512;
const MANIFEST_CAS_RETRIES: usize = 32;
const MAX_TIMESTAMP_DRIFT_SECS: u64 = 300;
const INSTALL_CAPABILITY_ID: &str = "builtin.ironhub_install";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IronhubLinkBuildError {
    #[error("invalid IronHub link configuration")]
    InvalidConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IronhubLinkStateError {
    #[error("IronHub install request was replayed")]
    NonceReplay,
    #[error("IronHub private manifest was replayed or downgraded")]
    ManifestReplay,
    #[error("invalid IronHub durable state input")]
    InvalidInput,
    #[error("IronHub durable state is unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub struct IronhubLinkStateStore {
    filesystem: Arc<dyn RootFilesystem>,
}

pub struct RebornIronhubLinkService {
    skill_management: Arc<ScopedSkillManagementPort>,
    extension_management: Arc<ExtensionLifecycleManager>,
    egress: Arc<dyn ironclaw_host_api::RuntimeHttpEgress>,
    state: Arc<IronhubLinkStateStore>,
    shared_key: IronhubSharedKey,
    install_capability: CapabilityId,
    manifest_url: String,
}

impl RebornIronhubLinkService {
    pub fn new(
        skill_management: Arc<ScopedSkillManagementPort>,
        extension_management: Arc<ExtensionLifecycleManager>,
        runtime_http_egress: Arc<dyn ironclaw_host_api::RuntimeHttpEgress>,
        state: Arc<IronhubLinkStateStore>,
        shared_key: IronhubSharedKey,
    ) -> Result<Self, IronhubLinkBuildError> {
        let install_capability = CapabilityId::new(INSTALL_CAPABILITY_ID)
            .map_err(|_| IronhubLinkBuildError::InvalidConfig)?;
        Ok(Self {
            skill_management,
            extension_management,
            egress: runtime_http_egress,
            state,
            shared_key,
            install_capability,
            manifest_url: crate::model::DEFAULT_IRONHUB_MANIFEST_URL.to_string(),
        })
    }

    pub fn with_manifest_url(mut self, manifest_url: String) -> Self {
        self.manifest_url = manifest_url;
        self
    }

    fn install_service(&self, scope: ResourceScope) -> IronHubService {
        let service = IronHubService::new_with_runtime_egress(
            Arc::clone(&self.skill_management),
            Arc::clone(&self.extension_management),
            Arc::clone(&self.egress),
            scope,
            self.install_capability.clone(),
        );
        #[cfg(test)]
        let service = super::service::configure_test_catalog(
            service,
            super::model::DEFAULT_IRONHUB_MANIFEST_URL,
            super::tests::test_manifest_verify_keys(),
        );
        service
            .with_manifest_url(self.manifest_url.clone())
            .with_link_state(Arc::clone(&self.state))
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;

    pub(crate) fn new_with_runtime_egress(
        skill_management: Arc<ScopedSkillManagementPort>,
        extension_management: Arc<ExtensionLifecycleManager>,
        runtime_http_egress: Arc<dyn RuntimeHttpEgress>,
        state: Arc<IronhubLinkStateStore>,
        shared_key: IronhubSharedKey,
    ) -> Result<RebornIronhubLinkService, IronhubLinkBuildError> {
        let install_capability = CapabilityId::new(INSTALL_CAPABILITY_ID)
            .map_err(|_| IronhubLinkBuildError::InvalidConfig)?;
        Ok(RebornIronhubLinkService {
            skill_management,
            extension_management,
            egress: runtime_http_egress,
            state,
            shared_key,
            install_capability,
            manifest_url: crate::model::DEFAULT_IRONHUB_MANIFEST_URL.to_string(),
        })
    }
}

impl IronhubLinkStateStore {
    pub fn new(filesystem: Arc<dyn RootFilesystem>) -> Self {
        Self { filesystem }
    }

    pub async fn consume_install_nonce(
        &self,
        caller: &ProductSurfaceCaller,
        nonce: &str,
        consumed_at: DateTime<Utc>,
    ) -> Result<(), IronhubLinkStateError> {
        if nonce.is_empty() || nonce.len() > MAX_NONCE_BYTES || nonce.chars().any(char::is_control)
        {
            return Err(IronhubLinkStateError::InvalidInput);
        }
        let path = nonce_path(caller, nonce)?;
        let record = ConsumedNonce { consumed_at };
        let body = serde_json::to_vec(&record).map_err(|error| {
            tracing::debug!(%error, "failed to serialize consumed IronHub nonce");
            IronhubLinkStateError::Unavailable
        })?;
        match self
            .filesystem
            .put(&path, Entry::bytes(body), CasExpectation::Absent)
            .await
        {
            Ok(_) => Ok(()),
            Err(FilesystemError::VersionMismatch { .. }) => Err(IronhubLinkStateError::NonceReplay),
            Err(error) => {
                tracing::debug!(%error, "failed to persist consumed IronHub nonce");
                Err(IronhubLinkStateError::Unavailable)
            }
        }
    }

    pub async fn record_private_manifest(
        &self,
        catalog_host: &str,
        signed_repo: &str,
        generated_at: DateTime<Utc>,
        signed_manifest_digest: &str,
    ) -> Result<(), IronhubLinkStateError> {
        let catalog_host = canonical_host(catalog_host)?;
        if signed_repo.trim().is_empty() || signed_repo.len() > 1024 {
            return Err(IronhubLinkStateError::InvalidInput);
        }
        let path = manifest_path(&catalog_host, signed_repo)?;
        let desired = PrivateManifestState {
            catalog_host,
            signed_repo: signed_repo.to_string(),
            generated_at,
            signed_manifest_digest: signed_manifest_digest.to_ascii_lowercase(),
        };

        for _ in 0..MANIFEST_CAS_RETRIES {
            let current = self.filesystem.get(&path).await.map_err(|error| {
                tracing::debug!(%error, "failed to read durable IronHub manifest state");
                IronhubLinkStateError::Unavailable
            })?;
            let cas = match current {
                Some(versioned) => {
                    let prior: PrivateManifestState = serde_json::from_slice(&versioned.entry.body)
                        .map_err(|error| {
                            tracing::debug!(
                                %error,
                                "failed to decode durable IronHub manifest state"
                            );
                            IronhubLinkStateError::Unavailable
                        })?;
                    if prior.catalog_host != desired.catalog_host
                        || prior.signed_repo != desired.signed_repo
                    {
                        return Err(IronhubLinkStateError::Unavailable);
                    }
                    if desired.generated_at <= prior.generated_at {
                        return Err(IronhubLinkStateError::ManifestReplay);
                    }
                    CasExpectation::Version(versioned.version)
                }
                None => CasExpectation::Absent,
            };
            let body = serde_json::to_vec(&desired).map_err(|error| {
                tracing::debug!(%error, "failed to serialize durable IronHub manifest state");
                IronhubLinkStateError::Unavailable
            })?;
            match self.filesystem.put(&path, Entry::bytes(body), cas).await {
                Ok(_) => return Ok(()),
                Err(FilesystemError::VersionMismatch { .. }) => {
                    tokio::task::yield_now().await;
                }
                Err(error) => {
                    tracing::debug!(%error, "failed to persist durable IronHub manifest state");
                    return Err(IronhubLinkStateError::Unavailable);
                }
            }
        }
        Err(IronhubLinkStateError::Unavailable)
    }

    pub async fn record_public_manifest(
        &self,
        manifest_url: &str,
        generated_at: DateTime<Utc>,
        signed_manifest_digest: &str,
    ) -> Result<(), IronhubLinkStateError> {
        let path = public_manifest_path(manifest_url)?;
        let desired = PublicManifestState {
            manifest_url: manifest_url.to_string(),
            generated_at,
            signed_manifest_digest: signed_manifest_digest.to_ascii_lowercase(),
        };
        for _ in 0..MANIFEST_CAS_RETRIES {
            let current = self.filesystem.get(&path).await.map_err(|error| {
                tracing::debug!(%error, "failed to read public IronHub manifest replay state");
                IronhubLinkStateError::Unavailable
            })?;
            let cas = match current {
                Some(versioned) => {
                    let prior: PublicManifestState = serde_json::from_slice(&versioned.entry.body)
                        .map_err(|error| {
                            tracing::debug!(
                                %error,
                                "failed to decode public IronHub manifest replay state"
                            );
                            IronhubLinkStateError::Unavailable
                        })?;
                    if desired.manifest_url != prior.manifest_url
                        || desired.generated_at < prior.generated_at
                        || (desired.generated_at == prior.generated_at
                            && desired.signed_manifest_digest != prior.signed_manifest_digest)
                    {
                        return Err(IronhubLinkStateError::ManifestReplay);
                    }
                    if desired == prior {
                        return Ok(());
                    }
                    CasExpectation::Version(versioned.version)
                }
                None => CasExpectation::Absent,
            };
            let body = serde_json::to_vec(&desired).map_err(|error| {
                tracing::debug!(%error, "failed to serialize public IronHub manifest replay state");
                IronhubLinkStateError::Unavailable
            })?;
            match self.filesystem.put(&path, Entry::bytes(body), cas).await {
                Ok(_) => return Ok(()),
                Err(FilesystemError::VersionMismatch { .. }) => tokio::task::yield_now().await,
                Err(error) => {
                    tracing::debug!(%error, "failed to persist public IronHub manifest replay state");
                    return Err(IronhubLinkStateError::Unavailable);
                }
            }
        }
        Err(IronhubLinkStateError::Unavailable)
    }
}

#[async_trait]
impl IronhubLinkService for RebornIronhubLinkService {
    async fn register(&self, request: IronhubRegisterRequest) -> Result<(), IronhubLinkError> {
        authenticate_register(&self.shared_key, &request)
    }

    async fn deliver_install(
        &self,
        caller: ProductSurfaceCaller,
        request: IronhubInstallDeliveryRequest,
    ) -> Result<IronhubInstallDeliveryResult, IronhubLinkError> {
        authenticate_install(&self.shared_key, &request)?;
        self.state
            .consume_install_nonce(&caller, &request.nonce, Utc::now())
            .await
            .map_err(map_state_error)?;

        let scope = ResourceScope {
            tenant_id: caller.tenant_id,
            user_id: caller.user_id,
            agent_id: caller.agent_id,
            project_id: caller.project_id,
            mission_id: None,
            thread_id: None,
            invocation_id: InvocationId::new(),
        };
        let response = self
            .install_service(scope)
            .execute(IronHubCommand::Install {
                name: request.slug.clone(),
                options: IronHubInstallOptions {
                    kind: None,
                    force: false,
                    acknowledge_unverified: false,
                    expected_version: Some(request.version),
                    expected_artifact_digest: Some(request.artifact_digest),
                    private_manifest_url: request.private_manifest_url,
                },
            })
            .await
            .map_err(map_install_error)?;

        Ok(IronhubInstallDeliveryResult {
            installed: response.phase == IronHubPhase::Installed,
            slug: request.slug,
            message: response.message.unwrap_or_default(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConsumedNonce {
    consumed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateManifestState {
    catalog_host: String,
    signed_repo: String,
    generated_at: DateTime<Utc>,
    signed_manifest_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PublicManifestState {
    manifest_url: String,
    generated_at: DateTime<Utc>,
    signed_manifest_digest: String,
}

fn nonce_path(
    caller: &ProductSurfaceCaller,
    nonce: &str,
) -> Result<VirtualPath, IronhubLinkStateError> {
    let mut hasher = Sha256::new();
    hash_length_prefixed(&mut hasher, caller.tenant_id.as_str().as_bytes());
    hash_length_prefixed(&mut hasher, caller.user_id.as_str().as_bytes());
    if let Some(agent_id) = &caller.agent_id {
        hash_length_prefixed(&mut hasher, agent_id.as_str().as_bytes());
    } else {
        hash_length_prefixed(&mut hasher, &[]);
    }
    if let Some(project_id) = &caller.project_id {
        hash_length_prefixed(&mut hasher, project_id.as_str().as_bytes());
    } else {
        hash_length_prefixed(&mut hasher, &[]);
    }
    hash_length_prefixed(&mut hasher, nonce.as_bytes());
    let digest = hex::encode(hasher.finalize());
    state_path(&format!("install-nonces/{digest}.json"))
}

fn manifest_path(
    catalog_host: &str,
    signed_repo: &str,
) -> Result<VirtualPath, IronhubLinkStateError> {
    let mut hasher = Sha256::new();
    hash_length_prefixed(&mut hasher, catalog_host.as_bytes());
    hash_length_prefixed(&mut hasher, signed_repo.as_bytes());
    let digest = hex::encode(hasher.finalize());
    state_path(&format!("private-manifests/{digest}.json"))
}

fn public_manifest_path(manifest_url: &str) -> Result<VirtualPath, IronhubLinkStateError> {
    if manifest_url.is_empty() || manifest_url.len() > 4096 {
        return Err(IronhubLinkStateError::InvalidInput);
    }
    let digest = hex::encode(Sha256::digest(manifest_url.as_bytes()));
    state_path(&format!("public-manifests/{digest}.json"))
}

fn hash_length_prefixed(hasher: &mut Sha256, field: &[u8]) {
    hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(field);
}

fn state_path(suffix: &str) -> Result<VirtualPath, IronhubLinkStateError> {
    VirtualPath::new(format!("{IRONHUB_STATE_ROOT}/{suffix}"))
        .map_err(|_| IronhubLinkStateError::Unavailable)
}

fn canonical_host(host: &str) -> Result<String, IronhubLinkStateError> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.chars().any(char::is_control) {
        return Err(IronhubLinkStateError::InvalidInput);
    }
    Ok(host)
}

fn authenticate_register(
    shared_key: &IronhubSharedKey,
    request: &IronhubRegisterRequest,
) -> Result<(), IronhubLinkError> {
    for (field, value) in [
        ("uid", request.uid.as_str()),
        ("aid", request.aid.as_str()),
        ("nonce", request.nonce.as_str()),
    ] {
        if value.is_empty()
            || value.len()
                > if field == "nonce" {
                    MAX_NONCE_BYTES
                } else {
                    MAX_LINK_ID_BYTES
                }
            || value.contains(':')
            || value.chars().any(char::is_control)
        {
            return Err(IronhubLinkError::InvalidInput {
                reason: format!("invalid register {field}"),
            });
        }
    }
    if !timestamp_fresh(request.ts) {
        return Err(IronhubLinkError::StaleTimestamp);
    }
    let challenge = RegisterChallenge {
        uid: &request.uid,
        aid: &request.aid,
        ts: request.ts,
        nonce: &request.nonce,
    };
    if verify_signature(shared_key, &challenge.payload(), &request.sig) {
        Ok(())
    } else {
        Err(IronhubLinkError::InvalidSignature)
    }
}

fn authenticate_install(
    shared_key: &IronhubSharedKey,
    request: &IronhubInstallDeliveryRequest,
) -> Result<(), IronhubLinkError> {
    if !timestamp_fresh(request.ts) {
        return Err(IronhubLinkError::StaleTimestamp);
    }
    let delivery = InstallDelivery {
        slug: &request.slug,
        version: &request.version,
        uid: &request.uid,
        aid: &request.aid,
        ts: request.ts,
        nonce: &request.nonce,
        artifact_digest: &request.artifact_digest,
        private_manifest_url: request.private_manifest_url.as_deref(),
    };
    if verify_signature(shared_key, &delivery.payload(), &request.sig) {
        Ok(())
    } else {
        Err(IronhubLinkError::InvalidSignature)
    }
}

fn timestamp_fresh(ts: u64) -> bool {
    let Ok(ts) = i64::try_from(ts) else {
        return false;
    };
    Utc::now().timestamp().abs_diff(ts) <= MAX_TIMESTAMP_DRIFT_SECS
}

fn map_state_error(error: IronhubLinkStateError) -> IronhubLinkError {
    match error {
        IronhubLinkStateError::NonceReplay | IronhubLinkStateError::ManifestReplay => {
            IronhubLinkError::Replay
        }
        IronhubLinkStateError::InvalidInput => IronhubLinkError::InvalidInput {
            reason: "invalid durable replay state input".to_string(),
        },
        IronhubLinkStateError::Unavailable => IronhubLinkError::Unavailable,
    }
}

fn map_install_error(error: IronHubCommandError) -> IronhubLinkError {
    match error {
        IronHubCommandError::InvalidInput { reason } | IronHubCommandError::Catalog { reason } => {
            IronhubLinkError::InvalidInput { reason }
        }
        IronHubCommandError::RuntimeHttpEgressUnavailable => IronhubLinkError::Install {
            reason: "runtime HTTP egress is unavailable".to_string(),
        },
        IronHubCommandError::Install { reason } => IronhubLinkError::Install { reason },
        IronHubCommandError::Product(_) => IronhubLinkError::Install {
            reason: "extension lifecycle failed".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use hmac::{Hmac, KeyInit, Mac};
    use ironclaw_filesystem::InMemoryBackend;
    use sha2::Sha256;

    use super::*;

    const SHARED_KEY: &str = "ihub_sk_LinkServiceTestKey0000000000000000000000000";

    fn shared_filesystem() -> Arc<dyn RootFilesystem> {
        Arc::new(InMemoryBackend::new())
    }

    fn shared_key() -> IronhubSharedKey {
        IronhubSharedKey::new(SHARED_KEY).expect("test shared key")
    }

    fn caller(user_id: &str) -> ProductSurfaceCaller {
        ProductSurfaceCaller::new(
            ironclaw_host_api::TenantId::new("tenant").expect("tenant"),
            ironclaw_host_api::UserId::new(user_id).expect("user"),
            Some(ironclaw_host_api::AgentId::new("agent").expect("agent")),
            None,
        )
    }

    fn sign(payload: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(SHARED_KEY.as_bytes()).expect("HMAC key");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn register_request(ts: u64) -> IronhubRegisterRequest {
        let mut request = IronhubRegisterRequest {
            uid: "user-1".to_string(),
            aid: "agent-1".to_string(),
            ts,
            nonce: "register-nonce".to_string(),
            sig: String::new(),
        };
        let challenge = RegisterChallenge {
            uid: &request.uid,
            aid: &request.aid,
            ts: request.ts,
            nonce: &request.nonce,
        };
        request.sig = sign(&challenge.payload());
        request
    }

    #[test]
    fn register_authentication_rejects_stale_timestamp_before_hmac() {
        let request = register_request(1);
        assert!(matches!(
            authenticate_register(&shared_key(), &request),
            Err(IronhubLinkError::StaleTimestamp)
        ));
    }

    #[test]
    fn register_authentication_rejects_bad_hmac() {
        let mut request = register_request(
            u64::try_from(Utc::now().timestamp()).expect("current positive timestamp"),
        );
        request.sig = "00".to_string();
        assert!(matches!(
            authenticate_register(&shared_key(), &request),
            Err(IronhubLinkError::InvalidSignature)
        ));
    }

    #[test]
    fn register_authentication_rejects_ambiguous_delimited_fields_before_hmac() {
        let mut request = register_request(
            u64::try_from(Utc::now().timestamp()).expect("current positive timestamp"),
        );
        request.uid = "user:alternate".to_string();

        assert!(matches!(
            authenticate_register(&shared_key(), &request),
            Err(IronhubLinkError::InvalidInput { .. })
        ));
    }

    #[tokio::test]
    async fn nonce_is_single_use_across_store_reconstruction() {
        let filesystem = shared_filesystem();
        let first = IronhubLinkStateStore::new(Arc::clone(&filesystem));
        let caller = caller("user-a");
        first
            .consume_install_nonce(&caller, "one-shot", Utc::now())
            .await
            .expect("first consumption");

        let reconstructed = IronhubLinkStateStore::new(filesystem);
        assert_eq!(
            reconstructed
                .consume_install_nonce(&caller, "one-shot", Utc::now())
                .await,
            Err(IronhubLinkStateError::NonceReplay)
        );
    }

    #[tokio::test]
    async fn nonce_consumption_is_scoped_to_authenticated_caller() {
        let store = IronhubLinkStateStore::new(shared_filesystem());
        store
            .consume_install_nonce(&caller("user-a"), "shared-nonce", Utc::now())
            .await
            .expect("first caller consumes nonce");
        store
            .consume_install_nonce(&caller("user-b"), "shared-nonce", Utc::now())
            .await
            .expect("another caller has an independent nonce namespace");
    }

    #[tokio::test]
    async fn private_manifest_key_ignores_rotating_url_token() {
        let filesystem = shared_filesystem();
        let first = IronhubLinkStateStore::new(Arc::clone(&filesystem));
        let generated_at = Utc::now();
        first
            .record_private_manifest("Catalog.Example.", "org/repo", generated_at, "digest-a")
            .await
            .expect("first manifest");

        let reconstructed = IronhubLinkStateStore::new(filesystem);
        assert_eq!(
            reconstructed
                .record_private_manifest("catalog.example", "org/repo", generated_at, "digest-a",)
                .await,
            Err(IronhubLinkStateError::ManifestReplay)
        );
    }

    #[tokio::test]
    async fn private_manifest_rejects_downgrade() {
        let store = IronhubLinkStateStore::new(shared_filesystem());
        let newer = Utc::now();
        store
            .record_private_manifest("catalog.example", "org/repo", newer, "digest-new")
            .await
            .expect("new manifest");

        assert_eq!(
            store
                .record_private_manifest(
                    "catalog.example",
                    "org/repo",
                    newer - chrono::Duration::seconds(1),
                    "digest-old",
                )
                .await,
            Err(IronhubLinkStateError::ManifestReplay)
        );
    }

    #[tokio::test]
    async fn public_manifest_replay_state_survives_store_reconstruction() {
        let filesystem = shared_filesystem();
        let first = IronhubLinkStateStore::new(Arc::clone(&filesystem));
        let manifest_url = "https://hub.ironclaw.com/api/catalog/manifest.json";
        let generated_at = Utc::now();
        first
            .record_public_manifest(manifest_url, generated_at, "digest-new")
            .await
            .expect("first manifest");

        let reconstructed = IronhubLinkStateStore::new(filesystem);
        reconstructed
            .record_public_manifest(manifest_url, generated_at, "digest-new")
            .await
            .expect("identical manifest remains idempotent");
        assert_eq!(
            reconstructed
                .record_public_manifest(
                    manifest_url,
                    generated_at - chrono::Duration::seconds(1),
                    "digest-old",
                )
                .await,
            Err(IronhubLinkStateError::ManifestReplay)
        );
        assert_eq!(
            reconstructed
                .record_public_manifest(manifest_url, generated_at, "digest-conflict")
                .await,
            Err(IronhubLinkStateError::ManifestReplay)
        );
    }
}
