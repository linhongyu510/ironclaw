use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use ironclaw_extensions::ExtensionInstallationStorePort;
use ironclaw_host_api::{
    CapabilityId, ExtensionId, NetworkPolicy, RuntimeHttpEgress, RuntimeHttpEgressError,
    RuntimeHttpEgressRequest, RuntimeHttpEgressResponse, RuntimeKind, VirtualPath,
};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use super::catalog::{classify_gate_and_digest, sha256_hex, verify_signed_manifest_with_keys};
use super::model::{
    IronHubArtifact, IronHubCommand, IronHubEntryKind, IronHubInstallOptions, IronHubManifest,
    IronHubPhase, IronHubProvenance, IronHubSkillEntry,
};
use super::service::{IronHubService, configure_test_catalog};

#[test]
fn signed_catalog_verification_accepts_only_the_selected_key() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let manifest = br#"{"version":"1"}"#;
    let signature = signing_key.sign(manifest);
    let envelope = serde_json::json!({
        "v": 1,
        "key_id": "test-key",
        "manifest_b64": URL_SAFE_NO_PAD.encode(manifest),
        "sig": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
    .to_string();
    let verify_key = hex::encode(signing_key.verifying_key().to_bytes());

    let verified =
        verify_signed_manifest_with_keys(envelope.as_bytes(), &[("test-key", &verify_key)])
            .expect("selected key verifies the envelope");
    assert_eq!(verified, manifest);
    assert!(
        verify_signed_manifest_with_keys(envelope.as_bytes(), &[("other-key", &verify_key)])
            .is_err()
    );
}

#[test]
fn unverified_entry_requires_non_model_operator_acknowledgement() {
    let manifest = IronHubManifest {
        version: "1".to_string(),
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        release_tag: "test".to_string(),
        repo: "nearai/ironhub".to_string(),
        tools: Vec::new(),
        skills: vec![IronHubSkillEntry {
            name: "community-skill".to_string(),
            trunk: String::new(),
            version: "0.1.0".to_string(),
            description: String::new(),
            provenance: IronHubProvenance::New,
            skill_md: IronHubArtifact {
                url: "https://hub.ironclaw.com/community-skill/SKILL.md".to_string(),
                size_bytes: 10,
                sha256: "a".repeat(64),
            },
        }],
    };

    let denied = classify_gate_and_digest(
        &manifest,
        "community-skill",
        Some(IronHubEntryKind::Skill),
        &IronHubInstallOptions::default(),
    )
    .expect_err("unverified content requires acknowledgement");
    assert!(denied.to_string().contains("UNVERIFIED community"));

    classify_gate_and_digest(
        &manifest,
        "community-skill",
        Some(IronHubEntryKind::Skill),
        &IronHubInstallOptions {
            acknowledge_unverified: true,
            ..IronHubInstallOptions::default()
        },
    )
    .expect("operator acknowledgement permits install");
}

#[tokio::test]
async fn verified_tool_and_skill_install_through_real_managers() {
    let services =
        crate::lifecycle_test_support::build_lifecycle_test_services("ironhub-owner", None, false)
            .await;
    let scope = crate::lifecycle_test_support::webui_gate_resource_scope_for_owner("ironhub-owner");
    let manifest_url = "https://hub.ironclaw.com/tests/native-install/manifest.json";
    let tool_url = "https://hub.ironclaw.com/tests/native-install/tool.wasm";
    let capabilities_url = "https://hub.ironclaw.com/tests/native-install/capabilities.json";
    let skill_url = "https://hub.ironclaw.com/tests/native-install/SKILL.md";
    let tool_bytes = include_bytes!(
        "../../../ironclaw_first_party_extensions/assets/github/wasm/github_tool.wasm"
    )
    .to_vec();
    let capabilities_bytes = br#"{"capabilities":[]}"#.to_vec();
    let skill_bytes =
        b"---\nname: installed-skill\ndescription: Installed by IronHub\n---\n# Installed\n"
            .to_vec();
    let manifest = signed_manifest(
        mixed_manifest_json(MixedManifestFixture {
            tool_url,
            tool_size: tool_bytes.len(),
            tool_sha: &sha256_hex(&tool_bytes),
            capabilities_url,
            capabilities_size: capabilities_bytes.len(),
            capabilities_sha: &sha256_hex(&capabilities_bytes),
            skill_url,
            skill_size: skill_bytes.len(),
            skill_sha: &sha256_hex(&skill_bytes),
        }),
        &test_signing_key(),
    );
    let egress = Arc::new(RecordingEgress::new([
        (manifest_url, manifest),
        (tool_url, tool_bytes),
        (capabilities_url, capabilities_bytes),
        (skill_url, skill_bytes),
    ]));
    let service = configure_test_catalog(
        IronHubService::new_with_runtime_egress(
            Arc::clone(&services.skill_management),
            Arc::clone(&services.extension_management),
            egress.clone(),
            scope.clone(),
            CapabilityId::new(super::IRONHUB_INSTALL_CAPABILITY_ID).expect("capability id"),
        ),
        manifest_url,
        test_manifest_verify_keys(),
    );

    let tool = service
        .execute(IronHubCommand::Install {
            name: "installed-tool".to_string(),
            options: IronHubInstallOptions {
                kind: Some(IronHubEntryKind::Tool),
                ..IronHubInstallOptions::default()
            },
        })
        .await
        .expect("verified tool installs");
    assert_eq!(tool.phase, IronHubPhase::Installed);
    let manifest_path =
        VirtualPath::new("/system/extensions/installed-tool/manifest.toml").expect("path");
    let materialized = services
        .filesystem
        .read_file(&manifest_path)
        .await
        .expect("tool manifest materialized");
    assert!(
        String::from_utf8(materialized)
            .expect("manifest utf8")
            .contains("reborn.extension_manifest.v3")
    );
    assert!(
        services
            .extension_management
            .installation_store_handle()
            .get_installation(
                &ironclaw_extensions::ExtensionInstallationId::new("installed-tool")
                    .expect("installation id")
            )
            .await
            .expect("installation read")
            .is_some(),
        "extension manager persisted the installation record"
    );
    assert!(
        services
            .extension_management
            .active_extensions_for_test()
            .snapshot()
            .get_extension(&ExtensionId::new("installed-tool").expect("extension id"))
            .is_some(),
        "extension manager activated and published the installed tool"
    );

    let skill = service
        .execute(IronHubCommand::Install {
            name: "installed-skill".to_string(),
            options: IronHubInstallOptions {
                kind: Some(IronHubEntryKind::Skill),
                ..IronHubInstallOptions::default()
            },
        })
        .await
        .expect("verified skill installs");
    assert_eq!(skill.phase, IronHubPhase::Installed);
    let installed_skill = services
        .skill_management
        .read_content_for_scope(scope, "installed-skill")
        .await
        .expect("skill manager reads installed skill");
    assert!(installed_skill.content.contains("# Installed"));

    let requests = egress.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests.iter().all(|request| {
        request.runtime == RuntimeKind::FirstParty
            && request.policy.deny_private_ip_ranges
            && request.capability_id.as_str() == super::IRONHUB_INSTALL_CAPABILITY_ID
    }));
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7_u8; 32])
}

fn test_manifest_verify_keys() -> &'static [(&'static str, &'static str)] {
    let verify_key = hex::encode(test_signing_key().verifying_key().to_bytes());
    let verify_key = Box::leak(verify_key.into_boxed_str());
    Box::leak(vec![("ironhub-test-key", verify_key as &str)].into_boxed_slice())
}

fn signed_manifest(manifest_json: String, signing_key: &SigningKey) -> Vec<u8> {
    let signature = signing_key.sign(manifest_json.as_bytes());
    serde_json::json!({
        "v": 1,
        "key_id": "ironhub-test-key",
        "manifest_b64": URL_SAFE_NO_PAD.encode(manifest_json.as_bytes()),
        "sig": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
    .to_string()
    .into_bytes()
}

struct MixedManifestFixture<'a> {
    tool_url: &'a str,
    tool_size: usize,
    tool_sha: &'a str,
    capabilities_url: &'a str,
    capabilities_size: usize,
    capabilities_sha: &'a str,
    skill_url: &'a str,
    skill_size: usize,
    skill_sha: &'a str,
}

fn mixed_manifest_json(fixture: MixedManifestFixture<'_>) -> String {
    let MixedManifestFixture {
        tool_url,
        tool_size,
        tool_sha,
        capabilities_url,
        capabilities_size,
        capabilities_sha,
        skill_url,
        skill_size,
        skill_sha,
    } = fixture;
    serde_json::json!({
        "version": "1",
        "generated_at": "2026-01-02T00:00:00Z",
        "release_tag": "test",
        "repo": "nearai/ironhub",
        "tools": [{
            "name": "installed-tool",
            "crate_name": "installed-tool",
            "version": "0.1.0",
            "description": "test tool",
            "provenance": "official",
            "wasm": {
                "url": tool_url,
                "size_bytes": tool_size,
                "sha256": tool_sha
            },
            "capabilities": {
                "url": capabilities_url,
                "size_bytes": capabilities_size,
                "sha256": capabilities_sha
            }
        }],
        "skills": [{
            "name": "installed-skill",
            "version": "0.1.0",
            "description": "test skill",
            "provenance": "official",
            "skill_md": {
                "url": skill_url,
                "size_bytes": skill_size,
                "sha256": skill_sha
            }
        }]
    })
    .to_string()
}

#[derive(Clone)]
struct RecordedRequest {
    runtime: RuntimeKind,
    capability_id: CapabilityId,
    policy: NetworkPolicy,
}

struct RecordingEgress {
    responses: Mutex<HashMap<String, VecDeque<Vec<u8>>>>,
    requests: Mutex<Vec<RecordedRequest>>,
}

impl RecordingEgress {
    fn new<const N: usize>(responses: [(&str, Vec<u8>); N]) -> Self {
        Self {
            responses: Mutex::new(
                responses
                    .into_iter()
                    .map(|(url, body)| (url.to_string(), VecDeque::from([body])))
                    .collect(),
            ),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("requests lock").clone()
    }
}

#[async_trait::async_trait]
impl RuntimeHttpEgress for RecordingEgress {
    async fn execute(
        &self,
        request: RuntimeHttpEgressRequest,
    ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
        self.requests
            .lock()
            .expect("requests lock")
            .push(RecordedRequest {
                runtime: request.runtime,
                capability_id: request.capability_id.clone(),
                policy: request.network_policy.clone(),
            });
        let body = self
            .responses
            .lock()
            .expect("responses lock")
            .get_mut(&request.url)
            .and_then(VecDeque::pop_front)
            .ok_or_else(|| RuntimeHttpEgressError::Request {
                reason: format!("unexpected test URL {}", request.url),
                request_bytes: 0,
                response_bytes: 0,
            })?;
        Ok(RuntimeHttpEgressResponse {
            status: 200,
            headers: Vec::new(),
            body,
            saved_body: None,
            request_bytes: 0,
            response_bytes: 0,
            redaction_applied: false,
        })
    }
}
