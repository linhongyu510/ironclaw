use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use ironclaw_host_api::{
    action::{NetworkMethod, NetworkPolicy, NetworkScheme, NetworkTargetPattern},
    http::{
        RuntimeCredentialSource, RuntimeCredentialTarget, RuntimeHttpEgress,
        RuntimeHttpEgressError, RuntimeHttpEgressRequest, RuntimeHttpEgressResponse,
    },
    ids::{CapabilityId, ExtensionId, InvocationId, SecretHandle, TenantId, UserId},
    resource::ResourceScope,
    runtime::RuntimeKind,
};
use ironclaw_network::{
    NetworkHttpEgress, NetworkHttpError, NetworkHttpRequest, NetworkHttpResponse, NetworkUsage,
};
use ironclaw_secrets::{CredentialPathPolicy, CredentialTargetPolicy, SecretMaterial, SecretStore};

use super::*;
use crate::sandbox_process::credential_firewall::{
    SandboxCredentialConnectionIdentity, StagedCredentialObligation,
    StagedCredentialObligationSource,
};
use crate::{
    HostHttpEgressService, http_body::UnsupportedRuntimeHttpBodyStore,
    obligations::NetworkObligationPolicyStore,
};

const HOST: &str = "api.example.com";
const REAL_SECRET: &str = "real-secret-must-remain-host-side";

#[derive(Default)]
struct RecordingHostEgress {
    requests: Mutex<Vec<RuntimeHttpEgressRequest>>,
}

impl RecordingHostEgress {
    fn take_requests(&self) -> Vec<RuntimeHttpEgressRequest> {
        std::mem::take(
            &mut *self
                .requests
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
        )
    }
}

#[async_trait]
impl RuntimeHttpEgress for RecordingHostEgress {
    async fn execute(
        &self,
        request: RuntimeHttpEgressRequest,
    ) -> Result<RuntimeHttpEgressResponse, RuntimeHttpEgressError> {
        self.requests
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(request);
        Ok(RuntimeHttpEgressResponse {
            status: 200,
            headers: vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("content-length".to_string(), "999".to_string()),
                ("connection".to_string(), "keep-alive".to_string()),
            ],
            body: b"sanitized-response".to_vec(),
            saved_body: None,
            request_bytes: 1,
            response_bytes: 18,
            redaction_applied: true,
        })
    }
}

#[derive(Default)]
struct RecordingNetworkEgress {
    requests: Mutex<Vec<NetworkHttpRequest>>,
}

#[async_trait]
impl NetworkHttpEgress for RecordingNetworkEgress {
    async fn execute(
        &self,
        request: NetworkHttpRequest,
    ) -> Result<NetworkHttpResponse, NetworkHttpError> {
        self.requests
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(request);
        Ok(NetworkHttpResponse {
            status: 200,
            headers: vec![
                ("content-type".to_string(), "text/plain".to_string()),
                (
                    "set-cookie".to_string(),
                    "session=origin-secret".to_string(),
                ),
            ],
            body: b"host-sanitized".to_vec(),
            usage: NetworkUsage {
                request_bytes: 1,
                response_bytes: 14,
                resolved_ip: None,
            },
        })
    }
}

struct Fixture {
    runtime: SandboxCredentialRuntime,
    adapter: SandboxProxyHttpAdapter,
    service: Arc<RecordingHostEgress>,
    scope: ResourceScope,
    capability_id: CapabilityId,
    provider: ExtensionId,
    token: String,
}

fn fixture(attach: bool) -> Fixture {
    let tenant_id = TenantId::new("tenant-a").expect("valid tenant");
    let user_id = UserId::new("user-a").expect("valid user");
    let scope = ResourceScope {
        tenant_id,
        user_id,
        agent_id: None,
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    };
    let capability_id = CapabilityId::new("builtin.shell").expect("valid capability");
    let provider = ExtensionId::new("example-basic").expect("valid provider");
    let secret_handle = SecretHandle::new("example-password").expect("valid secret handle");
    let runtime = SandboxCredentialRuntime::new();
    let token = runtime
        .placeholder_for(&scope, &provider)
        .expect("placeholder mints")
        .as_str()
        .to_string();
    runtime
        .secret_injection_store()
        .insert(
            &scope,
            &capability_id,
            &secret_handle,
            SecretMaterial::from(REAL_SECRET),
        )
        .expect("secret stages");
    runtime.open_static_window(
        &scope,
        &capability_id,
        vec![super::super::SandboxStaticCredentialGrant {
            provider_or_extension_id: provider.clone(),
            secret_handle,
            allowed_targets: vec![target_policy()],
        }],
        Duration::from_secs(60),
    );
    let service = Arc::new(RecordingHostEgress::default());
    if attach {
        let host_egress: Arc<dyn RuntimeHttpEgress> = service.clone();
        runtime
            .attach_http_egress(host_egress)
            .map_err(|_| "host egress was already attached")
            .expect("first attachment succeeds");
    }
    let adapter = SandboxProxyHttpAdapter::new(runtime.clone());
    Fixture {
        runtime,
        adapter,
        service,
        scope,
        capability_id,
        provider,
        token,
    }
}

fn target_policy() -> CredentialTargetPolicy {
    CredentialTargetPolicy {
        scheme: "https".to_string(),
        host: HOST.to_string(),
        port: None,
        path: CredentialPathPolicy::Prefix("/v1".to_string()),
        methods: vec![NetworkMethod::Get, NetworkMethod::Post],
    }
}

fn request(scheme: &str, token: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST /v1/items HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: {scheme} {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

fn identity(fixture: &Fixture) -> Option<SandboxCredentialConnectionIdentity<'_>> {
    Some(SandboxCredentialConnectionIdentity {
        tenant_id: &fixture.scope.tenant_id,
        user_id: &fixture.scope.user_id,
        invocation_id: fixture.scope.invocation_id,
    })
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

#[tokio::test]
async fn basic_maps_exact_authority_and_invokes_attached_host_service_without_secret_bytes() {
    let fixture = fixture(true);
    let body = br#"{"name":"demo"}"#;
    let serialized = fixture
        .adapter
        .execute(
            &request("Basic", &fixture.token, body),
            HOST,
            identity(&fixture),
            deadline(),
        )
        .await
        .expect("authorized request executes");

    let requests = fixture.service.take_requests();
    assert_eq!(
        requests.len(),
        1,
        "the attached host service is invoked once"
    );
    let outbound = &requests[0];
    assert_eq!(outbound.runtime, RuntimeKind::Sandbox);
    assert_eq!(outbound.scope, fixture.scope);
    assert_eq!(outbound.capability_id, fixture.capability_id);
    assert_eq!(outbound.method, NetworkMethod::Post);
    assert_eq!(outbound.url, format!("https://{HOST}/v1/items"));
    assert_eq!(outbound.body, body);
    assert_eq!(outbound.network_policy, NetworkPolicy::default());
    assert!(
        outbound
            .headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("authorization")
                && !name.eq_ignore_ascii_case("host")
                && !name.eq_ignore_ascii_case("content-length")
                && !name.eq_ignore_ascii_case("connection"))
    );
    assert_eq!(outbound.credential_injections.len(), 1);
    let injection = &outbound.credential_injections[0];
    assert_eq!(
        injection.source,
        RuntimeCredentialSource::StagedObligation {
            capability_id: fixture.capability_id.clone(),
        }
    );
    assert_eq!(
        injection.target,
        RuntimeCredentialTarget::Header {
            name: "Authorization".to_string(),
            prefix: Some("Basic ".to_string()),
        }
    );
    assert!(injection.required);

    let pre_host_bytes = format!("{}{:?}", outbound.url, outbound.headers);
    assert!(!pre_host_bytes.contains(REAL_SECRET));
    assert!(!pre_host_bytes.contains(&fixture.token));
    assert!(String::from_utf8_lossy(&serialized).starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(
        serialized
            .windows(b"Connection: close".len())
            .any(|w| w == b"Connection: close")
    );
    assert!(
        serialized
            .windows(b"Content-Length: 18".len())
            .any(|w| w == b"Content-Length: 18")
    );
    assert!(
        !serialized
            .windows(b"Content-Length: 999".len())
            .any(|w| w == b"Content-Length: 999")
    );
    assert!(serialized.ends_with(b"sanitized-response"));
}

#[tokio::test]
async fn bearer_maps_to_host_owned_authorization_injection() {
    let fixture = fixture(true);
    fixture
        .adapter
        .execute(
            &request("Bearer", &fixture.token, b""),
            HOST,
            identity(&fixture),
            deadline(),
        )
        .await
        .expect("authorized request executes");

    let requests = fixture.service.take_requests();
    let injection = &requests[0].credential_injections[0];
    assert_eq!(
        injection.target,
        RuntimeCredentialTarget::Header {
            name: "Authorization".to_string(),
            prefix: Some("Bearer ".to_string()),
        }
    );
}

#[tokio::test]
async fn canonical_host_service_materializes_the_staged_secret_after_adapter_translation() {
    let fixture = fixture(false);
    let network = Arc::new(RecordingNetworkEgress::default());
    let policy_store = Arc::new(NetworkObligationPolicyStore::new());
    policy_store.insert(
        &fixture.scope,
        &fixture.capability_id,
        NetworkPolicy {
            allowed_targets: vec![NetworkTargetPattern {
                scheme: Some(NetworkScheme::Https),
                host_pattern: HOST.to_string(),
                port: None,
            }],
            deny_private_ip_ranges: true,
            max_egress_bytes: Some(1024 * 1024),
        },
    );
    let host_service = HostHttpEgressService::production(
        network.clone(),
        SecretStore::ephemeral(),
        policy_store,
        fixture.runtime.secret_injection_store(),
        Arc::new(UnsupportedRuntimeHttpBodyStore),
    );
    fixture
        .runtime
        .attach_http_egress(Arc::new(host_service))
        .map_err(|_| "host egress was already attached")
        .expect("first attachment succeeds");

    let response = fixture
        .adapter
        .execute(
            &request("Bearer", &fixture.token, b""),
            HOST,
            identity(&fixture),
            deadline(),
        )
        .await
        .expect("canonical host egress executes");

    let network_requests = network
        .requests
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    assert_eq!(network_requests.len(), 1);
    let authorization = network_requests[0]
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_str());
    assert_eq!(
        authorization,
        Some("Bearer real-secret-must-remain-host-side")
    );
    assert!(
        String::from_utf8_lossy(&response).ends_with("host-sanitized"),
        "the adapter serializes the canonical host service's sanitized response"
    );
    assert!(
        !String::from_utf8_lossy(&response)
            .to_ascii_lowercase()
            .contains("set-cookie"),
        "the canonical host service removes sensitive response headers before serialization"
    );
}

#[tokio::test]
async fn overlapping_live_windows_fail_closed_before_host_service_invocation() {
    let fixture = fixture(true);
    let second_scope = ResourceScope {
        invocation_id: fixture.scope.invocation_id,
        ..fixture.scope.clone()
    };
    let second_capability = CapabilityId::new("builtin.shell.second").expect("valid capability");
    let second_handle = SecretHandle::new("second-password").expect("valid handle");
    let _second_lease = fixture.runtime.firewall.stage(
        &fixture.scope.tenant_id,
        &fixture.scope.user_id,
        StagedCredentialObligation::new(
            StagedCredentialObligationSource {
                scope: second_scope,
                capability_id: second_capability,
                provider_or_extension_id: fixture.provider.clone(),
                secret_handle: second_handle,
            },
            vec![target_policy()],
            Duration::from_secs(60),
        ),
    );

    let error = fixture
        .adapter
        .execute(
            &request("Bearer", &fixture.token, b""),
            HOST,
            identity(&fixture),
            deadline(),
        )
        .await
        .expect_err("ambiguous authority must fail closed");

    assert!(matches!(
        error,
        SandboxProxyHttpAdapterError::Authorization(
            StaticCredentialAuthorizationError::AmbiguousAuthority
        )
    ));
    assert!(fixture.service.take_requests().is_empty());
}

#[tokio::test]
async fn missing_live_window_fails_closed_before_host_service_invocation() {
    let fixture = fixture(true);
    fixture
        .runtime
        .close_static_window(&fixture.scope, &fixture.capability_id);

    let error = fixture
        .adapter
        .execute(
            &request("Bearer", &fixture.token, b""),
            HOST,
            identity(&fixture),
            deadline(),
        )
        .await
        .expect_err("missing authority must fail closed");

    assert!(matches!(
        error,
        SandboxProxyHttpAdapterError::Authorization(
            StaticCredentialAuthorizationError::NoAuthority
        )
    ));
    assert!(fixture.service.take_requests().is_empty());
}

#[tokio::test]
async fn unbound_runtime_fails_closed_after_authority_without_invoking_service() {
    let fixture = fixture(false);
    let error = fixture
        .adapter
        .execute(
            &request("Bearer", &fixture.token, b""),
            HOST,
            identity(&fixture),
            deadline(),
        )
        .await
        .expect_err("an unattached runtime must fail closed");

    assert!(matches!(
        error,
        SandboxProxyHttpAdapterError::HostEgressUnbound
    ));
    assert!(fixture.service.take_requests().is_empty());
}

#[test]
fn runtime_rejects_double_attachment_and_preserves_the_first_service() {
    let runtime = SandboxCredentialRuntime::new();
    let runtime_clone = runtime.clone();
    let first = Arc::new(RecordingHostEgress::default());
    let second = Arc::new(RecordingHostEgress::default());
    let first_dyn: Arc<dyn RuntimeHttpEgress> = first;
    let second_dyn: Arc<dyn RuntimeHttpEgress> = second.clone();

    assert!(runtime.attach_http_egress(first_dyn).is_ok());
    let rejected = runtime_clone
        .attach_http_egress(second_dyn)
        .expect_err("second attachment is rejected");
    assert!(Arc::ptr_eq(
        &rejected,
        &(second as Arc<dyn RuntimeHttpEgress>)
    ));
}

#[test]
fn ambiguous_or_unsupported_http_framing_is_rejected_before_dispatch() {
    let fixture = fixture(true);
    let duplicate_length = format!(
        "POST /v1/items HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        fixture.token
    );
    assert!(matches!(
        ParsedCredentialedRequest::parse(duplicate_length.as_bytes(), HOST),
        Err(SandboxProxyHttpAdapterError::Malformed(_))
    ));

    let chunked = format!(
        "POST /v1/items HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {}\r\nTransfer-Encoding: chunked\r\n\r\n",
        fixture.token
    );
    assert!(matches!(
        ParsedCredentialedRequest::parse(chunked.as_bytes(), HOST),
        Err(SandboxProxyHttpAdapterError::Malformed(_))
    ));

    let oversized = format!(
        "POST /v1/items HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n",
        fixture.token,
        MAX_CREDENTIALED_REQUEST_BODY_BYTES + 1
    );
    assert!(matches!(
        ParsedCredentialedRequest::parse(oversized.as_bytes(), HOST),
        Err(SandboxProxyHttpAdapterError::BodyTooLarge)
    ));
    assert!(fixture.service.take_requests().is_empty());
}
