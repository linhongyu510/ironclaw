use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;

use crate::attribution::PROVIDER_ATTRIBUTION_HEADER;
use crate::config::{MnesisConfig, MnesisLimits};
use crate::error::MnesisError;
use crate::url_check::{EndpointProfile, check_endpoint};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnesisLane {
    Knowledge,
    Memory,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MnesisRequest {
    pub lane: MnesisLane,
    pub operation: &'static str,
    pub body: Value,
    pub idempotent: bool,
    pub attribution: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MnesisResponse {
    pub status: u16,
    pub body: Value,
}

impl MnesisResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

#[derive(Debug, Error)]
#[error("Mnesis transport failure: {message}")]
pub struct MnesisTransportError {
    message: String,
    retryable: bool,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl MnesisTransportError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
            source: None,
        }
    }

    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
            source: None,
        }
    }

    pub fn with_source(
        message: impl Into<String>,
        retryable: bool,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            retryable,
            source: Some(Box::new(source)),
        }
    }

    pub fn is_retryable(&self) -> bool {
        self.retryable
    }
}

#[async_trait]
pub trait MnesisTransport: Send + Sync {
    async fn execute(&self, request: MnesisRequest)
    -> Result<MnesisResponse, MnesisTransportError>;
}

#[async_trait]
impl MnesisTransport for Arc<dyn MnesisTransport> {
    async fn execute(
        &self,
        request: MnesisRequest,
    ) -> Result<MnesisResponse, MnesisTransportError> {
        self.as_ref().execute(request).await
    }
}

pub struct MnesisHttpTransport {
    client: reqwest::Client,
    knowledge_endpoint: String,
    memory_endpoint: String,
    knowledge_authorization: reqwest::header::HeaderValue,
    memory_authorization: reqwest::header::HeaderValue,
    limits: MnesisLimits,
}

impl std::fmt::Debug for MnesisHttpTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MnesisHttpTransport")
            .field("knowledge_endpoint", &self.knowledge_endpoint)
            .field("memory_endpoint", &self.memory_endpoint)
            .finish_non_exhaustive()
    }
}

impl MnesisHttpTransport {
    pub fn new(
        config: &MnesisConfig,
        knowledge_bearer: &str,
        memory_bearer: &str,
    ) -> Result<Self, MnesisError> {
        check_endpoint(
            &config.knowledge_endpoint,
            config.profile,
            &config.host_allowlist,
        )?;
        check_endpoint(
            &config.memory_endpoint,
            config.profile,
            &config.host_allowlist,
        )?;

        let knowledge_authorization = authorization_header(knowledge_bearer)?;
        let memory_authorization = authorization_header(memory_bearer)?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/json, text/event-stream"),
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(config.limits.connect_timeout())
            .timeout(config.limits.request_timeout())
            .pool_max_idle_per_host(config.limits.max_idle_connections)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(config.profile == EndpointProfile::Production)
            .build()
            .map_err(|error| MnesisError::Client {
                reason: error.to_string(),
            })?;

        Ok(Self {
            client,
            knowledge_endpoint: config.knowledge_endpoint.trim_end_matches('/').to_string(),
            memory_endpoint: config.memory_endpoint.trim_end_matches('/').to_string(),
            knowledge_authorization,
            memory_authorization,
            limits: config.limits.clone(),
        })
    }

    fn endpoint(&self, lane: MnesisLane) -> &str {
        match lane {
            MnesisLane::Knowledge => &self.knowledge_endpoint,
            MnesisLane::Memory => &self.memory_endpoint,
        }
    }

    fn authorization(&self, lane: MnesisLane) -> &reqwest::header::HeaderValue {
        match lane {
            MnesisLane::Knowledge => &self.knowledge_authorization,
            MnesisLane::Memory => &self.memory_authorization,
        }
    }

    async fn bounded_body(
        &self,
        mut response: reqwest::Response,
        operation: &'static str,
    ) -> Result<Value, MnesisTransportError> {
        let event_stream = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case("text/event-stream")
            })
            .unwrap_or(false);

        let limit = self.limits.max_response_bytes;
        let mut collected: Vec<u8> = Vec::new();
        loop {
            let chunk = response.chunk().await.map_err(|error| {
                MnesisTransportError::with_source("reading the Mnesis body failed", true, error)
            })?;
            let Some(chunk) = chunk else { break };
            if collected.len() + chunk.len() > limit {
                return Err(MnesisTransportError::new(format!(
                    "response exceeded the {limit}-byte ceiling for {operation}"
                )));
            }
            collected.extend_from_slice(&chunk);
        }

        if collected.is_empty() {
            return Ok(Value::Null);
        }

        let payload = if event_stream {
            let text = std::str::from_utf8(&collected).map_err(|error| {
                MnesisTransportError::with_source(
                    format!("the Mnesis event stream was not UTF-8 for {operation}"),
                    false,
                    error,
                )
            })?;
            match last_event_payload(text) {
                Some(payload) => payload.into_bytes(),
                None => return Ok(Value::Null),
            }
        } else {
            collected
        };

        serde_json::from_slice(&payload).map_err(|error| {
            MnesisTransportError::with_source(
                format!("decoding the Mnesis body failed for {operation}"),
                false,
                error,
            )
        })
    }
}

fn authorization_header(bearer: &str) -> Result<reqwest::header::HeaderValue, MnesisError> {
    let mut value =
        reqwest::header::HeaderValue::from_str(&format!("Bearer {bearer}")).map_err(|error| {
            MnesisError::Client {
                reason: format!("credential is not a valid Authorization header value: {error}"),
            }
        })?;
    value.set_sensitive(true);
    Ok(value)
}

fn last_event_payload(text: &str) -> Option<String> {
    let mut events: Vec<String> = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                events.push(current.join("\n"));
                current.clear();
            }
            continue;
        }
        if let Some(data) = line.strip_prefix("data:") {
            current.push(data.strip_prefix(' ').unwrap_or(data));
        }
    }
    if !current.is_empty() {
        events.push(current.join("\n"));
    }
    events
        .into_iter()
        .rev()
        .find(|event| !event.trim().is_empty())
}

#[async_trait]
impl MnesisTransport for MnesisHttpTransport {
    async fn execute(
        &self,
        request: MnesisRequest,
    ) -> Result<MnesisResponse, MnesisTransportError> {
        let endpoint = self.endpoint(request.lane);
        let started = std::time::Instant::now();
        let total_deadline = self.limits.total_deadline();
        let max_attempts = if request.idempotent {
            self.limits.max_retries.saturating_add(1)
        } else {
            1
        };

        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut builder = self.client.post(endpoint).header(
                reqwest::header::AUTHORIZATION,
                self.authorization(request.lane).clone(),
            );
            if let Some(attribution) = &request.attribution {
                builder = builder.header(PROVIDER_ATTRIBUTION_HEADER, attribution);
            }
            let outcome = builder.json(&request.body).send().await.map_err(|error| {
                let retryable = error.is_timeout() || error.is_connect() || error.is_request();
                MnesisTransportError::with_source("the Mnesis request failed", retryable, error)
            });

            let error = match outcome {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let body = self.bounded_body(response, request.operation).await?;
                    tracing::debug!(
                        target: "ironclaw_memory_mnesis",
                        status,
                        operation = request.operation,
                        "Mnesis response"
                    );
                    return Ok(MnesisResponse { status, body });
                }
                Err(error) => error,
            };

            let exhausted = attempt >= max_attempts;
            let out_of_time = started.elapsed() >= total_deadline;
            if !error.is_retryable() || exhausted || out_of_time {
                return Err(error);
            }
            let backoff = self.limits.retry_backoff().saturating_mul(attempt);
            let remaining = total_deadline.saturating_sub(started.elapsed());
            if backoff >= remaining {
                return Err(error);
            }
            tokio::time::sleep(backoff).await;
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
mod mock {
    use std::sync::Mutex;

    use super::*;

    pub type MnesisMockHandler =
        Box<dyn Fn(&MnesisRequest) -> Option<MnesisResponse> + Send + Sync>;

    pub struct MockMnesisTransport {
        recorded: Mutex<Vec<MnesisRequest>>,
        handler: MnesisMockHandler,
    }

    impl MockMnesisTransport {
        pub fn new(handler: MnesisMockHandler) -> Self {
            Self {
                recorded: Mutex::new(Vec::new()),
                handler,
            }
        }

        pub fn always_ok(body: Value) -> Self {
            Self::new(Box::new(move |_request| {
                Some(MnesisResponse {
                    status: 200,
                    body: body.clone(),
                })
            }))
        }

        pub fn recorded(&self) -> Vec<MnesisRequest> {
            match self.recorded.lock() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }

        pub fn count_operation(&self, operation: &str) -> usize {
            self.recorded()
                .iter()
                .filter(|request| request.operation == operation)
                .count()
        }
    }

    #[async_trait]
    impl MnesisTransport for MockMnesisTransport {
        async fn execute(
            &self,
            request: MnesisRequest,
        ) -> Result<MnesisResponse, MnesisTransportError> {
            let response = (self.handler)(&request).unwrap_or(MnesisResponse {
                status: 404,
                body: Value::Null,
            });
            if let Ok(mut guard) = self.recorded.lock() {
                guard.push(request);
            }
            Ok(response)
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
pub use mock::{MnesisMockHandler, MockMnesisTransport};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretHandle;

    fn config(profile: EndpointProfile, endpoint: &str) -> MnesisConfig {
        MnesisConfig {
            knowledge_endpoint: format!("{endpoint}/rar/mcp"),
            memory_endpoint: format!("{endpoint}/memory/mcp"),
            knowledge_credential: SecretHandle::new("services/rar-clients").unwrap(),
            memory_credential: SecretHandle::new("services/memory-clients").unwrap(),
            host_allowlist: Vec::new(),
            profile,
            limits: MnesisLimits::default(),
        }
    }

    #[test]
    fn builds_for_an_https_endpoint() {
        let transport = MnesisHttpTransport::new(
            &config(EndpointProfile::Production, "https://mnesis.example.com"),
            "knowledge-token",
            "memory-token",
        )
        .unwrap();
        assert_eq!(
            transport.knowledge_endpoint,
            "https://mnesis.example.com/rar/mcp"
        );
    }

    #[test]
    fn each_lane_carries_its_own_credential() {
        let transport = MnesisHttpTransport::new(
            &config(EndpointProfile::Production, "https://mnesis.example.com"),
            "knowledge-token",
            "memory-token",
        )
        .unwrap();
        assert_ne!(
            transport.authorization(MnesisLane::Knowledge),
            transport.authorization(MnesisLane::Memory)
        );
        assert!(
            transport
                .authorization(MnesisLane::Knowledge)
                .is_sensitive()
        );
        assert!(transport.authorization(MnesisLane::Memory).is_sensitive());
    }

    #[test]
    fn refuses_a_blocked_endpoint_at_construction() {
        let error = MnesisHttpTransport::new(
            &config(EndpointProfile::Production, "https://169.254.169.254"),
            "knowledge-token",
            "memory-token",
        )
        .unwrap_err();
        assert!(matches!(error, MnesisError::InvalidEndpoint { .. }));
    }

    #[test]
    fn refuses_remote_plain_http() {
        let error = MnesisHttpTransport::new(
            &config(EndpointProfile::Production, "http://mnesis.example.com"),
            "knowledge-token",
            "memory-token",
        )
        .unwrap_err();
        assert!(matches!(error, MnesisError::InvalidEndpoint { .. }));
    }

    #[test]
    fn refuses_a_credential_that_is_not_a_header_value() {
        for (knowledge, memory) in [("bad\nvalue", "ok"), ("ok", "bad\nvalue")] {
            let error = MnesisHttpTransport::new(
                &config(EndpointProfile::Production, "https://mnesis.example.com"),
                knowledge,
                memory,
            )
            .unwrap_err();
            assert!(matches!(error, MnesisError::Client { .. }));
            assert!(!error.to_string().contains("bad"));
        }
    }

    #[test]
    fn debug_never_renders_the_client_or_credential() {
        let transport = MnesisHttpTransport::new(
            &config(EndpointProfile::Production, "https://mnesis.example.com"),
            "super-secret-knowledge",
            "super-secret-memory",
        )
        .unwrap();
        let rendered = format!("{transport:?}");
        assert!(!rendered.contains("super-secret-knowledge"));
        assert!(!rendered.contains("super-secret-memory"));
        assert!(!rendered.contains("Bearer"));
    }

    #[tokio::test]
    async fn the_mock_records_requests_and_defaults_to_not_found() {
        let mock = MockMnesisTransport::new(Box::new(|request| {
            (request.operation == "knowledge_search").then_some(MnesisResponse {
                status: 200,
                body: Value::Null,
            })
        }));
        let hit = mock
            .execute(MnesisRequest {
                lane: MnesisLane::Knowledge,
                operation: "knowledge_search",
                body: Value::Null,
                idempotent: true,
                attribution: None,
            })
            .await
            .unwrap();
        assert_eq!(hit.status, 200);

        let miss = mock
            .execute(MnesisRequest {
                lane: MnesisLane::Memory,
                operation: "record_interaction",
                body: Value::Null,
                idempotent: false,
                attribution: None,
            })
            .await
            .unwrap();
        assert_eq!(miss.status, 404);
        assert_eq!(mock.count_operation("knowledge_search"), 1);
        assert_eq!(mock.recorded().len(), 2);
    }

    #[test]
    fn extracts_the_payload_from_an_event_stream_frame() {
        let frame = "event: message\ndata: {\"result\":{\"protocolVersion\":\"2025-06-18\"}}\n\n";
        let payload = last_event_payload(frame).unwrap();
        let value: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["result"]["protocolVersion"], "2025-06-18");
    }

    #[test]
    fn takes_the_last_event_when_a_stream_carries_several() {
        let frame = "data: {\"seq\":1}\n\ndata: {\"seq\":2}\n\n";
        let payload = last_event_payload(frame).unwrap();
        assert_eq!(payload, "{\"seq\":2}");
    }

    #[test]
    fn joins_multi_line_data_fields_and_ignores_frames_without_data() {
        let frame = "data: {\"a\":\ndata: 1}\n\n";
        assert_eq!(last_event_payload(frame).unwrap(), "{\"a\":\n1}");
        assert!(last_event_payload("event: ping\n\n").is_none());
        assert!(last_event_payload("").is_none());
    }

    #[test]
    fn transport_errors_carry_their_retry_disposition() {
        assert!(MnesisTransportError::retryable("timeout").is_retryable());
        assert!(!MnesisTransportError::new("ceiling breached").is_retryable());
    }
}
