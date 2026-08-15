use async_trait::async_trait;
use ironclaw_memory::{
    MemoryInvocation, MemoryService, MemoryServiceContextRequest, MemoryServiceContextSnippet,
    MemoryServiceError, MemoryServiceErrorKind, memory_context_disabled,
};
use serde_json::{Value, json};

use crate::attribution::{OwnerScope, ProviderAttribution};
use crate::transport::{MnesisLane, MnesisRequest, MnesisTransport};

const MAX_SNIPPETS: usize = 20;
const MAX_QUERY_BYTES: usize = 4_096;
const UNNAMED_SOURCE: &str = "mnesis";
const ATTRIBUTION_DEADLINE_MS: u64 = 30_000;

pub struct MnesisMemoryService<T: MnesisTransport> {
    transport: T,
}

impl<T: MnesisTransport> std::fmt::Debug for MnesisMemoryService<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MnesisMemoryService")
            .finish_non_exhaustive()
    }
}

impl<T: MnesisTransport> MnesisMemoryService<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn attribution_for(&self, invocation: &MemoryInvocation) -> Option<String> {
        self.attribution_with_thread(invocation, None)
    }

    fn attribution_with_thread(
        &self,
        invocation: &MemoryInvocation,
        thread_id: Option<String>,
    ) -> Option<String> {
        let scope = &invocation.scope;
        let owner_scope = OwnerScope::narrowest(
            scope.tenant_id.as_str(),
            scope.user_id.as_str(),
            scope.agent_id.as_ref().map(|id| id.as_str().to_string()),
            scope.project_id.as_ref().map(|id| id.as_str().to_string()),
            thread_id,
        );
        let deadline_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis()
            .saturating_add(u128::from(ATTRIBUTION_DEADLINE_MS));
        ProviderAttribution {
            owner_scope,
            mission_id: scope.mission_id.as_ref().map(|id| id.as_str().to_string()),
            invocation_id: scope.invocation_id.to_string(),
            correlation_id: invocation.correlation_id.to_string(),
            deadline_at_ms: i64::try_from(deadline_at_ms).ok()?,
        }
        .encode()
        .ok()
    }

    async fn query_lane(
        &self,
        lane: MnesisLane,
        operation: &'static str,
        query: &str,
        limit: usize,
        attribution: Option<String>,
    ) -> Result<Vec<MnesisResult>, MemoryServiceError> {
        let body = match lane {
            MnesisLane::Knowledge => json!({ "query": query, "limit": limit, "hybrid": true }),
            MnesisLane::Memory => json!({ "query": query, "limit": limit }),
        };

        let response = self
            .transport
            .execute(MnesisRequest {
                lane,
                operation,
                body,
                idempotent: true,
                attribution,
            })
            .await
            .map_err(MemoryServiceError::unavailable_from)?;

        if !response.is_success() {
            return Err(if (500..600).contains(&response.status) {
                MemoryServiceError::unavailable()
            } else {
                MemoryServiceError::operation()
            });
        }

        Ok(decode_results(&response.body, limit))
    }
}

#[async_trait]
impl<T: MnesisTransport> MemoryService for MnesisMemoryService<T> {
    async fn read_long_term(
        &self,
        invocation: MemoryInvocation,
        request: MemoryServiceContextRequest,
    ) -> Result<Vec<MemoryServiceContextSnippet>, MemoryServiceError> {
        if memory_context_disabled(request.context_profile_id.as_str())
            || request.query.trim().is_empty()
        {
            return Ok(Vec::new());
        }
        if request.query.len() > MAX_QUERY_BYTES {
            return Err(MemoryServiceError::input());
        }

        let budget = request.max_snippets.min(MAX_SNIPPETS);
        if budget == 0 {
            return Ok(Vec::new());
        }
        let attribution = self.attribution_for(&invocation);

        let memory = degrade_availability(
            self.query_lane(
                MnesisLane::Memory,
                "memory_search",
                &request.query,
                budget,
                attribution,
            )
            .await,
        )?;

        let mut snippets: Vec<MemoryServiceContextSnippet> = memory
            .into_iter()
            .filter_map(|result| result.into_snippet())
            .collect();
        snippets.truncate(budget);
        Ok(snippets)
    }

    async fn read_short_term(
        &self,
        invocation: MemoryInvocation,
        request: MemoryServiceContextRequest,
    ) -> Result<Vec<MemoryServiceContextSnippet>, MemoryServiceError> {
        let Some(thread_id) = invocation.scope.thread_id.as_ref() else {
            return Ok(Vec::new());
        };
        if memory_context_disabled(request.context_profile_id.as_str())
            || request.query.trim().is_empty()
        {
            return Ok(Vec::new());
        }
        if request.query.len() > MAX_QUERY_BYTES {
            return Err(MemoryServiceError::input());
        }
        let budget = request.max_snippets.min(MAX_SNIPPETS);
        if budget == 0 {
            return Ok(Vec::new());
        }

        let attribution =
            self.attribution_with_thread(&invocation, Some(thread_id.as_str().to_string()));
        let results = degrade_availability(
            self.query_lane(
                MnesisLane::Memory,
                "read_short_term",
                &request.query,
                budget,
                attribution,
            )
            .await,
        )?;

        let mut snippets: Vec<MemoryServiceContextSnippet> = results
            .into_iter()
            .filter(|result| result.is_thread_scoped())
            .filter_map(|result| result.into_snippet())
            .collect();
        snippets.truncate(budget);
        Ok(snippets)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MnesisResult {
    pub relative_path: String,
    pub text: String,
    pub owner_scope: Option<ResultOwnerScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultOwnerScope {
    pub tenant_id: String,
    pub principal_id: String,
    pub agent_id: Option<String>,
    pub project_id: Option<String>,
    pub thread_id: Option<String>,
    pub record_class: Option<String>,
}

impl MnesisResult {
    fn is_thread_scoped(&self) -> bool {
        self.owner_scope
            .as_ref()
            .map(|scope| {
                scope.thread_id.is_some() && scope.record_class.as_deref() == Some("thread-private")
            })
            .unwrap_or(false)
    }

    fn into_snippet(self) -> Option<MemoryServiceContextSnippet> {
        let owner = self.owner_scope?;
        Some(MemoryServiceContextSnippet {
            tenant_id: owner.tenant_id,
            user_id: owner.principal_id,
            agent_id: owner.agent_id,
            project_id: owner.project_id,
            relative_path: self.relative_path,
            text: self.text,
        })
    }
}

fn degrade_availability(
    outcome: Result<Vec<MnesisResult>, MemoryServiceError>,
) -> Result<Vec<MnesisResult>, MemoryServiceError> {
    match outcome {
        Ok(results) => Ok(results),
        Err(error) if error.kind() == MemoryServiceErrorKind::Unavailable => {
            tracing::debug!(
                target: "ironclaw_memory_mnesis",
                "Mnesis lane unavailable; degrading to an empty memory lane"
            );
            Ok(Vec::new())
        }
        Err(error) => Err(error),
    }
}

fn decode_owner_scope(entry: &serde_json::Map<String, Value>) -> Option<ResultOwnerScope> {
    let authorization = entry.get("authorization")?.as_object()?;
    if authorization.get("kind")?.as_str()? != "owner-scope" {
        return None;
    }
    let scope = authorization.get("ownerScope")?.as_object()?;
    Some(ResultOwnerScope {
        tenant_id: scope.get("tenantId")?.as_str()?.to_string(),
        principal_id: scope.get("principalId")?.as_str()?.to_string(),
        agent_id: scope
            .get("agentId")
            .and_then(Value::as_str)
            .map(str::to_string),
        project_id: scope
            .get("projectId")
            .and_then(Value::as_str)
            .map(str::to_string),
        thread_id: scope
            .get("threadId")
            .and_then(Value::as_str)
            .map(str::to_string),
        record_class: scope
            .get("recordClass")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn decode_results(body: &Value, limit: usize) -> Vec<MnesisResult> {
    let entries = match body {
        Value::Array(entries) => entries.as_slice(),
        Value::Object(map) => match map.get("results") {
            Some(Value::Array(entries)) => entries.as_slice(),
            _ => &[],
        },
        _ => &[],
    };

    entries
        .iter()
        .filter_map(|entry| {
            let object = entry.as_object()?;
            let text = object
                .get("content")
                .or_else(|| object.get("text"))
                .and_then(Value::as_str)?;
            if text.trim().is_empty() {
                return None;
            }
            let path = object
                .get("relativePath")
                .or_else(|| object.get("relative_path"))
                .or_else(|| object.get("sourceUri"))
                .and_then(Value::as_str)
                .unwrap_or(UNNAMED_SOURCE);
            Some(MnesisResult {
                relative_path: safe_relative_path(path),
                text: text.to_string(),
                owner_scope: decode_owner_scope(object),
            })
        })
        .take(limit)
        .collect()
}

fn safe_relative_path(path: &str) -> String {
    let candidate = path.trim();
    let unsafe_path = candidate.is_empty()
        || candidate.starts_with('/')
        || candidate.starts_with('\\')
        || candidate.contains("..")
        || candidate.contains(':');
    if unsafe_path {
        UNNAMED_SOURCE.to_string()
    } else {
        candidate.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{MnesisResponse, MockMnesisTransport};

    #[test]
    fn decodes_the_contract_envelope_and_a_bare_array() {
        let enveloped = json!({"results": [{"relativePath": "a.md", "content": "alpha"}]});
        let decoded = decode_results(&enveloped, 10);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].relative_path, "a.md");
        assert_eq!(decoded[0].text, "alpha");

        let bare = json!([{"relative_path": "b.md", "text": "beta"}]);
        let decoded = decode_results(&bare, 10);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].relative_path, "b.md");
    }

    #[test]
    fn a_result_without_an_owner_scope_never_becomes_a_snippet() {
        let unscoped = MnesisResult {
            relative_path: "a.md".to_string(),
            text: "alpha".to_string(),
            owner_scope: None,
        };
        assert!(unscoped.into_snippet().is_none());
    }

    #[test]
    fn a_snippet_carries_the_owner_scope_mnesis_reported_not_the_caller_scope() {
        let body = json!({"results": [{
            "relativePath": "a.md",
            "content": "alpha",
            "authorization": {
                "kind": "owner-scope",
                "ownerScope": {
                    "tenantId": "tenant-from-mnesis",
                    "principalId": "principal-from-mnesis",
                    "agentId": "agent-from-mnesis",
                    "projectId": null
                }
            }
        }]});
        let snippet = decode_results(&body, 10)
            .remove(0)
            .into_snippet()
            .expect("an owner-scoped result becomes a snippet");
        assert_eq!(snippet.tenant_id, "tenant-from-mnesis");
        assert_eq!(snippet.user_id, "principal-from-mnesis");
        assert_eq!(snippet.agent_id.as_deref(), Some("agent-from-mnesis"));
        assert_eq!(snippet.project_id, None);
    }

    #[test]
    fn a_server_filesystem_path_never_reaches_a_snippet() {
        for hostile in ["/etc/passwd", "../../secret", "C:\\windows\\system32", "  "] {
            assert_eq!(safe_relative_path(hostile), UNNAMED_SOURCE, "{hostile}");
        }
        assert_eq!(safe_relative_path("notes/a.md"), "notes/a.md");
    }

    #[test]
    fn skips_entries_with_no_usable_text_and_honours_the_limit() {
        let body = json!({"results": [
            {"relativePath": "a.md", "content": "alpha"},
            {"relativePath": "b.md", "content": "   "},
            {"relativePath": "c.md"},
            {"relativePath": "d.md", "content": "delta"}
        ]});
        assert_eq!(decode_results(&body, 10).len(), 2);
        assert_eq!(decode_results(&body, 1).len(), 1);
    }

    #[test]
    fn an_unrecognized_body_decodes_to_no_results_rather_than_panicking() {
        assert!(decode_results(&Value::Null, 5).is_empty());
        assert!(decode_results(&json!("nonsense"), 5).is_empty());
        assert!(decode_results(&json!({"unexpected": 1}), 5).is_empty());
    }

    #[test]
    fn falls_back_to_the_source_uri_when_no_path_is_present() {
        let body = json!({"results": [{"sourceUri": "corpus/x", "content": "gamma"}]});
        let decoded = decode_results(&body, 10);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].relative_path, "corpus/x");
        assert_eq!(decoded[0].text, "gamma");
    }

    #[tokio::test]
    async fn a_lane_denial_is_an_operation_failure_and_a_5xx_is_unavailable() {
        let denied = MnesisMemoryService::new(MockMnesisTransport::new(Box::new(|_request| {
            Some(MnesisResponse {
                status: 403,
                body: Value::Null,
            })
        })));
        let error = denied
            .query_lane(MnesisLane::Knowledge, "knowledge_search", "q", 4, None)
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            ironclaw_memory::MemoryServiceErrorKind::Operation
        );

        let outage = MnesisMemoryService::new(MockMnesisTransport::new(Box::new(|_request| {
            Some(MnesisResponse {
                status: 503,
                body: Value::Null,
            })
        })));
        let error = outage
            .query_lane(MnesisLane::Memory, "memory_search", "q", 4, None)
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            ironclaw_memory::MemoryServiceErrorKind::Unavailable
        );
    }

    #[tokio::test]
    async fn both_lanes_are_queried_and_each_request_is_idempotent() {
        let service = MnesisMemoryService::new(MockMnesisTransport::always_ok(
            json!({"results": [{"relativePath": "a.md", "content": "alpha"}]}),
        ));
        let results = service
            .query_lane(MnesisLane::Knowledge, "knowledge_search", "q", 4, None)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        let recorded = service.transport.recorded();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].idempotent);
        assert_eq!(recorded[0].lane, MnesisLane::Knowledge);
    }
}
