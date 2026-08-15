use async_trait::async_trait;
use ironclaw_memory::{
    MemoryInvocation, MemoryService, MemoryServiceContextRequest, MemoryServiceContextSnippet,
    MemoryServiceError, memory_context_disabled,
};
use serde_json::{Value, json};

use crate::transport::{MnesisLane, MnesisRequest, MnesisTransport};

const MAX_SNIPPETS: usize = 20;
const MAX_QUERY_BYTES: usize = 4_096;
const UNNAMED_SOURCE: &str = "mnesis";

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

    async fn query_lane(
        &self,
        lane: MnesisLane,
        operation: &'static str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<(String, String)>, MemoryServiceError> {
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
        let knowledge_quota = budget.div_ceil(2);
        let memory_quota = budget - knowledge_quota;

        let knowledge = self
            .query_lane(
                MnesisLane::Knowledge,
                "knowledge_search",
                &request.query,
                knowledge_quota,
            )
            .await?;
        let memory = if memory_quota > 0 {
            self.query_lane(
                MnesisLane::Memory,
                "memory_search",
                &request.query,
                memory_quota,
            )
            .await?
        } else {
            Vec::new()
        };

        let scope = &invocation.scope;
        let mut snippets: Vec<MemoryServiceContextSnippet> = knowledge
            .into_iter()
            .chain(memory)
            .map(|(relative_path, text)| MemoryServiceContextSnippet {
                tenant_id: scope.tenant_id.as_str().to_string(),
                user_id: scope.user_id.as_str().to_string(),
                agent_id: scope.agent_id.as_ref().map(|id| id.as_str().to_string()),
                project_id: scope.project_id.as_ref().map(|id| id.as_str().to_string()),
                relative_path,
                text,
            })
            .collect();
        snippets.truncate(budget);
        Ok(snippets)
    }
}

fn decode_results(body: &Value, limit: usize) -> Vec<(String, String)> {
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
            Some((path.to_string(), text.to_string()))
        })
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{MnesisResponse, MockMnesisTransport};

    #[test]
    fn decodes_the_contract_envelope_and_a_bare_array() {
        let enveloped = json!({"results": [{"relativePath": "a.md", "content": "alpha"}]});
        assert_eq!(
            decode_results(&enveloped, 10),
            vec![("a.md".to_string(), "alpha".to_string())]
        );

        let bare = json!([{"relative_path": "b.md", "text": "beta"}]);
        assert_eq!(
            decode_results(&bare, 10),
            vec![("b.md".to_string(), "beta".to_string())]
        );
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
        let body = json!({"results": [{"sourceUri": "corpus://x", "content": "gamma"}]});
        assert_eq!(
            decode_results(&body, 10),
            vec![("corpus://x".to_string(), "gamma".to_string())]
        );
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
            .query_lane(MnesisLane::Knowledge, "knowledge_search", "q", 4)
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
            .query_lane(MnesisLane::Memory, "memory_search", "q", 4)
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
            .query_lane(MnesisLane::Knowledge, "knowledge_search", "q", 4)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        let recorded = service.transport.recorded();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].idempotent);
        assert_eq!(recorded[0].lane, MnesisLane::Knowledge);
    }
}
