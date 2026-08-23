//! Mnesis's wiring of the shared provider contract suite
//! (`ironclaw_memory::test_support`).
//!
//! Mnesis declares the long-term retrieval lane and interaction recording, but
//! no short-term lane, so it wires the retrieval-only suite: scope isolation
//! across tenant/user/agent/project. The backing is a STATEFUL fake Mnesis
//! server (not the scripted `MockMnesisTransport`): it stores what
//! `record_interaction` sends and answers `memory_search` only from rows whose
//! owner scope key matches the caller's exactly — the same key the real server
//! derives from the provider attribution header — so the contract proves the
//! provider derives a distinct owner scope per resource scope and round-trips
//! through it, end to end at this crate's seam.
//!
//! The suite seeds through the provider's own write operation, which for
//! Mnesis is `record_interaction`; there is no separate document write.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironclaw_memory::{
    MemoryInteractionMessage, MemoryInteractionRole, MemoryService, MemoryServiceRecordRequest,
};
use ironclaw_memory_mnesis::{
    MnesisMemoryService, MnesisRequest, MnesisResponse, MnesisTransport, MnesisTransportError,
};
use serde_json::{Value, json};

const ATTRIBUTION_PREFIX: &str = "mpa1.";
const OWNER_SCOPE_PREFIX: &str = "mos1.";

/// One stored row: the owner scope key the write was attributed to, plus the
/// verbatim message content.
#[derive(Clone)]
struct FakeRow {
    owner_key: String,
    content: String,
}

/// A stateful in-memory Mnesis server. `record_interaction` stores each
/// message under the request's owner scope key; `memory_search` returns only
/// rows carrying the caller's exact key. That key is the isolation boundary
/// the hosted deployment enforces, so a provider that derived the wrong scope
/// fails here rather than in production.
#[derive(Default)]
struct FakeMnesisServer {
    rows: Mutex<Vec<FakeRow>>,
}

impl FakeMnesisServer {
    /// Decode the owner scope key out of the provider attribution header.
    /// Element 1 of the attribution tuple is the canonical owner scope key.
    fn owner_key(attribution: Option<&str>) -> String {
        let encoded = attribution.expect("every Mnesis request must carry provider attribution");
        let payload = encoded
            .strip_prefix(ATTRIBUTION_PREFIX)
            .expect("provider attribution must carry the versioned prefix");
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .expect("provider attribution must be base64url");
        let tuple: Value =
            serde_json::from_slice(&bytes).expect("provider attribution must be a JSON tuple");
        tuple
            .get(1)
            .and_then(Value::as_str)
            .expect("provider attribution must carry an owner scope key")
            .to_string()
    }

    fn store(&self, owner_key: String, body: &Value) {
        let messages = body
            .get("messages")
            .and_then(Value::as_array)
            .expect("record_interaction body must carry messages");
        let mut rows = self.rows.lock().expect("fake server lock");
        for message in messages {
            let content = message
                .get("content")
                .and_then(Value::as_str)
                .expect("each recorded message must carry content");
            rows.push(FakeRow {
                owner_key: owner_key.clone(),
                content: content.to_string(),
            });
        }
    }

    /// Reverse the owner scope key back into its axes, so a stored row can be
    /// returned with the owner scope the real server would attach. The key is
    /// the canonical tuple `[version, recordClass, tenant, principal, agent,
    /// project, thread]`.
    fn owner_scope(owner_key: &str) -> Value {
        let payload = owner_key
            .strip_prefix(OWNER_SCOPE_PREFIX)
            .expect("owner scope key must carry the versioned prefix");
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .expect("owner scope key must be base64url");
        let tuple: Value =
            serde_json::from_slice(&bytes).expect("owner scope key must be a JSON tuple");
        json!({
            "recordClass": tuple[1],
            "tenantId": tuple[2],
            "principalId": tuple[3],
            "agentId": tuple[4],
            "projectId": tuple[5],
            "threadId": tuple[6],
        })
    }

    /// Exact-scope search: only rows written under the caller's own owner key
    /// are eligible, then a naive shared-token match against the query. Every
    /// hit carries back the owner scope it was stored under, never the
    /// caller's, so a provider that relabels a foreign record fails here.
    fn search(&self, owner_key: &str, body: &Value) -> Value {
        let query = body
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let limit = body
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(10)
            .max(1) as usize;
        let rows = self.rows.lock().expect("fake server lock");
        let matched: Vec<Value> = rows
            .iter()
            .filter(|row| row.owner_key == owner_key)
            .filter(|row| {
                query
                    .split_whitespace()
                    .any(|token| row.content.contains(token))
            })
            .take(limit)
            .map(|row| {
                json!({
                    "text": row.content,
                    "relativePath": "memory/contract.md",
                    "score": 1.0,
                    "authorization": {
                        "kind": "owner-scope",
                        "ownerScope": Self::owner_scope(&row.owner_key),
                    },
                })
            })
            .collect();
        json!({ "results": matched })
    }
}

/// Local wrapper so the suite can hold a handle to the same backing the
/// service writes through. `MnesisMemoryService` owns its transport by value,
/// and the orphan rule forbids implementing the transport trait for `Arc`
/// directly from this crate.
#[derive(Clone, Default)]
struct SharedFake(Arc<FakeMnesisServer>);

#[async_trait]
impl MnesisTransport for SharedFake {
    async fn execute(
        &self,
        request: MnesisRequest,
    ) -> Result<MnesisResponse, MnesisTransportError> {
        let owner_key = FakeMnesisServer::owner_key(request.attribution.as_deref());
        assert_eq!(
            request.body["method"], "tools/call",
            "the provider must reach the lane as JSON-RPC, not a bare payload"
        );
        assert_eq!(
            request.body["params"]["name"], request.operation,
            "the tool named on the wire must be the operation the caller asked for"
        );
        let arguments = &request.body["params"]["arguments"];
        let body = match request.operation {
            "record_interaction" => {
                self.0.store(owner_key, arguments);
                json!({ "recorded": true })
            }
            "memory_search" | "knowledge_search" => self.0.search(&owner_key, arguments),
            other => panic!("fake Mnesis server: unexpected operation {other}"),
        };
        Ok(MnesisResponse {
            status: 200,
            body: json!({ "result": { "structuredContent": body } }),
        })
    }
}

ironclaw_memory::memory_service_contract_retrieval_only!(
    mnesis_provider,
    || MnesisMemoryService::new(SharedFake::default()),
    async |service: &MnesisMemoryService<SharedFake>, invocation, request| {
        service
            .record_interaction(
                invocation,
                MemoryServiceRecordRequest {
                    messages: vec![MemoryInteractionMessage {
                        role: MemoryInteractionRole::User,
                        content: request.content.clone(),
                        name: None,
                    }],
                    turn_run_id: Some("contract-seed-run".to_string()),
                    metadata: Value::Null,
                },
            )
            .await
            .expect("seed write through Mnesis's own record_interaction operation");
    }
);
