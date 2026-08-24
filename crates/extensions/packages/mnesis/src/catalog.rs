use crate::transport::MnesisLane;

/// One tool the Mnesis lanes register, forwarded verbatim by the provider.
///
/// Generated from a live `tools/list` capture; `tests/mcp_tool_contract.rs`
/// pins the table against the frozen fixture so a server-side rename cannot
/// ship silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogTool {
    pub capability_id: &'static str,
    pub wire_name: &'static str,
    pub lane: MnesisLane,
    /// Whether the transport may retry. Mutations are sent once.
    pub idempotent: bool,
}

/// Every catalog tool, by the capability id the manifest declares.
///
/// `memory_search` and `search_knowledge` are absent: they keep their typed
/// lanes. `memory_record_interaction` is absent because it is a host-driven
/// lifecycle hook and must never be model-callable.
pub const CATALOG_TOOLS: &[CatalogTool] = &[
    CatalogTool {
        capability_id: "mnesis.hosted.memory.memory_add_fact",
        wire_name: "memory_add_fact",
        lane: MnesisLane::Memory,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.memory_add_learning",
        wire_name: "memory_add_learning",
        lane: MnesisLane::Memory,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.memory_add_session",
        wire_name: "memory_add_session",
        lane: MnesisLane::Memory,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.memory_export_obsidian_vault",
        wire_name: "memory_export_obsidian_vault",
        lane: MnesisLane::Memory,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.memory_feedback",
        wire_name: "memory_feedback",
        lane: MnesisLane::Memory,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.memory_graph_export",
        wire_name: "memory_graph_export",
        lane: MnesisLane::Memory,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.memory_knowledge_gaps",
        wire_name: "memory_knowledge_gaps",
        lane: MnesisLane::Memory,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.memory_query_related",
        wire_name: "memory_query_related",
        lane: MnesisLane::Memory,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.memory_run_maintenance",
        wire_name: "memory_run_maintenance",
        lane: MnesisLane::Memory,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.memory_stats",
        wire_name: "memory_stats",
        lane: MnesisLane::Memory,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.memory_temporal_query",
        wire_name: "memory_temporal_query",
        lane: MnesisLane::Memory,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.task_read",
        wire_name: "task_read",
        lane: MnesisLane::Memory,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.task_update_status",
        wire_name: "task_update_status",
        lane: MnesisLane::Memory,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.task_write",
        wire_name: "task_write",
        lane: MnesisLane::Memory,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.bootstrap",
        wire_name: "bootstrap",
        lane: MnesisLane::Knowledge,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.challenge_retrieval",
        wire_name: "challenge_retrieval",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.compilation_status",
        wire_name: "compilation_status",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.consolidation",
        wire_name: "consolidation",
        lane: MnesisLane::Knowledge,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.contradictions",
        wire_name: "contradictions",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.decompile",
        wire_name: "decompile",
        lane: MnesisLane::Knowledge,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.duplicates",
        wire_name: "duplicates",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.feedback",
        wire_name: "feedback",
        lane: MnesisLane::Knowledge,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.get_context",
        wire_name: "get_context",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.get_decision",
        wire_name: "get_decision",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.get_evidence",
        wire_name: "get_evidence",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.get_execution_attestation",
        wire_name: "get_execution_attestation",
        lane: MnesisLane::Knowledge,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.get_sources",
        wire_name: "get_sources",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.get_stats",
        wire_name: "get_stats",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.health",
        wire_name: "health",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.list_related",
        wire_name: "list_related",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.metrics",
        wire_name: "metrics",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.promote",
        wire_name: "promote",
        lane: MnesisLane::Knowledge,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.rar_export_obsidian_vault",
        wire_name: "rar_export_obsidian_vault",
        lane: MnesisLane::Knowledge,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.reflex_add",
        wire_name: "reflex_add",
        lane: MnesisLane::Knowledge,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.reflexes",
        wire_name: "reflexes",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.routing",
        wire_name: "routing",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.search",
        wire_name: "search",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.speculative",
        wire_name: "speculative",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.stale",
        wire_name: "stale",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.training",
        wire_name: "training",
        lane: MnesisLane::Knowledge,
        idempotent: false,
    },
    CatalogTool {
        capability_id: "mnesis.hosted.memory.verify_grounding",
        wire_name: "verify_grounding",
        lane: MnesisLane::Knowledge,
        idempotent: true,
    },
];

/// The catalog tool a capability id names, if any.
pub fn catalog_tool(capability_id: &str) -> Option<&'static CatalogTool> {
    CATALOG_TOOLS
        .iter()
        .find(|tool| tool.capability_id == capability_id)
}
