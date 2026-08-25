mod attribution;
mod catalog;
mod config;
mod error;
mod idempotency;
mod schema_assets;
mod service;
mod transport;
mod url_check;

pub const MNESIS_MEMORY_EXTENSION_ID: &str = "mnesis.hosted.memory";

pub const MEMORY_GUIDANCE_ASSETS: &[(&str, &str)] = &[];

pub use schema_assets::MEMORY_SCHEMA_ASSETS;

pub const MEMORY_MANIFEST_TOML: &str = include_str!("../manifest.toml");

pub use attribution::{
    OwnerAxes, OwnerRecordClass, OwnerScope, PROVIDER_ATTRIBUTION_HEADER, ProviderAttribution,
};
pub use catalog::{CATALOG_TOOLS, CatalogTool, catalog_tool};
pub use config::{
    DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_MAX_IDLE_CONNECTIONS, DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_RETRIES, DEFAULT_REQUEST_TIMEOUT_SECS, DEFAULT_RETRY_BACKOFF_MS,
    DEFAULT_TOTAL_DEADLINE_SECS, MnesisConfig, MnesisLimits,
};
pub use error::MnesisError;
pub use idempotency::{
    MAX_INTERACTION_BYTES, MAX_INTERACTION_MESSAGES, MAX_MESSAGE_BYTES, MAX_METADATA_ENTRIES,
    WriteIdentity, assert_interaction_bounds, operation_id, payload_digest,
};
pub use service::MnesisMemoryService;
pub use transport::{
    MAX_CONTEXT_SNIPPETS, MAX_KNOWLEDGE_SEARCH_RESULTS, MAX_MEMORY_SEARCH_RESULTS,
    MnesisHttpTransport, MnesisLane, MnesisRequest, MnesisResponse, MnesisTool, MnesisTransport,
    MnesisTransportError,
};
pub use url_check::EndpointProfile;

#[cfg(any(test, feature = "test-support"))]
pub use transport::{MnesisMockHandler, MockMnesisTransport};
