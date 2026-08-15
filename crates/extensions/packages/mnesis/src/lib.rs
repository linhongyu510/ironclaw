mod config;
mod error;
mod service;
mod transport;
mod url_check;

pub const MNESIS_MEMORY_EXTENSION_ID: &str = "mnesis.hosted.memory";

pub const MEMORY_GUIDANCE_ASSETS: &[(&str, &str)] = &[];

pub use config::{
    DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_MAX_IDLE_CONNECTIONS, DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_RETRIES, DEFAULT_REQUEST_TIMEOUT_SECS, DEFAULT_RETRY_BACKOFF_MS,
    DEFAULT_TOTAL_DEADLINE_SECS, MnesisConfig, MnesisLimits, SecretHandle, SecretHandleError,
};
pub use error::MnesisError;
pub use service::MnesisMemoryService;
pub use transport::{
    MnesisHttpTransport, MnesisLane, MnesisRequest, MnesisResponse, MnesisTransport,
    MnesisTransportError,
};
pub use url_check::EndpointProfile;

#[cfg(any(test, feature = "test-support"))]
pub use transport::{MnesisMockHandler, MockMnesisTransport};
