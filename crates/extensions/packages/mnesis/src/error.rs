use thiserror::Error;

#[derive(Debug, Error)]
pub enum MnesisError {
    #[error("invalid Mnesis endpoint: {reason}")]
    InvalidEndpoint { reason: String },

    #[error("failed to build the Mnesis HTTP client: {reason}")]
    Client { reason: String },

    #[error("Mnesis returned status {status} for {operation}")]
    Api {
        operation: &'static str,
        status: u16,
    },

    #[error("Mnesis response exceeded the {limit}-byte ceiling for {operation}")]
    ResponseTooLarge {
        operation: &'static str,
        limit: usize,
    },

    #[error("Mnesis returned an undecodable response body for {operation}: {reason}")]
    UndecodableResponse {
        operation: &'static str,
        reason: String,
    },

    #[error("Mnesis provider contract version {version} is unsupported")]
    UnsupportedContractVersion { version: u32 },
}
