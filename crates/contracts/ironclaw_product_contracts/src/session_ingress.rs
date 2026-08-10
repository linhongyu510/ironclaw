//! Session-channel ingress directory.
//!
//! The generic session-inbound route is parameterized by `extension_id`; the
//! product surface must confirm the named extension actually declares an
//! authenticated-session channel entrypoint before admitting a submission
//! under its identity. The directory is that confirmation — derived from the
//! deployment's resolved channel manifests, implemented by the extension
//! host, and consulted fail-closed (an unknown or non-session extension is a
//! 404, indistinguishable from an absent route).

/// Deployment directory of authenticated-session channel entrypoints.
pub trait SessionChannelDirectory: Send + Sync {
    /// Whether `extension_id` names a deployment channel whose declared
    /// ingress is the authenticated-session entrypoint.
    fn is_session_channel(&self, extension_id: &str) -> bool;
}
