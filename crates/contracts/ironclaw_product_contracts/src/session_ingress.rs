//! Session-channel ingress directory.
//!
//! The generic session-inbound route is parameterized by `extension_id`; the
//! product surface must confirm the named extension actually declares an
//! authenticated-session channel entrypoint before admitting a submission
//! under its identity. The directory is that confirmation — derived from the
//! deployment's resolved channel manifests, implemented by the extension
//! host, and consulted fail-closed (an unknown or non-session extension is a
//! 404, indistinguishable from an absent route).

/// The built-in session surface the product always owns.
///
/// A deployment may install no channel extension at all, and it still has a
/// browser chat — so there is always exactly one session surface to name.
/// This is the id `GET /session` advertises when no installed channel
/// declares the `authenticated_session` entrypoint; an installed session
/// channel CLAIMS the surface and advertises its own id instead. Keeping a
/// built-in default is what stops the generic session route from making the
/// browser's send path depend on an installed extension: the route stays
/// `{extension_id}`-parameterized either way, and the SPA still learns the
/// id from the server rather than carrying a channel name.
pub const BUILTIN_SESSION_SURFACE_ID: &str = "webui";

/// Deployment directory of authenticated-session channel entrypoints.
pub trait SessionChannelDirectory: Send + Sync {
    /// Whether `extension_id` names a deployment channel whose declared
    /// ingress is the authenticated-session entrypoint.
    fn is_session_channel(&self, extension_id: &str) -> bool;
}
