//! Late-bound client-bootstrap material for the web-app channel.
//!
//! The binary builds its binding table before composition has read the
//! deployment's VAPID keypair, so the slot is filled at assembly and read by
//! the host's generic client-bootstrap publisher. Until installed, consumers
//! fail closed with `WebAppError::RuntimeUnavailable`.
//!
//! **Two things left this struct when enrollment moved host-side (design
//! §8).** The subscription store became the host's generic per-user
//! delivery-registration store (`ironclaw_auth::delivery_registrations`), and
//! the push-service allowlist became the generic pre-storage endpoint check
//! against `[[channel.egress]]` — the host owns that allowlist, so the host
//! performs the check. What remains is the one thing that is genuinely
//! channel-shaped and genuinely late-bound: the public key a browser needs in
//! order to subscribe at all.

use std::sync::{Arc, RwLock};

use crate::error::WebAppError;

/// The channel's client-bootstrap material.
pub struct WebAppRuntime {
    /// The advertised RFC 8292 application-server public key (URL-safe
    /// base64). Public by definition — the signing half stays host-seeded in
    /// the secret store and is injected only at the egress boundary.
    pub vapid_public_key: String,
}

/// Cloneable installer/consumer handle around the runtime.
#[derive(Clone, Default)]
pub struct WebAppRuntimeSlot {
    inner: Arc<RwLock<Option<Arc<WebAppRuntime>>>>,
}

impl WebAppRuntimeSlot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the runtime. Exactly once per process; a second install is a
    /// wiring bug and fails loudly.
    pub fn install(&self, runtime: Arc<WebAppRuntime>) -> Result<(), WebAppError> {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.is_some() {
            return Err(WebAppError::RuntimeAlreadyInstalled);
        }
        *guard = Some(runtime);
        Ok(())
    }

    pub fn get(&self) -> Result<Arc<WebAppRuntime>, WebAppError> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or(WebAppError::RuntimeUnavailable)
    }

    pub fn is_installed(&self) -> bool {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> Arc<WebAppRuntime> {
        Arc::new(WebAppRuntime {
            vapid_public_key: "public-key".to_string(),
        })
    }

    #[test]
    fn the_slot_fails_closed_until_installed_and_refuses_a_second_install() {
        let slot = WebAppRuntimeSlot::new();
        assert!(!slot.is_installed());
        assert!(matches!(slot.get(), Err(WebAppError::RuntimeUnavailable)));

        slot.install(runtime()).expect("first install");
        assert!(slot.is_installed());
        assert_eq!(
            slot.get().expect("installed").vapid_public_key,
            "public-key"
        );

        assert!(
            matches!(
                slot.install(runtime()),
                Err(WebAppError::RuntimeAlreadyInstalled)
            ),
            "a second install is a wiring bug and must fail loudly"
        );
    }
}
