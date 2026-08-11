//! Late-bound runtime state for the web-app channel.
//!
//! The channel adapter is constructed by the binary's binding table before
//! composition has built storage, so the adapter holds this slot and
//! composition installs the runtime exactly once at assembly (the same boot
//! ordering the trigger poller's buffered post-submit hook resolves). Until
//! installed, consumers fail closed with `WebAppError::RuntimeUnavailable`.

use std::sync::{Arc, RwLock};

use crate::error::WebAppError;
use crate::store::WebAppSubscriptionStore;

/// Everything the channel adapter needs at send and enrollment time.
pub struct WebAppRuntime {
    pub subscriptions: Arc<dyn WebAppSubscriptionStore>,
    /// The advertised RFC 8292 application-server public key (URL-safe
    /// base64). Public by definition — the signing half stays host-seeded in
    /// the secret store and never reaches the adapter.
    pub vapid_public_key: String,
    /// Push-service hosts enrollments may target — the manifest's
    /// `[[channel.egress]]` host list, the same allowlist restricted egress
    /// enforces at send time.
    pub allowed_push_hosts: Vec<String>,
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
    use crate::store::{PushSubscriptionUpsertOutcome, WebAppSubscriptionStore};
    use crate::subscription::{PushEndpoint, PushSubscriptionRecord};
    use async_trait::async_trait;
    use ironclaw_host_api::resource::ResourceScope;

    struct NullStore;

    #[async_trait]
    impl WebAppSubscriptionStore for NullStore {
        async fn upsert_subscription(
            &self,
            _scope: &ResourceScope,
            _record: PushSubscriptionRecord,
        ) -> Result<PushSubscriptionUpsertOutcome, WebAppError> {
            Ok(PushSubscriptionUpsertOutcome::Enrolled)
        }

        async fn remove_subscription(
            &self,
            _scope: &ResourceScope,
            _endpoint: &PushEndpoint,
        ) -> Result<bool, WebAppError> {
            Ok(false)
        }

        async fn list_subscriptions(
            &self,
            _scope: &ResourceScope,
        ) -> Result<Vec<PushSubscriptionRecord>, WebAppError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn slot_fails_closed_then_installs_exactly_once() {
        let slot = WebAppRuntimeSlot::new();
        assert!(matches!(slot.get(), Err(WebAppError::RuntimeUnavailable)));
        assert!(!slot.is_installed());

        let runtime = Arc::new(WebAppRuntime {
            subscriptions: Arc::new(NullStore),
            vapid_public_key: "test-public-key".to_string(),
            allowed_push_hosts: vec!["push.example".to_string()],
        });
        slot.install(Arc::clone(&runtime)).expect("first install");
        assert!(slot.is_installed());
        assert!(slot.get().is_ok());
        assert!(matches!(
            slot.install(runtime),
            Err(WebAppError::RuntimeAlreadyInstalled)
        ));
    }
}
