use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use crate::error::MnesisError;

pub const PROVIDER_ATTRIBUTION_HEADER: &str = "X-Mnesis-Provider-Attribution";

const OWNER_SCOPE_VERSION: u32 = 1;
const ATTRIBUTION_VERSION: u32 = 1;
const OWNER_SCOPE_PREFIX: &str = "mos1.";
const ATTRIBUTION_PREFIX: &str = "mpa1.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerRecordClass {
    PrincipalPrivate,
    AgentPrivate,
    ProjectPrivate,
    ThreadPrivate,
    OrganizationShared,
}

impl OwnerRecordClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::PrincipalPrivate => "principal-private",
            Self::AgentPrivate => "agent-private",
            Self::ProjectPrivate => "project-private",
            Self::ThreadPrivate => "thread-private",
            Self::OrganizationShared => "organization-shared",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerScope {
    pub record_class: OwnerRecordClass,
    pub tenant_id: String,
    pub principal_id: String,
    pub agent_id: Option<String>,
    pub project_id: Option<String>,
    pub thread_id: Option<String>,
}

/// Named so the three optional axes cannot be transposed at a call site: a
/// swap here silently changes the derived record class and the owner key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnerAxes {
    pub agent_id: Option<String>,
    pub project_id: Option<String>,
    pub thread_id: Option<String>,
}

impl OwnerAxes {
    pub fn with_thread(thread_id: Option<String>) -> Self {
        Self {
            thread_id,
            ..Self::default()
        }
    }
}

impl OwnerScope {
    pub fn narrowest(
        tenant_id: impl Into<String>,
        principal_id: impl Into<String>,
        axes: OwnerAxes,
    ) -> Self {
        let OwnerAxes {
            agent_id,
            project_id,
            thread_id,
        } = axes;
        let record_class = if thread_id.is_some() {
            OwnerRecordClass::ThreadPrivate
        } else if project_id.is_some() {
            OwnerRecordClass::ProjectPrivate
        } else if agent_id.is_some() {
            OwnerRecordClass::AgentPrivate
        } else {
            OwnerRecordClass::PrincipalPrivate
        };
        Self {
            record_class,
            tenant_id: tenant_id.into(),
            principal_id: principal_id.into(),
            agent_id,
            project_id,
            thread_id,
        }
    }

    fn tuple(&self) -> Value {
        json!([
            OWNER_SCOPE_VERSION,
            self.record_class.as_str(),
            self.tenant_id,
            self.principal_id,
            self.agent_id,
            self.project_id,
            self.thread_id,
        ])
    }

    pub fn key(&self) -> Result<String, MnesisError> {
        let encoded = serde_json::to_vec(&self.tuple()).map_err(|error| MnesisError::Client {
            reason: format!("owner scope could not be encoded: {error}"),
        })?;
        Ok(format!(
            "{OWNER_SCOPE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(encoded)
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAttribution {
    pub owner_scope: OwnerScope,
    pub mission_id: Option<String>,
    pub invocation_id: String,
    pub correlation_id: String,
    pub deadline_at_ms: i64,
}

impl ProviderAttribution {
    pub fn encode(&self) -> Result<String, MnesisError> {
        if self.deadline_at_ms < 1 {
            return Err(MnesisError::Client {
                reason: "provider attribution deadline must be positive".to_string(),
            });
        }
        let tuple = json!([
            ATTRIBUTION_VERSION,
            self.owner_scope.key()?,
            self.mission_id,
            self.invocation_id,
            self.correlation_id,
            self.deadline_at_ms,
        ]);
        let encoded = serde_json::to_vec(&tuple).map_err(|error| MnesisError::Client {
            reason: format!("provider attribution could not be encoded: {error}"),
        })?;
        Ok(format!(
            "{ATTRIBUTION_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(encoded)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_OWNER_SCOPE_KEY: &str = "mos1.WzEsInRocmVhZC1wcml2YXRlIiwibmVhciBhaSIsIkpvc8OpIiwicmVzZWFyY2gtYWdlbnQiLCJjb21wYW55LWJyYWluIiwidGhyZWFkLTQyIl0";

    const FIXTURE_ATTRIBUTION: &str = "mpa1.WzEsIm1vczEuV3pFc0luUm9jbVZoWkMxd2NtbDJZWFJsSWl3aWJtVmhjaUJoYVNJc0lrcHZjOE9wSWl3aWNtVnpaV0Z5WTJndFlXZGxiblFpTENKamIyMXdZVzU1TFdKeVlXbHVJaXdpZEdoeVpXRmtMVFF5SWwwIiwibWVtb3J5IGV2YWx1YXRpb24iLCIxMTExMTExMS0yMjIyLTQzMzMtODQ0NC01NTU1NTU1NTU1NTUiLCJhYWFhYWFhYS1iYmJiLTRjY2MtOGRkZC1lZWVlZWVlZWVlZWUiLDE4MDAwMDAwMDAwMDBd";

    fn fixture_scope() -> OwnerScope {
        OwnerScope {
            record_class: OwnerRecordClass::ThreadPrivate,
            tenant_id: "near ai".to_string(),
            principal_id: "Jos\u{e9}".to_string(),
            agent_id: Some("research-agent".to_string()),
            project_id: Some("company-brain".to_string()),
            thread_id: Some("thread-42".to_string()),
        }
    }

    #[test]
    fn owner_scope_key_matches_the_frozen_typescript_fixture() {
        assert_eq!(fixture_scope().key().unwrap(), FIXTURE_OWNER_SCOPE_KEY);
    }

    #[test]
    fn attribution_encoding_matches_the_frozen_typescript_fixture() {
        let attribution = ProviderAttribution {
            owner_scope: fixture_scope(),
            mission_id: Some("memory evaluation".to_string()),
            invocation_id: "11111111-2222-4333-8444-555555555555".to_string(),
            correlation_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_string(),
            deadline_at_ms: 1_800_000_000_000,
        };
        assert_eq!(attribution.encode().unwrap(), FIXTURE_ATTRIBUTION);
    }

    #[test]
    fn narrowest_selects_the_record_class_from_the_axes_present() {
        assert_eq!(
            OwnerScope::narrowest("t", "p", OwnerAxes::default()).record_class,
            OwnerRecordClass::PrincipalPrivate
        );
        assert_eq!(
            OwnerScope::narrowest(
                "t",
                "p",
                OwnerAxes {
                    agent_id: Some("a".into()),
                    ..OwnerAxes::default()
                }
            )
            .record_class,
            OwnerRecordClass::AgentPrivate
        );
        assert_eq!(
            OwnerScope::narrowest(
                "t",
                "p",
                OwnerAxes {
                    agent_id: Some("a".into()),
                    project_id: Some("j".into()),
                    ..OwnerAxes::default()
                }
            )
            .record_class,
            OwnerRecordClass::ProjectPrivate
        );
        assert_eq!(
            OwnerScope::narrowest(
                "t",
                "p",
                OwnerAxes {
                    agent_id: Some("a".into()),
                    project_id: Some("j".into()),
                    thread_id: Some("h".into()),
                }
            )
            .record_class,
            OwnerRecordClass::ThreadPrivate
        );
    }

    #[test]
    fn a_non_positive_deadline_is_refused() {
        let attribution = ProviderAttribution {
            owner_scope: OwnerScope::narrowest("t", "p", OwnerAxes::default()),
            mission_id: None,
            invocation_id: "11111111-2222-4333-8444-555555555555".to_string(),
            correlation_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_string(),
            deadline_at_ms: 0,
        };
        assert!(attribution.encode().is_err());
    }
}
