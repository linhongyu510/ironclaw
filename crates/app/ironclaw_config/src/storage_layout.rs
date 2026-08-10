use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::RebornHome;

/// Version of the durable state layout represented by [`LayoutManifest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateLayoutVersion {
    V1,
}

impl Serialize for StateLayoutVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(1)
    }
}

impl<'de> Deserialize<'de> for StateLayoutVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            1 => Ok(Self::V1),
            version => Err(D::Error::custom(format!(
                "unsupported state layout version {version}; expected 1"
            ))),
        }
    }
}

/// Durable backend recorded by an installation layout manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DurableStateKind {
    #[serde(rename = "embedded-libsql")]
    EmbeddedLibSql,
    ExternalPostgres,
}

impl DurableStateKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::EmbeddedLibSql => "embedded-libsql",
            Self::ExternalPostgres => "external-postgres",
        }
    }
}

/// Ownership model the durable layout was established for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TenancyModel {
    SingleUser,
    MultiUser,
}

impl TenancyModel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SingleUser => "single-user",
            Self::MultiUser => "multi-user",
        }
    }
}

/// Minimum workspace separation required by an established durable layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceAccessFloor {
    SingleTrustedOperator,
    PerCallerIsolated,
}

impl WorkspaceAccessFloor {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SingleTrustedOperator => "single-trusted-operator",
            Self::PerCallerIsolated => "per-caller-isolated",
        }
    }
}

/// Durable security assumptions that survive process backend changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSecurityEnvelope {
    pub tenancy: TenancyModel,
    pub workspace_access_floor: WorkspaceAccessFloor,
}

/// The current deployment's durable-layout requirement.
///
/// This is supplied by composition after it resolves deployment policy; it
/// deliberately carries neither profile names nor process backend details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutRequirement {
    pub durable_state: DurableStateKind,
    pub security: DeploymentSecurityEnvelope,
}

/// Canonical durable paths below one validated [`RebornHome`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebornStoragePaths {
    state_root: PathBuf,
    system_root: PathBuf,
    workspace_root: PathBuf,
    runtime_root: PathBuf,
}

impl RebornStoragePaths {
    /// Derive canonical paths without inspecting or mutating the filesystem.
    pub fn from_home(home: &RebornHome) -> Self {
        let root = home.path();
        Self {
            state_root: root.join("state"),
            system_root: root.join("system"),
            workspace_root: root.join("workspaces"),
            runtime_root: root.join("runtime"),
        }
    }

    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    pub fn system_root(&self) -> &Path {
        &self.system_root
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }
}

/// Versioned, persisted record of durable storage assumptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutManifest {
    #[serde(deserialize_with = "deserialize_schema_version")]
    schema_version: u32,
    state_layout_version: StateLayoutVersion,
    durable_state: DurableStateKind,
    security: DeploymentSecurityEnvelope,
}

impl LayoutManifest {
    pub const SCHEMA_VERSION: u32 = 1;

    pub const fn new(requirement: LayoutRequirement) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            state_layout_version: StateLayoutVersion::V1,
            durable_state: requirement.durable_state,
            security: requirement.security,
        }
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub const fn state_layout_version(&self) -> StateLayoutVersion {
        self.state_layout_version
    }

    pub const fn requirement(&self) -> LayoutRequirement {
        LayoutRequirement {
            durable_state: self.durable_state,
            security: self.security,
        }
    }

    /// Admit only deployments that preserve the layout's durable assumptions.
    pub fn admit(&self, requested: LayoutRequirement) -> ProfileTransitionAdmission {
        let stored = self.requirement();
        if stored.durable_state != requested.durable_state {
            return ProfileTransitionAdmission::Rejected {
                reason: format!(
                    "durable state transition from {} to {} requires an explicit storage migration",
                    stored.durable_state.as_str(),
                    requested.durable_state.as_str()
                ),
            };
        }

        if stored.security.tenancy != requested.security.tenancy {
            return ProfileTransitionAdmission::Rejected {
                reason: format!(
                    "tenancy transition from {} to {} requires an explicit ownership migration",
                    stored.security.tenancy.as_str(),
                    requested.security.tenancy.as_str()
                ),
            };
        }

        if matches!(
            (
                stored.security.workspace_access_floor,
                requested.security.workspace_access_floor,
            ),
            (
                WorkspaceAccessFloor::PerCallerIsolated,
                WorkspaceAccessFloor::SingleTrustedOperator,
            )
        ) {
            return ProfileTransitionAdmission::Rejected {
                reason: format!(
                    "workspace access floor cannot weaken from {} to {}",
                    stored.security.workspace_access_floor.as_str(),
                    requested.security.workspace_access_floor.as_str()
                ),
            };
        }

        ProfileTransitionAdmission::Allowed
    }
}

fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version == LayoutManifest::SCHEMA_VERSION {
        Ok(version)
    } else {
        Err(D::Error::custom(format!(
            "unsupported layout manifest schema_version {version}; expected {}",
            LayoutManifest::SCHEMA_VERSION
        )))
    }
}

/// Result of comparing a stored layout manifest to a requested requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileTransitionAdmission {
    Allowed,
    Rejected { reason: String },
}
