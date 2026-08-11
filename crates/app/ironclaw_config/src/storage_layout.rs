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
        serializer.serialize_u8(match self {
            Self::V1 => 1,
        })
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebornStoragePaths {
    installation_root: PathBuf,
    state_root: PathBuf,
    system_root: PathBuf,
    workspace_root: PathBuf,
    runtime_root: PathBuf,
    logs_root: PathBuf,
    cache_root: PathBuf,
    temp_root: PathBuf,
}

impl RebornStoragePaths {
    /// Derive canonical paths without inspecting or mutating the filesystem.
    pub fn from_home(home: &RebornHome) -> Self {
        Self::from_installation_root(home.path())
    }

    /// Derive the complete canonical namespace set from one installation root.
    ///
    /// Production callers receive this root from [`RebornHome`]. This
    /// constructor intentionally does not accept independent state, system, or
    /// workspace paths, so test-support composition inputs cannot construct an
    /// arbitrary namespace layout either.
    pub fn from_installation_root(installation_root: impl AsRef<Path>) -> Self {
        let root = installation_root.as_ref();
        Self {
            installation_root: root.to_path_buf(),
            state_root: root.join("state"),
            system_root: root.join("system"),
            workspace_root: root.join("workspaces"),
            runtime_root: root.join("runtime"),
            logs_root: root.join("logs"),
            cache_root: root.join("cache"),
            temp_root: root.join("tmp"),
        }
    }

    pub fn installation_root(&self) -> &Path {
        &self.installation_root
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

    pub fn logs_root(&self) -> &Path {
        &self.logs_root
    }

    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    pub fn temp_root(&self) -> &Path {
        &self.temp_root
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
        match durable_state_transition(stored.durable_state, requested.durable_state) {
            DurableStateTransition::Compatible => {}
            DurableStateTransition::RequiresExplicitStorageMigration => {
                return ProfileTransitionAdmission::Rejected {
                    reason: format!(
                        "durable state transition from {} to {} requires an explicit storage migration",
                        stored.durable_state.as_str(),
                        requested.durable_state.as_str()
                    ),
                };
            }
        }

        match tenancy_transition(stored.security.tenancy, requested.security.tenancy) {
            TenancyTransition::Compatible => {}
            TenancyTransition::RequiresExplicitOwnershipMigration => {
                return ProfileTransitionAdmission::Rejected {
                    reason: format!(
                        "tenancy transition from {} to {} requires an explicit ownership migration",
                        stored.security.tenancy.as_str(),
                        requested.security.tenancy.as_str()
                    ),
                };
            }
        }

        match workspace_access_floor_transition(
            stored.security.workspace_access_floor,
            requested.security.workspace_access_floor,
        ) {
            WorkspaceAccessFloorTransition::Compatible => {}
            WorkspaceAccessFloorTransition::WeakensAccessFloor => {
                return ProfileTransitionAdmission::Rejected {
                    reason: format!(
                        "workspace access floor cannot weaken from {} to {}",
                        stored.security.workspace_access_floor.as_str(),
                        requested.security.workspace_access_floor.as_str()
                    ),
                };
            }
        }

        ProfileTransitionAdmission::Allowed
    }
}

/// Exhaustive durable-state transition matrix.
///
/// The lack of a wildcard is intentional: adding a durable-state variant must
/// make the compiler require a reviewed transition decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableStateTransition {
    Compatible,
    RequiresExplicitStorageMigration,
}

const fn durable_state_transition(
    stored: DurableStateKind,
    requested: DurableStateKind,
) -> DurableStateTransition {
    match (stored, requested) {
        (DurableStateKind::EmbeddedLibSql, DurableStateKind::EmbeddedLibSql) => {
            DurableStateTransition::Compatible
        }
        (DurableStateKind::EmbeddedLibSql, DurableStateKind::ExternalPostgres) => {
            DurableStateTransition::RequiresExplicitStorageMigration
        }
        (DurableStateKind::ExternalPostgres, DurableStateKind::EmbeddedLibSql) => {
            DurableStateTransition::RequiresExplicitStorageMigration
        }
        (DurableStateKind::ExternalPostgres, DurableStateKind::ExternalPostgres) => {
            DurableStateTransition::Compatible
        }
    }
}

/// Exhaustive tenant-ownership transition matrix.
///
/// The lack of a wildcard is intentional: adding a tenancy variant must make
/// the compiler require a reviewed transition decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenancyTransition {
    Compatible,
    RequiresExplicitOwnershipMigration,
}

const fn tenancy_transition(stored: TenancyModel, requested: TenancyModel) -> TenancyTransition {
    match (stored, requested) {
        (TenancyModel::SingleUser, TenancyModel::SingleUser) => TenancyTransition::Compatible,
        (TenancyModel::SingleUser, TenancyModel::MultiUser) => {
            TenancyTransition::RequiresExplicitOwnershipMigration
        }
        (TenancyModel::MultiUser, TenancyModel::SingleUser) => {
            TenancyTransition::RequiresExplicitOwnershipMigration
        }
        (TenancyModel::MultiUser, TenancyModel::MultiUser) => TenancyTransition::Compatible,
    }
}

/// Exhaustive workspace-access-floor transition matrix.
///
/// The lack of a wildcard is intentional: adding a workspace-access-floor
/// variant must make the compiler require a reviewed transition decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceAccessFloorTransition {
    Compatible,
    WeakensAccessFloor,
}

const fn workspace_access_floor_transition(
    stored: WorkspaceAccessFloor,
    requested: WorkspaceAccessFloor,
) -> WorkspaceAccessFloorTransition {
    match (stored, requested) {
        (
            WorkspaceAccessFloor::SingleTrustedOperator,
            WorkspaceAccessFloor::SingleTrustedOperator,
        ) => WorkspaceAccessFloorTransition::Compatible,
        (WorkspaceAccessFloor::SingleTrustedOperator, WorkspaceAccessFloor::PerCallerIsolated) => {
            WorkspaceAccessFloorTransition::Compatible
        }
        (WorkspaceAccessFloor::PerCallerIsolated, WorkspaceAccessFloor::SingleTrustedOperator) => {
            WorkspaceAccessFloorTransition::WeakensAccessFloor
        }
        (WorkspaceAccessFloor::PerCallerIsolated, WorkspaceAccessFloor::PerCallerIsolated) => {
            WorkspaceAccessFloorTransition::Compatible
        }
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
