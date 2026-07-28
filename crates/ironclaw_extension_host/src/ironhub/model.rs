use std::time::Duration;

use ironclaw_product::{LifecycleProductResponse, ProductSurfaceFailure};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub(crate) const DEFAULT_IRONHUB_MANIFEST_URL: &str =
    "https://hub.ironclaw.com/api/catalog/manifest.json";
pub(crate) const MANIFEST_VERIFY_KEYS: &[(&str, &str)] = &[(
    "5895a21abea89672",
    "f64d2d3a3228b16ca59450364d26b278071a1a425544f242504033341d8459bd",
)];
pub(crate) const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_SIGNED_MANIFEST_BYTES: u64 = MAX_MANIFEST_BYTES * 2;
pub(crate) const MAX_METADATA_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_WASM_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MANIFEST_CACHE_TTL: Duration = Duration::from_secs(60);
pub(crate) const MANIFEST_CACHE_MAX_ENTRIES: usize = 64;
pub(crate) const GENERIC_TOOL_INPUT_SCHEMA: &[u8] =
    br#"{"type":"object","additionalProperties":true}"#;
pub(crate) const GENERIC_TOOL_OUTPUT_SCHEMA: &[u8] =
    br#"{"description":"Raw JSON output from the installed IronHub tool"}"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IronHubEntryKind {
    Tool,
    Skill,
}

impl IronHubEntryKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::Skill => "skill",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IronHubProvenance {
    #[serde(alias = "repo")]
    Official,
    Trusted,
    Verified,
    Private,
    #[default]
    #[serde(alias = "community")]
    New,
}

impl IronHubProvenance {
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            Self::Official => "official",
            Self::Trusted => "trusted",
            Self::Verified => "verified",
            Self::Private => "private",
            Self::New => "new",
        }
    }

    pub(crate) fn is_community_unverified(self) -> bool {
        matches!(self, Self::New)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct IronHubManifest {
    pub(crate) version: String,
    pub(crate) generated_at: String,
    pub(crate) release_tag: String,
    pub(crate) repo: String,
    #[serde(default)]
    pub(crate) tools: Vec<IronHubToolEntry>,
    #[serde(default)]
    pub(crate) skills: Vec<IronHubSkillEntry>,
}

impl IronHubManifest {
    pub(crate) fn find_tool(&self, name: &str) -> Option<&IronHubToolEntry> {
        self.tools.iter().find(|entry| entry.name == name)
    }

    pub(crate) fn find_skill(&self, name: &str) -> Option<&IronHubSkillEntry> {
        self.skills.iter().find(|entry| entry.name == name)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct IronHubToolEntry {
    pub(crate) name: String,
    pub(crate) crate_name: String,
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) description: String,
    #[serde(default)]
    pub(crate) provenance: IronHubProvenance,
    pub(crate) wasm: IronHubArtifact,
    pub(crate) capabilities: IronHubArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct IronHubSkillEntry {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) trunk: String,
    #[serde(default)]
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) description: String,
    #[serde(default)]
    pub(crate) provenance: IronHubProvenance,
    pub(crate) skill_md: IronHubArtifact,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct IronHubArtifact {
    pub(crate) url: String,
    pub(crate) size_bytes: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct IronHubInstallOptions {
    pub kind: Option<IronHubEntryKind>,
    pub force: bool,
    pub acknowledge_unverified: bool,
    pub expected_version: Option<String>,
    pub expected_artifact_digest: Option<String>,
    pub private_manifest_url: Option<String>,
}

impl std::fmt::Debug for IronHubInstallOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IronHubInstallOptions")
            .field("kind", &self.kind)
            .field("force", &self.force)
            .field("acknowledge_unverified", &self.acknowledge_unverified)
            .field("expected_version", &self.expected_version)
            .field("expected_artifact_digest", &self.expected_artifact_digest)
            .field(
                "private_manifest_url",
                &self.private_manifest_url.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IronHubCommand {
    Search {
        query: String,
    },
    List {
        kind: Option<IronHubEntryKind>,
    },
    Info {
        name: String,
        kind: Option<IronHubEntryKind>,
    },
    Install {
        name: String,
        options: IronHubInstallOptions,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IronHubEntrySummary {
    pub kind: IronHubEntryKind,
    pub name: String,
    pub version: String,
    pub description: String,
    pub provenance: IronHubProvenance,
    pub artifact_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IronHubPhase {
    Discovered,
    Installed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IronHubResponse {
    pub phase: IronHubPhase,
    pub entries: Vec<IronHubEntrySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleProductResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl IronHubResponse {
    pub(crate) fn discovered(entries: Vec<IronHubEntrySummary>) -> Self {
        Self {
            phase: IronHubPhase::Discovered,
            entries,
            lifecycle: None,
            message: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum IronHubCommandError {
    #[error("IronHub runtime HTTP egress is unavailable")]
    RuntimeHttpEgressUnavailable,
    #[error("invalid IronHub input: {reason}")]
    InvalidInput { reason: String },
    #[error("IronHub catalog failed: {reason}")]
    Catalog { reason: String },
    #[error("IronHub install failed: {reason}")]
    Install { reason: String },
    #[error("IronHub lifecycle failed: {0}")]
    Product(#[from] ProductSurfaceFailure),
}

#[derive(Debug, Deserialize)]
pub(crate) struct SignedManifestEnvelope {
    pub(crate) v: u8,
    pub(crate) key_id: String,
    pub(crate) manifest_b64: String,
    pub(crate) sig: String,
}
