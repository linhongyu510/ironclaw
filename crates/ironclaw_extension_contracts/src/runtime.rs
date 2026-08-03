//! Neutral extension **runtime descriptor** — what an installable extension
//! declares about *how* it is executed, after manifest boundary validation has
//! converted manifest strings into typed internal values.
//!
//! This is the contract the W7 `mcp → extensions` / `scripts → extensions`
//! layer-matrix exceptions named as their removal condition ("remove when
//! extension runtime descriptors move to a neutral contract"): a runtimes-layer
//! lane must be able to read the runtime stanza it executes without importing
//! the registry crate that parses manifests.
//!
//! Deliberately *not* here: [`ExtensionPackage`][pkg] and [`ExtensionManifest`][man].
//! Those stay in `ironclaw_extensions` — they carry the whole parsed manifest
//! tree and a `PackageRootBinding` typed on `ironclaw_filesystem::VirtualPath`,
//! which the §11.2.3 contracts-purity allowlist (`{ironclaw_host_api}` only)
//! forbids this crate from naming. A lane therefore receives the extension id,
//! its capability descriptors, and this runtime descriptor — the three things it
//! actually reads — rather than the package it may not depend on.
//!
//! [pkg]: https://docs.rs/ironclaw_extensions
//! [man]: https://docs.rs/ironclaw_extensions

use ironclaw_host_api::runtime::RuntimeKind;
use thiserror::Error;

/// Rejected extension asset path.
///
/// The registry crate folds this into its own `ExtensionError::InvalidAssetPath`
/// so manifest parsing keeps one error taxonomy; the validation itself is pure
/// string checking and belongs with the type it constructs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid extension asset path '{path}': {reason}")]
pub struct ExtensionAssetPathError {
    pub path: String,
    pub reason: String,
}

impl ExtensionAssetPathError {
    fn new(path: &str, reason: &str) -> Self {
        Self {
            path: path.to_string(),
            reason: reason.to_string(),
        }
    }
}

/// Manifest-local path for assets such as WASM modules.
///
/// Resolution against a package root lives in `ironclaw_extensions`
/// (`resolve_asset_under`) because it needs `ironclaw_filesystem::VirtualPath`,
/// which this crate may not name. The orphan rule makes that a free function
/// rather than an inherent method — the same cost the WS1.4 DTO moves recorded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtensionAssetPath(String);

impl ExtensionAssetPath {
    pub fn new(value: impl Into<String>) -> Result<Self, ExtensionAssetPathError> {
        let value = value.into();
        validate_asset_path(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_asset_path(value: &str) -> Result<(), ExtensionAssetPathError> {
    if value.is_empty() {
        return Err(ExtensionAssetPathError::new(
            value,
            "asset path must not be empty",
        ));
    }
    if value.contains('\0') || value.chars().any(char::is_control) {
        return Err(ExtensionAssetPathError::new(
            value,
            "NUL/control characters are not allowed",
        ));
    }
    if value.contains("://") {
        return Err(ExtensionAssetPathError::new(
            value,
            "URLs are not extension asset paths",
        ));
    }
    if value.starts_with('/') {
        return Err(ExtensionAssetPathError::new(
            value,
            "asset path must be relative",
        ));
    }
    if looks_like_windows_path(value) || value.contains('\\') {
        return Err(ExtensionAssetPathError::new(
            value,
            "host path separators are not allowed",
        ));
    }
    for segment in value.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ExtensionAssetPathError::new(
                value,
                "empty or dot path segments are not allowed",
            ));
        }
    }
    Ok(())
}

fn looks_like_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        || (bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/'))
}

/// Declarative runtime metadata for an extension package after boundary
/// validation has converted manifest strings into typed internal values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionRuntime {
    Wasm {
        module: ExtensionAssetPath,
    },
    Script {
        runner: String,
        image: Option<String>,
        command: String,
        args: Vec<String>,
    },
    Mcp {
        transport: String,
        command: Option<String>,
        args: Vec<String>,
        url: Option<String>,
    },
    FirstParty {
        service: String,
    },
    System {
        service: String,
    },
}

impl ExtensionRuntime {
    pub fn kind(&self) -> RuntimeKind {
        match self {
            Self::Wasm { .. } => RuntimeKind::Wasm,
            Self::Script { .. } => RuntimeKind::Script,
            Self::Mcp { .. } => RuntimeKind::Mcp,
            Self::FirstParty { .. } => RuntimeKind::FirstParty,
            Self::System { .. } => RuntimeKind::System,
        }
    }
}
