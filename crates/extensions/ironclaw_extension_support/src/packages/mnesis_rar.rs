//! Mnesis retrieval MCP package: the model-visible half of the integration,
//! paired with the `mnesis` memory provider's ambient half. Separate packages
//! because a v3 manifest declares `[runtime]` or `[mcp]`, never both.
//!
//! Not in [`super::PACKAGES`], like `nearai`: the shipped `[mcp].server` is a
//! placeholder the host rewrites from deployment configuration, which a
//! `fn() -> PackageBundle` cannot produce. The embeds live here; the patch
//! lives with the endpoint authority.

use std::borrow::Cow;

use super::{PackageAsset, PackageBundle, bytes_asset};

pub const MNESIS_RAR_ID: &str = "mnesis-rar";

pub const MNESIS_RAR_MANIFEST_ASSET_PATH: &str = "manifest.toml";

const MANIFEST: &str = include_str!("../../../packages/mnesis-rar/manifest.toml");

/// The package as shipped. Callers that dispatch its tools must replace
/// `manifest_toml` and the [`MNESIS_RAR_MANIFEST_ASSET_PATH`] asset with an
/// endpoint-patched manifest.
pub fn mnesis_rar_bundle() -> PackageBundle {
    PackageBundle {
        id: MNESIS_RAR_ID,
        display_name: "Mnesis Retrieval",
        manifest_toml: Cow::Borrowed(MANIFEST),
        assets: assets(),
        onboarding: None,
        trust_effects: None,
    }
}

fn assets() -> Vec<PackageAsset> {
    vec![
        bytes_asset(MNESIS_RAR_MANIFEST_ASSET_PATH, MANIFEST.as_bytes()),
        bytes_asset(
            "schemas/mnesis-rar/search_knowledge.input.v1.json",
            include_bytes!(
                "../../../packages/mnesis-rar/schemas/mnesis-rar/search_knowledge.input.v1.json"
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_bundle_carries_the_manifest_and_every_asset() {
        let bundle = mnesis_rar_bundle();
        assert_eq!(bundle.id, MNESIS_RAR_ID);
        assert_eq!(bundle.manifest_toml.as_ref(), MANIFEST);

        let paths = bundle
            .assets
            .iter()
            .map(|asset| asset.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec![
                "manifest.toml",
                "schemas/mnesis-rar/search_knowledge.input.v1.json",
            ]
        );
    }

    #[test]
    fn shipped_manifest_declares_the_placeholder_server_the_host_patches() {
        assert!(
            MANIFEST.contains("[mcp]"),
            "shipped manifest must declare an [mcp] table for the host to patch"
        );
        assert!(
            MANIFEST.contains("server = "),
            "shipped manifest must declare [mcp].server for the host to overwrite"
        );
        assert!(
            !MANIFEST.contains("[runtime]"),
            "an [mcp] manifest must not declare [runtime]; the two are exclusive"
        );
    }

    #[test]
    fn discovery_namespace_equals_the_extension_id() {
        assert!(
            MANIFEST.contains(&format!("namespace = \"{MNESIS_RAR_ID}\"")),
            "namespace must equal the extension id"
        );
    }
}
