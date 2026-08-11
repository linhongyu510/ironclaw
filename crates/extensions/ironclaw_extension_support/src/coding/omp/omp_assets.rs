//! Compile-embedded omp registration assets (issue #7392 slice 3).
//!
//! The model-visible omp descriptions and input schemas are pinned contract
//! bytes owned by this crate. They are embedded HERE with single-segment
//! `include_str!` paths (inside the owning crate root) and exposed as public
//! constants so downstream crates — `ironclaw_host_runtime`'s
//! test-support-gated omp registration — resolve them through this crate's
//! public API instead of cross-crate reach-ins (see
//! `ironclaw_architecture_tests::reborn_cross_crate_include_scan`, §11.2.7).
//!
//! The `omp_registration_assets_byte_match_pinned_fixtures` root test keeps
//! these byte-identical to `tests/fixtures/omp_coding_contract/`.

/// Pinned model-visible `read` tool description (the RENDERED prompt;
/// `read` is the issue-target context).
pub const OMP_READ_DESCRIPTION: &str = include_str!("assets/prompts/read.rendered.md");
/// Pinned model-visible `write` tool description.
pub const OMP_WRITE_DESCRIPTION: &str = include_str!("assets/prompts/write.md");
/// Pinned model-visible `edit` tool description (the hashline prompt).
pub const OMP_EDIT_DESCRIPTION: &str = include_str!("assets/prompts/hashline.md");
/// Pinned model-visible `glob` tool description.
pub const OMP_GLOB_DESCRIPTION: &str = include_str!("assets/prompts/glob.md");
/// Pinned model-visible `grep` tool description.
pub const OMP_GREP_DESCRIPTION: &str = include_str!("assets/prompts/grep.md");

/// Pinned `read` input schema.
pub const OMP_READ_SCHEMA: &str = include_str!("assets/schemas/read.json");
/// Pinned `write` input schema.
pub const OMP_WRITE_SCHEMA: &str = include_str!("assets/schemas/write.json");
/// Pinned `edit` input schema.
pub const OMP_EDIT_SCHEMA: &str = include_str!("assets/schemas/edit.json");
/// Pinned `glob` input schema.
pub const OMP_GLOB_SCHEMA: &str = include_str!("assets/schemas/glob.json");
/// Pinned `grep` input schema.
pub const OMP_GREP_SCHEMA: &str = include_str!("assets/schemas/grep.json");
