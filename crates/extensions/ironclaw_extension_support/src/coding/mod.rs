//! First-party coding capability engines.
//!
//! The v1 coding families (`read_file`/`write_file`/`list_dir`/`glob`/`grep`/
//! `apply_patch`) were retired at the coding-tool cutover (issue #7392): the
//! pinned coding engines under [`pinned`] are the only coding surface, dispatched by
//! the host runtime's first-party coding adapter. This module keeps only what the
//! pinned coding engines share — the bounded-input constants (`config`) and the mount
//! grant permission check (`paths`).

mod config;

mod paths;

/// Pinned coding engines (issue #7392); wired to production
/// dispatch through the host runtime's first-party coding adapter.
#[doc(hidden)]
pub mod pinned;
