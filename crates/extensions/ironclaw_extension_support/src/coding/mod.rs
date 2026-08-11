//! First-party coding capability engines.
//!
//! The v1 coding families (`read_file`/`write_file`/`list_dir`/`glob`/`grep`/
//! `apply_patch`) were retired at the omp cutover (issue #7392): the pinned
//! omp-parity engines under [`omp`] are the only coding surface, dispatched by
//! the host runtime's first-party omp adapter. This module keeps only what the
//! omp engines share — the bounded-input constants (`config`) and the mount
//! grant permission check (`paths`).

mod config;
mod paths;

/// Pinned omp-parity coding engines (issue #7392); wired to production
/// dispatch through the host runtime's first-party omp adapter.
#[doc(hidden)]
pub mod omp;
