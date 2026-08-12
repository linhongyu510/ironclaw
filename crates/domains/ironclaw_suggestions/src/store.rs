//! The single writer for the suggestions doc (spec §5): every mutation —
//! CAS claim, success result, failure — goes through `SuggestionsStore`.
//! Nothing else touches the mount. Backed by a `/suggestions` mount alias on
//! a [`ScopedFilesystem`], one JSON doc per `(tenant_id, user_id)` — the
//! [`ScopedFilesystem`] resolves the alias against its caller-supplied
//! [`ResourceScope`] and enforces per-grant ACL before backend dispatch, so
//! tenant/user isolation is structural rather than something this crate must
//! re-derive.

use std::sync::Arc;

use chrono::Utc;
use ironclaw_filesystem::{CasExpectation, Entry, FilesystemError, RecordVersion, RootFilesystem, ScopedFilesystem};
use ironclaw_host_api::path::ScopedPath;
use ironclaw_host_api::resource::ResourceScope;
use thiserror::Error;
use uuid::Uuid;

use super::types::{ActiveJob, LastError, LastResult, SuggestionCard, SuggestionsDoc};

/// Bounded retry budget for the CAS read-modify-write loops below. A write
/// only retries on a genuine concurrent-writer conflict
/// (`FilesystemError::VersionMismatch`); anything else surfaces immediately.
const MAX_CAS_ATTEMPTS: u32 = 8;

/// Mount-relative path for the single per-(tenant, user) suggestions
/// document. The `/suggestions` alias resolves through the caller's
/// `ResourceScope` to `/tenants/<tenant>/users/<user>/suggestions`, so this
/// suffix is constant across every scope.
const DOC_PATH: &str = "/suggestions/doc.json";

#[derive(Debug, Error)]
pub enum SuggestionsStoreError {
    #[error("invalid suggestions doc path: {reason}")]
    InvalidPath { reason: String },
    #[error("suggestions store backend error: {0}")]
    Backend(#[from] FilesystemError),
    #[error("stored suggestions doc is corrupt: {reason}")]
    Corrupt { reason: String },
    #[error("suggestions doc claim did not converge after {attempts} attempts")]
    ClaimContention { attempts: u32 },
}

/// Outcome of [`SuggestionsStore::claim_active_job`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// This call won the claim; `job_id` is the id to run generation under.
    Claimed { job_id: Uuid },
    /// A generation is already claimed (by this call or a concurrent
    /// racer) — the caller must not start a second run. `job_id` is the
    /// SAME id every racer observes, so both dedupe onto one run (spec §4:
    /// "the claim write MUST be compare-and-swap... concurrent POSTs must
    /// not start two loops").
    AlreadyClaimed { job_id: Uuid },
}

pub struct SuggestionsStore<F>
where
    F: RootFilesystem + ?Sized,
{
    filesystem: Arc<ScopedFilesystem<F>>,
}

impl<F> Clone for SuggestionsStore<F>
where
    F: RootFilesystem + ?Sized,
{
    fn clone(&self) -> Self {
        Self {
            filesystem: Arc::clone(&self.filesystem),
        }
    }
}

impl<F> SuggestionsStore<F>
where
    F: RootFilesystem + ?Sized,
{
    pub fn new(filesystem: Arc<ScopedFilesystem<F>>) -> Self {
        Self { filesystem }
    }

    /// Read the current doc. `None` (absent doc) derives the same view as an
    /// empty doc (spec §4) — callers pass `SuggestionsDoc::empty()` through
    /// `derive_suggestions_view` in that case.
    pub async fn read_doc(
        &self,
        scope: &ResourceScope,
    ) -> Result<Option<SuggestionsDoc>, SuggestionsStoreError> {
        Ok(match self.read_versioned(scope).await? {
            ReadOutcome::Current(doc, _) => Some(doc),
            ReadOutcome::Absent | ReadOutcome::Incompatible(_) => None,
        })
    }

    /// Attempt to claim `active_job` for a new generation run. Fails closed
    /// toward dedupe: if a claim is already present the call returns
    /// `AlreadyClaimed` with that claim's `job_id` rather than overwriting
    /// it — callers that determined the existing claim's run is dead must
    /// clear it first via [`record_failure`](Self::record_failure) before
    /// calling this again.
    pub async fn claim_active_job(
        &self,
        scope: &ResourceScope,
        thread_id: ironclaw_host_api::ids::ThreadId,
        run_id: ironclaw_host_api::turn::TurnRunId,
    ) -> Result<ClaimOutcome, SuggestionsStoreError> {
        let path = doc_path()?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let (doc, cas) = read_outcome_for_write(self.read_versioned(scope).await?);
            if let Some(active_job) = &doc.active_job {
                return Ok(ClaimOutcome::AlreadyClaimed {
                    job_id: active_job.job_id,
                });
            }
            let job_id = Uuid::new_v4();
            let mut next = doc;
            next.active_job = Some(ActiveJob {
                job_id,
                thread_id: thread_id.clone(),
                run_id,
                started_at: Utc::now(),
            });
            match self.write_doc(scope, &path, &next, cas).await {
                Ok(()) => return Ok(ClaimOutcome::Claimed { job_id }),
                Err(SuggestionsStoreError::Backend(FilesystemError::VersionMismatch {
                    ..
                })) => {
                    // A concurrent writer changed the doc between our read
                    // and write (or created it first) — re-read and retry.
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(SuggestionsStoreError::ClaimContention {
            attempts: MAX_CAS_ATTEMPTS,
        })
    }

    /// Record a successful generation and clear `active_job`. Idempotent
    /// per `job_id`: a second call for the same in-flight job overwrites
    /// (last write wins, spec §6). A call whose `job_id` no longer matches
    /// the doc's current `active_job` (a stale/superseded run) is a no-op —
    /// it must not clobber a newer claim.
    pub async fn record_result(
        &self,
        scope: &ResourceScope,
        job_id: Uuid,
        cards: Vec<SuggestionCard>,
    ) -> Result<(), SuggestionsStoreError> {
        self.apply_job_outcome(scope, job_id, |doc| {
            doc.active_job = None;
            doc.last_error = None;
            doc.last_result = Some(LastResult {
                cards: cards.clone(),
                completed_at: Utc::now(),
            });
        })
        .await
    }

    /// Record a failed generation and clear `active_job`. Same stale-job
    /// no-op guard as [`record_result`](Self::record_result). Also the
    /// mechanism for clearing a crash-recovery `active_job` before a fresh
    /// claim (spec §5): the caller passes the dead job's own `job_id`.
    pub async fn record_failure(
        &self,
        scope: &ResourceScope,
        job_id: Uuid,
        message: String,
    ) -> Result<(), SuggestionsStoreError> {
        self.apply_job_outcome(scope, job_id, |doc| {
            doc.active_job = None;
            doc.last_error = Some(LastError {
                message: message.clone(),
                failed_at: Utc::now(),
            });
        })
        .await
    }

    /// Corrects `active_job.run_id` to the run id the turn coordinator
    /// actually assigned. The caller mints a placeholder run id at claim time
    /// (needed before the real one is known — the hidden thread and the
    /// turn submission that mints it happen after the claim), so the doc
    /// briefly carries that placeholder; this call reconciles it once
    /// `TurnCoordinator::submit_turn` returns the authoritative id. Same
    /// stale-job no-op guard as [`record_result`](Self::record_result):
    /// a superseded claim's correction is silently dropped.
    pub async fn update_active_job_run_id(
        &self,
        scope: &ResourceScope,
        job_id: Uuid,
        run_id: ironclaw_host_api::turn::TurnRunId,
    ) -> Result<(), SuggestionsStoreError> {
        self.apply_job_outcome(scope, job_id, |doc| {
            if let Some(active_job) = doc.active_job.as_mut() {
                active_job.run_id = run_id;
            }
        })
        .await
    }

    async fn apply_job_outcome(
        &self,
        scope: &ResourceScope,
        job_id: Uuid,
        mut apply: impl FnMut(&mut SuggestionsDoc),
    ) -> Result<(), SuggestionsStoreError> {
        let path = doc_path()?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let (doc, cas) = read_outcome_for_write(self.read_versioned(scope).await?);
            let matches_active_job = doc
                .active_job
                .as_ref()
                .is_some_and(|active| active.job_id == job_id);
            if !matches_active_job {
                // Either a newer claim already replaced this job's slot, or
                // the slot was already cleared (this outcome is a late
                // duplicate of one already applied) — recording it now would
                // clobber unrelated state. Silently drop; the authoritative
                // writer for the current slot (if any) is responsible for
                // its own outcome.
                return Ok(());
            }
            let mut next = doc;
            apply(&mut next);
            match self.write_doc(scope, &path, &next, cas).await {
                Ok(()) => return Ok(()),
                Err(SuggestionsStoreError::Backend(FilesystemError::VersionMismatch {
                    ..
                })) => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(SuggestionsStoreError::ClaimContention {
            attempts: MAX_CAS_ATTEMPTS,
        })
    }

    async fn read_versioned(
        &self,
        scope: &ResourceScope,
    ) -> Result<ReadOutcome, SuggestionsStoreError> {
        let path = doc_path()?;
        let Some(entry) = self.filesystem.get(scope, &path).await? else {
            return Ok(ReadOutcome::Absent);
        };
        let doc: SuggestionsDoc = serde_json::from_slice(&entry.entry.body).map_err(|error| {
            SuggestionsStoreError::Corrupt {
                reason: error.to_string(),
            }
        })?;
        if doc.schema_version != super::types::SUGGESTIONS_SCHEMA_VERSION {
            // Wrong schema version reads as absent (spec §4) — the caller
            // regenerates rather than migrating — but the path DOES exist,
            // so its `RecordVersion` must be preserved for the write side:
            // a mutation CAS-ing against `Absent` here would conflict
            // forever against the still-present incompatible document.
            return Ok(ReadOutcome::Incompatible(entry.version));
        }
        Ok(ReadOutcome::Current(doc, entry.version))
    }

    async fn write_doc(
        &self,
        scope: &ResourceScope,
        path: &ScopedPath,
        doc: &SuggestionsDoc,
        cas: CasExpectation,
    ) -> Result<(), SuggestionsStoreError> {
        let body = serde_json::to_vec(doc).map_err(|error| SuggestionsStoreError::Corrupt {
            reason: error.to_string(),
        })?;
        self.filesystem
            .put(scope, path, Entry::bytes(body), cas)
            .await?;
        Ok(())
    }
}

/// Result of a version-tracked doc read, distinguishing "nothing at this
/// path" from "something exists but this store can't interpret it as the
/// current schema" — the two cases read alike to callers (both derive an
/// empty doc) but must CAS differently on write: an `Incompatible` document
/// still occupies the path, so overwriting it must expect its `RecordVersion`,
/// not `Absent`.
enum ReadOutcome {
    Absent,
    Incompatible(RecordVersion),
    Current(SuggestionsDoc, RecordVersion),
}

/// Resolves a [`ReadOutcome`] into the `(doc, CasExpectation)` pair every
/// read-modify-write loop in this store needs: a working (possibly empty)
/// doc to mutate, and the CAS expectation that correctly targets whatever is
/// actually at the path today.
fn read_outcome_for_write(outcome: ReadOutcome) -> (SuggestionsDoc, CasExpectation) {
    match outcome {
        ReadOutcome::Current(doc, version) => (doc, CasExpectation::Version(version)),
        ReadOutcome::Incompatible(version) => {
            (SuggestionsDoc::empty(), CasExpectation::Version(version))
        }
        ReadOutcome::Absent => (SuggestionsDoc::empty(), CasExpectation::Absent),
    }
}

fn doc_path() -> Result<ScopedPath, SuggestionsStoreError> {
    ScopedPath::new(DOC_PATH).map_err(|error| SuggestionsStoreError::InvalidPath {
        reason: error.to_string(),
    })
}
