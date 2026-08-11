//! The single writer for the suggestions doc (spec §5): every mutation —
//! CAS claim, success result, failure — goes through `SuggestionsStore`.
//! Nothing else touches the mount. Backed by a `RootFilesystem` mount, one
//! JSON doc per `(tenant_id, user_id)`.

use std::sync::Arc;

use chrono::Utc;
use ironclaw_filesystem::{CasExpectation, Entry, FilesystemError, RecordVersion, RootFilesystem};
use ironclaw_host_api::ids::{TenantId, UserId};
use ironclaw_host_api::path::VirtualPath;
use thiserror::Error;
use uuid::Uuid;

use super::types::{ActiveJob, LastError, LastResult, SuggestionCard, SuggestionsDoc};

/// Bounded retry budget for the CAS read-modify-write loops below. A write
/// only retries on a genuine concurrent-writer conflict
/// (`FilesystemError::VersionMismatch`); anything else surfaces immediately.
const MAX_CAS_ATTEMPTS: u32 = 8;

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

#[derive(Clone)]
pub struct SuggestionsStore {
    filesystem: Arc<dyn RootFilesystem>,
}

impl SuggestionsStore {
    pub fn new(filesystem: Arc<dyn RootFilesystem>) -> Self {
        Self { filesystem }
    }

    /// Read the current doc. `None` (absent doc) derives the same view as an
    /// empty doc (spec §4) — callers pass `SuggestionsDoc::empty()` through
    /// `derive_suggestions_view` in that case.
    pub async fn read_doc(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Option<SuggestionsDoc>, SuggestionsStoreError> {
        Ok(self
            .read_versioned(tenant_id, user_id)
            .await?
            .map(|(doc, _)| doc))
    }

    /// Attempt to claim `active_job` for a new generation run. Fails closed
    /// toward dedupe: if a claim is already present the call returns
    /// `AlreadyClaimed` with that claim's `job_id` rather than overwriting
    /// it — callers that determined the existing claim's run is dead must
    /// clear it first via [`record_failure`](Self::record_failure) before
    /// calling this again.
    pub async fn claim_active_job(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        thread_id: ironclaw_host_api::ids::ThreadId,
        run_id: ironclaw_host_api::turn::TurnRunId,
    ) -> Result<ClaimOutcome, SuggestionsStoreError> {
        let path = doc_path(tenant_id, user_id)?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let (doc, cas) = match self.read_versioned(tenant_id, user_id).await? {
                Some((doc, version)) => (doc, CasExpectation::Version(version)),
                None => (SuggestionsDoc::empty(), CasExpectation::Absent),
            };
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
            match self.write_doc(&path, &next, cas).await {
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
        tenant_id: &TenantId,
        user_id: &UserId,
        job_id: Uuid,
        cards: Vec<SuggestionCard>,
    ) -> Result<(), SuggestionsStoreError> {
        self.apply_job_outcome(tenant_id, user_id, job_id, |doc| {
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
        tenant_id: &TenantId,
        user_id: &UserId,
        job_id: Uuid,
        message: String,
    ) -> Result<(), SuggestionsStoreError> {
        self.apply_job_outcome(tenant_id, user_id, job_id, |doc| {
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
        tenant_id: &TenantId,
        user_id: &UserId,
        job_id: Uuid,
        run_id: ironclaw_host_api::turn::TurnRunId,
    ) -> Result<(), SuggestionsStoreError> {
        self.apply_job_outcome(tenant_id, user_id, job_id, |doc| {
            if let Some(active_job) = doc.active_job.as_mut() {
                active_job.run_id = run_id;
            }
        })
        .await
    }

    async fn apply_job_outcome(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
        job_id: Uuid,
        mut apply: impl FnMut(&mut SuggestionsDoc),
    ) -> Result<(), SuggestionsStoreError> {
        let path = doc_path(tenant_id, user_id)?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let (doc, cas) = match self.read_versioned(tenant_id, user_id).await? {
                Some((doc, version)) => (doc, CasExpectation::Version(version)),
                None => (SuggestionsDoc::empty(), CasExpectation::Absent),
            };
            let superseded = doc
                .active_job
                .as_ref()
                .is_some_and(|active| active.job_id != job_id);
            if superseded {
                // A newer claim already replaced this job's slot; recording
                // this outcome would clobber it. Silently drop — the newer
                // run's own outcome is authoritative.
                return Ok(());
            }
            let mut next = doc;
            apply(&mut next);
            match self.write_doc(&path, &next, cas).await {
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

    // `pub(crate)`, not private: the CAS-race test below deliberately drives
    // stale reads and writes out of `claim_active_job`'s own retry loop to
    // deterministically force the exact interleaving CAS exists to resolve
    // (real concurrent execution against `InMemoryBackend` was tried first —
    // see that test's doc comment for why it can't be trusted to land the
    // race reliably).
    pub(crate) async fn read_versioned(
        &self,
        tenant_id: &TenantId,
        user_id: &UserId,
    ) -> Result<Option<(SuggestionsDoc, RecordVersion)>, SuggestionsStoreError> {
        let path = doc_path(tenant_id, user_id)?;
        let Some(entry) = self.filesystem.get(&path).await? else {
            return Ok(None);
        };
        let doc: SuggestionsDoc = serde_json::from_slice(&entry.entry.body).map_err(|error| {
            SuggestionsStoreError::Corrupt {
                reason: error.to_string(),
            }
        })?;
        if doc.schema_version != super::types::SUGGESTIONS_SCHEMA_VERSION {
            // Wrong schema version reads as absent (spec §4) — the caller
            // regenerates rather than migrating.
            return Ok(None);
        }
        Ok(Some((doc, entry.version)))
    }

    pub(crate) async fn write_doc(
        &self,
        path: &VirtualPath,
        doc: &SuggestionsDoc,
        cas: CasExpectation,
    ) -> Result<(), SuggestionsStoreError> {
        let body = serde_json::to_vec(doc).map_err(|error| SuggestionsStoreError::Corrupt {
            reason: error.to_string(),
        })?;
        self.filesystem.put(path, Entry::bytes(body), cas).await?;
        Ok(())
    }
}

fn doc_path(tenant_id: &TenantId, user_id: &UserId) -> Result<VirtualPath, SuggestionsStoreError> {
    VirtualPath::new(format!(
        "/tenants/{}/users/{}/suggestions/doc.json",
        tenant_id.as_str(),
        user_id.as_str()
    ))
    .map_err(|error| SuggestionsStoreError::InvalidPath {
        reason: error.to_string(),
    })
}
