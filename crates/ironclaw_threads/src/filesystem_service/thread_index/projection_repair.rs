//! Recovery for thread-index rows that exist durably but project no listing row.
//!
//! The sidebar reads the ordered projection, never the index directory, and the
//! projection only carries a row when the stored entry holds the listing keys.
//! A row written without them is therefore invisible to `list_threads` even
//! though its thread record, index record and messages are all intact — and
//! because a scope's completion marker suppresses the migration that would
//! rewrite it, nothing repairs it for the life of the volume.
//!
//! Kept beside the index query rather than inside it: this is migration-shaped
//! repair work, the same concern `startup_migration` and `transcript_migration`
//! own for their projections.

use ironclaw_filesystem::{
    CasExpectation, FileType, Filter, IndexValue, OrderedPage, Page, RootFilesystem, SortDirection,
};
use ironclaw_host_api::ids::ThreadId;

use crate::{FilesystemSessionThreadService, SessionThreadError, ThreadScope};

use super::{
    CURRENT_THREAD_INDEX_PROJECTION_VERSION, THREAD_ACTIVITY_SORT_KEY, THREAD_ID_INDEX_KEY,
    THREAD_INDEX_SUFFIX, THREAD_SCOPE_INDEX_KEY, ThreadIndexRecord, thread_activity_index_spec,
    thread_index_cache_key, thread_index_key, thread_index_name, thread_index_record_path,
    thread_index_root,
};
use crate::filesystem_service::{deserialize, invalid_path, is_not_found};

impl<F> FilesystemSessionThreadService<F>
where
    F: RootFilesystem,
{
    /// Repair rows the listing projection cannot see, when there are any.
    ///
    /// Discovery cannot run through the projection, because a damaged row is
    /// exactly what the projection is missing. It compares the durable index
    /// directory against the projected rows instead and only pays for repair
    /// when they disagree.
    ///
    /// Bounded on purpose: the comparison costs one directory listing and one
    /// capped query, and a scope holding more rows than [`Page::MAX_LIMIT`] is
    /// skipped rather than walked page by page. This runs inside a live listing
    /// request, so an unbounded scan would put a latency spike proportional to
    /// scope size on whichever request arrives first after a restart. Scopes
    /// that large keep their existing behaviour and are repaired by the
    /// explicit migration.
    pub(super) async fn reconcile_thread_index_projection(
        &self,
        scope: &ThreadScope,
    ) -> Result<(), SessionThreadError> {
        let root = thread_index_root(scope)?;
        let durable = match self
            .filesystem
            .list_dir(&scope.to_resource_scope(), &root)
            .await
        {
            Ok(entries) => entries,
            // A scope that has never written an index row has nothing to
            // reconcile; the initial migration owns that case.
            Err(error) if is_not_found(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let index_rows: Vec<&str> = durable
            .iter()
            .filter(|entry| entry.file_type == FileType::File)
            .filter_map(|entry| entry.name.strip_suffix(THREAD_INDEX_SUFFIX))
            .collect();
        if index_rows.is_empty() || index_rows.len() > Page::MAX_LIMIT as usize {
            return Ok(());
        }
        if self.count_projected_thread_index_rows(scope).await? >= index_rows.len() {
            return Ok(());
        }
        for raw_id in index_rows {
            let thread_id = ThreadId::new(raw_id.to_string()).map_err(invalid_path)?;
            self.restore_thread_index_projection(scope, &thread_id)
                .await?;
        }
        Ok(())
    }

    /// Count the rows the listing projection can actually see for `scope`.
    ///
    /// Capped at [`Page::MAX_LIMIT`]; callers only reach this after confirming
    /// the scope holds no more index rows than that, so a single query answers
    /// the comparison exactly.
    async fn count_projected_thread_index_rows(
        &self,
        scope: &ThreadScope,
    ) -> Result<usize, SessionThreadError> {
        let root = thread_index_root(scope)?;
        let page = OrderedPage::new(
            thread_index_name()?,
            thread_index_key(THREAD_ACTIVITY_SORT_KEY)?,
            thread_index_key(THREAD_ID_INDEX_KEY)?,
            SortDirection::Ascending,
            Page::MAX_LIMIT,
        );
        let rows = self
            .filesystem
            .query_ordered(
                &scope.to_resource_scope(),
                &root,
                &Filter::Eq {
                    key: thread_index_key(THREAD_SCOPE_INDEX_KEY)?,
                    value: IndexValue::Text(thread_index_cache_key(scope)),
                },
                &page,
            )
            .await?;
        Ok(rows.len())
    }

    /// Rewrite one index row so the ordered projection picks it up again.
    ///
    /// Writes the entry through `put` rather than the usual merge helper on
    /// purpose. `cas_update` skips the write whenever the decoded snapshot
    /// equals what it read, and that comparison sees only the record body,
    /// never the entry's indexed sidecar. A row whose body already matches a
    /// rebuild but whose keys are gone would take that no-op path and stay
    /// invisible while the repair reported success. Writing the entry directly
    /// keeps recovery independent of body equality, so it holds for every way a
    /// row can lose its keys rather than only for bodies that predate
    /// `projection_schema_version`.
    async fn restore_thread_index_projection(
        &self,
        scope: &ThreadScope,
        thread_id: &ThreadId,
    ) -> Result<(), SessionThreadError> {
        let path = thread_index_record_path(scope, thread_id)?;
        let Some(versioned) = self
            .filesystem
            .get(&scope.to_resource_scope(), &path)
            .await?
        else {
            return Ok(());
        };
        let mut record = deserialize::<ThreadIndexRecord>(&versioned.entry.body)?;
        // A row whose body disagrees with its own path is not ours to rewrite;
        // stale and cross-scope rows belong to the explicit migration.
        if record.record.scope != *scope || record.record.thread_id != *thread_id {
            return Ok(());
        }
        // The ordered projection needs every key the spec declares
        // (`scope_key`, `activity_sort`, `thread_id`), not just the partition
        // key: `query_ordered` filters on `scope_key` but sorts and paginates
        // on the other two, so a row missing either of them is just as
        // invisible to listing as one missing `scope_key` outright. Comparing
        // against what a fresh rebuild would set — rather than only checking
        // presence — also catches a row whose stored value has drifted from
        // what the current record would produce (e.g. a stale `activity_sort`
        // left behind by a body-only write).
        let rebuilt = Self::thread_index_entry(&record)?;
        let projection_current = thread_activity_index_spec()?
            .keys
            .iter()
            .all(|key| versioned.entry.indexed.get(key) == rebuilt.indexed.get(key));
        if projection_current {
            return Ok(());
        }
        record.projection_schema_version = CURRENT_THREAD_INDEX_PROJECTION_VERSION;
        self.filesystem
            .put(
                &scope.to_resource_scope(),
                &path,
                Self::thread_index_entry(&record)?,
                CasExpectation::Version(versioned.version),
            )
            .await?;
        self.mark_thread_index_known(scope, thread_id);
        Ok(())
    }
}
