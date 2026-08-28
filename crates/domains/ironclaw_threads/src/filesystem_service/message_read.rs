//! Bounded transcript materialization for filesystem-backed exports.

use serde::Deserialize;

use ironclaw_filesystem::{OrderedPage, OrderedQueryCursor, Page, RootFilesystem, SortDirection};
use ironclaw_host_api::ids::ThreadId;
use ironclaw_host_api::turn::TurnRunId;

use crate::{MessageKind, MessageStatus, SessionThreadError, ThreadMessageRecord, ThreadScope};

use super::{
    FilesystemSessionThreadService, deserialize, fs_index_key, message_sequence_index_spec,
    messages_root, thread_partition_filter,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct MessageReadBudget {
    remaining_messages: usize,
    remaining_bytes: usize,
}

impl MessageReadBudget {
    pub(super) fn new(max_messages: usize, max_bytes: usize) -> Self {
        Self {
            remaining_messages: max_messages,
            remaining_bytes: max_bytes,
        }
    }

    fn page_limit(self) -> u32 {
        self.remaining_messages
            .saturating_add(1)
            .min(Page::MAX_LIMIT as usize) as u32
    }

    fn consume(&mut self, bytes: usize) -> bool {
        if self.remaining_messages == 0 || bytes > self.remaining_bytes {
            return false;
        }
        self.remaining_messages -= 1;
        self.remaining_bytes -= bytes;
        true
    }
}

pub(super) enum MessageReadResult {
    Complete(Vec<ThreadMessageRecord>),
    LimitExceeded,
}

impl<F> FilesystemSessionThreadService<F>
where
    F: RootFilesystem + 'static,
{
    pub(super) async fn read_thread_messages(
        &self,
        scope: &ThreadScope,
        thread_id: &ThreadId,
        mut budget: Option<MessageReadBudget>,
    ) -> Result<MessageReadResult, SessionThreadError> {
        self.ensure_transcript_indexes_migrated(scope).await?;
        let root = messages_root(scope, thread_id)?;
        let index = message_sequence_index_spec()?;
        let sequence_key = fs_index_key("sequence")?;
        let message_id_key = fs_index_key("message_id")?;
        let mut messages = Vec::new();
        let mut cursor = None;

        loop {
            let page_limit = budget
                .map(MessageReadBudget::page_limit)
                .unwrap_or(Page::MAX_LIMIT)
                .max(1);
            let mut page = OrderedPage::new(
                index.name.clone(),
                sequence_key.clone(),
                message_id_key.clone(),
                SortDirection::Ascending,
                page_limit,
            );
            if let Some(after) = cursor.take() {
                page = page.after(after);
            }
            let entries = match self
                .filesystem
                .query_ordered(
                    &scope.to_resource_scope(),
                    &root,
                    &thread_partition_filter(thread_id)?,
                    &page,
                )
                .await
            {
                Ok(entries) => entries,
                Err(error) => return Err(error.into()),
            };
            let entry_count = entries.len();
            for versioned in &entries {
                if !versioned.path.as_str().ends_with(".json") {
                    continue;
                }
                if let Some(remaining) = budget.as_mut()
                    && !remaining.consume(versioned.entry.body.len())
                {
                    return Ok(MessageReadResult::LimitExceeded);
                }
                let record = deserialize::<ThreadMessageRecord>(&versioned.entry.body)?;
                if &record.thread_id == thread_id {
                    messages.push(record);
                }
            }
            cursor = entries
                .last()
                .map(|entry| {
                    let value =
                        entry
                            .entry
                            .indexed
                            .get(&sequence_key)
                            .cloned()
                            .ok_or_else(|| {
                                SessionThreadError::Backend(
                                    "ordered message row is missing sequence index".to_string(),
                                )
                            })?;
                    let tie_breaker = entry
                        .entry
                        .indexed
                        .get(&message_id_key)
                        .cloned()
                        .ok_or_else(|| {
                            SessionThreadError::Backend(
                                "ordered message row is missing message_id index".to_string(),
                            )
                        })?;
                    Ok::<_, SessionThreadError>(OrderedQueryCursor { value, tie_breaker })
                })
                .transpose()?;
            if entry_count < page_limit as usize {
                break;
            }
        }

        messages.sort_by_key(|message| message.sequence);
        Ok(MessageReadResult::Complete(messages))
    }
}

#[derive(Deserialize)]
struct MessageRunIdentity<'a> {
    #[serde(borrow)]
    turn_run_id: Option<&'a str>,
    #[serde(borrow)]
    source_binding_id: Option<&'a str>,
    kind: MessageKind,
    status: MessageStatus,
}

impl<F> FilesystemSessionThreadService<F>
where
    F: RootFilesystem + 'static,
{
    pub(super) async fn read_completed_run_messages(
        &self,
        scope: &ThreadScope,
        thread_id: &ThreadId,
        turn_run_id: TurnRunId,
        max_messages: usize,
        max_bytes: usize,
    ) -> Result<MessageReadResult, SessionThreadError> {
        self.ensure_transcript_indexes_migrated(scope).await?;
        let root = messages_root(scope, thread_id)?;
        let index = message_sequence_index_spec()?;
        let sequence_key = fs_index_key("sequence")?;
        let message_id_key = fs_index_key("message_id")?;
        let run_id = turn_run_id.to_string();
        let subagent_binding = format!("subagent-result:{run_id}");
        let mut budget = MessageReadBudget::new(max_messages, max_bytes);
        let mut messages = Vec::new();
        let mut cursor = None;
        let mut seen_match = false;
        loop {
            let page_limit = budget.page_limit().max(1);
            let mut page = OrderedPage::new(
                index.name.clone(),
                sequence_key.clone(),
                message_id_key.clone(),
                SortDirection::Descending,
                page_limit,
            );
            if let Some(after) = cursor.take() {
                page = page.after(after);
            }
            let entries = self
                .filesystem
                .query_ordered(
                    &scope.to_resource_scope(),
                    &root,
                    &thread_partition_filter(thread_id)?,
                    &page,
                )
                .await?;
            let entry_count = entries.len();
            let mut older_nonmatch = false;
            for versioned in &entries {
                if !versioned.path.as_str().ends_with(".json") {
                    continue;
                }
                let identity: MessageRunIdentity<'_> =
                    serde_json::from_slice(&versioned.entry.body).map_err(|error| {
                        SessionThreadError::Backend(format!(
                            "invalid transcript message identity: {error}"
                        ))
                    })?;
                let run_match = identity.turn_run_id == Some(run_id.as_str());
                let binding_match = identity.source_binding_id == Some(subagent_binding.as_str())
                    && identity.kind == MessageKind::System
                    && identity.status == MessageStatus::Finalized;
                if !run_match && !binding_match {
                    if seen_match && identity.turn_run_id.is_some() {
                        older_nonmatch = true;
                    }
                    continue;
                }
                seen_match = true;
                if !budget.consume(versioned.entry.body.len()) {
                    return Ok(MessageReadResult::LimitExceeded);
                }
                let record = deserialize::<ThreadMessageRecord>(&versioned.entry.body)?;
                if &record.thread_id == thread_id {
                    messages.push(record);
                }
            }
            cursor = entries
                .last()
                .map(|entry| {
                    Ok::<_, SessionThreadError>(OrderedQueryCursor {
                        value: entry.entry.indexed.get(&sequence_key).cloned().ok_or_else(
                            || {
                                SessionThreadError::Backend(
                                    "ordered message row is missing sequence index".to_string(),
                                )
                            },
                        )?,
                        tie_breaker: entry
                            .entry
                            .indexed
                            .get(&message_id_key)
                            .cloned()
                            .ok_or_else(|| {
                                SessionThreadError::Backend(
                                    "ordered message row is missing message_id index".to_string(),
                                )
                            })?,
                    })
                })
                .transpose()?;
            if older_nonmatch || entry_count < page_limit as usize {
                break;
            }
        }
        messages.sort_by_key(|message| message.sequence);
        Ok(MessageReadResult::Complete(messages))
    }
}
