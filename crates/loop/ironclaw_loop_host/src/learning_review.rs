//! Shared post-run learning review for the Reborn runtime.
//!
//! Every successful owned run can produce bounded memory candidates and one
//! skill-routing decision. This phase stores candidate records only. It does
//! not write provider memory, install skills, change the agent prompt, or send
//! user notifications.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, RwLock};

use async_trait::async_trait;
use ironclaw_filesystem::{
    CasExpectation, Entry, FilesystemError, Filter, Page, RootFilesystem, ScopedFilesystem,
};
use ironclaw_host_api::{path::ScopedPath, resource::ResourceScope};
use ironclaw_memory::{
    LearningAction, LearningCandidateInsert, LearningCandidateStore, LearningCandidateStoreError,
    LearningReview, LearningReviewRecord, LearningScope, MAX_LEARNING_UNRESOLVED_PROPOSALS,
};
use ironclaw_product_contracts::operator_llm::{LearningRuntimeController, LearningSettings};
use ironclaw_safety::LeakDetector;
use ironclaw_threads::{
    CompletedRunMessages, CompletedRunMessagesRequest, MessageKind, SessionThreadService,
    ThreadMessageRecord, ThreadScope,
};
use ironclaw_turns::{TurnError, TurnEventKind, TurnEventSink, TurnLifecycleEvent, TurnRunId};
use tokio::{sync::Semaphore, task::JoinHandle};

const TRANSCRIPT_READ_LIMIT: usize = 64;
const TRANSCRIPT_MAX_BYTES: usize = 16 * 1024;
const LEARNING_REVIEW_OUTPUT_MAX_BYTES: usize = 32 * 1024;
pub(crate) const LEARNING_REVIEW_MAX_TOKENS: u32 = 4_096;
const CANDIDATE_RECORD_MAX_BYTES: usize = 32 * 1024;
const MAX_CONCURRENT_REVIEWS: usize = 4;
const CANDIDATE_DIRECTORY: &str = "/tenant-shared/learning-candidates";
const LEARNING_REVIEW_SYSTEM_PROMPT: &str = include_str!("../prompts/learning_review.md");
/// Fan out the single turn-event sink slot to independent best-effort sinks.
pub struct CompositeTurnEventSink {
    sinks: Vec<Arc<dyn TurnEventSink>>,
}

impl CompositeTurnEventSink {
    pub fn new(sinks: Vec<Arc<dyn TurnEventSink>>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl TurnEventSink for CompositeTurnEventSink {
    async fn publish(&self, event: TurnLifecycleEvent) -> Result<(), TurnError> {
        for sink in &self.sinks {
            if let Err(error) = sink.publish(event.clone()).await {
                tracing::debug!(%error, "turn-event sink failed");
            }
        }
        Ok(())
    }
}

/// Live deployment-wide gate shared by settings and the turn-event sink.
pub struct LearningRuntimeControllerImpl {
    settings: RwLock<LearningSettings>,
}

impl LearningRuntimeControllerImpl {
    pub fn new(settings: LearningSettings) -> Self {
        Self {
            settings: RwLock::new(settings),
        }
    }

    pub fn enabled(&self) -> bool {
        match self.settings.read() {
            Ok(settings) => settings.enabled,
            Err(poisoned) => poisoned.into_inner().enabled,
        }
    }

    pub fn current_model(&self) -> Option<String> {
        match self.settings.read() {
            Ok(settings) => settings.model.clone(),
            Err(poisoned) => poisoned.into_inner().model.clone(),
        }
    }
}

impl Default for LearningRuntimeControllerImpl {
    fn default() -> Self {
        Self::new(LearningSettings::default())
    }
}

impl LearningRuntimeController for LearningRuntimeControllerImpl {
    fn apply(&self, settings: LearningSettings) {
        match self.settings.write() {
            Ok(mut current) => *current = settings,
            Err(poisoned) => *poisoned.into_inner() = settings,
        }
    }
}

#[derive(Debug)]
pub struct LearningInferenceError(String);

impl std::fmt::Display for LearningInferenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl LearningInferenceError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[async_trait]
pub trait LearningInferencePort: Send + Sync {
    async fn infer(&self, system: &str, user: &str) -> Result<String, LearningInferenceError>;
}

/// Durable candidate store. A run owns one immutable record, so an exclusive
/// CAS write makes repeated completion events idempotent without a mutex.
pub struct FilesystemLearningCandidateStore<F: RootFilesystem + ?Sized> {
    filesystem: Arc<ScopedFilesystem<F>>,
    storage_scope: ResourceScope,
}

impl<F: RootFilesystem + ?Sized> FilesystemLearningCandidateStore<F> {
    pub fn new(filesystem: Arc<ScopedFilesystem<F>>, storage_scope: ResourceScope) -> Self {
        Self {
            filesystem,
            storage_scope,
        }
    }

    fn directory(scope: &LearningScope) -> Result<ScopedPath, LearningCandidateStoreError> {
        let project = match scope.project_id() {
            Some(project) => format!("project-{}", project.as_str()),
            None => "project-none".to_string(),
        };
        ScopedPath::new(format!(
            "{CANDIDATE_DIRECTORY}/{}/{}/{}/{}",
            scope.tenant_id().as_str(),
            scope.user_id().as_str(),
            scope.agent_id().as_str(),
            project,
        ))
        .map_err(|error| {
            tracing::debug!(%error, "learning candidate path construction failed");
            LearningCandidateStoreError::InvalidData
        })
    }

    fn path(
        scope: &LearningScope,
        run_id: TurnRunId,
    ) -> Result<ScopedPath, LearningCandidateStoreError> {
        let directory = Self::directory(scope)?;
        ScopedPath::new(format!("{}/{}.json", directory.as_str(), run_id)).map_err(|error| {
            tracing::debug!(%error, ?run_id, "learning candidate path construction failed");
            LearningCandidateStoreError::InvalidData
        })
    }
}

#[async_trait]
impl<F: RootFilesystem + ?Sized> LearningCandidateStore for FilesystemLearningCandidateStore<F> {
    async fn insert_if_absent(
        &self,
        record: &LearningReviewRecord,
    ) -> Result<LearningCandidateInsert, LearningCandidateStoreError> {
        if record.idempotency_key.as_str() != format!("learning-review:{}", record.run_id) {
            return Err(LearningCandidateStoreError::InvalidData);
        }
        record
            .review
            .validate()
            .map_err(|_| LearningCandidateStoreError::InvalidData)?;
        let bytes = serde_json::to_vec(record).map_err(|error| {
            tracing::debug!(%error, run_id = ?record.run_id, "learning candidate serialization failed");
            LearningCandidateStoreError::InvalidData
        })?;
        if bytes.len() > CANDIDATE_RECORD_MAX_BYTES {
            return Err(LearningCandidateStoreError::InvalidData);
        }
        let path = Self::path(&record.scope, record.run_id)?;
        match self
            .filesystem
            .put(
                &self.storage_scope,
                &path,
                Entry::bytes(bytes),
                CasExpectation::Absent,
            )
            .await
        {
            Ok(_) => Ok(LearningCandidateInsert::Created),
            Err(FilesystemError::VersionMismatch { .. }) => {
                Ok(LearningCandidateInsert::AlreadyExists)
            }
            Err(error) => {
                tracing::debug!(%error, run_id = ?record.run_id, "learning candidate write failed");
                Err(LearningCandidateStoreError::Unavailable)
            }
        }
    }

    async fn get(
        &self,
        scope: &LearningScope,
        run_id: TurnRunId,
    ) -> Result<Option<LearningReviewRecord>, LearningCandidateStoreError> {
        let path = Self::path(scope, run_id)?;
        let Some(row) = self
            .filesystem
            .get(&self.storage_scope, &path)
            .await
            .map_err(|error| {
                tracing::debug!(%error, ?run_id, "learning candidate read failed");
                LearningCandidateStoreError::Unavailable
            })?
        else {
            return Ok(None);
        };
        let record: LearningReviewRecord =
            serde_json::from_slice(&row.entry.body).map_err(|error| {
                tracing::debug!(%error, ?run_id, "learning candidate deserialization failed");
                LearningCandidateStoreError::InvalidData
            })?;
        if &record.scope != scope
            || record.run_id != run_id
            || record.idempotency_key.as_str() != format!("learning-review:{run_id}")
        {
            return Err(LearningCandidateStoreError::InvalidData);
        }
        record
            .review
            .validate()
            .map_err(|_| LearningCandidateStoreError::InvalidData)?;
        Ok(Some(record))
    }

    async fn list_unresolved(
        &self,
        scope: &LearningScope,
    ) -> Result<Vec<LearningReviewRecord>, LearningCandidateStoreError> {
        let prefix = Self::directory(scope)?;
        let rows = match self
            .filesystem
            .query(
                &self.storage_scope,
                &prefix,
                &Filter::All,
                Page::first(MAX_LEARNING_UNRESOLVED_PROPOSALS),
            )
            .await
        {
            Ok(rows) => rows,
            Err(FilesystemError::NotFound { .. }) => return Ok(Vec::new()),
            Err(error) => {
                tracing::debug!(%error, "learning candidate query failed");
                return Err(LearningCandidateStoreError::Unavailable);
            }
        };
        rows.into_iter()
            .map(|row| {
                let record: LearningReviewRecord = serde_json::from_slice(&row.entry.body)
                    .map_err(|error| {
                        tracing::debug!(%error, "learning candidate deserialization failed");
                        LearningCandidateStoreError::InvalidData
                    })?;
                if &record.scope != scope
                    || record.idempotency_key.as_str()
                        != format!("learning-review:{}", record.run_id)
                {
                    return Err(LearningCandidateStoreError::InvalidData);
                }
                record
                    .review
                    .validate()
                    .map_err(|_| LearningCandidateStoreError::InvalidData)?;
                Ok(record)
            })
            .collect()
    }
}

/// Runtime-owned post-run tasks. Shutdown aborts all remaining model and store
/// work before their dependencies are dropped.
pub struct LearningReviewTasks {
    handles: Mutex<Vec<JoinHandle<()>>>,
    in_flight: Arc<Mutex<BTreeSet<TurnRunId>>>,
    permits: Arc<Semaphore>,
}

impl Default for LearningReviewTasks {
    fn default() -> Self {
        Self {
            handles: Mutex::new(Vec::new()),
            in_flight: Arc::new(Mutex::new(BTreeSet::new())),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_REVIEWS)),
        }
    }
}

impl LearningReviewTasks {
    pub fn new() -> Self {
        Self::default()
    }

    fn spawn(&self, job: LearningReviewJob) {
        let run_id = job.run_id;
        let permit = match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::debug!(
                    ?run_id,
                    limit = MAX_CONCURRENT_REVIEWS,
                    "learning review dropped because concurrency is saturated"
                );
                return;
            }
        };
        {
            let mut in_flight = match self.in_flight.lock() {
                Ok(in_flight) => in_flight,
                Err(poisoned) => poisoned.into_inner(),
            };
            if !in_flight.insert(run_id) {
                tracing::debug!(?run_id, "duplicate learning review dropped");
                return;
            }
        }
        let in_flight = Arc::clone(&self.in_flight);
        let handle = tokio::spawn(async move {
            let _permit = permit;
            job.run().await;
            match in_flight.lock() {
                Ok(mut in_flight) => {
                    in_flight.remove(&run_id);
                }
                Err(poisoned) => {
                    poisoned.into_inner().remove(&run_id);
                }
            }
        });
        let mut handles = match self.handles.lock() {
            Ok(handles) => handles,
            Err(poisoned) => poisoned.into_inner(),
        };
        handles.retain(|handle| !handle.is_finished());
        handles.push(handle);
    }

    pub async fn shutdown(&self) {
        let handles = {
            let mut handles = match self.handles.lock() {
                Ok(handles) => handles,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut *handles)
        };
        for handle in &handles {
            handle.abort();
        }
        for handle in handles {
            if let Err(error) = handle.await {
                if error.is_panic() {
                    tracing::error!(%error, "learning review task panicked during shutdown");
                } else {
                    tracing::debug!(%error, "learning review task cancelled during shutdown");
                }
            }
        }
        match self.in_flight.lock() {
            Ok(mut in_flight) => in_flight.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
    }
}

/// Successful-run subscriber for the shared learning router.
pub struct LearningReviewTurnEventSink {
    thread_service: Arc<dyn SessionThreadService>,
    inference: Arc<dyn LearningInferencePort>,
    candidate_store: Arc<dyn LearningCandidateStore>,
    tasks: Arc<LearningReviewTasks>,
    controller: Arc<LearningRuntimeControllerImpl>,
}

impl LearningReviewTurnEventSink {
    pub fn new(
        thread_service: Arc<dyn SessionThreadService>,
        inference: Arc<dyn LearningInferencePort>,
        candidate_store: Arc<dyn LearningCandidateStore>,
        tasks: Arc<LearningReviewTasks>,
        controller: Arc<LearningRuntimeControllerImpl>,
    ) -> Self {
        Self {
            thread_service,
            inference,
            candidate_store,
            tasks,
            controller,
        }
    }
}

#[async_trait]
impl TurnEventSink for LearningReviewTurnEventSink {
    async fn publish(&self, event: TurnLifecycleEvent) -> Result<(), TurnError> {
        if !matches!(event.kind, TurnEventKind::Completed) || !self.controller.enabled() {
            return Ok(());
        }
        let Some(user_id) = event
            .owner_user_id
            .clone()
            .or_else(|| event.scope.explicit_owner_user_id().cloned())
        else {
            return Ok(());
        };
        let Some(agent_id) = event.scope.agent_id.clone() else {
            return Ok(());
        };
        let thread_scope = ThreadScope {
            tenant_id: event.scope.tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: event.scope.project_id.clone(),
            owner_user_id: Some(user_id.clone()),
            mission_id: None,
        };
        let learning_scope = LearningScope::new(
            event.scope.tenant_id.clone(),
            user_id,
            agent_id,
            event.scope.project_id.clone(),
        );
        self.tasks.spawn(LearningReviewJob {
            thread_service: Arc::clone(&self.thread_service),
            inference: Arc::clone(&self.inference),
            candidate_store: Arc::clone(&self.candidate_store),
            controller: Arc::clone(&self.controller),
            thread_scope,
            thread_id: event.scope.thread_id.clone(),
            run_id: event.run_id,
            learning_scope,
        });
        Ok(())
    }
}

struct LearningReviewJob {
    thread_service: Arc<dyn SessionThreadService>,
    inference: Arc<dyn LearningInferencePort>,
    candidate_store: Arc<dyn LearningCandidateStore>,
    controller: Arc<LearningRuntimeControllerImpl>,
    thread_scope: ThreadScope,
    thread_id: ironclaw_host_api::ids::ThreadId,
    run_id: TurnRunId,
    learning_scope: LearningScope,
}

impl LearningReviewJob {
    async fn run(self) {
        if !self.controller.enabled() {
            return;
        }
        match self
            .candidate_store
            .get(&self.learning_scope, self.run_id)
            .await
        {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) => {
                tracing::debug!(?error, run_id = ?self.run_id, "learning idempotency check failed");
                return;
            }
        }
        let messages = match self
            .thread_service
            .list_completed_run_messages_bounded(CompletedRunMessagesRequest {
                scope: self.thread_scope,
                thread_id: self.thread_id,
                turn_run_id: self.run_id.to_string(),
                max_messages: TRANSCRIPT_READ_LIMIT,
                max_bytes: TRANSCRIPT_MAX_BYTES,
            })
            .await
        {
            Ok(CompletedRunMessages::Complete(messages)) => messages,
            Ok(CompletedRunMessages::LimitExceeded) => {
                tracing::debug!(run_id = ?self.run_id, "learning review transcript exceeded bounds");
                return;
            }
            Err(error) => {
                tracing::debug!(%error, run_id = ?self.run_id, "learning review transcript read failed");
                return;
            }
        };
        let transcript = format_transcript(&messages);
        if transcript.content.is_empty() || !self.controller.enabled() {
            return;
        }
        let unresolved_proposals = match self
            .candidate_store
            .list_unresolved(&self.learning_scope)
            .await
        {
            Ok(records) => records
                .into_iter()
                .flat_map(|record| record.review.memory)
                .take(MAX_LEARNING_UNRESOLVED_PROPOSALS as usize)
                .collect::<Vec<_>>(),
            Err(error) => {
                tracing::debug!(?error, run_id = ?self.run_id, "learning unresolved candidate read failed");
                Vec::new()
            }
        };
        let user_prompt = match serde_json::to_string(&serde_json::json!({
            "transcript": transcript.content.as_str(),
            "related_memories": [],
            "unresolved_proposals": unresolved_proposals,
        })) {
            Ok(prompt) => prompt,
            Err(error) => {
                tracing::debug!(%error, run_id = ?self.run_id, "learning review input encoding failed");
                return;
            }
        };
        let output = match self
            .inference
            .infer(LEARNING_REVIEW_SYSTEM_PROMPT, &user_prompt)
            .await
        {
            Ok(output) if output.len() <= LEARNING_REVIEW_OUTPUT_MAX_BYTES => output,
            Ok(_) => {
                tracing::debug!(
                    run_id = ?self.run_id,
                    limit = LEARNING_REVIEW_OUTPUT_MAX_BYTES,
                    "learning review provider output exceeded byte limit"
                );
                return;
            }
            Err(error) => {
                tracing::debug!(%error, run_id = ?self.run_id, "learning review inference failed");
                return;
            }
        };
        let review = match parse_review(&output)
            .and_then(|review| seal_review_sources(review, &transcript))
            .and_then(reject_secret_bearing_candidates)
        {
            Ok(review) => review,
            Err(reason) => {
                tracing::debug!(%reason, run_id = ?self.run_id, "learning review output rejected");
                return;
            }
        };
        if !self.controller.enabled() {
            return;
        }
        let record = match LearningReviewRecord::new(self.run_id, self.learning_scope, review) {
            Ok(record) => record,
            Err(error) => {
                tracing::debug!(?error, run_id = ?self.run_id, "learning review record rejected");
                return;
            }
        };
        if let Err(error) = self.candidate_store.insert_if_absent(&record).await {
            tracing::debug!(?error, run_id = ?self.run_id, "learning candidate persistence failed");
        }
    }
}

fn parse_review(output: &str) -> Result<LearningReview, &'static str> {
    if output.len() > LEARNING_REVIEW_OUTPUT_MAX_BYTES {
        return Err("output too large");
    }
    let review: LearningReview = serde_json::from_str(output).map_err(|_| "invalid JSON")?;
    review.validate().map_err(|_| "invalid learning review")?;
    Ok(review)
}

struct FormattedTranscript {
    content: String,
    source_indices: BTreeSet<u16>,
    tainted_indices: BTreeSet<u16>,
}

fn seal_review_sources(
    mut review: LearningReview,
    transcript: &FormattedTranscript,
) -> Result<LearningReview, &'static str> {
    let transcript_tainted = !transcript.tainted_indices.is_empty();
    for proposal in &mut review.memory {
        if !proposal
            .source_message_indices
            .iter()
            .all(|index| transcript.source_indices.contains(index))
        {
            return Err("unknown source message index");
        }
        proposal.tainted |= transcript_tainted
            || proposal
                .source_message_indices
                .iter()
                .any(|index| transcript.tainted_indices.contains(index));
    }
    if !review
        .skill
        .source_message_indices
        .iter()
        .all(|index| transcript.source_indices.contains(index))
    {
        return Err("unknown skill source message index");
    }
    if review.skill.action == LearningAction::Distill {
        review.skill.tainted |= transcript_tainted
            || review
                .skill
                .source_message_indices
                .iter()
                .any(|index| transcript.tainted_indices.contains(index));
    }
    Ok(review)
}

fn reject_secret_bearing_candidates(
    review: LearningReview,
) -> Result<LearningReview, &'static str> {
    let detector = LeakDetector::new();
    if review
        .memory
        .iter()
        .any(|proposal| !detector.scan(&proposal.content).is_clean())
        || review
            .skill
            .reason
            .as_deref()
            .is_some_and(|reason| !detector.scan(reason).is_clean())
    {
        return Err("secret detected in learning candidate");
    }
    Ok(review)
}

fn format_transcript(messages: &[ThreadMessageRecord]) -> FormattedTranscript {
    let mut output = String::new();
    let mut source_indices = BTreeSet::new();
    let mut tainted_indices = BTreeSet::new();
    for (index, message) in messages.iter().enumerate() {
        let role = match message.kind {
            MessageKind::User => "user",
            MessageKind::Assistant => "assistant",
            MessageKind::ToolResultReference => "tool_result",
            MessageKind::System => "system",
            _ => continue,
        };
        let Some(content) = message.content.as_deref() else {
            continue;
        };
        let mut line = format!("[{index}] {role}: ");
        if matches!(message.kind, MessageKind::ToolResultReference)
            && let Some(call) = message.tool_result_provider_call.as_ref()
        {
            line.push_str("capability=");
            line.push_str(call.capability_id.as_str());
            line.push(' ');
        }
        line.push_str(content);
        line.push('\n');
        if output.len().saturating_add(line.len()) > TRANSCRIPT_MAX_BYTES {
            break;
        }
        let Ok(index) = u16::try_from(index) else {
            break;
        };
        output.push_str(&line);
        source_indices.insert(index);
        if matches!(message.kind, MessageKind::ToolResultReference)
            || message.source_binding_id.is_some()
        {
            tainted_indices.insert(index);
        }
    }
    FormattedTranscript {
        content: output,
        source_indices,
        tainted_indices,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironclaw_host_api::ids::{AgentId, TenantId, ThreadId, UserId};
    use ironclaw_memory::{
        LearningAction, LearningDecision, LearningExplicitness, MemoryLearningProposal,
        MemoryLearningProposalKind,
    };
    use ironclaw_product_contracts::operator_llm::MemoryWritePolicy;
    use ironclaw_threads::{
        AppendToolResultReferenceRequest, EnsureThreadRequest, InMemorySessionThreadService,
        ToolResultSafeSummary,
    };
    use ironclaw_turns::{EventCursor, TurnScope, TurnStatus};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    #[test]
    fn review_semaphore_caps_concurrency_and_drops_newest() {
        let tasks = LearningReviewTasks::new();
        let held = (0..MAX_CONCURRENT_REVIEWS)
            .map(|_| {
                Arc::clone(&tasks.permits)
                    .try_acquire_owned()
                    .expect("configured review permit")
            })
            .collect::<Vec<_>>();
        assert!(
            Arc::clone(&tasks.permits).try_acquire_owned().is_err(),
            "the newest review must be dropped when all permits are held"
        );
        drop(held);
        assert!(Arc::clone(&tasks.permits).try_acquire_owned().is_ok());
    }

    #[test]
    fn parser_accepts_only_valid_bounded_reviews() {
        let review = LearningReview {
            memory: vec![MemoryLearningProposal {
                kind: MemoryLearningProposalKind::Fact,
                content: "The project uses Rust".to_string(),
                source_message_indices: vec![0],
                confidence_basis_points: 8_000,
                explicitness: LearningExplicitness::Explicit,
                tainted: false,
            }],
            skill: LearningDecision {
                action: LearningAction::Skip,
                reason: None,
                source_message_indices: Vec::new(),
                tainted: false,
            },
        };
        let json = serde_json::to_string(&review).expect("serialize");
        assert_eq!(parse_review(&json).expect("parse"), review);
        assert!(parse_review("```json\n{}\n```").is_err());
    }

    #[test]
    fn host_rejects_unknown_model_source_references() {
        let review = LearningReview {
            memory: vec![MemoryLearningProposal {
                kind: MemoryLearningProposalKind::Fact,
                content: "Unsupported claim".to_string(),
                source_message_indices: vec![1],

                confidence_basis_points: 8_000,
                explicitness: LearningExplicitness::Inferred,
                tainted: false,
            }],
            skill: LearningDecision::skip(),
        };
        let transcript = FormattedTranscript {
            content: "[0] user: hello".to_string(),
            source_indices: BTreeSet::from([0]),
            tainted_indices: BTreeSet::new(),
        };
        assert!(seal_review_sources(review, &transcript).is_err());
    }

    #[test]
    fn parser_rejects_oversized_provider_output_before_json_parse() {
        assert_eq!(
            parse_review(&"x".repeat(LEARNING_REVIEW_OUTPUT_MAX_BYTES + 1)),
            Err("output too large")
        );
    }

    #[test]
    fn host_rejects_secret_bearing_candidate_text() {
        let token = format!("ghp_{}", "x".repeat(36));
        let review = LearningReview {
            memory: vec![MemoryLearningProposal {
                kind: MemoryLearningProposalKind::Fact,
                content: token,
                source_message_indices: vec![0],
                confidence_basis_points: 8_000,
                explicitness: LearningExplicitness::Explicit,
                tainted: false,
            }],
            skill: LearningDecision::skip(),
        };
        assert_eq!(
            reject_secret_bearing_candidates(review),
            Err("secret detected in learning candidate")
        );
    }

    #[test]
    fn host_taints_skill_decisions_when_transcript_contains_untrusted_data() {
        let review = LearningReview {
            memory: Vec::new(),
            skill: LearningDecision {
                action: LearningAction::Distill,
                reason: Some("procedure".to_string()),
                source_message_indices: vec![0],
                tainted: false,
            },
        };
        let transcript = FormattedTranscript {
            content: "[0] system: child".to_string(),
            source_indices: BTreeSet::from([0]),
            tainted_indices: BTreeSet::from([0]),
        };
        let sealed = seal_review_sources(review, &transcript).expect("seal");
        assert!(sealed.skill.tainted);
    }
    #[test]
    fn transcript_budget_keeps_only_complete_lines() {
        let thread_id = ThreadId::new("learning-thread").expect("thread");
        let message = |sequence, content| ThreadMessageRecord {
            message_id: ironclaw_threads::ThreadMessageId::new(),
            thread_id: thread_id.clone(),
            sequence,
            kind: MessageKind::User,
            status: ironclaw_threads::MessageStatus::Accepted,
            created_at: None,
            updated_at: None,
            actor_id: None,
            source_binding_id: None,
            reply_target_binding_id: None,
            turn_id: None,
            turn_run_id: None,
            tool_result_ref: None,
            tool_result_provider_call: None,
            content: Some(content),
            attachments: Vec::new(),
            redaction_ref: None,
        };
        let transcript = format_transcript(&[
            message(1, "first".to_string()),
            message(2, "x".repeat(TRANSCRIPT_MAX_BYTES)),
        ]);
        assert_eq!(transcript.content, "[0] user: first\n");
        assert_eq!(transcript.source_indices, BTreeSet::from([0]));
    }

    struct RecordingInference {
        calls: AtomicUsize,
        users: Mutex<Vec<String>>,
        output: String,
    }

    #[async_trait]
    impl LearningInferencePort for RecordingInference {
        async fn infer(&self, _system: &str, user: &str) -> Result<String, LearningInferenceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.users
                .lock()
                .expect("users lock")
                .push(user.to_string());
            Ok(self.output.clone())
        }
    }

    #[derive(Default)]
    struct RecordingCandidateStore {
        records: Mutex<Vec<LearningReviewRecord>>,
        inserted: Notify,
    }

    #[async_trait]
    impl LearningCandidateStore for RecordingCandidateStore {
        async fn insert_if_absent(
            &self,
            record: &LearningReviewRecord,
        ) -> Result<LearningCandidateInsert, LearningCandidateStoreError> {
            self.records
                .lock()
                .expect("records lock")
                .push(record.clone());
            self.inserted.notify_one();
            Ok(LearningCandidateInsert::Created)
        }

        async fn get(
            &self,
            scope: &LearningScope,
            run_id: TurnRunId,
        ) -> Result<Option<LearningReviewRecord>, LearningCandidateStoreError> {
            Ok(self
                .records
                .lock()
                .expect("records lock")
                .iter()
                .find(|record| &record.scope == scope && record.run_id == run_id)
                .cloned())
        }

        async fn list_unresolved(
            &self,
            scope: &LearningScope,
        ) -> Result<Vec<LearningReviewRecord>, LearningCandidateStoreError> {
            Ok(self
                .records
                .lock()
                .expect("records lock")
                .iter()
                .filter(|record| &record.scope == scope)
                .take(MAX_LEARNING_UNRESOLVED_PROPOSALS as usize)
                .cloned()
                .collect())
        }
    }

    #[tokio::test]
    async fn completed_owned_run_routes_and_persists_a_candidate_record() {
        let tenant_id = TenantId::new("learning-tenant").expect("tenant");
        let user_id = UserId::new("learning-user").expect("user");
        let agent_id = AgentId::new("learning-agent").expect("agent");
        let thread_id = ThreadId::new("learning-thread").expect("thread");
        let thread_scope = ThreadScope {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            project_id: None,
            owner_user_id: Some(user_id.clone()),
            mission_id: None,
        };
        let run_id = TurnRunId::new();
        let threads = Arc::new(InMemorySessionThreadService::default());
        threads
            .ensure_thread(EnsureThreadRequest {
                scope: thread_scope,
                thread_id: Some(thread_id.clone()),
                created_by_actor_id: user_id.as_str().to_string(),
                title: None,
                metadata_json: None,
            })
            .await
            .expect("ensure thread");
        threads
            .append_tool_result_reference(AppendToolResultReferenceRequest {
                intrinsic_outcome: None,
                scope: ThreadScope {
                    tenant_id: tenant_id.clone(),
                    agent_id: agent_id.clone(),
                    project_id: None,
                    owner_user_id: Some(user_id.clone()),
                    mission_id: None,
                },
                thread_id: thread_id.clone(),
                turn_run_id: run_id.to_string(),
                result_ref: "result:learning".to_string(),
                safe_summary: ToolResultSafeSummary::new("The user prefers concise status reports")
                    .expect("summary"),
                provider_call: None,
                model_observation: None,
            })
            .await
            .expect("append result");

        let inference = Arc::new(RecordingInference {
            calls: AtomicUsize::new(0),
            users: Mutex::new(Vec::new()),
            output: serde_json::json!({
                "memory": [{
                    "kind": "preference",
                    "content": "The user prefers concise status reports",
                    "source_message_indices": [0],
                    "confidence_basis_points": 9000,
                    "explicitness": "explicit",
                    "tainted": false
                }],
                "skill": {
                    "action": "skip",
                    "reason": null,
                    "source_message_indices": []
                }
            })
            .to_string(),
        });
        let store = Arc::new(RecordingCandidateStore::default());
        store.records.lock().expect("records lock").push(
            LearningReviewRecord::new(
                TurnRunId::new(),
                LearningScope::new(tenant_id.clone(), user_id.clone(), agent_id.clone(), None),
                LearningReview {
                    memory: vec![MemoryLearningProposal {
                        kind: MemoryLearningProposalKind::Fact,
                        content: "An unresolved prior candidate".to_string(),
                        source_message_indices: vec![0],
                        confidence_basis_points: 7_000,
                        explicitness: LearningExplicitness::Inferred,
                        tainted: false,
                    }],
                    skill: LearningDecision::skip(),
                },
            )
            .expect("prior record"),
        );
        let controller = Arc::new(LearningRuntimeControllerImpl::new(LearningSettings {
            enabled: true,
            model: Some("learning-model".to_string()),
            memory_write_policy: MemoryWritePolicy::Staged,
        }));
        let tasks = Arc::new(LearningReviewTasks::new());
        let sink = LearningReviewTurnEventSink::new(
            threads,
            inference.clone(),
            store.clone(),
            Arc::clone(&tasks),
            controller,
        );
        let event = TurnLifecycleEvent {
            cursor: EventCursor::default(),
            scope: TurnScope::new_with_owner(
                tenant_id,
                Some(agent_id),
                None,
                thread_id,
                Some(user_id.clone()),
            ),
            occurred_at: None,
            owner_user_id: Some(user_id),
            run_id,
            status: TurnStatus::Completed,
            kind: TurnEventKind::Completed,
            blocked_gate: None,
            sanitized_reason: None,
            detail: None,
            retryable: None,
        };
        sink.publish(event.clone()).await.expect("publish");
        sink.publish(event).await.expect("replay publish");

        tokio::time::timeout(std::time::Duration::from_secs(1), store.inserted.notified())
            .await
            .expect("candidate insert");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(inference.calls.load(Ordering::SeqCst), 1);
        {
            let users = inference.users.lock().expect("users lock");
            let input: serde_json::Value =
                serde_json::from_str(&users[0]).expect("learning input JSON");
            assert_eq!(
                input["unresolved_proposals"]
                    .as_array()
                    .expect("unresolved proposals")
                    .len(),
                1
            );
        }
        {
            let records = store.records.lock().expect("records lock");
            assert_eq!(records.len(), 2);
            let record = records.last().expect("new record");
            assert_eq!(record.run_id, run_id);
            assert_eq!(record.scope.user_id().as_str(), "learning-user");
            assert_eq!(record.review.memory.len(), 1);
            assert!(
                record.review.memory[0].tainted,
                "the host must taint tool-derived proposals even when the model says false"
            );
        }
        tasks.shutdown().await;
    }
}
