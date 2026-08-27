use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ironclaw_libsql_runtime::{
    LibSqlReadConnectionLease, LibSqlRuntime, LibSqlWriteConnectionLease,
};
use libsql::{Row, Value, params};

use crate::{
    CollectorCoverage, HourlyAutomationUsage, HourlyModelUsage, HourlyRunFailure,
    HourlyUserActivity, LifecycleEvent, TelemetryBatch,
    error::TelemetryRepositoryError,
    repository::{
        TelemetryPage, TelemetryRepository, TelemetryScanPageRequest, automation_text,
        decode_collector_id, decode_cursor, decode_event_id, decode_failure_category,
        decode_model_id, decode_provider_id, decode_subject_id, decode_tenant_id, decode_user_id,
        encode_cursor, lifecycle_event_text, lifecycle_subject_text, origin_text, page_rows,
        parse_automation, parse_event, parse_origin, parse_subject, timestamp_text,
    },
};

const MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS telemetry_hourly_user_activity_v0 (
  tenant_id TEXT NOT NULL,
  window_start TEXT NOT NULL,
  user_id TEXT NOT NULL,
  origin_kind TEXT NOT NULL CHECK (origin_kind IN ('human','parent_agent','system','automation','other')),
  run_count INTEGER NOT NULL CHECK (run_count >= 0),
  runs_with_reported_tool_calls_count INTEGER NOT NULL CHECK (runs_with_reported_tool_calls_count >= 0),
  tool_count_reported_run_count INTEGER NOT NULL CHECK (tool_count_reported_run_count >= 0),
  reported_tool_call_count INTEGER NOT NULL CHECK (reported_tool_call_count >= 0),
  completed_count INTEGER NOT NULL CHECK (completed_count >= 0),
  failed_count INTEGER NOT NULL CHECK (failed_count >= 0),
  cancelled_count INTEGER NOT NULL CHECK (cancelled_count >= 0),
  recovery_required_count INTEGER NOT NULL CHECK (recovery_required_count >= 0),
  total_run_latency_ms INTEGER NOT NULL CHECK (total_run_latency_ms >= 0),
  first_observed_at TEXT NOT NULL,
  last_observed_at TEXT NOT NULL,
  schema_version INTEGER NOT NULL CHECK (schema_version = 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, window_start, user_id, origin_kind),
  CHECK (completed_count + failed_count + cancelled_count + recovery_required_count = run_count),
  CHECK (runs_with_reported_tool_calls_count <= tool_count_reported_run_count),
  CHECK (tool_count_reported_run_count <= run_count)
);
CREATE INDEX IF NOT EXISTS telemetry_activity_tenant_user_time_v0
  ON telemetry_hourly_user_activity_v0 (tenant_id, user_id, window_start);
CREATE TABLE IF NOT EXISTS telemetry_hourly_model_usage_v0 (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  window_start TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  effective_model_id TEXT NOT NULL,
  inference_count INTEGER NOT NULL CHECK (inference_count >= 0),
  usage_reported_count INTEGER NOT NULL CHECK (usage_reported_count >= 0),
  input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
  output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
  cache_read_input_tokens INTEGER NOT NULL CHECK (cache_read_input_tokens >= 0),
  cache_creation_input_tokens INTEGER NOT NULL CHECK (cache_creation_input_tokens >= 0),
  first_observed_at TEXT NOT NULL,
  last_observed_at TEXT NOT NULL,
  schema_version INTEGER NOT NULL CHECK (schema_version = 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, user_id, window_start, provider_id, effective_model_id),
  CHECK (usage_reported_count <= inference_count)
);
CREATE INDEX IF NOT EXISTS telemetry_model_tenant_time_model_v0
  ON telemetry_hourly_model_usage_v0 (tenant_id, window_start, provider_id, effective_model_id);
CREATE TABLE IF NOT EXISTS telemetry_hourly_run_failures_v0 (
  tenant_id TEXT NOT NULL,
  window_start TEXT NOT NULL,
  user_id TEXT NOT NULL,
  failure_category TEXT NOT NULL,
  failure_count INTEGER NOT NULL CHECK (failure_count >= 0),
  first_observed_at TEXT NOT NULL,
  last_observed_at TEXT NOT NULL,
  schema_version INTEGER NOT NULL CHECK (schema_version = 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, window_start, user_id, failure_category)
);
CREATE TABLE IF NOT EXISTS telemetry_hourly_automation_usage_v0 (
  tenant_id TEXT NOT NULL,
  window_start TEXT NOT NULL,
  user_id TEXT NOT NULL,
  automation_kind TEXT NOT NULL CHECK (automation_kind IN ('cron','once','manual')),
  run_count INTEGER NOT NULL CHECK (run_count >= 0),
  completed_count INTEGER NOT NULL CHECK (completed_count >= 0),
  failed_count INTEGER NOT NULL CHECK (failed_count >= 0),
  cancelled_count INTEGER NOT NULL CHECK (cancelled_count >= 0),
  recovery_required_count INTEGER NOT NULL CHECK (recovery_required_count >= 0),
  first_observed_at TEXT NOT NULL,
  last_observed_at TEXT NOT NULL,
  schema_version INTEGER NOT NULL CHECK (schema_version = 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, window_start, user_id, automation_kind),
  CHECK (completed_count + failed_count + cancelled_count + recovery_required_count = run_count)
);
CREATE TABLE IF NOT EXISTS telemetry_lifecycle_events_v0 (
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  user_id TEXT,
  event_kind TEXT NOT NULL,
  subject_kind TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  schema_version INTEGER NOT NULL CHECK (schema_version = 0),
  PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS telemetry_lifecycle_tenant_time_v0
  ON telemetry_lifecycle_events_v0 (tenant_id, occurred_at, event_id);
CREATE INDEX IF NOT EXISTS telemetry_lifecycle_subject_history_v0
  ON telemetry_lifecycle_events_v0 (tenant_id, subject_kind, subject_id, occurred_at, event_id);
CREATE TABLE IF NOT EXISTS telemetry_collector_hourly_v0 (
  tenant_id TEXT NOT NULL,
  window_start TEXT NOT NULL,
  collector_instance_id TEXT NOT NULL,
  accepted_observation_count INTEGER NOT NULL CHECK (accepted_observation_count >= 0),
  queue_full_drop_count INTEGER NOT NULL CHECK (queue_full_drop_count >= 0),
  closed_drop_count INTEGER NOT NULL CHECK (closed_drop_count >= 0),
  invalid_drop_count INTEGER NOT NULL CHECK (invalid_drop_count >= 0),
  write_failed_observation_count INTEGER NOT NULL CHECK (write_failed_observation_count >= 0),
  first_observed_at TEXT NOT NULL,
  last_observed_at TEXT NOT NULL,
  schema_version INTEGER NOT NULL CHECK (schema_version = 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, window_start, collector_instance_id)
);
"#;

/// libSQL telemetry adapter. The runtime is admitted by composition and is
/// never constructed or selected by this repository.
pub(crate) struct LibSqlTelemetryRepository {
    runtime: Arc<LibSqlRuntime>,
}

impl LibSqlTelemetryRepository {
    pub(crate) fn from_runtime(runtime: Arc<LibSqlRuntime>) -> Self {
        Self { runtime }
    }

    async fn writer(
        &self,
        operation: &'static str,
    ) -> Result<LibSqlWriteConnectionLease, TelemetryRepositoryError> {
        self.runtime
            .write()
            .await
            .map_err(|source| TelemetryRepositoryError::StorageAdmission {
                operation,
                source: Box::new(source),
            })
    }

    async fn reader(
        &self,
        operation: &'static str,
    ) -> Result<LibSqlReadConnectionLease, TelemetryRepositoryError> {
        self.runtime
            .read()
            .await
            .map_err(|source| TelemetryRepositoryError::StorageAdmission {
                operation,
                source: Box::new(source),
            })
    }

    async fn transaction_batch(
        &self,
        batch: &TelemetryBatch,
    ) -> Result<(), TelemetryRepositoryError> {
        let connection = self.writer("acquiring telemetry batch writer").await?;
        let transaction = connection
            .transaction_with_behavior(libsql::TransactionBehavior::Immediate)
            .await
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "beginning telemetry batch transaction",
                source: Box::new(source),
            })?;
        for row in batch.activity() {
            check_activity_overflow(&transaction, row).await?;
        }
        for row in batch.model_usage() {
            check_model_overflow(&transaction, row).await?;
        }
        for row in batch.run_failures() {
            check_failure_overflow(&transaction, row).await?;
        }
        for row in batch.automation_usage() {
            check_automation_overflow(&transaction, row).await?;
        }
        for row in batch.collector_coverage() {
            check_coverage_overflow(&transaction, row).await?;
        }
        for row in batch.activity() {
            upsert_activity(&transaction, row).await?;
        }
        for row in batch.model_usage() {
            upsert_model(&transaction, row).await?;
        }
        for row in batch.run_failures() {
            upsert_failure(&transaction, row).await?;
        }
        for row in batch.automation_usage() {
            upsert_automation(&transaction, row).await?;
        }
        for row in batch.lifecycle_events() {
            upsert_lifecycle(&transaction, row).await?;
        }
        for row in batch.collector_coverage() {
            upsert_coverage(&transaction, row).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "committing telemetry batch transaction",
                source: Box::new(source),
            })
    }
}

impl From<Arc<LibSqlRuntime>> for crate::TelemetryRepositoryAdapter {
    fn from(runtime: Arc<LibSqlRuntime>) -> Self {
        crate::TelemetryRepositoryAdapter {
            inner: Arc::new(LibSqlTelemetryRepository::from_runtime(runtime)),
        }
    }
}

#[async_trait]
impl TelemetryRepository for LibSqlTelemetryRepository {
    async fn migrate(&self) -> Result<(), TelemetryRepositoryError> {
        let connection = self.writer("acquiring telemetry migration writer").await?;
        let transaction = connection
            .transaction_with_behavior(libsql::TransactionBehavior::Immediate)
            .await
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "beginning telemetry migration transaction",
                source: Box::new(source),
            })?;
        transaction
            .execute_batch(MIGRATION)
            .await
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "running telemetry migration",
                source: Box::new(source),
            })?;
        transaction
            .commit()
            .await
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "committing telemetry migration",
                source: Box::new(source),
            })
    }

    async fn upsert_batch(&self, batch: &TelemetryBatch) -> Result<(), TelemetryRepositoryError> {
        self.transaction_batch(batch).await
    }

    async fn scan_activity_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyUserActivity>, TelemetryRepositoryError> {
        let range = request.range();
        let to = range.effective_to();
        if range.from() >= to {
            return Ok(TelemetryPage::new(Vec::new(), None));
        }
        let connection = self.reader("acquiring telemetry activity reader").await?;
        let (sql, bind) = activity_query(request, &range.tenant_id().to_string(), to)?;
        let mut rows = connection.query(&sql, bind).await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "scanning telemetry activity",
                source: Box::new(source),
            }
        })?;
        let mut values = Vec::new();
        while let Some(row) =
            rows.next()
                .await
                .map_err(|source| TelemetryRepositoryError::StorageOperation {
                    operation: "reading telemetry activity",
                    source: Box::new(source),
                })?
        {
            values.push(activity_from_row(&row)?);
        }
        let (values, has_more) = page_rows(values, request.page_size());
        let next = has_more
            .then(|| {
                values.last().map(|row| {
                    encode_cursor(
                        row.window_start(),
                        &[row.user_id().as_str(), origin_text(row.origin_kind())],
                    )
                })
            })
            .flatten();
        Ok(TelemetryPage::new(values, next))
    }

    async fn scan_model_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyModelUsage>, TelemetryRepositoryError> {
        let range = request.range();
        let to = range.effective_to();
        if range.from() >= to {
            return Ok(TelemetryPage::new(Vec::new(), None));
        }
        let connection = self.reader("acquiring telemetry model reader").await?;
        let (sql, bind) = model_query(request, &range.tenant_id().to_string(), to)?;
        let mut rows = connection.query(&sql, bind).await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "scanning telemetry model usage",
                source: Box::new(source),
            }
        })?;
        let mut values = Vec::new();
        while let Some(row) =
            rows.next()
                .await
                .map_err(|source| TelemetryRepositoryError::StorageOperation {
                    operation: "reading telemetry model usage",
                    source: Box::new(source),
                })?
        {
            values.push(model_from_row(&row)?);
        }
        let (values, has_more) = page_rows(values, request.page_size());
        let next = has_more
            .then(|| {
                values.last().map(|row| {
                    encode_cursor(
                        row.window_start(),
                        &[
                            row.user_id().as_str(),
                            row.provider_id().as_str(),
                            row.effective_model_id().as_str(),
                        ],
                    )
                })
            })
            .flatten();
        Ok(TelemetryPage::new(values, next))
    }

    async fn scan_failure_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyRunFailure>, TelemetryRepositoryError> {
        let range = request.range();
        let to = range.effective_to();
        if range.from() >= to {
            return Ok(TelemetryPage::new(Vec::new(), None));
        }
        let connection = self.reader("acquiring telemetry failure reader").await?;
        let (sql, bind) = failure_query(request, &range.tenant_id().to_string(), to)?;
        let mut rows = connection.query(&sql, bind).await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "scanning telemetry failures",
                source: Box::new(source),
            }
        })?;
        let mut values = Vec::new();
        while let Some(row) =
            rows.next()
                .await
                .map_err(|source| TelemetryRepositoryError::StorageOperation {
                    operation: "reading telemetry failures",
                    source: Box::new(source),
                })?
        {
            values.push(failure_from_row(&row)?);
        }
        let (values, has_more) = page_rows(values, request.page_size());
        let next = has_more
            .then(|| {
                values.last().map(|row| {
                    encode_cursor(
                        row.window_start(),
                        &[row.user_id().as_str(), row.failure_category().as_str()],
                    )
                })
            })
            .flatten();
        Ok(TelemetryPage::new(values, next))
    }

    async fn scan_automation_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyAutomationUsage>, TelemetryRepositoryError> {
        let range = request.range();
        let to = range.effective_to();
        if range.from() >= to {
            return Ok(TelemetryPage::new(Vec::new(), None));
        }
        let connection = self.reader("acquiring telemetry automation reader").await?;
        let (sql, bind) = automation_query(request, &range.tenant_id().to_string(), to)?;
        let mut rows = connection.query(&sql, bind).await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "scanning telemetry automation",
                source: Box::new(source),
            }
        })?;
        let mut values = Vec::new();
        while let Some(row) =
            rows.next()
                .await
                .map_err(|source| TelemetryRepositoryError::StorageOperation {
                    operation: "reading telemetry automation",
                    source: Box::new(source),
                })?
        {
            values.push(automation_from_row(&row)?);
        }
        let (values, has_more) = page_rows(values, request.page_size());
        let next = has_more
            .then(|| {
                values.last().map(|row| {
                    encode_cursor(
                        row.window_start(),
                        &[
                            row.user_id().as_str(),
                            automation_text(row.automation_kind()),
                        ],
                    )
                })
            })
            .flatten();
        Ok(TelemetryPage::new(values, next))
    }

    async fn scan_lifecycle_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<LifecycleEvent>, TelemetryRepositoryError> {
        let range = request.range();
        let to = range.effective_to();
        if range.from() >= to {
            return Ok(TelemetryPage::new(Vec::new(), None));
        }
        let connection = self.reader("acquiring telemetry lifecycle reader").await?;
        let (sql, bind) = lifecycle_query(request, &range.tenant_id().to_string(), to)?;
        let mut rows = connection.query(&sql, bind).await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "scanning telemetry lifecycle",
                source: Box::new(source),
            }
        })?;
        let mut values = Vec::new();
        while let Some(row) =
            rows.next()
                .await
                .map_err(|source| TelemetryRepositoryError::StorageOperation {
                    operation: "reading telemetry lifecycle",
                    source: Box::new(source),
                })?
        {
            values.push(lifecycle_from_row(&row)?);
        }
        let (values, has_more) = page_rows(values, request.page_size());
        let next = has_more
            .then(|| {
                values
                    .last()
                    .map(|row| encode_cursor(row.occurred_at(), &[row.event_id().as_str()]))
            })
            .flatten();
        Ok(TelemetryPage::new(values, next))
    }

    async fn scan_coverage_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<CollectorCoverage>, TelemetryRepositoryError> {
        let range = request.range();
        let to = range.effective_to();
        if range.from() >= to {
            return Ok(TelemetryPage::new(Vec::new(), None));
        }
        let connection = self.reader("acquiring telemetry coverage reader").await?;
        let (sql, bind) = coverage_query(request, &range.tenant_id().to_string(), to)?;
        let mut rows = connection.query(&sql, bind).await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "scanning telemetry coverage",
                source: Box::new(source),
            }
        })?;
        let mut values = Vec::new();
        while let Some(row) =
            rows.next()
                .await
                .map_err(|source| TelemetryRepositoryError::StorageOperation {
                    operation: "reading telemetry coverage",
                    source: Box::new(source),
                })?
        {
            values.push(coverage_from_row(&row)?);
        }
        let (values, has_more) = page_rows(values, request.page_size());
        let next = has_more
            .then(|| {
                values.last().map(|row| {
                    encode_cursor(row.window_start(), &[row.collector_instance_id().as_str()])
                })
            })
            .flatten();
        Ok(TelemetryPage::new(values, next))
    }
}

async fn upsert_activity(
    tx: &libsql::Transaction,
    row: &HourlyUserActivity,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_hourly_user_activity_v0 (tenant_id,window_start,user_id,origin_kind,run_count,runs_with_reported_tool_calls_count,tool_count_reported_run_count,reported_tool_call_count,completed_count,failed_count,cancelled_count,recovery_required_count,total_run_latency_ms,first_observed_at,last_observed_at,schema_version,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?) ON CONFLICT(tenant_id,window_start,user_id,origin_kind) DO UPDATE SET run_count=telemetry_hourly_user_activity_v0.run_count+excluded.run_count,runs_with_reported_tool_calls_count=telemetry_hourly_user_activity_v0.runs_with_reported_tool_calls_count+excluded.runs_with_reported_tool_calls_count,tool_count_reported_run_count=telemetry_hourly_user_activity_v0.tool_count_reported_run_count+excluded.tool_count_reported_run_count,reported_tool_call_count=telemetry_hourly_user_activity_v0.reported_tool_call_count+excluded.reported_tool_call_count,completed_count=telemetry_hourly_user_activity_v0.completed_count+excluded.completed_count,failed_count=telemetry_hourly_user_activity_v0.failed_count+excluded.failed_count,cancelled_count=telemetry_hourly_user_activity_v0.cancelled_count+excluded.cancelled_count,recovery_required_count=telemetry_hourly_user_activity_v0.recovery_required_count+excluded.recovery_required_count,total_run_latency_ms=telemetry_hourly_user_activity_v0.total_run_latency_ms+excluded.total_run_latency_ms,first_observed_at=MIN(telemetry_hourly_user_activity_v0.first_observed_at,excluded.first_observed_at),last_observed_at=MAX(telemetry_hourly_user_activity_v0.last_observed_at,excluded.last_observed_at),updated_at=excluded.updated_at", params![row.tenant_id().as_str(), timestamp_text(row.window_start()), row.user_id().as_str(), origin_text(row.origin_kind()), row.run_count() as i64, row.runs_with_reported_tool_calls_count() as i64, row.tool_count_reported_run_count() as i64, row.reported_tool_call_count() as i64, row.completed_count() as i64, row.failed_count() as i64, row.cancelled_count() as i64, row.recovery_required_count() as i64, row.total_run_latency_ms() as i64, timestamp_text(row.first_observed_at()), timestamp_text(row.last_observed_at()), timestamp_text(row.last_observed_at())]).await.map_err(|source| TelemetryRepositoryError::StorageOperation { operation: "upserting telemetry activity", source: Box::new(source) }).map(|_| ())
}

async fn check_activity_overflow(
    tx: &libsql::Transaction,
    row: &HourlyUserActivity,
) -> Result<(), TelemetryRepositoryError> {
    let mut rows = tx.query("SELECT run_count,runs_with_reported_tool_calls_count,tool_count_reported_run_count,reported_tool_call_count,completed_count,failed_count,cancelled_count,recovery_required_count,total_run_latency_ms FROM telemetry_hourly_user_activity_v0 WHERE tenant_id=? AND window_start=? AND user_id=? AND origin_kind=?", params![row.tenant_id().as_str(),timestamp_text(row.window_start()),row.user_id().as_str(),origin_text(row.origin_kind())]).await.map_err(|source|TelemetryRepositoryError::StorageOperation {operation:"checking telemetry activity overflow",source: Box::new(source)})?;
    if let Some(existing) =
        rows.next()
            .await
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "reading telemetry activity overflow",
                source: Box::new(source),
            })?
    {
        for (idx, incoming) in [
            row.run_count(),
            row.runs_with_reported_tool_calls_count(),
            row.tool_count_reported_run_count(),
            row.reported_tool_call_count(),
            row.completed_count(),
            row.failed_count(),
            row.cancelled_count(),
            row.recovery_required_count(),
            row.total_run_latency_ms(),
        ]
        .into_iter()
        .enumerate()
        {
            check_libsql_counter(&existing, idx, incoming, "activity")?;
        }
    }
    Ok(())
}

async fn check_model_overflow(
    tx: &libsql::Transaction,
    row: &HourlyModelUsage,
) -> Result<(), TelemetryRepositoryError> {
    let mut rows=tx.query("SELECT inference_count,usage_reported_count,input_tokens,output_tokens,cache_read_input_tokens,cache_creation_input_tokens FROM telemetry_hourly_model_usage_v0 WHERE tenant_id=? AND user_id=? AND window_start=? AND provider_id=? AND effective_model_id=?",params![row.tenant_id().as_str(),row.user_id().as_str(),timestamp_text(row.window_start()),row.provider_id().as_str(),row.effective_model_id().as_str()]).await.map_err(|source|TelemetryRepositoryError::StorageOperation {operation:"checking telemetry model overflow",source: Box::new(source)})?;
    if let Some(existing) =
        rows.next()
            .await
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "reading telemetry model overflow",
                source: Box::new(source),
            })?
    {
        for (idx, incoming) in [
            row.inference_count(),
            row.usage_reported_count(),
            row.input_tokens(),
            row.output_tokens(),
            row.cache_read_input_tokens(),
            row.cache_creation_input_tokens(),
        ]
        .into_iter()
        .enumerate()
        {
            check_libsql_counter(&existing, idx, incoming, "model")?;
        }
    }
    Ok(())
}
async fn check_failure_overflow(
    tx: &libsql::Transaction,
    row: &HourlyRunFailure,
) -> Result<(), TelemetryRepositoryError> {
    let mut rows=tx.query("SELECT failure_count FROM telemetry_hourly_run_failures_v0 WHERE tenant_id=? AND window_start=? AND user_id=? AND failure_category=?",params![row.tenant_id().as_str(),timestamp_text(row.window_start()),row.user_id().as_str(),row.failure_category().as_str()]).await.map_err(|source|TelemetryRepositoryError::StorageOperation {operation:"checking telemetry failure overflow",source: Box::new(source)})?;
    if let Some(existing) =
        rows.next()
            .await
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "reading telemetry failure overflow",
                source: Box::new(source),
            })?
    {
        check_libsql_counter(&existing, 0, row.failure_count(), "failure")?;
    }
    Ok(())
}
async fn check_automation_overflow(
    tx: &libsql::Transaction,
    row: &HourlyAutomationUsage,
) -> Result<(), TelemetryRepositoryError> {
    let mut rows=tx.query("SELECT run_count,completed_count,failed_count,cancelled_count,recovery_required_count FROM telemetry_hourly_automation_usage_v0 WHERE tenant_id=? AND window_start=? AND user_id=? AND automation_kind=?",params![row.tenant_id().as_str(),timestamp_text(row.window_start()),row.user_id().as_str(),automation_text(row.automation_kind())]).await.map_err(|source|TelemetryRepositoryError::StorageOperation {operation:"checking telemetry automation overflow",source: Box::new(source)})?;
    if let Some(existing) =
        rows.next()
            .await
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "reading telemetry automation overflow",
                source: Box::new(source),
            })?
    {
        for (idx, incoming) in [
            row.run_count(),
            row.completed_count(),
            row.failed_count(),
            row.cancelled_count(),
            row.recovery_required_count(),
        ]
        .into_iter()
        .enumerate()
        {
            check_libsql_counter(&existing, idx, incoming, "automation")?;
        }
    }
    Ok(())
}
async fn check_coverage_overflow(
    tx: &libsql::Transaction,
    row: &CollectorCoverage,
) -> Result<(), TelemetryRepositoryError> {
    let mut rows=tx.query("SELECT accepted_observation_count,queue_full_drop_count,closed_drop_count,invalid_drop_count,write_failed_observation_count FROM telemetry_collector_hourly_v0 WHERE tenant_id=? AND window_start=? AND collector_instance_id=?",params![row.tenant_id().as_str(),timestamp_text(row.window_start()),row.collector_instance_id().as_str()]).await.map_err(|source|TelemetryRepositoryError::StorageOperation {operation:"checking telemetry coverage overflow",source: Box::new(source)})?;
    if let Some(existing) =
        rows.next()
            .await
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "reading telemetry coverage overflow",
                source: Box::new(source),
            })?
    {
        for (idx, incoming) in [
            row.accepted_observation_count(),
            row.queue_full_drop_count(),
            row.closed_drop_count(),
            row.invalid_drop_count(),
            row.write_failed_observation_count(),
        ]
        .into_iter()
        .enumerate()
        {
            check_libsql_counter(&existing, idx, incoming, "coverage")?;
        }
    }
    Ok(())
}
fn check_libsql_counter(
    row: &Row,
    index: usize,
    incoming: u64,
    family: &'static str,
) -> Result<(), TelemetryRepositoryError> {
    let current: i64 =
        row.get(index as i32)
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "decoding telemetry overflow counter",
                source: Box::new(source),
            })?;
    crate::repository::checked_counter_sum(current, incoming, family)
}

async fn upsert_model(
    tx: &libsql::Transaction,
    row: &HourlyModelUsage,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_hourly_model_usage_v0 (tenant_id,user_id,window_start,provider_id,effective_model_id,inference_count,usage_reported_count,input_tokens,output_tokens,cache_read_input_tokens,cache_creation_input_tokens,first_observed_at,last_observed_at,schema_version,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,?) ON CONFLICT(tenant_id,user_id,window_start,provider_id,effective_model_id) DO UPDATE SET inference_count=telemetry_hourly_model_usage_v0.inference_count+excluded.inference_count,usage_reported_count=telemetry_hourly_model_usage_v0.usage_reported_count+excluded.usage_reported_count,input_tokens=telemetry_hourly_model_usage_v0.input_tokens+excluded.input_tokens,output_tokens=telemetry_hourly_model_usage_v0.output_tokens+excluded.output_tokens,cache_read_input_tokens=telemetry_hourly_model_usage_v0.cache_read_input_tokens+excluded.cache_read_input_tokens,cache_creation_input_tokens=telemetry_hourly_model_usage_v0.cache_creation_input_tokens+excluded.cache_creation_input_tokens,first_observed_at=MIN(telemetry_hourly_model_usage_v0.first_observed_at,excluded.first_observed_at),last_observed_at=MAX(telemetry_hourly_model_usage_v0.last_observed_at,excluded.last_observed_at),updated_at=excluded.updated_at", params![row.tenant_id().as_str(), row.user_id().as_str(), timestamp_text(row.window_start()), row.provider_id().as_str(), row.effective_model_id().as_str(), row.inference_count() as i64, row.usage_reported_count() as i64, row.input_tokens() as i64, row.output_tokens() as i64, row.cache_read_input_tokens() as i64, row.cache_creation_input_tokens() as i64, timestamp_text(row.first_observed_at()), timestamp_text(row.last_observed_at()), timestamp_text(row.last_observed_at())]).await.map_err(|source| TelemetryRepositoryError::StorageOperation { operation: "upserting telemetry model usage", source: Box::new(source) }).map(|_| ())
}

async fn upsert_failure(
    tx: &libsql::Transaction,
    row: &HourlyRunFailure,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_hourly_run_failures_v0 (tenant_id,window_start,user_id,failure_category,failure_count,first_observed_at,last_observed_at,schema_version,updated_at) VALUES (?,?,?,?,?,?,?,0,?) ON CONFLICT(tenant_id,window_start,user_id,failure_category) DO UPDATE SET failure_count=telemetry_hourly_run_failures_v0.failure_count+excluded.failure_count,first_observed_at=MIN(telemetry_hourly_run_failures_v0.first_observed_at,excluded.first_observed_at),last_observed_at=MAX(telemetry_hourly_run_failures_v0.last_observed_at,excluded.last_observed_at),updated_at=excluded.updated_at", params![row.tenant_id().as_str(), timestamp_text(row.window_start()), row.user_id().as_str(), row.failure_category().as_str(), row.failure_count() as i64, timestamp_text(row.first_observed_at()), timestamp_text(row.last_observed_at()), timestamp_text(row.last_observed_at())]).await.map_err(|source| TelemetryRepositoryError::StorageOperation { operation: "upserting telemetry failure", source: Box::new(source) }).map(|_| ())
}

async fn upsert_automation(
    tx: &libsql::Transaction,
    row: &HourlyAutomationUsage,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_hourly_automation_usage_v0 (tenant_id,window_start,user_id,automation_kind,run_count,completed_count,failed_count,cancelled_count,recovery_required_count,first_observed_at,last_observed_at,schema_version,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,0,?) ON CONFLICT(tenant_id,window_start,user_id,automation_kind) DO UPDATE SET run_count=telemetry_hourly_automation_usage_v0.run_count+excluded.run_count,completed_count=telemetry_hourly_automation_usage_v0.completed_count+excluded.completed_count,failed_count=telemetry_hourly_automation_usage_v0.failed_count+excluded.failed_count,cancelled_count=telemetry_hourly_automation_usage_v0.cancelled_count+excluded.cancelled_count,recovery_required_count=telemetry_hourly_automation_usage_v0.recovery_required_count+excluded.recovery_required_count,first_observed_at=MIN(telemetry_hourly_automation_usage_v0.first_observed_at,excluded.first_observed_at),last_observed_at=MAX(telemetry_hourly_automation_usage_v0.last_observed_at,excluded.last_observed_at),updated_at=excluded.updated_at", params![row.tenant_id().as_str(), timestamp_text(row.window_start()), row.user_id().as_str(), automation_text(row.automation_kind()), row.run_count() as i64, row.completed_count() as i64, row.failed_count() as i64, row.cancelled_count() as i64, row.recovery_required_count() as i64, timestamp_text(row.first_observed_at()), timestamp_text(row.last_observed_at()), timestamp_text(row.last_observed_at())]).await.map_err(|source| TelemetryRepositoryError::StorageOperation { operation: "upserting telemetry automation", source: Box::new(source) }).map(|_| ())
}

async fn upsert_lifecycle(
    tx: &libsql::Transaction,
    row: &LifecycleEvent,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_lifecycle_events_v0 (tenant_id,event_id,user_id,event_kind,subject_kind,subject_id,occurred_at,schema_version) VALUES (?,?,?,?,?,?,?,0) ON CONFLICT(tenant_id,event_id) DO NOTHING", params![row.tenant_id().as_str(), row.event_id().as_str(), row.user_id().map(|id| id.as_str()), lifecycle_event_text(row.event_kind()), lifecycle_subject_text(row.subject_kind()), row.subject_id().as_str(), timestamp_text(row.occurred_at())]).await.map_err(|source| TelemetryRepositoryError::StorageOperation { operation: "upserting telemetry lifecycle", source: Box::new(source) }).map(|_| ())
}

async fn upsert_coverage(
    tx: &libsql::Transaction,
    row: &CollectorCoverage,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_collector_hourly_v0 (tenant_id,window_start,collector_instance_id,accepted_observation_count,queue_full_drop_count,closed_drop_count,invalid_drop_count,write_failed_observation_count,first_observed_at,last_observed_at,schema_version,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,0,?) ON CONFLICT(tenant_id,window_start,collector_instance_id) DO UPDATE SET accepted_observation_count=telemetry_collector_hourly_v0.accepted_observation_count+excluded.accepted_observation_count,queue_full_drop_count=telemetry_collector_hourly_v0.queue_full_drop_count+excluded.queue_full_drop_count,closed_drop_count=telemetry_collector_hourly_v0.closed_drop_count+excluded.closed_drop_count,invalid_drop_count=telemetry_collector_hourly_v0.invalid_drop_count+excluded.invalid_drop_count,write_failed_observation_count=telemetry_collector_hourly_v0.write_failed_observation_count+excluded.write_failed_observation_count,first_observed_at=MIN(telemetry_collector_hourly_v0.first_observed_at,excluded.first_observed_at),last_observed_at=MAX(telemetry_collector_hourly_v0.last_observed_at,excluded.last_observed_at),updated_at=excluded.updated_at", params![row.tenant_id().as_str(), timestamp_text(row.window_start()), row.collector_instance_id().as_str(), row.accepted_observation_count() as i64, row.queue_full_drop_count() as i64, row.closed_drop_count() as i64, row.invalid_drop_count() as i64, row.write_failed_observation_count() as i64, timestamp_text(row.first_observed_at()), timestamp_text(row.last_observed_at()), timestamp_text(row.last_observed_at())]).await.map_err(|source| TelemetryRepositoryError::StorageOperation { operation: "upserting telemetry coverage", source: Box::new(source) }).map(|_| ())
}

type LibSqlParams = libsql::params::Params;

fn params(values: impl IntoIterator<Item = Value>) -> LibSqlParams {
    LibSqlParams::Positional(values.into_iter().collect())
}

fn text_value(value: impl Into<String>) -> Value {
    Value::Text(value.into())
}

fn optional_text_value(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |value| Value::Text(value.to_owned()))
}

fn integer_value(value: i64) -> Value {
    Value::Integer(value)
}

fn activity_query(
    request: &TelemetryScanPageRequest,
    tenant: &str,
    to: DateTime<Utc>,
) -> Result<(String, LibSqlParams), TelemetryRepositoryError> {
    let range = request.range();
    let from = timestamp_text(range.from());
    let to = timestamp_text(to);
    let limit = (request.page_size() + 1) as i64;
    let mut values = vec![text_value(tenant), text_value(from), text_value(to)];
    let predicate = if let Some(cursor) = request.after() {
        let (window, fields) = decode_cursor(cursor, 2)?;
        values.extend([
            text_value(timestamp_text(window)),
            text_value(timestamp_text(window)),
            text_value(&fields[0]),
            text_value(timestamp_text(window)),
            text_value(&fields[0]),
            text_value(&fields[1]),
        ]);
        " AND (window_start>? OR (window_start=? AND user_id>?) OR (window_start=? AND user_id=? AND origin_kind>?))"
    } else {
        ""
    };
    values.push(integer_value(limit));
    Ok((
        format!(
            "SELECT tenant_id,window_start,user_id,origin_kind,run_count,runs_with_reported_tool_calls_count,tool_count_reported_run_count,reported_tool_call_count,completed_count,failed_count,cancelled_count,recovery_required_count,total_run_latency_ms,first_observed_at,last_observed_at FROM telemetry_hourly_user_activity_v0 WHERE tenant_id=? AND window_start>=? AND window_start<?{predicate} ORDER BY window_start,user_id,origin_kind LIMIT ?"
        ),
        params(values),
    ))
}

fn model_query(
    request: &TelemetryScanPageRequest,
    tenant: &str,
    to: DateTime<Utc>,
) -> Result<(String, LibSqlParams), TelemetryRepositoryError> {
    let range = request.range();
    let from = timestamp_text(range.from());
    let to = timestamp_text(to);
    let limit = (request.page_size() + 1) as i64;
    let provider = range.provider_id().map(|value| value.as_str());
    let model = range.effective_model_id().map(|value| value.as_str());
    let mut values = vec![
        text_value(tenant),
        text_value(from),
        text_value(to),
        optional_text_value(provider),
        optional_text_value(provider),
        optional_text_value(model),
        optional_text_value(model),
    ];
    let predicate = if let Some(cursor) = request.after() {
        let (window, fields) = decode_cursor(cursor, 3)?;
        values.extend([
            text_value(timestamp_text(window)),
            text_value(timestamp_text(window)),
            text_value(&fields[0]),
            text_value(timestamp_text(window)),
            text_value(&fields[0]),
            text_value(&fields[1]),
            text_value(timestamp_text(window)),
            text_value(&fields[0]),
            text_value(&fields[1]),
            text_value(&fields[2]),
        ]);
        " AND (window_start>? OR (window_start=? AND user_id>?) OR (window_start=? AND user_id=? AND provider_id>?) OR (window_start=? AND user_id=? AND provider_id=? AND effective_model_id>?))"
    } else {
        ""
    };
    values.push(integer_value(limit));
    Ok((
        format!(
            "SELECT tenant_id,user_id,window_start,provider_id,effective_model_id,inference_count,usage_reported_count,input_tokens,output_tokens,cache_read_input_tokens,cache_creation_input_tokens,first_observed_at,last_observed_at FROM telemetry_hourly_model_usage_v0 WHERE tenant_id=? AND window_start>=? AND window_start<? AND (? IS NULL OR provider_id=?) AND (? IS NULL OR effective_model_id=?){predicate} ORDER BY window_start,user_id,provider_id,effective_model_id LIMIT ?"
        ),
        params(values),
    ))
}

fn failure_query(
    request: &TelemetryScanPageRequest,
    tenant: &str,
    to: DateTime<Utc>,
) -> Result<(String, LibSqlParams), TelemetryRepositoryError> {
    let range = request.range();
    let mut values = vec![
        text_value(tenant),
        text_value(timestamp_text(range.from())),
        text_value(timestamp_text(to)),
    ];
    let limit = (request.page_size() + 1) as i64;
    let predicate = if let Some(cursor) = request.after() {
        let (window, fields) = decode_cursor(cursor, 2)?;
        values.extend([
            text_value(timestamp_text(window)),
            text_value(timestamp_text(window)),
            text_value(&fields[0]),
            text_value(timestamp_text(window)),
            text_value(&fields[0]),
            text_value(&fields[1]),
        ]);
        " AND (window_start>? OR (window_start=? AND user_id>?) OR (window_start=? AND user_id=? AND failure_category>?))"
    } else {
        ""
    };
    values.push(integer_value(limit));
    Ok((
        format!(
            "SELECT tenant_id,window_start,user_id,failure_category,failure_count,first_observed_at,last_observed_at FROM telemetry_hourly_run_failures_v0 WHERE tenant_id=? AND window_start>=? AND window_start<?{predicate} ORDER BY window_start,user_id,failure_category LIMIT ?"
        ),
        params(values),
    ))
}

fn automation_query(
    request: &TelemetryScanPageRequest,
    tenant: &str,
    to: DateTime<Utc>,
) -> Result<(String, LibSqlParams), TelemetryRepositoryError> {
    let range = request.range();
    let mut values = vec![
        text_value(tenant),
        text_value(timestamp_text(range.from())),
        text_value(timestamp_text(to)),
    ];
    let limit = (request.page_size() + 1) as i64;
    let predicate = if let Some(cursor) = request.after() {
        let (window, fields) = decode_cursor(cursor, 2)?;
        values.extend([
            text_value(timestamp_text(window)),
            text_value(timestamp_text(window)),
            text_value(&fields[0]),
            text_value(timestamp_text(window)),
            text_value(&fields[0]),
            text_value(&fields[1]),
        ]);
        " AND (window_start>? OR (window_start=? AND user_id>?) OR (window_start=? AND user_id=? AND automation_kind>?))"
    } else {
        ""
    };
    values.push(integer_value(limit));
    Ok((
        format!(
            "SELECT tenant_id,window_start,user_id,automation_kind,run_count,completed_count,failed_count,cancelled_count,recovery_required_count,first_observed_at,last_observed_at FROM telemetry_hourly_automation_usage_v0 WHERE tenant_id=? AND window_start>=? AND window_start<?{predicate} ORDER BY window_start,user_id,automation_kind LIMIT ?"
        ),
        params(values),
    ))
}

fn lifecycle_query(
    request: &TelemetryScanPageRequest,
    tenant: &str,
    to: DateTime<Utc>,
) -> Result<(String, LibSqlParams), TelemetryRepositoryError> {
    let range = request.range();
    let mut values = vec![
        text_value(tenant),
        text_value(timestamp_text(range.from())),
        text_value(timestamp_text(to)),
    ];
    let limit = (request.page_size() + 1) as i64;
    let predicate = if let Some(cursor) = request.after() {
        let (occurred, fields) = decode_cursor(cursor, 1)?;
        values.extend([
            text_value(timestamp_text(occurred)),
            text_value(timestamp_text(occurred)),
            text_value(&fields[0]),
        ]);
        " AND (occurred_at>? OR (occurred_at=? AND event_id>?))"
    } else {
        ""
    };
    values.push(integer_value(limit));
    Ok((
        format!(
            "SELECT tenant_id,event_id,user_id,event_kind,subject_kind,subject_id,occurred_at FROM telemetry_lifecycle_events_v0 WHERE tenant_id=? AND occurred_at>=? AND occurred_at<?{predicate} ORDER BY occurred_at,event_id LIMIT ?"
        ),
        params(values),
    ))
}

fn coverage_query(
    request: &TelemetryScanPageRequest,
    tenant: &str,
    to: DateTime<Utc>,
) -> Result<(String, LibSqlParams), TelemetryRepositoryError> {
    let range = request.range();
    let mut values = vec![
        text_value(tenant),
        text_value(timestamp_text(range.from())),
        text_value(timestamp_text(to)),
    ];
    let limit = (request.page_size() + 1) as i64;
    let predicate = if let Some(cursor) = request.after() {
        let (window, fields) = decode_cursor(cursor, 1)?;
        values.extend([
            text_value(timestamp_text(window)),
            text_value(timestamp_text(window)),
            text_value(&fields[0]),
        ]);
        " AND (window_start>? OR (window_start=? AND collector_instance_id>?))"
    } else {
        ""
    };
    values.push(integer_value(limit));
    Ok((
        format!(
            "SELECT tenant_id,window_start,collector_instance_id,accepted_observation_count,queue_full_drop_count,closed_drop_count,invalid_drop_count,write_failed_observation_count,first_observed_at,last_observed_at FROM telemetry_collector_hourly_v0 WHERE tenant_id=? AND window_start>=? AND window_start<?{predicate} ORDER BY window_start,collector_instance_id LIMIT ?"
        ),
        params(values),
    ))
}

fn string(row: &Row, index: usize) -> Result<String, TelemetryRepositoryError> {
    row.get(index as i32)
        .map_err(|source| TelemetryRepositoryError::StorageOperation {
            operation: "decoding telemetry text",
            source: Box::new(source),
        })
}
fn integer(row: &Row, index: usize) -> Result<u64, TelemetryRepositoryError> {
    let value: i64 =
        row.get(index as i32)
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "decoding telemetry counter",
                source: Box::new(source),
            })?;
    u64::try_from(value).map_err(|_| TelemetryRepositoryError::CounterOverflow {
        family: "persisted",
    })
}
fn time(row: &Row, index: usize) -> Result<DateTime<Utc>, TelemetryRepositoryError> {
    let value = string(row, index)?;
    crate::repository::parse_timestamp(&value, "timestamp")
}

fn activity_from_row(row: &Row) -> Result<HourlyUserActivity, TelemetryRepositoryError> {
    Ok(HourlyUserActivity::new(
        decode_tenant_id(string(row, 0)?)?,
        time(row, 1)?,
        decode_user_id(string(row, 2)?)?,
        parse_origin(&string(row, 3)?)?,
        integer(row, 4)?,
        integer(row, 5)?,
        integer(row, 6)?,
        integer(row, 7)?,
        integer(row, 8)?,
        integer(row, 9)?,
        integer(row, 10)?,
        integer(row, 11)?,
        integer(row, 12)?,
        time(row, 13)?,
        time(row, 14)?,
    )?)
}
fn model_from_row(row: &Row) -> Result<HourlyModelUsage, TelemetryRepositoryError> {
    Ok(HourlyModelUsage::new(
        decode_tenant_id(string(row, 0)?)?,
        decode_user_id(string(row, 1)?)?,
        time(row, 2)?,
        decode_provider_id(string(row, 3)?)?,
        decode_model_id(string(row, 4)?)?,
        integer(row, 5)?,
        integer(row, 6)?,
        integer(row, 7)?,
        integer(row, 8)?,
        integer(row, 9)?,
        integer(row, 10)?,
        time(row, 11)?,
        time(row, 12)?,
    )?)
}
fn failure_from_row(row: &Row) -> Result<HourlyRunFailure, TelemetryRepositoryError> {
    Ok(HourlyRunFailure::new(
        decode_tenant_id(string(row, 0)?)?,
        time(row, 1)?,
        decode_user_id(string(row, 2)?)?,
        decode_failure_category(string(row, 3)?)?,
        integer(row, 4)?,
        time(row, 5)?,
        time(row, 6)?,
    )?)
}
fn automation_from_row(row: &Row) -> Result<HourlyAutomationUsage, TelemetryRepositoryError> {
    Ok(HourlyAutomationUsage::new(
        decode_tenant_id(string(row, 0)?)?,
        time(row, 1)?,
        decode_user_id(string(row, 2)?)?,
        parse_automation(&string(row, 3)?)?,
        integer(row, 4)?,
        integer(row, 5)?,
        integer(row, 6)?,
        integer(row, 7)?,
        integer(row, 8)?,
        time(row, 9)?,
        time(row, 10)?,
    )?)
}
fn lifecycle_from_row(row: &Row) -> Result<LifecycleEvent, TelemetryRepositoryError> {
    Ok(LifecycleEvent::new(
        decode_tenant_id(string(row, 0)?)?,
        decode_event_id(string(row, 1)?)?,
        row.get::<Option<String>>(2)
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "decoding lifecycle user",
                source: Box::new(source),
            })?
            .map(decode_user_id)
            .transpose()?,
        parse_event(&string(row, 3)?)?,
        parse_subject(&string(row, 4)?)?,
        decode_subject_id(string(row, 5)?)?,
        time(row, 6)?,
    )?)
}
fn coverage_from_row(row: &Row) -> Result<CollectorCoverage, TelemetryRepositoryError> {
    Ok(CollectorCoverage::new(
        decode_tenant_id(string(row, 0)?)?,
        time(row, 1)?,
        decode_collector_id(string(row, 2)?)?,
        integer(row, 3)?,
        integer(row, 4)?,
        integer(row, 5)?,
        integer(row, 6)?,
        integer(row, 7)?,
        time(row, 8)?,
        time(row, 9)?,
    )?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn libsql_migration_has_shared_schema_v0_shape() {
        crate::repository::assert_schema_v0_shape(super::MIGRATION, false);
    }

    #[test]
    fn libsql_batch_has_one_write_admission() {
        crate::repository::assert_single_batch_admission(
            include_str!("libsql.rs"),
            "transaction_batch",
            "self.writer(",
        );
    }
}
