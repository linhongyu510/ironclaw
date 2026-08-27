use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;
use tokio_postgres::Row;

use crate::{
    CollectorCoverage, HourlyAutomationUsage, HourlyModelUsage, HourlyRunFailure,
    HourlyUserActivity, LifecycleEvent, TelemetryBatch,
    error::TelemetryRepositoryError,
    repository::{
        TelemetryPage, TelemetryRepository, TelemetryScanPageRequest, automation_text,
        decode_collector_id, decode_cursor, decode_event_id, decode_failure_category,
        decode_model_id, decode_provider_id, decode_subject_id, decode_tenant_id, decode_user_id,
        encode_cursor, lifecycle_event_text, lifecycle_subject_text, normalize_timestamp,
        origin_text, page_rows, parse_automation, parse_event, parse_origin, parse_subject,
    },
};

const MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS telemetry_hourly_user_activity_v0 (
  tenant_id TEXT NOT NULL, window_start TIMESTAMPTZ NOT NULL, user_id TEXT NOT NULL,
  origin_kind TEXT NOT NULL CHECK (origin_kind IN ('human','parent_agent','system','automation','other')),
  run_count BIGINT NOT NULL CHECK (run_count >= 0), runs_with_reported_tool_calls_count BIGINT NOT NULL CHECK (runs_with_reported_tool_calls_count >= 0),
  tool_count_reported_run_count BIGINT NOT NULL CHECK (tool_count_reported_run_count >= 0), reported_tool_call_count BIGINT NOT NULL CHECK (reported_tool_call_count >= 0),
  completed_count BIGINT NOT NULL CHECK (completed_count >= 0), failed_count BIGINT NOT NULL CHECK (failed_count >= 0), cancelled_count BIGINT NOT NULL CHECK (cancelled_count >= 0), recovery_required_count BIGINT NOT NULL CHECK (recovery_required_count >= 0), total_run_latency_ms BIGINT NOT NULL CHECK (total_run_latency_ms >= 0),
  first_observed_at TIMESTAMPTZ NOT NULL, last_observed_at TIMESTAMPTZ NOT NULL, schema_version SMALLINT NOT NULL CHECK (schema_version = 0), updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, window_start, user_id, origin_kind),
  CHECK (completed_count + failed_count + cancelled_count + recovery_required_count = run_count),
  CHECK (runs_with_reported_tool_calls_count <= tool_count_reported_run_count), CHECK (tool_count_reported_run_count <= run_count)
);
CREATE INDEX IF NOT EXISTS telemetry_activity_tenant_user_time_v0 ON telemetry_hourly_user_activity_v0 (tenant_id, user_id, window_start);
CREATE TABLE IF NOT EXISTS telemetry_hourly_model_usage_v0 (
  tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, window_start TIMESTAMPTZ NOT NULL, provider_id TEXT NOT NULL, effective_model_id TEXT NOT NULL,
  inference_count BIGINT NOT NULL CHECK (inference_count >= 0), usage_reported_count BIGINT NOT NULL CHECK (usage_reported_count >= 0), input_tokens BIGINT NOT NULL CHECK (input_tokens >= 0), output_tokens BIGINT NOT NULL CHECK (output_tokens >= 0), cache_read_input_tokens BIGINT NOT NULL CHECK (cache_read_input_tokens >= 0), cache_creation_input_tokens BIGINT NOT NULL CHECK (cache_creation_input_tokens >= 0),
  first_observed_at TIMESTAMPTZ NOT NULL, last_observed_at TIMESTAMPTZ NOT NULL, schema_version SMALLINT NOT NULL CHECK (schema_version = 0), updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, user_id, window_start, provider_id, effective_model_id), CHECK (usage_reported_count <= inference_count)
);
CREATE INDEX IF NOT EXISTS telemetry_model_tenant_time_model_v0 ON telemetry_hourly_model_usage_v0 (tenant_id, window_start, provider_id, effective_model_id);
CREATE TABLE IF NOT EXISTS telemetry_hourly_run_failures_v0 (
  tenant_id TEXT NOT NULL, window_start TIMESTAMPTZ NOT NULL, user_id TEXT NOT NULL, failure_category TEXT NOT NULL, failure_count BIGINT NOT NULL CHECK (failure_count >= 0), first_observed_at TIMESTAMPTZ NOT NULL, last_observed_at TIMESTAMPTZ NOT NULL, schema_version SMALLINT NOT NULL CHECK (schema_version = 0), updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, window_start, user_id, failure_category)
);
CREATE TABLE IF NOT EXISTS telemetry_hourly_automation_usage_v0 (
  tenant_id TEXT NOT NULL, window_start TIMESTAMPTZ NOT NULL, user_id TEXT NOT NULL, automation_kind TEXT NOT NULL CHECK (automation_kind IN ('cron','once','manual')),
  run_count BIGINT NOT NULL CHECK (run_count >= 0), completed_count BIGINT NOT NULL CHECK (completed_count >= 0), failed_count BIGINT NOT NULL CHECK (failed_count >= 0), cancelled_count BIGINT NOT NULL CHECK (cancelled_count >= 0), recovery_required_count BIGINT NOT NULL CHECK (recovery_required_count >= 0), first_observed_at TIMESTAMPTZ NOT NULL, last_observed_at TIMESTAMPTZ NOT NULL, schema_version SMALLINT NOT NULL CHECK (schema_version = 0), updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, window_start, user_id, automation_kind), CHECK (completed_count + failed_count + cancelled_count + recovery_required_count = run_count)
);
CREATE TABLE IF NOT EXISTS telemetry_lifecycle_events_v0 (
  tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, user_id TEXT NULL, event_kind TEXT NOT NULL, subject_kind TEXT NOT NULL, subject_id TEXT NOT NULL, occurred_at TIMESTAMPTZ NOT NULL, schema_version SMALLINT NOT NULL CHECK (schema_version = 0), PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS telemetry_lifecycle_tenant_time_v0 ON telemetry_lifecycle_events_v0 (tenant_id, occurred_at, event_id);
CREATE INDEX IF NOT EXISTS telemetry_lifecycle_subject_history_v0 ON telemetry_lifecycle_events_v0 (tenant_id, subject_kind, subject_id, occurred_at, event_id);
CREATE TABLE IF NOT EXISTS telemetry_collector_hourly_v0 (
  tenant_id TEXT NOT NULL, window_start TIMESTAMPTZ NOT NULL, collector_instance_id TEXT NOT NULL, accepted_observation_count BIGINT NOT NULL CHECK (accepted_observation_count >= 0), queue_full_drop_count BIGINT NOT NULL CHECK (queue_full_drop_count >= 0), closed_drop_count BIGINT NOT NULL CHECK (closed_drop_count >= 0), invalid_drop_count BIGINT NOT NULL CHECK (invalid_drop_count >= 0), write_failed_observation_count BIGINT NOT NULL CHECK (write_failed_observation_count >= 0), first_observed_at TIMESTAMPTZ NOT NULL, last_observed_at TIMESTAMPTZ NOT NULL, schema_version SMALLINT NOT NULL CHECK (schema_version = 0), updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, window_start, collector_instance_id)
);
"#;

/// PostgreSQL telemetry adapter over a pool admitted by composition.
pub(crate) struct PostgresTelemetryRepository {
    pool: deadpool_postgres::Pool,
}

impl PostgresTelemetryRepository {
    pub(crate) fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }
}

impl From<deadpool_postgres::Pool> for crate::TelemetryRepositoryAdapter {
    fn from(pool: deadpool_postgres::Pool) -> Self {
        crate::TelemetryRepositoryAdapter {
            inner: Arc::new(PostgresTelemetryRepository::new(pool)),
        }
    }
}

#[async_trait]
impl TelemetryRepository for PostgresTelemetryRepository {
    async fn migrate(&self) -> Result<(), TelemetryRepositoryError> {
        let mut client = self.pool.get().await.map_err(|source| {
            TelemetryRepositoryError::StoragePoolAdmission {
                operation: "acquiring telemetry migration client",
                source: Box::new(source),
            }
        })?;
        let transaction = client.transaction().await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "beginning telemetry migration transaction",
                source: Box::new(source),
            }
        })?;
        transaction
            .batch_execute(MIGRATION)
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
        let mut client = self.pool.get().await.map_err(|source| {
            TelemetryRepositoryError::StoragePoolAdmission {
                operation: "acquiring telemetry batch client",
                source: Box::new(source),
            }
        })?;
        let transaction = client.transaction().await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "beginning telemetry batch transaction",
                source: Box::new(source),
            }
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

    async fn scan_activity_page(
        &self,
        request: &TelemetryScanPageRequest,
    ) -> Result<TelemetryPage<HourlyUserActivity>, TelemetryRepositoryError> {
        let range = request.range();
        let to = range.effective_to();
        if range.from() >= to {
            return Ok(TelemetryPage::new(Vec::new(), None));
        }
        let client = self.pool.get().await.map_err(|source| {
            TelemetryRepositoryError::StoragePoolAdmission {
                operation: "acquiring telemetry activity reader",
                source: Box::new(source),
            }
        })?;
        let (sql, boxed) = activity_query(request, to)?;
        let params = boxed
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = client.query(&sql, &params).await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "scanning telemetry activity",
                source: Box::new(source),
            }
        })?;
        let values = rows
            .iter()
            .map(activity_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let (values, more) = page_rows(values, request.page_size());
        let next = more
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
        let client = self.pool.get().await.map_err(|source| {
            TelemetryRepositoryError::StoragePoolAdmission {
                operation: "acquiring telemetry model reader",
                source: Box::new(source),
            }
        })?;
        let (sql, boxed) = model_query(request, to)?;
        let params = boxed
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = client.query(&sql, &params).await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "scanning telemetry model usage",
                source: Box::new(source),
            }
        })?;
        let values = rows
            .iter()
            .map(model_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let (values, more) = page_rows(values, request.page_size());
        let next = more
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
        let client = self.pool.get().await.map_err(|source| {
            TelemetryRepositoryError::StoragePoolAdmission {
                operation: "acquiring telemetry failure reader",
                source: Box::new(source),
            }
        })?;
        let (sql, boxed) = failure_query(request, to)?;
        let params = boxed
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = client.query(&sql, &params).await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "scanning telemetry failures",
                source: Box::new(source),
            }
        })?;
        let values = rows
            .iter()
            .map(failure_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let (values, more) = page_rows(values, request.page_size());
        let next = more
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
        let client = self.pool.get().await.map_err(|source| {
            TelemetryRepositoryError::StoragePoolAdmission {
                operation: "acquiring telemetry automation reader",
                source: Box::new(source),
            }
        })?;
        let (sql, boxed) = automation_query(request, to)?;
        let params = boxed
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = client.query(&sql, &params).await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "scanning telemetry automation",
                source: Box::new(source),
            }
        })?;
        let values = rows
            .iter()
            .map(automation_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let (values, more) = page_rows(values, request.page_size());
        let next = more
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
        let client = self.pool.get().await.map_err(|source| {
            TelemetryRepositoryError::StoragePoolAdmission {
                operation: "acquiring telemetry lifecycle reader",
                source: Box::new(source),
            }
        })?;
        let (sql, boxed) = lifecycle_query(request, to)?;
        let params = boxed
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = client.query(&sql, &params).await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "scanning telemetry lifecycle",
                source: Box::new(source),
            }
        })?;
        let values = rows
            .iter()
            .map(lifecycle_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let (values, more) = page_rows(values, request.page_size());
        let next = more
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
        let client = self.pool.get().await.map_err(|source| {
            TelemetryRepositoryError::StoragePoolAdmission {
                operation: "acquiring telemetry coverage reader",
                source: Box::new(source),
            }
        })?;
        let (sql, boxed) = coverage_query(request, to)?;
        let params = boxed
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = client.query(&sql, &params).await.map_err(|source| {
            TelemetryRepositoryError::StorageOperation {
                operation: "scanning telemetry coverage",
                source: Box::new(source),
            }
        })?;
        let values = rows
            .iter()
            .map(coverage_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let (values, more) = page_rows(values, request.page_size());
        let next = more
            .then(|| {
                values.last().map(|row| {
                    encode_cursor(row.window_start(), &[row.collector_instance_id().as_str()])
                })
            })
            .flatten();
        Ok(TelemetryPage::new(values, next))
    }
}

async fn upsert_activity<C: GenericClient + Sync>(
    tx: &C,
    row: &HourlyUserActivity,
) -> Result<(), TelemetryRepositoryError> {
    let first_observed_at = normalize_timestamp(row.first_observed_at());
    let last_observed_at = normalize_timestamp(row.last_observed_at());
    let window_start = normalize_timestamp(row.window_start());
    tx.execute("INSERT INTO telemetry_hourly_user_activity_v0 (tenant_id,window_start,user_id,origin_kind,run_count,runs_with_reported_tool_calls_count,tool_count_reported_run_count,reported_tool_call_count,completed_count,failed_count,cancelled_count,recovery_required_count,total_run_latency_ms,first_observed_at,last_observed_at,schema_version,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,0,$15) ON CONFLICT (tenant_id,window_start,user_id,origin_kind) DO UPDATE SET run_count=telemetry_hourly_user_activity_v0.run_count+EXCLUDED.run_count,runs_with_reported_tool_calls_count=telemetry_hourly_user_activity_v0.runs_with_reported_tool_calls_count+EXCLUDED.runs_with_reported_tool_calls_count,tool_count_reported_run_count=telemetry_hourly_user_activity_v0.tool_count_reported_run_count+EXCLUDED.tool_count_reported_run_count,reported_tool_call_count=telemetry_hourly_user_activity_v0.reported_tool_call_count+EXCLUDED.reported_tool_call_count,completed_count=telemetry_hourly_user_activity_v0.completed_count+EXCLUDED.completed_count,failed_count=telemetry_hourly_user_activity_v0.failed_count+EXCLUDED.failed_count,cancelled_count=telemetry_hourly_user_activity_v0.cancelled_count+EXCLUDED.cancelled_count,recovery_required_count=telemetry_hourly_user_activity_v0.recovery_required_count+EXCLUDED.recovery_required_count,total_run_latency_ms=telemetry_hourly_user_activity_v0.total_run_latency_ms+EXCLUDED.total_run_latency_ms,first_observed_at=LEAST(telemetry_hourly_user_activity_v0.first_observed_at,EXCLUDED.first_observed_at),last_observed_at=GREATEST(telemetry_hourly_user_activity_v0.last_observed_at,EXCLUDED.last_observed_at),updated_at=EXCLUDED.updated_at", &[&row.tenant_id().as_str(), &window_start, &row.user_id().as_str(), &origin_text(row.origin_kind()), &(row.run_count() as i64), &(row.runs_with_reported_tool_calls_count() as i64), &(row.tool_count_reported_run_count() as i64), &(row.reported_tool_call_count() as i64), &(row.completed_count() as i64), &(row.failed_count() as i64), &(row.cancelled_count() as i64), &(row.recovery_required_count() as i64), &(row.total_run_latency_ms() as i64), &first_observed_at, &last_observed_at]).await.map_err(|source|TelemetryRepositoryError::StorageOperation {operation:"upserting telemetry activity",source: Box::new(source)}).map(|_|())
}

async fn check_activity_overflow<C: GenericClient + Sync>(
    tx: &C,
    row: &HourlyUserActivity,
) -> Result<(), TelemetryRepositoryError> {
    let tenant = row.tenant_id().as_str().to_owned();
    let user = row.user_id().as_str().to_owned();
    let origin = origin_text(row.origin_kind());
    let existing = tx
        .query_opt(
            "SELECT run_count,runs_with_reported_tool_calls_count,tool_count_reported_run_count,reported_tool_call_count,completed_count,failed_count,cancelled_count,recovery_required_count,total_run_latency_ms FROM telemetry_hourly_user_activity_v0 WHERE tenant_id=$1 AND window_start=$2 AND user_id=$3 AND origin_kind=$4",
            &[&tenant, &normalize_timestamp(row.window_start()), &user, &origin],
        )
        .await
        .map_err(|source| TelemetryRepositoryError::StorageOperation {
            operation: "checking telemetry activity overflow",
            source: Box::new(source),
        })?;
    if let Some(existing) = existing {
        for (index, incoming) in [
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
            check_postgres_counter(&existing, index, incoming, "activity")?;
        }
    }
    Ok(())
}

async fn check_model_overflow<C: GenericClient + Sync>(
    tx: &C,
    row: &HourlyModelUsage,
) -> Result<(), TelemetryRepositoryError> {
    let tenant = row.tenant_id().as_str().to_owned();
    let user = row.user_id().as_str().to_owned();
    let provider = row.provider_id().as_str().to_owned();
    let model = row.effective_model_id().as_str().to_owned();
    let existing = tx
        .query_opt(
            "SELECT inference_count,usage_reported_count,input_tokens,output_tokens,cache_read_input_tokens,cache_creation_input_tokens FROM telemetry_hourly_model_usage_v0 WHERE tenant_id=$1 AND user_id=$2 AND window_start=$3 AND provider_id=$4 AND effective_model_id=$5",
            &[&tenant, &user, &normalize_timestamp(row.window_start()), &provider, &model],
        )
        .await
        .map_err(|source| TelemetryRepositoryError::StorageOperation {
            operation: "checking telemetry model overflow",
            source: Box::new(source),
        })?;
    if let Some(existing) = existing {
        for (index, incoming) in [
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
            check_postgres_counter(&existing, index, incoming, "model")?;
        }
    }
    Ok(())
}

async fn check_failure_overflow<C: GenericClient + Sync>(
    tx: &C,
    row: &HourlyRunFailure,
) -> Result<(), TelemetryRepositoryError> {
    let tenant = row.tenant_id().as_str().to_owned();
    let user = row.user_id().as_str().to_owned();
    let category = row.failure_category().as_str().to_owned();
    let existing = tx
        .query_opt(
            "SELECT failure_count FROM telemetry_hourly_run_failures_v0 WHERE tenant_id=$1 AND window_start=$2 AND user_id=$3 AND failure_category=$4",
            &[&tenant, &normalize_timestamp(row.window_start()), &user, &category],
        )
        .await
        .map_err(|source| TelemetryRepositoryError::StorageOperation {
            operation: "checking telemetry failure overflow",
            source: Box::new(source),
        })?;
    if let Some(existing) = existing {
        check_postgres_counter(&existing, 0, row.failure_count(), "failure")?;
    }
    Ok(())
}

async fn check_automation_overflow<C: GenericClient + Sync>(
    tx: &C,
    row: &HourlyAutomationUsage,
) -> Result<(), TelemetryRepositoryError> {
    let tenant = row.tenant_id().as_str().to_owned();
    let user = row.user_id().as_str().to_owned();
    let kind = automation_text(row.automation_kind());
    let existing = tx
        .query_opt(
            "SELECT run_count,completed_count,failed_count,cancelled_count,recovery_required_count FROM telemetry_hourly_automation_usage_v0 WHERE tenant_id=$1 AND window_start=$2 AND user_id=$3 AND automation_kind=$4",
            &[&tenant, &normalize_timestamp(row.window_start()), &user, &kind],
        )
        .await
        .map_err(|source| TelemetryRepositoryError::StorageOperation {
            operation: "checking telemetry automation overflow",
            source: Box::new(source),
        })?;
    if let Some(existing) = existing {
        for (index, incoming) in [
            row.run_count(),
            row.completed_count(),
            row.failed_count(),
            row.cancelled_count(),
            row.recovery_required_count(),
        ]
        .into_iter()
        .enumerate()
        {
            check_postgres_counter(&existing, index, incoming, "automation")?;
        }
    }
    Ok(())
}

async fn check_coverage_overflow<C: GenericClient + Sync>(
    tx: &C,
    row: &CollectorCoverage,
) -> Result<(), TelemetryRepositoryError> {
    let tenant = row.tenant_id().as_str().to_owned();
    let collector = row.collector_instance_id().as_str().to_owned();
    let existing = tx
        .query_opt(
            "SELECT accepted_observation_count,queue_full_drop_count,closed_drop_count,invalid_drop_count,write_failed_observation_count FROM telemetry_collector_hourly_v0 WHERE tenant_id=$1 AND window_start=$2 AND collector_instance_id=$3",
            &[&tenant, &normalize_timestamp(row.window_start()), &collector],
        )
        .await
        .map_err(|source| TelemetryRepositoryError::StorageOperation {
            operation: "checking telemetry coverage overflow",
            source: Box::new(source),
        })?;
    if let Some(existing) = existing {
        for (index, incoming) in [
            row.accepted_observation_count(),
            row.queue_full_drop_count(),
            row.closed_drop_count(),
            row.invalid_drop_count(),
            row.write_failed_observation_count(),
        ]
        .into_iter()
        .enumerate()
        {
            check_postgres_counter(&existing, index, incoming, "coverage")?;
        }
    }
    Ok(())
}

fn check_postgres_counter(
    row: &Row,
    index: usize,
    incoming: u64,
    family: &'static str,
) -> Result<(), TelemetryRepositoryError> {
    let current: i64 =
        row.try_get(index)
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "decoding telemetry overflow counter",
                source: Box::new(source),
            })?;
    crate::repository::checked_counter_sum(current, incoming, family)
}

async fn upsert_model<C: GenericClient + Sync>(
    tx: &C,
    row: &HourlyModelUsage,
) -> Result<(), TelemetryRepositoryError> {
    let first_observed_at = normalize_timestamp(row.first_observed_at());
    let last_observed_at = normalize_timestamp(row.last_observed_at());
    let window_start = normalize_timestamp(row.window_start());
    tx.execute("INSERT INTO telemetry_hourly_model_usage_v0 (tenant_id,user_id,window_start,provider_id,effective_model_id,inference_count,usage_reported_count,input_tokens,output_tokens,cache_read_input_tokens,cache_creation_input_tokens,first_observed_at,last_observed_at,schema_version,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,0,$13) ON CONFLICT (tenant_id,user_id,window_start,provider_id,effective_model_id) DO UPDATE SET inference_count=telemetry_hourly_model_usage_v0.inference_count+EXCLUDED.inference_count,usage_reported_count=telemetry_hourly_model_usage_v0.usage_reported_count+EXCLUDED.usage_reported_count,input_tokens=telemetry_hourly_model_usage_v0.input_tokens+EXCLUDED.input_tokens,output_tokens=telemetry_hourly_model_usage_v0.output_tokens+EXCLUDED.output_tokens,cache_read_input_tokens=telemetry_hourly_model_usage_v0.cache_read_input_tokens+EXCLUDED.cache_read_input_tokens,cache_creation_input_tokens=telemetry_hourly_model_usage_v0.cache_creation_input_tokens+EXCLUDED.cache_creation_input_tokens,first_observed_at=LEAST(telemetry_hourly_model_usage_v0.first_observed_at,EXCLUDED.first_observed_at),last_observed_at=GREATEST(telemetry_hourly_model_usage_v0.last_observed_at,EXCLUDED.last_observed_at),updated_at=EXCLUDED.updated_at", &[&row.tenant_id().as_str(),&row.user_id().as_str(),&window_start,&row.provider_id().as_str(),&row.effective_model_id().as_str(),&(row.inference_count() as i64),&(row.usage_reported_count() as i64),&(row.input_tokens() as i64),&(row.output_tokens() as i64),&(row.cache_read_input_tokens() as i64),&(row.cache_creation_input_tokens() as i64),&first_observed_at,&last_observed_at]).await.map_err(|source|TelemetryRepositoryError::StorageOperation {operation:"upserting telemetry model usage",source: Box::new(source)}).map(|_|())
}
async fn upsert_failure<C: GenericClient + Sync>(
    tx: &C,
    row: &HourlyRunFailure,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_hourly_run_failures_v0 (tenant_id,window_start,user_id,failure_category,failure_count,first_observed_at,last_observed_at,schema_version,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,0,$7) ON CONFLICT (tenant_id,window_start,user_id,failure_category) DO UPDATE SET failure_count=telemetry_hourly_run_failures_v0.failure_count+EXCLUDED.failure_count,first_observed_at=LEAST(telemetry_hourly_run_failures_v0.first_observed_at,EXCLUDED.first_observed_at),last_observed_at=GREATEST(telemetry_hourly_run_failures_v0.last_observed_at,EXCLUDED.last_observed_at),updated_at=EXCLUDED.updated_at", &[&row.tenant_id().as_str(),&normalize_timestamp(row.window_start()),&row.user_id().as_str(),&row.failure_category().as_str(),&(row.failure_count() as i64),&normalize_timestamp(row.first_observed_at()),&normalize_timestamp(row.last_observed_at())]).await.map_err(|source|TelemetryRepositoryError::StorageOperation {operation:"upserting telemetry failure",source: Box::new(source)}).map(|_|())
}
async fn upsert_automation<C: GenericClient + Sync>(
    tx: &C,
    row: &HourlyAutomationUsage,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_hourly_automation_usage_v0 (tenant_id,window_start,user_id,automation_kind,run_count,completed_count,failed_count,cancelled_count,recovery_required_count,first_observed_at,last_observed_at,schema_version,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0,$11) ON CONFLICT (tenant_id,window_start,user_id,automation_kind) DO UPDATE SET run_count=telemetry_hourly_automation_usage_v0.run_count+EXCLUDED.run_count,completed_count=telemetry_hourly_automation_usage_v0.completed_count+EXCLUDED.completed_count,failed_count=telemetry_hourly_automation_usage_v0.failed_count+EXCLUDED.failed_count,cancelled_count=telemetry_hourly_automation_usage_v0.cancelled_count+EXCLUDED.cancelled_count,recovery_required_count=telemetry_hourly_automation_usage_v0.recovery_required_count+EXCLUDED.recovery_required_count,first_observed_at=LEAST(telemetry_hourly_automation_usage_v0.first_observed_at,EXCLUDED.first_observed_at),last_observed_at=GREATEST(telemetry_hourly_automation_usage_v0.last_observed_at,EXCLUDED.last_observed_at),updated_at=EXCLUDED.updated_at", &[&row.tenant_id().as_str(),&normalize_timestamp(row.window_start()),&row.user_id().as_str(),&automation_text(row.automation_kind()),&(row.run_count() as i64),&(row.completed_count() as i64),&(row.failed_count() as i64),&(row.cancelled_count() as i64),&(row.recovery_required_count() as i64),&normalize_timestamp(row.first_observed_at()),&normalize_timestamp(row.last_observed_at())]).await.map_err(|source|TelemetryRepositoryError::StorageOperation {operation:"upserting telemetry automation",source: Box::new(source)}).map(|_|())
}
async fn upsert_lifecycle<C: GenericClient + Sync>(
    tx: &C,
    row: &LifecycleEvent,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_lifecycle_events_v0 (tenant_id,event_id,user_id,event_kind,subject_kind,subject_id,occurred_at,schema_version) VALUES ($1,$2,$3,$4,$5,$6,$7,0) ON CONFLICT (tenant_id,event_id) DO NOTHING", &[&row.tenant_id().as_str(),&row.event_id().as_str(),&row.user_id().map(|id|id.as_str()),&lifecycle_event_text(row.event_kind()),&lifecycle_subject_text(row.subject_kind()),&row.subject_id().as_str(),&normalize_timestamp(row.occurred_at())]).await.map_err(|source|TelemetryRepositoryError::StorageOperation {operation:"upserting telemetry lifecycle",source: Box::new(source)}).map(|_|())
}
async fn upsert_coverage<C: GenericClient + Sync>(
    tx: &C,
    row: &CollectorCoverage,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_collector_hourly_v0 (tenant_id,window_start,collector_instance_id,accepted_observation_count,queue_full_drop_count,closed_drop_count,invalid_drop_count,write_failed_observation_count,first_observed_at,last_observed_at,schema_version,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0,$11) ON CONFLICT (tenant_id,window_start,collector_instance_id) DO UPDATE SET accepted_observation_count=telemetry_collector_hourly_v0.accepted_observation_count+EXCLUDED.accepted_observation_count,queue_full_drop_count=telemetry_collector_hourly_v0.queue_full_drop_count+EXCLUDED.queue_full_drop_count,closed_drop_count=telemetry_collector_hourly_v0.closed_drop_count+EXCLUDED.closed_drop_count,invalid_drop_count=telemetry_collector_hourly_v0.invalid_drop_count+EXCLUDED.invalid_drop_count,write_failed_observation_count=telemetry_collector_hourly_v0.write_failed_observation_count+EXCLUDED.write_failed_observation_count,first_observed_at=LEAST(telemetry_collector_hourly_v0.first_observed_at,EXCLUDED.first_observed_at),last_observed_at=GREATEST(telemetry_collector_hourly_v0.last_observed_at,EXCLUDED.last_observed_at),updated_at=EXCLUDED.updated_at", &[&row.tenant_id().as_str(),&normalize_timestamp(row.window_start()),&row.collector_instance_id().as_str(),&(row.accepted_observation_count() as i64),&(row.queue_full_drop_count() as i64),&(row.closed_drop_count() as i64),&(row.invalid_drop_count() as i64),&(row.write_failed_observation_count() as i64),&normalize_timestamp(row.first_observed_at()),&normalize_timestamp(row.last_observed_at())]).await.map_err(|source|TelemetryRepositoryError::StorageOperation {operation:"upserting telemetry coverage",source: Box::new(source)}).map(|_|())
}

type PgValue = Box<dyn tokio_postgres::types::ToSql + Sync + Send>;
type PgParams = Vec<PgValue>;
fn pg_value<T: tokio_postgres::types::ToSql + Sync + Send + 'static>(value: T) -> PgValue {
    Box::new(value)
}
fn activity_query(
    request: &TelemetryScanPageRequest,
    to: DateTime<Utc>,
) -> Result<(String, PgParams), TelemetryRepositoryError> {
    let r = request.range();
    let mut values = vec![
        pg_value(r.tenant_id().as_str().to_owned()),
        pg_value(r.from()),
        pg_value(to),
    ];
    let predicate = if let Some(cursor) = request.after() {
        let (window, fields) = decode_cursor(cursor, 2)?;
        values.extend([
            pg_value(window),
            pg_value(window),
            pg_value(fields[0].clone()),
            pg_value(window),
            pg_value(fields[0].clone()),
            pg_value(fields[1].clone()),
        ]);
        " AND (window_start>$4 OR (window_start=$5 AND user_id>$6) OR (window_start=$7 AND user_id=$8 AND origin_kind>$9))"
    } else {
        ""
    };
    let limit = (request.page_size() + 1) as i64;
    values.push(pg_value(limit));
    Ok((
        format!(
            "SELECT tenant_id,window_start,user_id,origin_kind,run_count,runs_with_reported_tool_calls_count,tool_count_reported_run_count,reported_tool_call_count,completed_count,failed_count,cancelled_count,recovery_required_count,total_run_latency_ms,first_observed_at,last_observed_at FROM telemetry_hourly_user_activity_v0 WHERE tenant_id=$1 AND window_start>=$2 AND window_start<$3{predicate} ORDER BY window_start,user_id,origin_kind LIMIT ${}",
            values.len()
        ),
        values,
    ))
}
fn model_query(
    request: &TelemetryScanPageRequest,
    to: DateTime<Utc>,
) -> Result<(String, PgParams), TelemetryRepositoryError> {
    let r = request.range();
    let mut values = vec![
        pg_value(r.tenant_id().as_str().to_owned()),
        pg_value(r.from()),
        pg_value(to),
        pg_value(r.provider_id().map(|v| v.as_str().to_owned())),
        pg_value(r.provider_id().map(|v| v.as_str().to_owned())),
        pg_value(r.effective_model_id().map(|v| v.as_str().to_owned())),
        pg_value(r.effective_model_id().map(|v| v.as_str().to_owned())),
    ];
    let predicate = if let Some(cursor) = request.after() {
        let (window, fields) = decode_cursor(cursor, 3)?;
        values.extend([
            pg_value(window),
            pg_value(window),
            pg_value(fields[0].clone()),
            pg_value(window),
            pg_value(fields[0].clone()),
            pg_value(fields[1].clone()),
            pg_value(window),
            pg_value(fields[0].clone()),
            pg_value(fields[1].clone()),
            pg_value(fields[2].clone()),
        ]);
        " AND (window_start>$8 OR (window_start=$9 AND user_id>$10) OR (window_start=$11 AND user_id=$12 AND provider_id>$13) OR (window_start=$14 AND user_id=$15 AND provider_id=$16 AND effective_model_id>$17))"
    } else {
        ""
    };
    let limit = (request.page_size() + 1) as i64;
    values.push(pg_value(limit));
    Ok((
        format!(
            "SELECT tenant_id,user_id,window_start,provider_id,effective_model_id,inference_count,usage_reported_count,input_tokens,output_tokens,cache_read_input_tokens,cache_creation_input_tokens,first_observed_at,last_observed_at FROM telemetry_hourly_model_usage_v0 WHERE tenant_id=$1 AND window_start>=$2 AND window_start<$3 AND ($4::text IS NULL OR provider_id=$5::text) AND ($6::text IS NULL OR effective_model_id=$7::text){predicate} ORDER BY window_start,user_id,provider_id,effective_model_id LIMIT ${}",
            values.len()
        ),
        values,
    ))
}
fn failure_query(
    request: &TelemetryScanPageRequest,
    to: DateTime<Utc>,
) -> Result<(String, PgParams), TelemetryRepositoryError> {
    let r = request.range();
    let mut values = vec![
        pg_value(r.tenant_id().as_str().to_owned()),
        pg_value(r.from()),
        pg_value(to),
    ];
    let predicate = if let Some(cursor) = request.after() {
        let (window, fields) = decode_cursor(cursor, 2)?;
        values.extend([
            pg_value(window),
            pg_value(window),
            pg_value(fields[0].clone()),
            pg_value(window),
            pg_value(fields[0].clone()),
            pg_value(fields[1].clone()),
        ]);
        " AND (window_start>$4 OR (window_start=$5 AND user_id>$6) OR (window_start=$7 AND user_id=$8 AND failure_category>$9))"
    } else {
        ""
    };
    let limit = (request.page_size() + 1) as i64;
    values.push(pg_value(limit));
    Ok((
        format!(
            "SELECT tenant_id,window_start,user_id,failure_category,failure_count,first_observed_at,last_observed_at FROM telemetry_hourly_run_failures_v0 WHERE tenant_id=$1 AND window_start>=$2 AND window_start<$3{predicate} ORDER BY window_start,user_id,failure_category LIMIT ${}",
            values.len()
        ),
        values,
    ))
}
fn automation_query(
    request: &TelemetryScanPageRequest,
    to: DateTime<Utc>,
) -> Result<(String, PgParams), TelemetryRepositoryError> {
    let r = request.range();
    let mut values = vec![
        pg_value(r.tenant_id().as_str().to_owned()),
        pg_value(r.from()),
        pg_value(to),
    ];
    let predicate = if let Some(cursor) = request.after() {
        let (window, fields) = decode_cursor(cursor, 2)?;
        values.extend([
            pg_value(window),
            pg_value(window),
            pg_value(fields[0].clone()),
            pg_value(window),
            pg_value(fields[0].clone()),
            pg_value(fields[1].clone()),
        ]);
        " AND (window_start>$4 OR (window_start=$5 AND user_id>$6) OR (window_start=$7 AND user_id=$8 AND automation_kind>$9))"
    } else {
        ""
    };
    let limit = (request.page_size() + 1) as i64;
    values.push(pg_value(limit));
    Ok((
        format!(
            "SELECT tenant_id,window_start,user_id,automation_kind,run_count,completed_count,failed_count,cancelled_count,recovery_required_count,first_observed_at,last_observed_at FROM telemetry_hourly_automation_usage_v0 WHERE tenant_id=$1 AND window_start>=$2 AND window_start<$3{predicate} ORDER BY window_start,user_id,automation_kind LIMIT ${}",
            values.len()
        ),
        values,
    ))
}
fn lifecycle_query(
    request: &TelemetryScanPageRequest,
    to: DateTime<Utc>,
) -> Result<(String, PgParams), TelemetryRepositoryError> {
    let r = request.range();
    let mut values = vec![
        pg_value(r.tenant_id().as_str().to_owned()),
        pg_value(r.from()),
        pg_value(to),
    ];
    let predicate = if let Some(cursor) = request.after() {
        let (occurred, fields) = decode_cursor(cursor, 1)?;
        values.extend([
            pg_value(occurred),
            pg_value(occurred),
            pg_value(fields[0].clone()),
        ]);
        " AND (occurred_at>$4 OR (occurred_at=$5 AND event_id>$6))"
    } else {
        ""
    };
    let limit = (request.page_size() + 1) as i64;
    values.push(pg_value(limit));
    Ok((
        format!(
            "SELECT tenant_id,event_id,user_id,event_kind,subject_kind,subject_id,occurred_at FROM telemetry_lifecycle_events_v0 WHERE tenant_id=$1 AND occurred_at>=$2 AND occurred_at<$3{predicate} ORDER BY occurred_at,event_id LIMIT ${}",
            values.len()
        ),
        values,
    ))
}
fn coverage_query(
    request: &TelemetryScanPageRequest,
    to: DateTime<Utc>,
) -> Result<(String, PgParams), TelemetryRepositoryError> {
    let r = request.range();
    let mut values = vec![
        pg_value(r.tenant_id().as_str().to_owned()),
        pg_value(r.from()),
        pg_value(to),
    ];
    let predicate = if let Some(cursor) = request.after() {
        let (window, fields) = decode_cursor(cursor, 1)?;
        values.extend([
            pg_value(window),
            pg_value(window),
            pg_value(fields[0].clone()),
        ]);
        " AND (window_start>$4 OR (window_start=$5 AND collector_instance_id>$6))"
    } else {
        ""
    };
    let limit = (request.page_size() + 1) as i64;
    values.push(pg_value(limit));
    Ok((
        format!(
            "SELECT tenant_id,window_start,collector_instance_id,accepted_observation_count,queue_full_drop_count,closed_drop_count,invalid_drop_count,write_failed_observation_count,first_observed_at,last_observed_at FROM telemetry_collector_hourly_v0 WHERE tenant_id=$1 AND window_start>=$2 AND window_start<$3{predicate} ORDER BY window_start,collector_instance_id LIMIT ${}",
            values.len()
        ),
        values,
    ))
}

fn text(row: &Row, index: usize) -> Result<String, TelemetryRepositoryError> {
    row.try_get(index)
        .map_err(|source| TelemetryRepositoryError::StorageOperation {
            operation: "decoding telemetry text",
            source: Box::new(source),
        })
}
fn number(row: &Row, index: usize) -> Result<u64, TelemetryRepositoryError> {
    let value: i64 =
        row.try_get(index)
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "decoding telemetry counter",
                source: Box::new(source),
            })?;
    u64::try_from(value).map_err(|_| TelemetryRepositoryError::CounterOverflow {
        family: "persisted",
    })
}
fn datetime(row: &Row, index: usize) -> Result<DateTime<Utc>, TelemetryRepositoryError> {
    row.try_get(index)
        .map_err(|source| TelemetryRepositoryError::StorageOperation {
            operation: "decoding telemetry timestamp",
            source: Box::new(source),
        })
        .map(normalize_timestamp)
}
fn activity_from_row(row: &Row) -> Result<HourlyUserActivity, TelemetryRepositoryError> {
    Ok(HourlyUserActivity::new(
        decode_tenant_id(text(row, 0)?)?,
        datetime(row, 1)?,
        decode_user_id(text(row, 2)?)?,
        parse_origin(&text(row, 3)?)?,
        number(row, 4)?,
        number(row, 5)?,
        number(row, 6)?,
        number(row, 7)?,
        number(row, 8)?,
        number(row, 9)?,
        number(row, 10)?,
        number(row, 11)?,
        number(row, 12)?,
        datetime(row, 13)?,
        datetime(row, 14)?,
    )?)
}
fn model_from_row(row: &Row) -> Result<HourlyModelUsage, TelemetryRepositoryError> {
    Ok(HourlyModelUsage::new(
        decode_tenant_id(text(row, 0)?)?,
        decode_user_id(text(row, 1)?)?,
        datetime(row, 2)?,
        decode_provider_id(text(row, 3)?)?,
        decode_model_id(text(row, 4)?)?,
        number(row, 5)?,
        number(row, 6)?,
        number(row, 7)?,
        number(row, 8)?,
        number(row, 9)?,
        number(row, 10)?,
        datetime(row, 11)?,
        datetime(row, 12)?,
    )?)
}
fn failure_from_row(row: &Row) -> Result<HourlyRunFailure, TelemetryRepositoryError> {
    Ok(HourlyRunFailure::new(
        decode_tenant_id(text(row, 0)?)?,
        datetime(row, 1)?,
        decode_user_id(text(row, 2)?)?,
        decode_failure_category(text(row, 3)?)?,
        number(row, 4)?,
        datetime(row, 5)?,
        datetime(row, 6)?,
    )?)
}
fn automation_from_row(row: &Row) -> Result<HourlyAutomationUsage, TelemetryRepositoryError> {
    Ok(HourlyAutomationUsage::new(
        decode_tenant_id(text(row, 0)?)?,
        datetime(row, 1)?,
        decode_user_id(text(row, 2)?)?,
        parse_automation(&text(row, 3)?)?,
        number(row, 4)?,
        number(row, 5)?,
        number(row, 6)?,
        number(row, 7)?,
        number(row, 8)?,
        datetime(row, 9)?,
        datetime(row, 10)?,
    )?)
}
fn lifecycle_from_row(row: &Row) -> Result<LifecycleEvent, TelemetryRepositoryError> {
    let user_id: Option<String> =
        row.try_get(2)
            .map_err(|source| TelemetryRepositoryError::StorageOperation {
                operation: "decoding lifecycle user",
                source: Box::new(source),
            })?;
    let user_id = user_id.map(decode_user_id).transpose()?;
    Ok(LifecycleEvent::new(
        decode_tenant_id(text(row, 0)?)?,
        decode_event_id(text(row, 1)?)?,
        user_id,
        parse_event(&text(row, 3)?)?,
        parse_subject(&text(row, 4)?)?,
        decode_subject_id(text(row, 5)?)?,
        datetime(row, 6)?,
    )?)
}
fn coverage_from_row(row: &Row) -> Result<CollectorCoverage, TelemetryRepositoryError> {
    Ok(CollectorCoverage::new(
        decode_tenant_id(text(row, 0)?)?,
        datetime(row, 1)?,
        decode_collector_id(text(row, 2)?)?,
        number(row, 3)?,
        number(row, 4)?,
        number(row, 5)?,
        number(row, 6)?,
        number(row, 7)?,
        datetime(row, 8)?,
        datetime(row, 9)?,
    )?)
}
#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::{MIGRATION, model_query};
    use crate::repository::{TelemetryScanPageRequest, TelemetryScanRequest};
    use ironclaw_telemetry_contracts::observation::{CanonicalTenantId, ProviderId};

    #[test]
    fn postgres_upserts_bind_both_activity_observation_timestamps() {
        let source = include_str!("postgres.rs");
        let activity = source
            .split_once("async fn upsert_activity")
            .and_then(|(_, rest)| rest.split_once("async fn check_activity_overflow"))
            .map(|(body, _)| body)
            .expect("activity upsert body");

        assert!(activity.contains("row.first_observed_at()"));
        assert!(activity.contains("row.last_observed_at()"));
    }

    #[test]
    fn postgres_upserts_bind_both_model_observation_timestamps() {
        let source = include_str!("postgres.rs");
        let model = source
            .split_once("async fn upsert_model")
            .and_then(|(_, rest)| rest.split_once("async fn upsert_failure"))
            .map(|(body, _)| body)
            .expect("model upsert body");

        assert!(model.contains("row.first_observed_at()"));
        assert!(model.contains("row.last_observed_at()"));
    }

    #[test]
    fn postgres_model_scan_types_nullable_filter_parameters() {
        let tenant = CanonicalTenantId::new("tenant-a".to_owned()).expect("test tenant");
        let from = DateTime::parse_from_rfc3339("2026-08-26T00:00:00Z")
            .expect("test from")
            .with_timezone(&Utc);
        let to = DateTime::parse_from_rfc3339("2026-08-27T00:00:00Z")
            .expect("test to")
            .with_timezone(&Utc);
        let range = TelemetryScanRequest::new(tenant, from, to, to).expect("test range");
        let request = TelemetryScanPageRequest::new(range, 10, None).expect("test page");

        let (sql, values) = model_query(&request, to).expect("unfiltered model query");
        assert!(sql.contains("$4::text IS NULL"));
        assert!(sql.contains("$6::text IS NULL"));
        assert_eq!(values.len(), 8);

        let filtered_range = request
            .range()
            .clone()
            .with_provider_id(Some(ProviderId::new("provider-a").expect("test provider")));
        let filtered_request =
            TelemetryScanPageRequest::new(filtered_range, 10, None).expect("filtered page");
        let (filtered_sql, filtered_values) =
            model_query(&filtered_request, to).expect("filtered model query");
        assert!(filtered_sql.contains("$4::text IS NULL"));
        assert!(filtered_sql.contains("$6::text IS NULL"));
        assert_eq!(filtered_values.len(), 8);
    }

    #[test]
    fn postgres_migration_has_shared_schema_v0_shape() {
        crate::repository::assert_schema_v0_shape(MIGRATION, true);
    }

    #[test]
    fn postgres_batch_has_one_pool_admission() {
        crate::repository::assert_single_batch_admission(
            include_str!("postgres.rs"),
            "upsert_batch",
            "self.pool",
        );
    }
}
