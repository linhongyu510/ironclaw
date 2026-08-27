use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;
use ironclaw_telemetry_contracts::observation::{
    AutomationKind, CanonicalTenantId, CanonicalUserId, LifecycleEventKind, LifecycleSubjectKind,
    OriginKind,
};
use tokio_postgres::Row;

use crate::{
    CollectorCoverage, HourlyAutomationUsage, HourlyModelUsage, HourlyRunFailure,
    HourlyUserActivity, LifecycleEvent, TelemetryBatch,
    error::TelemetryRepositoryError,
    repository::{
        TelemetryPage, TelemetryRepository, TelemetryScanPageRequest, decode_cursor, encode_cursor,
        page_rows,
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
pub struct PostgresTelemetryRepository {
    pool: deadpool_postgres::Pool,
}

impl PostgresTelemetryRepository {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TelemetryRepository for PostgresTelemetryRepository {
    async fn migrate(&self) -> Result<(), TelemetryRepositoryError> {
        let mut client =
            self.pool
                .get()
                .await
                .map_err(|source| TelemetryRepositoryError::PostgresPool {
                    operation: "acquiring telemetry migration client",
                    source,
                })?;
        let transaction =
            client
                .transaction()
                .await
                .map_err(|source| TelemetryRepositoryError::Postgres {
                    operation: "beginning telemetry migration transaction",
                    source,
                })?;
        transaction
            .batch_execute(MIGRATION)
            .await
            .map_err(|source| TelemetryRepositoryError::Postgres {
                operation: "running telemetry migration",
                source,
            })?;
        transaction
            .commit()
            .await
            .map_err(|source| TelemetryRepositoryError::Postgres {
                operation: "committing telemetry migration",
                source,
            })
    }

    async fn upsert_batch(&self, batch: &TelemetryBatch) -> Result<(), TelemetryRepositoryError> {
        let mut client =
            self.pool
                .get()
                .await
                .map_err(|source| TelemetryRepositoryError::PostgresPool {
                    operation: "acquiring telemetry batch client",
                    source,
                })?;
        let transaction =
            client
                .transaction()
                .await
                .map_err(|source| TelemetryRepositoryError::Postgres {
                    operation: "beginning telemetry batch transaction",
                    source,
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
            .map_err(|source| TelemetryRepositoryError::Postgres {
                operation: "committing telemetry batch transaction",
                source,
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
        let client =
            self.pool
                .get()
                .await
                .map_err(|source| TelemetryRepositoryError::PostgresPool {
                    operation: "acquiring telemetry activity reader",
                    source,
                })?;
        let (sql, boxed) = activity_query(request, to)?;
        let params = boxed
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = client.query(&sql, &params).await.map_err(|source| {
            TelemetryRepositoryError::Postgres {
                operation: "scanning telemetry activity",
                source,
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
        let client =
            self.pool
                .get()
                .await
                .map_err(|source| TelemetryRepositoryError::PostgresPool {
                    operation: "acquiring telemetry model reader",
                    source,
                })?;
        let (sql, boxed) = model_query(request, to)?;
        let params = boxed
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = client.query(&sql, &params).await.map_err(|source| {
            TelemetryRepositoryError::Postgres {
                operation: "scanning telemetry model usage",
                source,
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
        let client =
            self.pool
                .get()
                .await
                .map_err(|source| TelemetryRepositoryError::PostgresPool {
                    operation: "acquiring telemetry failure reader",
                    source,
                })?;
        let (sql, boxed) = failure_query(request, to)?;
        let params = boxed
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = client.query(&sql, &params).await.map_err(|source| {
            TelemetryRepositoryError::Postgres {
                operation: "scanning telemetry failures",
                source,
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
        let client =
            self.pool
                .get()
                .await
                .map_err(|source| TelemetryRepositoryError::PostgresPool {
                    operation: "acquiring telemetry automation reader",
                    source,
                })?;
        let (sql, boxed) = automation_query(request, to)?;
        let params = boxed
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = client.query(&sql, &params).await.map_err(|source| {
            TelemetryRepositoryError::Postgres {
                operation: "scanning telemetry automation",
                source,
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
        let client =
            self.pool
                .get()
                .await
                .map_err(|source| TelemetryRepositoryError::PostgresPool {
                    operation: "acquiring telemetry lifecycle reader",
                    source,
                })?;
        let (sql, boxed) = lifecycle_query(request, to)?;
        let params = boxed
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = client.query(&sql, &params).await.map_err(|source| {
            TelemetryRepositoryError::Postgres {
                operation: "scanning telemetry lifecycle",
                source,
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
        let client =
            self.pool
                .get()
                .await
                .map_err(|source| TelemetryRepositoryError::PostgresPool {
                    operation: "acquiring telemetry coverage reader",
                    source,
                })?;
        let (sql, boxed) = coverage_query(request, to)?;
        let params = boxed
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = client.query(&sql, &params).await.map_err(|source| {
            TelemetryRepositoryError::Postgres {
                operation: "scanning telemetry coverage",
                source,
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
    tx.execute("INSERT INTO telemetry_hourly_user_activity_v0 (tenant_id,window_start,user_id,origin_kind,run_count,runs_with_reported_tool_calls_count,tool_count_reported_run_count,reported_tool_call_count,completed_count,failed_count,cancelled_count,recovery_required_count,total_run_latency_ms,first_observed_at,last_observed_at,schema_version,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,0,$15) ON CONFLICT (tenant_id,window_start,user_id,origin_kind) DO UPDATE SET run_count=telemetry_hourly_user_activity_v0.run_count+EXCLUDED.run_count,runs_with_reported_tool_calls_count=telemetry_hourly_user_activity_v0.runs_with_reported_tool_calls_count+EXCLUDED.runs_with_reported_tool_calls_count,tool_count_reported_run_count=telemetry_hourly_user_activity_v0.tool_count_reported_run_count+EXCLUDED.tool_count_reported_run_count,reported_tool_call_count=telemetry_hourly_user_activity_v0.reported_tool_call_count+EXCLUDED.reported_tool_call_count,completed_count=telemetry_hourly_user_activity_v0.completed_count+EXCLUDED.completed_count,failed_count=telemetry_hourly_user_activity_v0.failed_count+EXCLUDED.failed_count,cancelled_count=telemetry_hourly_user_activity_v0.cancelled_count+EXCLUDED.cancelled_count,recovery_required_count=telemetry_hourly_user_activity_v0.recovery_required_count+EXCLUDED.recovery_required_count,total_run_latency_ms=telemetry_hourly_user_activity_v0.total_run_latency_ms+EXCLUDED.total_run_latency_ms,first_observed_at=LEAST(telemetry_hourly_user_activity_v0.first_observed_at,EXCLUDED.first_observed_at),last_observed_at=GREATEST(telemetry_hourly_user_activity_v0.last_observed_at,EXCLUDED.last_observed_at),updated_at=EXCLUDED.updated_at", &[&row.tenant_id().as_str(), &row.window_start(), &row.user_id().as_str(), &origin_text(row.origin_kind()), &(row.run_count() as i64), &(row.runs_with_reported_tool_calls_count() as i64), &(row.tool_count_reported_run_count() as i64), &(row.reported_tool_call_count() as i64), &(row.completed_count() as i64), &(row.failed_count() as i64), &(row.cancelled_count() as i64), &(row.recovery_required_count() as i64), &(row.total_run_latency_ms() as i64), &row.last_observed_at()]).await.map_err(|source|TelemetryRepositoryError::Postgres{operation:"upserting telemetry activity",source}).map(|_|())
}

fn checked_counter_sum(
    current: i64,
    incoming: u64,
    family: &'static str,
) -> Result<(), TelemetryRepositoryError> {
    let current =
        u64::try_from(current).map_err(|_| TelemetryRepositoryError::CounterOverflow { family })?;
    let total = current
        .checked_add(incoming)
        .ok_or(TelemetryRepositoryError::CounterOverflow { family })?;
    if total > ironclaw_telemetry_contracts::observation::MAX_DURABLE_COUNTER {
        return Err(TelemetryRepositoryError::CounterOverflow { family });
    }
    Ok(())
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
            &[&tenant, &row.window_start(), &user, &origin],
        )
        .await
        .map_err(|source| TelemetryRepositoryError::Postgres {
            operation: "checking telemetry activity overflow",
            source,
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
            &[&tenant, &user, &row.window_start(), &provider, &model],
        )
        .await
        .map_err(|source| TelemetryRepositoryError::Postgres {
            operation: "checking telemetry model overflow",
            source,
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
            &[&tenant, &row.window_start(), &user, &category],
        )
        .await
        .map_err(|source| TelemetryRepositoryError::Postgres {
            operation: "checking telemetry failure overflow",
            source,
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
            &[&tenant, &row.window_start(), &user, &kind],
        )
        .await
        .map_err(|source| TelemetryRepositoryError::Postgres {
            operation: "checking telemetry automation overflow",
            source,
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
            &[&tenant, &row.window_start(), &collector],
        )
        .await
        .map_err(|source| TelemetryRepositoryError::Postgres {
            operation: "checking telemetry coverage overflow",
            source,
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
    let current: i64 = row
        .try_get(index)
        .map_err(|source| TelemetryRepositoryError::Postgres {
            operation: "decoding telemetry overflow counter",
            source,
        })?;
    checked_counter_sum(current, incoming, family)
}

async fn upsert_model<C: GenericClient + Sync>(
    tx: &C,
    row: &HourlyModelUsage,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_hourly_model_usage_v0 (tenant_id,user_id,window_start,provider_id,effective_model_id,inference_count,usage_reported_count,input_tokens,output_tokens,cache_read_input_tokens,cache_creation_input_tokens,first_observed_at,last_observed_at,schema_version,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,0,$13) ON CONFLICT (tenant_id,user_id,window_start,provider_id,effective_model_id) DO UPDATE SET inference_count=telemetry_hourly_model_usage_v0.inference_count+EXCLUDED.inference_count,usage_reported_count=telemetry_hourly_model_usage_v0.usage_reported_count+EXCLUDED.usage_reported_count,input_tokens=telemetry_hourly_model_usage_v0.input_tokens+EXCLUDED.input_tokens,output_tokens=telemetry_hourly_model_usage_v0.output_tokens+EXCLUDED.output_tokens,cache_read_input_tokens=telemetry_hourly_model_usage_v0.cache_read_input_tokens+EXCLUDED.cache_read_input_tokens,cache_creation_input_tokens=telemetry_hourly_model_usage_v0.cache_creation_input_tokens+EXCLUDED.cache_creation_input_tokens,first_observed_at=LEAST(telemetry_hourly_model_usage_v0.first_observed_at,EXCLUDED.first_observed_at),last_observed_at=GREATEST(telemetry_hourly_model_usage_v0.last_observed_at,EXCLUDED.last_observed_at),updated_at=EXCLUDED.updated_at", &[&row.tenant_id().as_str(),&row.user_id().as_str(),&row.window_start(),&row.provider_id().as_str(),&row.effective_model_id().as_str(),&(row.inference_count() as i64),&(row.usage_reported_count() as i64),&(row.input_tokens() as i64),&(row.output_tokens() as i64),&(row.cache_read_input_tokens() as i64),&(row.cache_creation_input_tokens() as i64),&row.last_observed_at(),]).await.map_err(|source|TelemetryRepositoryError::Postgres{operation:"upserting telemetry model usage",source}).map(|_|())
}
async fn upsert_failure<C: GenericClient + Sync>(
    tx: &C,
    row: &HourlyRunFailure,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_hourly_run_failures_v0 (tenant_id,window_start,user_id,failure_category,failure_count,first_observed_at,last_observed_at,schema_version,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,0,$7) ON CONFLICT (tenant_id,window_start,user_id,failure_category) DO UPDATE SET failure_count=telemetry_hourly_run_failures_v0.failure_count+EXCLUDED.failure_count,first_observed_at=LEAST(telemetry_hourly_run_failures_v0.first_observed_at,EXCLUDED.first_observed_at),last_observed_at=GREATEST(telemetry_hourly_run_failures_v0.last_observed_at,EXCLUDED.last_observed_at),updated_at=EXCLUDED.updated_at", &[&row.tenant_id().as_str(),&row.window_start(),&row.user_id().as_str(),&row.failure_category().as_str(),&(row.failure_count() as i64),&row.first_observed_at(),&row.last_observed_at()]).await.map_err(|source|TelemetryRepositoryError::Postgres{operation:"upserting telemetry failure",source}).map(|_|())
}
async fn upsert_automation<C: GenericClient + Sync>(
    tx: &C,
    row: &HourlyAutomationUsage,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_hourly_automation_usage_v0 (tenant_id,window_start,user_id,automation_kind,run_count,completed_count,failed_count,cancelled_count,recovery_required_count,first_observed_at,last_observed_at,schema_version,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0,$11) ON CONFLICT (tenant_id,window_start,user_id,automation_kind) DO UPDATE SET run_count=telemetry_hourly_automation_usage_v0.run_count+EXCLUDED.run_count,completed_count=telemetry_hourly_automation_usage_v0.completed_count+EXCLUDED.completed_count,failed_count=telemetry_hourly_automation_usage_v0.failed_count+EXCLUDED.failed_count,cancelled_count=telemetry_hourly_automation_usage_v0.cancelled_count+EXCLUDED.cancelled_count,recovery_required_count=telemetry_hourly_automation_usage_v0.recovery_required_count+EXCLUDED.recovery_required_count,first_observed_at=LEAST(telemetry_hourly_automation_usage_v0.first_observed_at,EXCLUDED.first_observed_at),last_observed_at=GREATEST(telemetry_hourly_automation_usage_v0.last_observed_at,EXCLUDED.last_observed_at),updated_at=EXCLUDED.updated_at", &[&row.tenant_id().as_str(),&row.window_start(),&row.user_id().as_str(),&automation_text(row.automation_kind()),&(row.run_count() as i64),&(row.completed_count() as i64),&(row.failed_count() as i64),&(row.cancelled_count() as i64),&(row.recovery_required_count() as i64),&row.first_observed_at(),&row.last_observed_at()]).await.map_err(|source|TelemetryRepositoryError::Postgres{operation:"upserting telemetry automation",source}).map(|_|())
}
async fn upsert_lifecycle<C: GenericClient + Sync>(
    tx: &C,
    row: &LifecycleEvent,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_lifecycle_events_v0 (tenant_id,event_id,user_id,event_kind,subject_kind,subject_id,occurred_at,schema_version) VALUES ($1,$2,$3,$4,$5,$6,$7,0) ON CONFLICT (tenant_id,event_id) DO NOTHING", &[&row.tenant_id().as_str(),&row.event_id().as_str(),&row.user_id().map(|id|id.as_str()),&lifecycle_event_text(row.event_kind()),&lifecycle_subject_text(row.subject_kind()),&row.subject_id().as_str(),&row.occurred_at()]).await.map_err(|source|TelemetryRepositoryError::Postgres{operation:"upserting telemetry lifecycle",source}).map(|_|())
}
async fn upsert_coverage<C: GenericClient + Sync>(
    tx: &C,
    row: &CollectorCoverage,
) -> Result<(), TelemetryRepositoryError> {
    tx.execute("INSERT INTO telemetry_collector_hourly_v0 (tenant_id,window_start,collector_instance_id,accepted_observation_count,queue_full_drop_count,closed_drop_count,invalid_drop_count,write_failed_observation_count,first_observed_at,last_observed_at,schema_version,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0,$11) ON CONFLICT (tenant_id,window_start,collector_instance_id) DO UPDATE SET accepted_observation_count=telemetry_collector_hourly_v0.accepted_observation_count+EXCLUDED.accepted_observation_count,queue_full_drop_count=telemetry_collector_hourly_v0.queue_full_drop_count+EXCLUDED.queue_full_drop_count,closed_drop_count=telemetry_collector_hourly_v0.closed_drop_count+EXCLUDED.closed_drop_count,invalid_drop_count=telemetry_collector_hourly_v0.invalid_drop_count+EXCLUDED.invalid_drop_count,write_failed_observation_count=telemetry_collector_hourly_v0.write_failed_observation_count+EXCLUDED.write_failed_observation_count,first_observed_at=LEAST(telemetry_collector_hourly_v0.first_observed_at,EXCLUDED.first_observed_at),last_observed_at=GREATEST(telemetry_collector_hourly_v0.last_observed_at,EXCLUDED.last_observed_at),updated_at=EXCLUDED.updated_at", &[&row.tenant_id().as_str(),&row.window_start(),&row.collector_instance_id().as_str(),&(row.accepted_observation_count() as i64),&(row.queue_full_drop_count() as i64),&(row.closed_drop_count() as i64),&(row.invalid_drop_count() as i64),&(row.write_failed_observation_count() as i64),&row.first_observed_at(),&row.last_observed_at()]).await.map_err(|source|TelemetryRepositoryError::Postgres{operation:"upserting telemetry coverage",source}).map(|_|())
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
            "SELECT tenant_id,user_id,window_start,provider_id,effective_model_id,inference_count,usage_reported_count,input_tokens,output_tokens,cache_read_input_tokens,cache_creation_input_tokens,first_observed_at,last_observed_at FROM telemetry_hourly_model_usage_v0 WHERE tenant_id=$1 AND window_start>=$2 AND window_start<$3 AND ($4 IS NULL OR provider_id=$5) AND ($6 IS NULL OR effective_model_id=$7){predicate} ORDER BY window_start,user_id,provider_id,effective_model_id LIMIT ${}",
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
        .map_err(|source| TelemetryRepositoryError::Postgres {
            operation: "decoding telemetry text",
            source,
        })
}
fn number(row: &Row, index: usize) -> Result<u64, TelemetryRepositoryError> {
    let value: i64 = row
        .try_get(index)
        .map_err(|source| TelemetryRepositoryError::Postgres {
            operation: "decoding telemetry counter",
            source,
        })?;
    u64::try_from(value).map_err(|_| TelemetryRepositoryError::CounterOverflow {
        family: "persisted",
    })
}
fn datetime(row: &Row, index: usize) -> Result<DateTime<Utc>, TelemetryRepositoryError> {
    row.try_get(index)
        .map_err(|source| TelemetryRepositoryError::Postgres {
            operation: "decoding telemetry timestamp",
            source,
        })
}
fn tenant(value: String) -> Result<CanonicalTenantId, TelemetryRepositoryError> {
    CanonicalTenantId::new(value).map_err(|_| TelemetryRepositoryError::InvalidCursor)
}
fn user(value: String) -> Result<CanonicalUserId, TelemetryRepositoryError> {
    CanonicalUserId::new(value).map_err(|_| TelemetryRepositoryError::InvalidCursor)
}
fn activity_from_row(row: &Row) -> Result<HourlyUserActivity, TelemetryRepositoryError> {
    Ok(HourlyUserActivity::new(
        tenant(text(row, 0)?)?,
        datetime(row, 1)?,
        user(text(row, 2)?)?,
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
        tenant(text(row, 0)?)?,
        user(text(row, 1)?)?,
        datetime(row, 2)?,
        ironclaw_telemetry_contracts::observation::ProviderId::new(text(row, 3)?)
            .map_err(|_| TelemetryRepositoryError::InvalidCursor)?,
        ironclaw_telemetry_contracts::observation::EffectiveModelId::new(text(row, 4)?)
            .map_err(|_| TelemetryRepositoryError::InvalidCursor)?,
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
        tenant(text(row, 0)?)?,
        datetime(row, 1)?,
        user(text(row, 2)?)?,
        ironclaw_telemetry_contracts::observation::FailureCategory::new(text(row, 3)?)
            .map_err(|_| TelemetryRepositoryError::InvalidCursor)?,
        number(row, 4)?,
        datetime(row, 5)?,
        datetime(row, 6)?,
    )?)
}
fn automation_from_row(row: &Row) -> Result<HourlyAutomationUsage, TelemetryRepositoryError> {
    Ok(HourlyAutomationUsage::new(
        tenant(text(row, 0)?)?,
        datetime(row, 1)?,
        user(text(row, 2)?)?,
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
            .map_err(|source| TelemetryRepositoryError::Postgres {
                operation: "decoding lifecycle user",
                source,
            })?;
    let user_id = user_id.map(user).transpose()?;
    Ok(LifecycleEvent::new(
        tenant(text(row, 0)?)?,
        ironclaw_telemetry_contracts::observation::LifecycleEventId::new(text(row, 1)?)
            .map_err(|_| TelemetryRepositoryError::InvalidCursor)?,
        user_id,
        parse_event(&text(row, 3)?)?,
        parse_subject(&text(row, 4)?)?,
        ironclaw_telemetry_contracts::observation::SubjectId::new(text(row, 5)?)
            .map_err(|_| TelemetryRepositoryError::InvalidCursor)?,
        datetime(row, 6)?,
    )?)
}
fn coverage_from_row(row: &Row) -> Result<CollectorCoverage, TelemetryRepositoryError> {
    Ok(CollectorCoverage::new(
        tenant(text(row, 0)?)?,
        datetime(row, 1)?,
        ironclaw_telemetry_contracts::observation::CollectorInstanceId::new(text(row, 2)?)
            .map_err(|_| TelemetryRepositoryError::InvalidCursor)?,
        number(row, 3)?,
        number(row, 4)?,
        number(row, 5)?,
        number(row, 6)?,
        number(row, 7)?,
        datetime(row, 8)?,
        datetime(row, 9)?,
    )?)
}
fn origin_text(value: OriginKind) -> &'static str {
    match value {
        OriginKind::Human => "human",
        OriginKind::ParentAgent => "parent_agent",
        OriginKind::System => "system",
        OriginKind::Automation => "automation",
        OriginKind::Other => "other",
    }
}
fn parse_origin(value: &str) -> Result<OriginKind, TelemetryRepositoryError> {
    match value {
        "human" => Ok(OriginKind::Human),
        "parent_agent" => Ok(OriginKind::ParentAgent),
        "system" => Ok(OriginKind::System),
        "automation" => Ok(OriginKind::Automation),
        "other" => Ok(OriginKind::Other),
        value => Err(TelemetryRepositoryError::UnknownEnum {
            field: "origin_kind",
            value: value.to_owned(),
        }),
    }
}
fn automation_text(value: AutomationKind) -> &'static str {
    match value {
        AutomationKind::Cron => "cron",
        AutomationKind::Once => "once",
        AutomationKind::Manual => "manual",
    }
}
fn parse_automation(value: &str) -> Result<AutomationKind, TelemetryRepositoryError> {
    match value {
        "cron" => Ok(AutomationKind::Cron),
        "once" => Ok(AutomationKind::Once),
        "manual" => Ok(AutomationKind::Manual),
        value => Err(TelemetryRepositoryError::UnknownEnum {
            field: "automation_kind",
            value: value.to_owned(),
        }),
    }
}
fn lifecycle_event_text(value: LifecycleEventKind) -> &'static str {
    match value {
        LifecycleEventKind::MemberAdded => "member_added",
        LifecycleEventKind::MemberRemoved => "member_removed",
        LifecycleEventKind::RoutineCreated => "routine_created",
        LifecycleEventKind::RoutineEnabled => "routine_enabled",
        LifecycleEventKind::RoutineDisabled => "routine_disabled",
        LifecycleEventKind::RoutineDeleted => "routine_deleted",
    }
}
fn parse_event(value: &str) -> Result<LifecycleEventKind, TelemetryRepositoryError> {
    match value {
        "member_added" => Ok(LifecycleEventKind::MemberAdded),
        "member_removed" => Ok(LifecycleEventKind::MemberRemoved),
        "routine_created" => Ok(LifecycleEventKind::RoutineCreated),
        "routine_enabled" => Ok(LifecycleEventKind::RoutineEnabled),
        "routine_disabled" => Ok(LifecycleEventKind::RoutineDisabled),
        "routine_deleted" => Ok(LifecycleEventKind::RoutineDeleted),
        value => Err(TelemetryRepositoryError::UnknownEnum {
            field: "event_kind",
            value: value.to_owned(),
        }),
    }
}
fn lifecycle_subject_text(value: LifecycleSubjectKind) -> &'static str {
    match value {
        LifecycleSubjectKind::Tenant => "tenant",
        LifecycleSubjectKind::User => "user",
        LifecycleSubjectKind::Routine => "routine",
    }
}
fn parse_subject(value: &str) -> Result<LifecycleSubjectKind, TelemetryRepositoryError> {
    match value {
        "tenant" => Ok(LifecycleSubjectKind::Tenant),
        "user" => Ok(LifecycleSubjectKind::User),
        "routine" => Ok(LifecycleSubjectKind::Routine),
        value => Err(TelemetryRepositoryError::UnknownEnum {
            field: "subject_kind",
            value: value.to_owned(),
        }),
    }
}
