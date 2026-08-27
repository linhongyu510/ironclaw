//! Private worker seam for routing multi-tenant batches into scoped writes.

use super::*;
use async_trait::async_trait;

#[derive(Default)]
struct TenantBatchRows {
    activity: Vec<HourlyUserActivity>,
    model_usage: Vec<HourlyModelUsage>,
    run_failures: Vec<HourlyRunFailure>,
    automation_usage: Vec<HourlyAutomationUsage>,
    lifecycle_events: Vec<LifecycleEvent>,
    collector_coverage: Vec<CollectorCoverage>,
}

fn split_batch_by_tenant(
    batch: &TelemetryBatch,
) -> Result<Vec<(ResourceScope, TelemetryBatch)>, TelemetryRepositoryError> {
    let mut grouped = BTreeMap::<TenantId, TenantBatchRows>::new();
    for row in batch.activity() {
        grouped
            .entry(row.tenant_id().clone())
            .or_default()
            .activity
            .push(row.clone());
    }
    for row in batch.model_usage() {
        grouped
            .entry(row.tenant_id().clone())
            .or_default()
            .model_usage
            .push(row.clone());
    }
    for row in batch.run_failures() {
        grouped
            .entry(row.tenant_id().clone())
            .or_default()
            .run_failures
            .push(row.clone());
    }
    for row in batch.automation_usage() {
        grouped
            .entry(row.tenant_id().clone())
            .or_default()
            .automation_usage
            .push(row.clone());
    }
    for row in batch.lifecycle_events() {
        grouped
            .entry(row.tenant_id().clone())
            .or_default()
            .lifecycle_events
            .push(row.clone());
    }
    for row in batch.collector_coverage() {
        grouped
            .entry(row.tenant_id().clone())
            .or_default()
            .collector_coverage
            .push(row.clone());
    }

    grouped
        .into_iter()
        .map(|(tenant_id, rows)| {
            let scope = ResourceScope {
                tenant_id,
                user_id: WorkerUserId::from_trusted("__telemetry_worker__".to_owned()),
                agent_id: None,
                project_id: None,
                mission_id: None,
                thread_id: None,
                invocation_id: InvocationId::new(),
            };
            let batch = TelemetryBatch::new(
                rows.activity,
                rows.model_usage,
                rows.run_failures,
                rows.automation_usage,
                rows.lifecycle_events,
                rows.collector_coverage,
            )?;
            Ok((scope, batch))
        })
        .collect()
}

#[async_trait]
impl<F> TelemetryBatchSink for FilesystemTelemetryRepository<F>
where
    F: ironclaw_filesystem::RootFilesystem + ?Sized,
{
    async fn apply_batch(
        &self,
        batch: &TelemetryBatch,
    ) -> Result<BatchApplyReport, TelemetryRepositoryError> {
        let mut report = BatchApplyReport::default();
        for (scope, tenant_batch) in split_batch_by_tenant(batch)? {
            let tenant_report = self
                .apply_scoped_batch(ScopedTelemetryBatch::new(scope, tenant_batch))
                .await?;
            report.applied_prefix = report
                .applied_prefix
                .saturating_add(tenant_report.applied_prefix);
            report.failed_record_count = report
                .failed_record_count
                .saturating_add(tenant_report.failed_record_count);
        }
        Ok(report)
    }
}
