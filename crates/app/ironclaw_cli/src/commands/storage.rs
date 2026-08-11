use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Args, Subcommand};
use ironclaw_composition::host_api::{TenantId, UserId};

use crate::context::RebornCliContext;

/// Operate the bounded, offline durable-layout adoption flow.
#[derive(Debug, Args)]
pub(crate) struct StorageCommand {
    #[command(subcommand)]
    command: StorageSubcommand,
}

#[derive(Debug, Subcommand)]
enum StorageSubcommand {
    /// Adopt one supported legacy storage root into the canonical layout.
    Adopt(StorageAdoptCommand),
}

#[derive(Debug, Args)]
struct StorageAdoptCommand {
    /// Confirm every old IronClaw process is stopped before any source mutation.
    #[arg(long)]
    confirm_processes_stopped: bool,

    /// Confirm an operator-owned backup or volume snapshot exists.
    #[arg(long)]
    confirm_backup_snapshot: bool,

    /// Explicit external legacy workspace to copy into one tenant/user leaf.
    #[arg(long)]
    workspace_source: Option<PathBuf>,

    /// Authenticated tenant that owns --workspace-source.
    #[arg(long)]
    tenant: Option<String>,

    /// Authenticated user that owns --workspace-source.
    #[arg(long)]
    user: Option<String>,

    /// Confirm the previewed workspace copy. The source remains unchanged.
    #[arg(long)]
    confirm_workspace_import: bool,
}

impl StorageCommand {
    pub(crate) fn execute(self, context: RebornCliContext) -> anyhow::Result<()> {
        match self.command {
            StorageSubcommand::Adopt(command) => command.execute(context),
        }
    }
}

impl StorageAdoptCommand {
    fn execute(self, context: RebornCliContext) -> anyhow::Result<()> {
        let workspace_import = self.workspace_import_options()?;
        let outcome = crate::runtime::adopt_storage_layout(
            &context,
            self.confirm_processes_stopped,
            self.confirm_backup_snapshot,
            workspace_import,
        )?;
        match outcome {
            crate::runtime::StorageAdoptionOutcome::Adopted => {
                println!("durable storage layout adoption completed");
            }
            crate::runtime::StorageAdoptionOutcome::MigrationDryRunValidated => {
                println!("durable storage layout is ready; migration dry-run made no changes");
            }
        }
        Ok(())
    }

    fn workspace_import_options(
        &self,
    ) -> anyhow::Result<Option<crate::runtime::storage_layout::WorkspaceImportOptions>> {
        let workspace_import = match (&self.workspace_source, &self.tenant, &self.user) {
            (None, None, None) => None,
            (Some(source), Some(tenant), Some(user)) => {
                Some(crate::runtime::storage_layout::WorkspaceImportOptions {
                    source: source.clone(),
                    tenant: TenantId::new(tenant.clone())
                        .context("--tenant must be a valid typed tenant id")?,
                    user: UserId::new(user.clone())
                        .context("--user must be a valid typed user id")?,
                    confirmed: self.confirm_workspace_import,
                })
            }
            _ => anyhow::bail!(
                "--workspace-source, --tenant, and --user must be supplied together; IronClaw never infers a workspace owner"
            ),
        };
        if self.confirm_workspace_import && workspace_import.is_none() {
            anyhow::bail!(
                "--confirm-workspace-import requires --workspace-source, --tenant, and --user"
            );
        }
        Ok(workspace_import)
    }
}

#[cfg(test)]
mod tests {
    use super::StorageAdoptCommand;

    #[test]
    fn workspace_import_flags_must_be_complete() {
        for command in [
            StorageAdoptCommand {
                confirm_processes_stopped: true,
                confirm_backup_snapshot: true,
                workspace_source: Some("/tmp/workspace".into()),
                tenant: None,
                user: None,
                confirm_workspace_import: false,
            },
            StorageAdoptCommand {
                confirm_processes_stopped: true,
                confirm_backup_snapshot: true,
                workspace_source: None,
                tenant: None,
                user: None,
                confirm_workspace_import: true,
            },
        ] {
            let error = command
                .workspace_import_options()
                .expect_err("partial workspace import flags must be rejected by the CLI");
            assert!(
                error.to_string().contains("workspace"),
                "unexpected error: {error:#}"
            );
        }
    }
}
