use std::path::Path;
use std::sync::Arc;

use ironclaw_filesystem::LibSqlRootFilesystem;
use ironclaw_host_api::ids::UserId;
use ironclaw_skills::ScopedSkillManagementPort;

/// List standalone user skills from the same canonical libSQL filesystem the
/// runtime uses, then merge the embedded bundled catalog.
pub async fn list_reborn_local_skills_from_state(
    owner_id: impl Into<String>,
    state_root: impl AsRef<Path>,
) -> Result<
    Vec<ironclaw_skills::SkillSummary>,
    ironclaw_extension_host::skill_listing::RebornSkillListError,
> {
    let state_root = state_root.as_ref();
    let database_path = crate::filesystem_assembly::standalone_db_path(state_root);
    if !database_path.try_exists().map_err(|error| {
        ironclaw_extension_host::skill_listing::RebornSkillListError::Unavailable {
            reason: format!("standalone skill database could not be inspected: {error}"),
        }
    })? {
        return ironclaw_extension_host::skill_listing::list_reborn_skills_from_management(None)
            .await;
    }

    let owner_user_id = UserId::new(owner_id.into()).map_err(|error| {
        ironclaw_extension_host::skill_listing::RebornSkillListError::InvalidRequest {
            reason: error.to_string(),
        }
    })?;
    let database = crate::filesystem_assembly::open_standalone_libsql_database(state_root)
        .await
        .map_err(|error| {
            ironclaw_extension_host::skill_listing::RebornSkillListError::Unavailable {
                reason: error.to_string(),
            }
        })?;
    let runtime = Arc::new(
        ironclaw_libsql_runtime::LibSqlRuntime::new(database).map_err(|error| {
            ironclaw_extension_host::skill_listing::RebornSkillListError::Unavailable {
                reason: error.to_string(),
            }
        })?,
    );
    let filesystem = Arc::new(LibSqlRootFilesystem::from_runtime(runtime));
    filesystem.run_migrations().await.map_err(|error| {
        ironclaw_extension_host::skill_listing::RebornSkillListError::Unavailable {
            reason: error.to_string(),
        }
    })?;
    let skill_management = Arc::new(ScopedSkillManagementPort::new_with_mount_resolver(
        owner_user_id,
        filesystem,
        Arc::new(
            crate::factory::production_backend_assembly::production_skill_management_mount_view,
        ),
    ));

    ironclaw_extension_host::skill_listing::list_reborn_skills_from_management(Some(
        skill_management,
    ))
    .await
}
