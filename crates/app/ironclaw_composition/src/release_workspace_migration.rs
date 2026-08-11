//! One-way compatibility import for IronClaw 1.0's shared host workspace.
//!
//! The source remains untouched as the rollback authority. Files are copied
//! create-only into the current tenant/user workspace and verified by digest.

use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use ironclaw_host_api::ids::{TenantId, UserId};
use sha2::{Digest, Sha256};

use crate::RebornBuildError;

const MAX_WORKSPACE_ENTRIES: usize = 1_000_000;
const MAX_WORKSPACE_BYTES: u64 = 1_099_511_627_776;

#[derive(Debug, Clone)]
pub(crate) struct LegacyWorkspaceMigrationInput {
    pub(crate) source: PathBuf,
    pub(crate) workspace_root: PathBuf,
    pub(crate) tenant_id: TenantId,
    pub(crate) user_id: UserId,
}

pub(crate) async fn migrate_legacy_workspace_snapshot(
    input: LegacyWorkspaceMigrationInput,
) -> Result<(), RebornBuildError> {
    tokio::task::spawn_blocking(move || migrate_legacy_workspace_snapshot_blocking(&input))
        .await
        .map_err(|error| invalid(format!("workspace migration worker failed: {error}")))?
        .map_err(invalid)
}

fn migrate_legacy_workspace_snapshot_blocking(
    input: &LegacyWorkspaceMigrationInput,
) -> Result<(), String> {
    let source_metadata = std::fs::symlink_metadata(&input.source)
        .map_err(|error| format!("legacy snapshot source is not readable: {error}"))?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_dir() {
        return Err(
            "legacy snapshot source must be a real directory, not a symlink or special file"
                .to_string(),
        );
    }
    let source = input
        .source
        .canonicalize()
        .map_err(|error| format!("legacy snapshot source is not readable: {error}"))?;
    std::fs::create_dir_all(&input.workspace_root)
        .map_err(|error| format!("workspace root could not be created: {error}"))?;
    let workspace_root = input
        .workspace_root
        .canonicalize()
        .map_err(|error| format!("workspace root is not accessible: {error}"))?;
    if source.starts_with(&workspace_root) || workspace_root.starts_with(&source) {
        return Err("legacy snapshot source and live workspace root must not overlap".to_string());
    }

    let target_relative = PathBuf::from("tenants")
        .join(input.tenant_id.as_str())
        .join("users")
        .join(input.user_id.as_str());
    let target = ensure_relative_directory(&workspace_root, &target_relative)
        .map_err(|error| format!("scoped workspace target is unsafe: {error}"))?;
    let staging =
        ensure_relative_directory(&workspace_root, Path::new(".ironclaw-migration-staging"))
            .map_err(|error| format!("workspace staging directory is unsafe: {error}"))?;

    let mut entries_seen = 0_usize;
    let mut bytes_verified = 0_u64;
    let mut pending = vec![source.clone()];
    while let Some(directory) = pending.pop() {
        let relative = directory
            .strip_prefix(&source)
            .map_err(|error| format!("workspace source path escaped its root: {error}"))?;
        ensure_relative_directory(&target, relative)
            .map_err(|error| format!("workspace directory is unsafe: {error}"))?;

        let read_dir = std::fs::read_dir(&directory)
            .map_err(|error| format!("workspace directory could not be read: {error}"))?;
        let mut entries = Vec::new();
        for entry in read_dir {
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > MAX_WORKSPACE_ENTRIES {
                return Err("legacy workspace entry bound exceeded".to_string());
            }
            entries.push(
                entry.map_err(|error| format!("workspace entry could not be read: {error}"))?,
            );
        }
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries.into_iter().rev() {
            let metadata = std::fs::symlink_metadata(entry.path())
                .map_err(|error| format!("workspace entry metadata could not be read: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err(
                    "legacy workspace contains a symlink; replace it with a regular in-root file before retrying"
                        .to_string(),
                );
            }
            if metadata.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if !metadata.is_file() {
                return Err("legacy workspace contains an unsupported special file".to_string());
            }

            let relative = entry
                .path()
                .strip_prefix(&source)
                .map_err(|error| format!("workspace source path escaped its root: {error}"))?
                .to_path_buf();
            let destination = target.join(relative);
            let (source_hash, source_bytes) = hash_file(&entry.path())?;
            bytes_verified = bytes_verified
                .checked_add(source_bytes)
                .filter(|bytes| *bytes <= MAX_WORKSPACE_BYTES)
                .ok_or_else(|| "legacy workspace byte bound exceeded".to_string())?;
            match std::fs::symlink_metadata(&destination) {
                Ok(destination_metadata) => {
                    if !destination_metadata.is_file() {
                        return Err(
                            "legacy workspace destination conflicts with a non-file entry"
                                .to_string(),
                        );
                    }
                    let (destination_hash, destination_bytes) = hash_file(&destination)?;
                    if source_bytes != destination_bytes || source_hash != destination_hash {
                        return Err(
                            "legacy workspace destination contains divergent content; no files were overwritten"
                                .to_string(),
                        );
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    copy_file_create_only(
                        &entry.path(),
                        &destination,
                        &staging,
                        &source_hash,
                        source_bytes,
                    )?;
                }
                Err(error) => {
                    return Err(format!(
                        "workspace destination metadata could not be read: {error}"
                    ));
                }
            }
        }
    }
    let _ = std::fs::remove_dir(&staging);
    Ok(())
}

fn hash_file(path: &Path) -> Result<([u8; 32], u64), String> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("workspace file could not be opened: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut bytes = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("workspace file could not be read: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        bytes = bytes.saturating_add(read as u64);
    }
    Ok((digest.finalize().into(), bytes))
}

fn ensure_relative_directory(root: &Path, relative: &Path) -> Result<PathBuf, String> {
    let mut directory = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err("workspace directory contains a non-normal path component".to_string());
        };
        directory.push(segment);
        match std::fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("workspace destination directory is a symlink".to_string());
            }
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err("workspace destination directory is not a directory".to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&directory).map_err(|error| {
                    format!("workspace destination directory could not be created: {error}")
                })?;
                let metadata = std::fs::symlink_metadata(&directory).map_err(|error| {
                    format!("workspace destination directory could not be verified: {error}")
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(
                        "workspace destination directory changed during creation".to_string()
                    );
                }
            }
            Err(error) => {
                return Err(format!(
                    "workspace destination directory metadata could not be read: {error}"
                ));
            }
        }
    }
    Ok(directory)
}

fn copy_file_create_only(
    source: &Path,
    destination: &Path,
    staging: &Path,
    expected_hash: &[u8; 32],
    expected_bytes: u64,
) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "workspace destination has no parent directory".to_string())?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|error| format!("workspace destination parent could not be read: {error}"))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err("workspace destination parent is unsafe".to_string());
    }
    let temporary = staging.join(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut source_file = std::fs::File::open(source)
            .map_err(|error| format!("workspace source file could not be opened: {error}"))?;
        let mut temporary_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("workspace staging file could not be created: {error}"))?;
        std::io::copy(&mut source_file, &mut temporary_file)
            .map_err(|error| format!("workspace staging copy failed: {error}"))?;
        temporary_file
            .flush()
            .map_err(|error| format!("workspace staging file could not be flushed: {error}"))?;
        temporary_file
            .sync_all()
            .map_err(|error| format!("workspace staging file could not be synced: {error}"))?;
        std::fs::set_permissions(
            &temporary,
            source_file
                .metadata()
                .map_err(|error| {
                    format!("workspace source permissions could not be read: {error}")
                })?
                .permissions(),
        )
        .map_err(|error| format!("workspace staging permissions could not be set: {error}"))?;
        let (actual_hash, actual_bytes) = hash_file(&temporary)?;
        if actual_bytes != expected_bytes || &actual_hash != expected_hash {
            return Err("workspace staging verification failed".to_string());
        }
        std::fs::hard_link(&temporary, destination).map_err(|error| {
            format!("workspace destination could not be published create-only: {error}")
        })?;
        let (published_hash, published_bytes) = hash_file(destination)?;
        if published_bytes != expected_bytes || &published_hash != expected_hash {
            return Err("workspace destination read-back verification failed".to_string());
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&temporary);
    result
}

fn invalid(reason: String) -> RebornBuildError {
    RebornBuildError::InvalidConfig {
        reason: format!("legacy workspace migration failed: {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(source: PathBuf, workspace_root: PathBuf) -> LegacyWorkspaceMigrationInput {
        LegacyWorkspaceMigrationInput {
            source,
            workspace_root,
            tenant_id: TenantId::new("tenant-a").unwrap(),
            user_id: UserId::new("user-a").unwrap(),
        }
    }

    #[tokio::test]
    async fn copies_nested_snapshot_into_scoped_workspace_and_is_idempotent() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("legacy");
        let workspace_root = temporary.path().join("workspace");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("nested/file.txt"), b"durable bytes").unwrap();

        let migration = input(source.clone(), workspace_root.clone());
        migrate_legacy_workspace_snapshot(migration.clone())
            .await
            .unwrap();
        migrate_legacy_workspace_snapshot(migration).await.unwrap();

        assert_eq!(
            std::fs::read(workspace_root.join("tenants/tenant-a/users/user-a/nested/file.txt"))
                .unwrap(),
            b"durable bytes"
        );
        assert_eq!(
            std::fs::read(source.join("nested/file.txt")).unwrap(),
            b"durable bytes",
            "rollback source must remain intact"
        );
    }

    #[tokio::test]
    async fn refuses_to_overwrite_divergent_destination_content() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("legacy");
        let workspace_root = temporary.path().join("workspace");
        let destination = workspace_root.join("tenants/tenant-a/users/user-a/file.txt");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(source.join("file.txt"), b"old bytes").unwrap();
        std::fs::write(&destination, b"new bytes").unwrap();

        let error = migrate_legacy_workspace_snapshot(input(source, workspace_root))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("divergent content"));
        assert_eq!(std::fs::read(destination).unwrap(), b"new bytes");
    }
}
