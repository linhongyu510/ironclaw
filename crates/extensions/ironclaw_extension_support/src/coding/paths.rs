use ironclaw_filesystem::FilesystemOperation;
use ironclaw_host_api::mount::MountPermissions;

/// Whether the caller's mount grant permits `operation`. Shared with the omp
/// engines: their path resolution checks the grant before every filesystem
/// access.
pub(super) fn operation_allowed(
    permissions: &MountPermissions,
    operation: FilesystemOperation,
) -> bool {
    match operation {
        FilesystemOperation::ReadFile => permissions.read,
        FilesystemOperation::WriteFile
        | FilesystemOperation::AppendFile
        | FilesystemOperation::CreateSubtreeAtomic => permissions.write,
        FilesystemOperation::ListDir => permissions.list,
        FilesystemOperation::Stat => permissions.read || permissions.list,
        FilesystemOperation::Delete => permissions.delete,
        FilesystemOperation::CreateDirAll => permissions.write,
        FilesystemOperation::MountLocal | FilesystemOperation::Connect => false,
        // Coding tools never use the unified record/index/txn/event surface
        // — they are bytes-only. If a future code path routes here, treat
        // record-plane reads as `read` and writes as `write` to stay
        // fail-closed. `Append` (event-plane append) is distinct from
        // `AppendFile` (byte-plane append onto a regular file) but both
        // map to `permissions.write`.
        FilesystemOperation::Query => permissions.read && permissions.list,
        FilesystemOperation::EnsureIndex
        | FilesystemOperation::BeginTxn
        | FilesystemOperation::Append
        | FilesystemOperation::ReserveSeq => permissions.write,
        FilesystemOperation::Tail | FilesystemOperation::HeadSeq => permissions.read,
    }
}
