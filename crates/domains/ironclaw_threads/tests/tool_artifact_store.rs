use std::sync::Arc;

use ironclaw_filesystem::InMemoryBackend;
use ironclaw_host_api::{
    artifact::{
        AccountedArtifactPersister, ArtifactAccessPort, ArtifactDigest, ArtifactId,
        ArtifactLineRange, ArtifactNamespaceId, ArtifactOwnerScope, ArtifactPersistencePort,
        ArtifactReadRequest, ArtifactReadTarget, ArtifactSelector, ArtifactWriteError,
        ArtifactWriteMetadata,
    },
    ids::{CapabilityId, InvocationId, RunId, UserId},
    resource::{
        ReservationStatus, ResourceEstimate, ResourceReceipt, ResourceScope, ResourceUsage,
    },
};
use ironclaw_threads::DurableToolArtifactStore;

fn owner_scope() -> ArtifactOwnerScope {
    let scope = ResourceScope::local_default(
        UserId::new("artifact-owner").expect("owner id"),
        InvocationId::new(),
    )
    .expect("resource scope");
    ArtifactOwnerScope::from_resource_scope(&scope)
}

fn metadata(namespace: ArtifactNamespaceId) -> ArtifactWriteMetadata {
    ArtifactWriteMetadata {
        write_key: None,
        owner_scope: owner_scope(),
        namespace,
        producer_capability_id: CapabilityId::new("builtin.grep").expect("capability id"),
        content_type: "text/plain".to_string(),
        expected_bytes: None,
    }
}

fn read_request(
    namespace: ArtifactNamespaceId,
    artifact_id: ArtifactId,
    selector: ArtifactSelector,
) -> ArtifactReadRequest {
    ArtifactReadRequest {
        owner_scope: owner_scope(),
        namespace,
        target: ArtifactReadTarget {
            artifact_id,
            selector,
            max_output_bytes: 24 * 1024,
        },
    }
}

#[tokio::test]
async fn finalized_artifact_supports_indexed_line_reads() {
    let store =
        DurableToolArtifactStore::new(Arc::new(InMemoryBackend::new())).expect("artifact store");
    let namespace = ArtifactNamespaceId::from_root_run(RunId::new());

    let first = store
        .allocate(metadata(namespace))
        .await
        .expect("allocate first artifact");
    let second = store
        .allocate(metadata(namespace))
        .await
        .expect("allocate second artifact");
    assert_eq!(first.artifact_id().get(), 0);
    assert_eq!(second.artifact_id().get(), 1);

    store
        .append(&first, b"one\ntwo\n")
        .await
        .expect("append first chunk");
    assert!(
        store
            .read(read_request(
                namespace,
                first.artifact_id(),
                ArtifactSelector::Full,
            ))
            .await
            .expect("read incomplete artifact")
            .is_none(),
        "incomplete artifacts must not be model-readable"
    );

    store
        .append(&first, b"three\nfour\n")
        .await
        .expect("append second chunk");
    let completed = store.finalize(first).await.expect("finalize artifact");
    assert_eq!(completed.byte_len, 19);
    assert_eq!(completed.total_lines, Some(4));

    assert_eq!(
        completed.digest,
        ArtifactDigest::from_bytes(b"one\ntwo\nthree\nfour\n")
    );
    let lines = store
        .read(read_request(
            namespace,
            completed.artifact_ref.id(),
            ArtifactSelector::Lines(ArtifactLineRange { start: 2, end: 3 }),
        ))
        .await
        .expect("read artifact")
        .expect("finalized artifact");
    assert_eq!(lines.content, b"two\nthree\n");
    assert_eq!(lines.total_bytes, 19);
    assert_eq!(lines.total_lines, Some(4));
}

#[tokio::test]
async fn accounted_persistence_rejects_bytes_not_covered_by_receipt() {
    let store =
        DurableToolArtifactStore::new(Arc::new(InMemoryBackend::new())).expect("artifact store");
    let namespace = ArtifactNamespaceId::from_root_run(RunId::new());
    let scope = ResourceScope::local_default(
        UserId::new("artifact-owner").expect("owner id"),
        InvocationId::new(),
    )
    .expect("resource scope");
    let receipt = ResourceReceipt {
        id: Default::default(),
        scope,
        status: ReservationStatus::Reconciled,
        estimate: ResourceEstimate::default(),
        actual: Some(ResourceUsage {
            output_bytes: 3,
            ..ResourceUsage::default()
        }),
    };

    let error = store
        .persist(metadata(namespace), b"four", &receipt)
        .await
        .expect_err("receipt must cover every persisted output byte");

    assert_eq!(error, ArtifactWriteError::Budget);
}
