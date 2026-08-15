use sha2::{Digest, Sha256};

use crate::error::MnesisError;

const OPERATION_ID_DOMAIN: &str = "mnesis-provider-operation-v1";
const PAYLOAD_DIGEST_DOMAIN: &str = "mnesis-provider-payload-v1";

pub const MAX_INTERACTION_MESSAGES: usize = 64;
pub const MAX_MESSAGE_BYTES: usize = 8_192;
pub const MAX_INTERACTION_BYTES: usize = 128 * 1_024;
pub const MAX_METADATA_ENTRIES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteIdentity {
    pub tenant_id: String,
    pub principal_id: String,
    pub invocation_id: String,
    pub turn_run_id: Option<String>,
}

pub fn operation_id(identity: &WriteIdentity) -> Result<String, MnesisError> {
    if identity.tenant_id.is_empty()
        || identity.principal_id.is_empty()
        || identity.invocation_id.is_empty()
    {
        return Err(MnesisError::Client {
            reason: "a write requires trusted tenant, principal, and invocation identity"
                .to_string(),
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(OPERATION_ID_DOMAIN.as_bytes());
    hasher.update([0]);
    for part in [
        identity.tenant_id.as_str(),
        identity.principal_id.as_str(),
        identity.invocation_id.as_str(),
        identity.turn_run_id.as_deref().unwrap_or(""),
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    Ok(hex(&hasher.finalize()))
}

pub fn payload_digest(operation_kind: &str, owner_scope_key: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PAYLOAD_DIGEST_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(operation_kind.as_bytes());
    hasher.update([0]);
    hasher.update(owner_scope_key.as_bytes());
    hasher.update([0]);
    hasher.update(payload);
    hex(&hasher.finalize())
}

pub fn assert_interaction_bounds(
    message_count: usize,
    largest_message_bytes: usize,
    aggregate_bytes: usize,
    metadata_entries: usize,
) -> Result<(), MnesisError> {
    if message_count == 0 || message_count > MAX_INTERACTION_MESSAGES {
        return Err(MnesisError::Client {
            reason: format!("interaction message count must be 1 to {MAX_INTERACTION_MESSAGES}"),
        });
    }
    if largest_message_bytes > MAX_MESSAGE_BYTES {
        return Err(MnesisError::Client {
            reason: format!("a single message exceeds {MAX_MESSAGE_BYTES} bytes"),
        });
    }
    if aggregate_bytes > MAX_INTERACTION_BYTES {
        return Err(MnesisError::Client {
            reason: format!("the interaction exceeds {MAX_INTERACTION_BYTES} bytes"),
        });
    }
    if metadata_entries > MAX_METADATA_ENTRIES {
        return Err(MnesisError::Client {
            reason: format!("metadata exceeds {MAX_METADATA_ENTRIES} entries"),
        });
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        rendered.push_str(&format!("{byte:02x}"));
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> WriteIdentity {
        WriteIdentity {
            tenant_id: "tenant".to_string(),
            principal_id: "principal".to_string(),
            invocation_id: "invocation".to_string(),
            turn_run_id: Some("run-1".to_string()),
        }
    }

    #[test]
    fn the_operation_id_is_stable_for_the_same_trusted_identity() {
        assert_eq!(
            operation_id(&identity()).unwrap(),
            operation_id(&identity()).unwrap()
        );
        assert_eq!(operation_id(&identity()).unwrap().len(), 64);
    }

    #[test]
    fn every_identity_axis_changes_the_operation_id() {
        let base = operation_id(&identity()).unwrap();
        for mutate in [
            |i: &mut WriteIdentity| i.tenant_id = "other".to_string(),
            |i: &mut WriteIdentity| i.principal_id = "other".to_string(),
            |i: &mut WriteIdentity| i.invocation_id = "other".to_string(),
            |i: &mut WriteIdentity| i.turn_run_id = Some("run-2".to_string()),
            |i: &mut WriteIdentity| i.turn_run_id = None,
        ] {
            let mut changed = identity();
            mutate(&mut changed);
            assert_ne!(operation_id(&changed).unwrap(), base);
        }
    }

    #[test]
    fn field_boundaries_cannot_be_shifted_to_collide() {
        let mut left = identity();
        left.tenant_id = "a".to_string();
        left.principal_id = "bc".to_string();
        let mut right = identity();
        right.tenant_id = "ab".to_string();
        right.principal_id = "c".to_string();
        assert_ne!(operation_id(&left).unwrap(), operation_id(&right).unwrap());
    }

    #[test]
    fn a_write_without_trusted_identity_is_refused() {
        for blank in [
            |i: &mut WriteIdentity| i.tenant_id.clear(),
            |i: &mut WriteIdentity| i.principal_id.clear(),
            |i: &mut WriteIdentity| i.invocation_id.clear(),
        ] {
            let mut broken = identity();
            blank(&mut broken);
            assert!(operation_id(&broken).is_err());
        }
    }

    #[test]
    fn the_payload_digest_binds_kind_scope_and_body() {
        let base = payload_digest("record_interaction", "mos1.abc", b"payload");
        assert_ne!(base, payload_digest("other_kind", "mos1.abc", b"payload"));
        assert_ne!(
            base,
            payload_digest("record_interaction", "mos1.xyz", b"payload")
        );
        assert_ne!(
            base,
            payload_digest("record_interaction", "mos1.abc", b"other")
        );
        assert_eq!(
            base,
            payload_digest("record_interaction", "mos1.abc", b"payload")
        );
    }

    #[test]
    fn interaction_bounds_hold_at_and_over_every_limit() {
        assert_interaction_bounds(1, 0, 0, 0).unwrap();
        assert_interaction_bounds(
            MAX_INTERACTION_MESSAGES,
            MAX_MESSAGE_BYTES,
            MAX_INTERACTION_BYTES,
            MAX_METADATA_ENTRIES,
        )
        .unwrap();
        assert!(assert_interaction_bounds(0, 0, 0, 0).is_err());
        assert!(assert_interaction_bounds(MAX_INTERACTION_MESSAGES + 1, 0, 0, 0).is_err());
        assert!(assert_interaction_bounds(1, MAX_MESSAGE_BYTES + 1, 0, 0).is_err());
        assert!(assert_interaction_bounds(1, 0, MAX_INTERACTION_BYTES + 1, 0).is_err());
        assert!(assert_interaction_bounds(1, 0, 0, MAX_METADATA_ENTRIES + 1).is_err());
    }

    #[test]
    fn a_bounds_rejection_never_echoes_payload_content() {
        let error = assert_interaction_bounds(1, MAX_MESSAGE_BYTES + 1, 0, 0).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("8192"));
        assert!(!rendered.contains("payload"));
    }
}
