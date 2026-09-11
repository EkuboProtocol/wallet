use super::*;
use crate::migration_transfer::{INSTALLER_LIMITS, tests::UnusedStore};
use zeroize::Zeroizing;

fn header() -> Header {
    let (owner, service, profile) = UnusedStore.identity();
    let (_, relay) =
        crate::custody_envelope::WrappingKey::from_material(Zeroizing::new([0x44; 32]))
            .enroll(
                crate::custody_envelope::CustodyBinding::new(
                    &owner,
                    &service,
                    profile,
                    Uuid::new_v4(),
                )
                .unwrap(),
            )
            .unwrap();
    Header {
        destination: Destination {
            owner,
            service,
            profile,
        },
        session: Uuid::new_v4(),
        stage: Uuid::new_v4(),
        source: DatabaseTransfer {
            bytes: 1024,
            sha256: [0x55; 32],
        },
        accounts: 0,
        relay: hex::encode(relay.as_bytes()),
    }
}

#[test]
fn recovery_rejects_wrong_destination_invalid_identity_and_bounds_before_storage() {
    for mutation in 0..8 {
        let mut value = serde_json::to_value(header()).unwrap();
        match mutation {
            0 => value["destination"]["owner"] = serde_json::json!("other owner"),
            1 => value["stage"] = serde_json::json!(Uuid::nil()),
            2 => value["session"] = serde_json::json!(Uuid::nil()),
            3 => value["accounts"] = serde_json::json!(INSTALLER_LIMITS.accounts + 1),
            4 => value["source"]["bytes"] = serde_json::json!(INSTALLER_LIMITS.database_bytes + 1),
            5 => value["relay"] = serde_json::json!("00"),
            6 => value["path"] = serde_json::json!("caller-selected"),
            _ => value["source"]["bytes"] = serde_json::json!(0),
        }
        let mut bytes = MAGIC.to_vec();
        write_frame(&mut bytes, &serde_json::to_vec(&value).unwrap()).unwrap();
        let boundary = bytes.len();
        bytes.extend_from_slice(b"unread metadata");
        let mut input = std::io::Cursor::new(bytes);
        assert!(super::super::receive(&UnusedStore, &mut input, INSTALLER_LIMITS).is_err());
        assert_eq!(input.position(), boundary as u64);
    }
}

#[test]
fn recovery_metadata_budget_is_checked_before_payload_or_storage_reads() {
    let mut header = header();
    header.accounts = 1;
    let mut bytes = MAGIC.to_vec();
    write_frame(&mut bytes, &encode(&header, MAX_HEADER_BYTES).unwrap()).unwrap();
    bytes.extend_from_slice(&100_u32.to_le_bytes());
    let boundary = bytes.len();
    bytes.extend_from_slice(&[0; 100]);
    let mut input = std::io::Cursor::new(bytes);
    let limits = TransferLimits {
        total_metadata_bytes: 99,
        ..INSTALLER_LIMITS
    };
    assert!(super::super::receive(&UnusedStore, &mut input, limits).is_err());
    assert_eq!(input.position(), boundary as u64);
}

#[test]
fn recovery_reply_must_match_the_original_staged_result() {
    let original = header();
    let previous = super::super::StagingReply {
        session: original.session,
        stage: original.stage,
        canonical: original.source.clone(),
        relay: WrappedDataKey::from_bytes(&hex::decode(&original.relay).unwrap()).unwrap(),
    };
    assert!(validate_reply(&previous, &previous).is_ok());
    for mutation in 0..5 {
        let mut reply = super::super::StagingReply {
            session: previous.session(),
            stage: previous.stage(),
            canonical: previous.canonical().clone(),
            relay: previous.relay().clone(),
        };
        match mutation {
            0 => reply.session = Uuid::new_v4(),
            1 => reply.stage = Uuid::new_v4(),
            2 => reply.canonical.bytes += 1,
            3 => reply.canonical.sha256[0] ^= 1,
            _ => {
                reply.relay =
                    WrappedDataKey::from_bytes(&hex::decode(header().relay).unwrap()).unwrap();
            }
        }
        assert!(validate_reply(&previous, &reply).is_err());
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[test]
fn recovery_forwarding_rejects_checkpoint_substitution_before_service_output() {
    let header = header();
    let checkpoint = super::super::RecoveryCheckpoint {
        version: 1,
        destination: header.destination.clone(),
        session: header.session,
        stage: header.stage,
        source: header.source.clone(),
        source_fingerprint: [0x66; 32],
        canonical: header.source.clone(),
        relay_digest: WrappedDataKey::from_bytes(&hex::decode(&header.relay).unwrap())
            .unwrap()
            .digest(),
    };
    for mutation in 0..6 {
        let mut value = serde_json::to_value(&header).unwrap();
        match mutation {
            0 => value["destination"]["profile"] = serde_json::json!(Uuid::new_v4()),
            1 => value["session"] = serde_json::json!(Uuid::new_v4()),
            2 => value["stage"] = serde_json::json!(Uuid::new_v4()),
            3 => value["source"]["bytes"] = serde_json::json!(2048),
            4 => value["relay"] = serde_json::json!(self::header().relay),
            _ => value["accounts"] = serde_json::json!(INSTALLER_LIMITS.accounts + 1),
        }
        let mut bytes = MAGIC.to_vec();
        write_frame(&mut bytes, &serde_json::to_vec(&value).unwrap()).unwrap();
        let boundary = bytes.len();
        bytes.extend_from_slice(b"unread metadata");
        let mut input = std::io::Cursor::new(bytes);
        let mut output = Vec::new();
        assert!(
            relay_request(
                &mut input,
                &mut output,
                &checkpoint.destination,
                &checkpoint,
                INSTALLER_LIMITS
            )
            .is_err()
        );
        assert_eq!(input.position(), u64::try_from(boundary).unwrap());
        assert!(output.is_empty());
    }
}
