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
