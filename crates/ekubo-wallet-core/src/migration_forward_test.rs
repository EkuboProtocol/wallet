use super::*;
use crate::migration_transfer::INSTALLER_LIMITS;
use std::io::Cursor;

fn request() -> (Header, WalletMetadata, Vec<u8>) {
    let database = vec![0x33; 32 * 1024 + 7];
    let header = Header {
        session: Uuid::new_v4(),
        destination: Destination {
            owner: "linux:uid:1000".into(),
            service: "linux:uid:2000".into(),
            profile: Uuid::new_v4(),
        },
        accounts: 1,
        database: DatabaseTransfer::describe(&mut database.as_slice()).unwrap(),
    };
    let wallet = WalletMetadata {
        instance_id: Uuid::new_v4(),
        id: "source".into(),
        address: alloy::primitives::Address::repeat_byte(0x11),
        created_at: chrono::DateTime::from_timestamp_millis(1000).unwrap(),
        source: crate::config::WalletSource::Imported,
        exported_at: None,
    };
    (header, wallet, database)
}

fn prefix(header: &Header) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    write_frame(&mut bytes, &encode(header, MAX_HEADER_BYTES).unwrap()).unwrap();
    bytes
}

fn wire(header: &Header, wallet: &WalletMetadata, database: &[u8]) -> Vec<u8> {
    let mut bytes = prefix(header);
    bytes.extend([0x11; 32]);
    write_frame(
        &mut bytes,
        &encode(wallet, INSTALLER_LIMITS.metadata_bytes).unwrap(),
    )
    .unwrap();
    bytes.extend([0x22; 32]);
    bytes.extend(database);
    bytes
}

#[test]
fn forwarding_preserves_request_and_leaves_the_next_owner_phase_unread() {
    let (header, wallet, database) = request();
    let expected = wire(&header, &wallet, &database);
    let mut bytes = expected.clone();
    bytes.extend(b"next phase");
    let mut input = Cursor::new(bytes);
    let mut output = Vec::new();
    let forwarded = relay_request(
        &mut input,
        &mut output,
        &header.destination,
        INSTALLER_LIMITS,
    )
    .unwrap();
    assert_eq!(output, expected);
    assert_eq!(input.position(), expected.len() as u64);
    assert_eq!(forwarded.session(), header.session);
    assert_eq!(forwarded.source(), &header.database);
    assert_eq!(forwarded.wallets(), &[wallet]);
}

#[test]
fn wrong_destination_or_header_limits_cannot_forward_any_bytes() {
    for change in 0..5 {
        let (mut header, _, _) = request();
        let destination = header.destination.clone();
        match change {
            0 => header.destination.profile = Uuid::new_v4(),
            1 => header.destination.owner = "linux:uid:1001".into(),
            2 => header.accounts = INSTALLER_LIMITS.accounts + 1,
            3 => header.database.bytes = INSTALLER_LIMITS.database_bytes + 1,
            _ => header.session = Uuid::nil(),
        }
        let mut output = Vec::new();
        assert!(
            relay_request(
                &mut prefix(&header).as_slice(),
                &mut output,
                &destination,
                INSTALLER_LIMITS
            )
            .is_err()
        );
        assert!(output.is_empty());
    }
}

#[test]
fn aggregate_metadata_limit_fails_before_reading_metadata_or_account_key() {
    let (header, wallet, database) = request();
    let mut limits = INSTALLER_LIMITS;
    limits.total_metadata_bytes = 1;
    let mut input = Cursor::new(wire(&header, &wallet, &database));
    let mut output = Vec::new();
    assert!(relay_request(&mut input, &mut output, &header.destination, limits).is_err());
    assert_eq!(input.position(), (prefix(&header).len() + 32 + 4) as u64);
    assert_eq!(output.len(), prefix(&header).len() + 32);
}

#[test]
fn truncated_keys_ciphertext_and_wrong_digest_never_complete_forwarding() {
    let (header, wallet, database) = request();
    let complete = wire(&header, &wallet, &database);
    for end in [prefix(&header).len() + 31, complete.len() - 1] {
        assert!(
            relay_request(
                &mut &complete[..end],
                &mut Vec::new(),
                &header.destination,
                INSTALLER_LIMITS
            )
            .is_err()
        );
    }
    let mut damaged = complete;
    *damaged.last_mut().unwrap() ^= 1;
    assert!(
        relay_request(
            &mut damaged.as_slice(),
            &mut Vec::new(),
            &header.destination,
            INSTALLER_LIMITS
        )
        .is_err()
    );
}
