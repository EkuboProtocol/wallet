use super::*;
use crate::migration_transfer::{INSTALLER_LIMITS, relay_request_with_intent};
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

#[test]
fn journal_failure_cannot_consume_keys_or_forward_any_transfer_bytes() {
    let (header, wallet, database) = request();
    let mut input = Cursor::new(wire(&header, &wallet, &database));
    let mut output = Vec::new();
    let mut called = false;
    assert!(
        relay_request_with_intent(
            &mut input,
            &mut output,
            &header.destination,
            INSTALLER_LIMITS,
            |intent| {
                called = true;
                assert_eq!(intent.session, header.session);
                assert!(intent.destination == header.destination);
                assert_eq!(intent.source, header.database);
                anyhow::bail!("synthetic journal failure")
            }
        )
        .is_err()
    );
    assert!(called);
    assert_eq!(input.position(), prefix(&header).len() as u64);
    assert!(output.is_empty());
}

#[test]
fn failed_service_write_leaves_an_intent_without_consuming_source_keys() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (header, wallet, database) = request();
    let mut input = Cursor::new(wire(&header, &wallet, &database));
    let mut recorded = None;
    assert!(
        relay_request_with_intent(
            &mut input,
            &mut Broken,
            &header.destination,
            INSTALLER_LIMITS,
            |intent| {
                recorded = Some(intent.clone());
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(recorded.unwrap().session, header.session);
    assert_eq!(input.position(), prefix(&header).len() as u64);
}

struct OwnerStream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    fail_flush: bool,
}
impl Read for OwnerStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(bytes)
    }
}
impl Write for OwnerStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self.fail_flush {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}

fn staged_reply(header: &Header) -> StagingReply {
    let (_, relay) =
        crate::custody_envelope::WrappingKey::from_material(zeroize::Zeroizing::new([0x44; 32]))
            .enroll(
                crate::custody_envelope::CustodyBinding::new(
                    &header.destination.owner,
                    &header.destination.service,
                    header.destination.profile,
                    Uuid::new_v4(),
                )
                .unwrap(),
            )
            .unwrap();
    StagingReply {
        session: header.session,
        stage: Uuid::new_v4(),
        canonical: header.database.clone(),
        relay,
    }
}

#[test]
fn source_checkpoint_completes_handshake_without_consuming_next_phase() {
    use crate::policy_store::{
        DatabaseKey, PolicyStore, migration_database::MigrationDatabaseSnapshot,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("source.db");
    let key = [0x43; 32];
    drop(PolicyStore::open(&path, &DatabaseKey::new(key)).unwrap());
    let mut snapshot =
        MigrationDatabaseSnapshot::freeze(&path, zeroize::Zeroizing::new(key)).unwrap();
    let (mut header, _, _) = request();
    let mut request_bytes = Vec::new();
    header.session = super::super::send(
        &mut request_bytes,
        header.destination.clone(),
        zeroize::Zeroizing::new(key),
        &[],
        vec![],
        &mut snapshot,
        INSTALLER_LIMITS,
    )
    .unwrap();
    let request = relay_request(
        &mut request_bytes.as_slice(),
        &mut Vec::new(),
        &header.destination,
        INSTALLER_LIMITS,
    )
    .unwrap();
    let reply = staged_reply(&header);
    let mut service_bytes = Vec::new();
    reply.write_to(&mut service_bytes).unwrap();
    let mut checkpoint_bytes = Vec::new();
    reply
        .write_source_checkpoint(&mut checkpoint_bytes, header.destination, &mut snapshot)
        .unwrap();
    let checkpoint_len = checkpoint_bytes.len();
    checkpoint_bytes.extend(b"owner next");
    let mut owner = OwnerStream {
        input: Cursor::new(checkpoint_bytes),
        output: vec![],
        fail_flush: false,
    };
    let service_len = service_bytes.len();
    service_bytes.extend(b"service next");
    let mut service = Cursor::new(service_bytes);
    let (relayed, checkpoint) = request.finish(&mut service, &mut owner).unwrap();
    assert_eq!(checkpoint.source, snapshot.transfer().unwrap());
    assert_eq!(
        checkpoint.source_fingerprint,
        snapshot.source_fingerprint().unwrap()
    );
    assert_eq!(checkpoint.stage, relayed.stage());
    assert_eq!(owner.input.position(), checkpoint_len as u64);
    assert_eq!(service.position(), service_len as u64);
    assert_eq!(owner.output, service.get_ref()[..service_len]);
}

#[test]
fn checkpoint_substitution_truncation_and_missing_evidence_cannot_finish() {
    let (header, wallet, database) = request();
    let reply = staged_reply(&header);
    for mutation in 0..12 {
        let request = relay_request(
            &mut wire(&header, &wallet, &database).as_slice(),
            &mut Vec::new(),
            &header.destination,
            INSTALLER_LIMITS,
        )
        .unwrap();
        let mut checkpoint = RecoveryCheckpoint {
            version: 1,
            destination: header.destination.clone(),
            session: header.session,
            stage: reply.stage(),
            source: header.database.clone(),
            canonical: reply.canonical().clone(),
            source_fingerprint: [0x77; 32],
            relay_digest: reply.relay().digest(),
        };
        match mutation {
            0 => checkpoint.version = 2,
            1 => checkpoint.destination.owner.push('x'),
            2 => checkpoint.destination.service.push('x'),
            3 => checkpoint.destination.profile = Uuid::new_v4(),
            4 => checkpoint.session = Uuid::new_v4(),
            5 => checkpoint.stage = Uuid::new_v4(),
            6 => checkpoint.source.bytes += 1,
            7 => checkpoint.canonical.bytes += 1,
            8 => checkpoint.relay_digest[0] ^= 1,
            _ => {}
        }
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &encode(&checkpoint, MAX_HEADER_BYTES).unwrap()).unwrap();
        match mutation {
            9 => {
                bytes.pop();
            }
            10 => bytes.clear(),
            11 => bytes = (MAX_HEADER_BYTES + 1).to_le_bytes().to_vec(),
            _ => {}
        }
        let mut owner = OwnerStream {
            input: Cursor::new(bytes),
            output: vec![],
            fail_flush: false,
        };
        let mut service = Vec::new();
        reply.write_to(&mut service).unwrap();
        assert!(request.finish(&mut service.as_slice(), &mut owner).is_err());
    }
}

#[test]
fn invalid_service_reply_or_owner_flush_failure_does_not_read_checkpoint() {
    let (header, wallet, database) = request();
    for mutation in 0..4 {
        let request = relay_request(
            &mut wire(&header, &wallet, &database).as_slice(),
            &mut Vec::new(),
            &header.destination,
            INSTALLER_LIMITS,
        )
        .unwrap();
        let mut reply = staged_reply(&header);
        match mutation {
            0 => reply.session = Uuid::new_v4(),
            1 => reply.stage = Uuid::nil(),
            2 => reply.canonical.bytes = crate::installer_checkpoint::MAX_DATABASE_BYTES + 1,
            _ => {}
        }
        let mut service = Vec::new();
        reply.write_to(&mut service).unwrap();
        let mut owner = OwnerStream {
            input: Cursor::new(vec![0x55; 32]),
            output: vec![],
            fail_flush: mutation == 3,
        };
        assert!(request.finish(&mut service.as_slice(), &mut owner).is_err());
        assert_eq!(owner.input.position(), 0);
        if mutation != 3 {
            assert!(owner.output.is_empty());
        }
    }
}
