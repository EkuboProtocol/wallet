use super::*;
use crate::custody_staging::StagedRecord;
use crate::database_staging::{CanonicalDatabase, StagedDatabase};
use std::{fs::File, io::Cursor};

fn limits() -> TransferLimits {
    TransferLimits {
        accounts: 4,
        metadata_bytes: 4096,
        total_metadata_bytes: 8192,
        database_bytes: 16 * 1024 * 1024,
    }
}

struct UnusedStore;
impl CredentialStagingStore for UnusedStore {
    fn identity(&self) -> (String, String, Uuid) {
        (
            "linux:uid:1000".into(),
            "linux:uid:2000".into(),
            Uuid::from_u128(1),
        )
    }
    fn create_new(&self, _: Uuid, _: StagedRecord, _: &[u8]) -> Result<()> {
        panic!("invalid request must not stage credentials")
    }
    fn read(&self, _: Uuid, _: StagedRecord) -> Result<Zeroizing<Vec<u8>>> {
        panic!("invalid request must not read credentials")
    }
}
impl DatabaseStagingStore for UnusedStore {
    fn receive_database(&self, _: Uuid, _: &DatabaseTransfer, _: &mut dyn Read) -> Result<()> {
        panic!("invalid request must not stage a database")
    }
    fn open_staged_database(&self, _: Uuid) -> Result<File> {
        unreachable!()
    }
    fn staged_database(&self, _: Uuid) -> Result<StagedDatabase<'_>> {
        unreachable!()
    }
    fn create_canonical_database(&self, _: Uuid) -> Result<CanonicalDatabase<'_>> {
        unreachable!()
    }
    fn canonical_database(&self, _: Uuid) -> Result<StagedDatabase<'_>> {
        unreachable!()
    }
}

fn header() -> Header {
    let (owner, service, profile) = UnusedStore.identity();
    Header {
        session: Uuid::new_v4(),
        destination: Destination {
            owner,
            service,
            profile,
        },
        accounts: 0,
        database: DatabaseTransfer {
            bytes: 1024,
            sha256: [0; 32],
        },
    }
}

fn framed(header: &Header) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    write_frame(&mut bytes, &encode(header, MAX_HEADER_BYTES).unwrap()).unwrap();
    bytes
}

#[test]
fn destination_and_admission_fail_before_reading_keys_or_writing_any_state() {
    for change in 0..6 {
        let mut header = header();
        match change {
            0 => header.destination.profile = Uuid::new_v4(),
            1 => header.destination.owner = "linux:uid:1001".into(),
            2 => header.destination.service = "linux:uid:2001".into(),
            3 => header.accounts = limits().accounts + 1,
            4 => header.database.bytes = limits().database_bytes + 1,
            _ => header.session = Uuid::nil(),
        }
        let mut bytes = framed(&header);
        let boundary = bytes.len();
        bytes.extend_from_slice(&[0x77; 32]);
        let mut input = Cursor::new(bytes);
        assert!(receive(&UnusedStore, &mut input, limits()).is_err());
        assert_eq!(input.position(), boundary as u64);
    }
}

#[test]
fn frames_reject_lengths_budgets_unknown_fields_and_truncated_keys() {
    for length in [0, MAX_HEADER_BYTES + 1, u32::MAX] {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&length.to_le_bytes());
        assert!(receive(&UnusedStore, &mut bytes.as_slice(), limits()).is_err());
    }
    let mut value = serde_json::to_value(header()).unwrap();
    value["path"] = serde_json::json!("/tmp/caller-selected.db");
    let mut bytes = MAGIC.to_vec();
    write_frame(&mut bytes, &serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(receive(&UnusedStore, &mut bytes.as_slice(), limits()).is_err());
    for size in [0, 1, 31] {
        let mut bytes = framed(&header());
        bytes.extend(std::iter::repeat_n(0x55, size));
        assert!(receive(&UnusedStore, &mut bytes.as_slice(), limits()).is_err());
    }
    let mut input = Cursor::new(100_u32.to_le_bytes());
    assert!(read_frame::<WalletMetadata>(&mut input, 200, &mut 99).is_err());
    assert_eq!(
        input.position(),
        4,
        "budget rejected before payload read/allocation"
    );
}

#[test]
fn invalid_account_key_never_creates_a_stage() {
    let mut header = header();
    header.accounts = 1;
    let mut bytes = framed(&header);
    bytes.extend_from_slice(&[0x33; 32]);
    let wallet = WalletMetadata {
        instance_id: Uuid::new_v4(),
        id: "test".into(),
        address: alloy::primitives::Address::ZERO,
        created_at: chrono::Utc::now(),
        source: crate::config::WalletSource::Imported,
        exported_at: None,
    };
    write_frame(&mut bytes, &serde_json::to_vec(&wallet).unwrap()).unwrap();
    bytes.extend_from_slice(&[0; 32]);
    assert!(receive(&UnusedStore, &mut bytes.as_slice(), limits()).is_err());
}

#[test]
fn reply_rejects_wrong_session_invalid_stage_database_and_relay() {
    use crate::custody_envelope::{CustodyBinding, WrappingKey};
    let session = Uuid::new_v4();
    let (_, relay) = WrappingKey::from_material(Zeroizing::new([0x44; 32]))
        .enroll(CustodyBinding::new("owner", "service", Uuid::new_v4(), Uuid::new_v4()).unwrap())
        .unwrap();
    for mutation in 0..5 {
        let mut reply = Reply {
            session,
            stage: Uuid::new_v4(),
            canonical: DatabaseTransfer {
                bytes: 1024,
                sha256: [0; 32],
            },
            relay: hex::encode(relay.as_bytes()),
        };
        match mutation {
            0 => reply.session = Uuid::new_v4(),
            1 => reply.stage = Uuid::nil(),
            2 => reply.canonical.bytes = 0,
            3 => reply.relay.truncate(20),
            _ => reply.relay = "00".repeat(crate::custody_envelope::SEALED_KEY_BYTES),
        }
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &encode(&reply, MAX_HEADER_BYTES).unwrap()).unwrap();
        assert!(read_reply(&mut bytes.as_slice(), session).is_err());
    }
}
