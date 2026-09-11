use super::*;
use crate::policy_store::{DatabaseKey, PolicyStore};
use zeroize::Zeroizing;

struct Stream {
    input: std::io::Cursor<Vec<u8>>,
    output: Vec<u8>,
}
impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(bytes)
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn checkpoint_recovers_original_transfer_after_source_snapshot_is_lost() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("source.db");
    let key = [0x43; 32];
    drop(PolicyStore::open(&path, &DatabaseKey::new(key)).unwrap());
    let destination = Destination {
        owner: "owner".into(),
        service: "service".into(),
        profile: Uuid::new_v4(),
    };
    let (_, relay) =
        crate::custody_envelope::WrappingKey::from_material(Zeroizing::new([0x44; 32]))
            .enroll(
                crate::custody_envelope::CustodyBinding::new(
                    "owner",
                    "service",
                    destination.profile,
                    Uuid::new_v4(),
                )
                .unwrap(),
            )
            .unwrap();
    let mut snapshot = MigrationDatabaseSnapshot::freeze(&path, Zeroizing::new(key)).unwrap();
    let reply = StagingReply {
        session: Uuid::new_v4(),
        stage: Uuid::new_v4(),
        canonical: snapshot.transfer().unwrap(),
        relay,
    };
    let checkpoint =
        RecoveryCheckpoint::capture(destination.clone(), &reply, &mut snapshot).unwrap();
    let encoded = serde_json::to_vec(&checkpoint).unwrap();
    assert!(!String::from_utf8_lossy(&encoded).contains(&hex::encode(reply.relay().as_bytes())));
    drop(snapshot);
    let checkpoint: RecoveryCheckpoint = serde_json::from_slice(&encoded).unwrap();
    let mut snapshot = MigrationDatabaseSnapshot::freeze(&path, Zeroizing::new(key)).unwrap();
    assert_ne!(snapshot.transfer().unwrap(), checkpoint.source);
    let wire_reply = super::super::Reply {
        session: reply.session(),
        stage: reply.stage(),
        canonical: reply.canonical().clone(),
        relay: hex::encode(reply.relay().as_bytes()),
    };
    let mut bytes = Vec::new();
    super::super::write_frame(&mut bytes, &serde_json::to_vec(&wire_reply).unwrap()).unwrap();
    let mut stream = Stream {
        input: std::io::Cursor::new(bytes),
        output: Vec::new(),
    };
    checkpoint
        .exchange(
            &mut stream,
            destination.clone(),
            &snapshot,
            reply.relay().clone(),
            &[],
        )
        .unwrap();
    let mut request = std::io::Cursor::new(&stream.output[8..]);
    let header: serde_json::Value =
        super::super::read_frame(&mut request, 4096, &mut 4096).unwrap();
    assert_eq!(
        header["source"],
        serde_json::to_value(&checkpoint.source).unwrap()
    );
    for mutation in 0..4 {
        let mut invalid = checkpoint.clone();
        match mutation {
            0 => invalid.version = 2,
            1 => invalid.destination.profile = Uuid::new_v4(),
            2 => invalid.relay_digest[0] ^= 1,
            _ => invalid.source_fingerprint[0] ^= 1,
        }
        stream.output.clear();
        assert!(
            invalid
                .exchange(
                    &mut stream,
                    destination.clone(),
                    &snapshot,
                    reply.relay().clone(),
                    &[]
                )
                .is_err()
        );
        assert!(stream.output.is_empty());
    }
}
