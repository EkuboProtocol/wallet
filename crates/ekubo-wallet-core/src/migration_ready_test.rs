use super::*;
use crate::installer_checkpoint::Destination;
use std::path::Path;

fn fixture() -> (tempfile::TempDir, RecoveryCheckpoint) {
    let dir = tempfile::tempdir().unwrap();
    let stage = Uuid::new_v4();
    let account = Uuid::new_v4();
    let mut digest = Sha256::new();
    for (record, bytes) in [
        (ServiceCredentialRecord::WrappingKey, vec![1; 32]),
        (
            ServiceCredentialRecord::Enrollment,
            b"synthetic enrollment".to_vec(),
        ),
        (ServiceCredentialRecord::DatabaseKey, vec![2; 64]),
        (ServiceCredentialRecord::AccountKey(account), vec![3; 64]),
    ] {
        crate::custody_staging::digest_record(&mut digest, record, &bytes).unwrap();
        std::fs::write(dir.path().join(record.file_name()), &bytes).unwrap();
        std::fs::write(
            dir.path()
                .join(StagedRecord::Credential(record).file_name(stage).unwrap()),
            &bytes,
        )
        .unwrap();
    }
    let credentials = CredentialStage {
        version: 1,
        stage,
        records: 4,
        digest: digest.finalize().into(),
    };
    let database = b"synthetic encrypted database";
    let transfer = DatabaseTransfer {
        bytes: u64::try_from(database.len()).unwrap(),
        sha256: Sha256::digest(database).into(),
    };
    let checkpoint = RecoveryCheckpoint {
        version: 1,
        destination: Destination {
            owner: "owner".into(),
            service: "service".into(),
            profile: Uuid::new_v4(),
        },
        session: Uuid::new_v4(),
        stage,
        source: transfer.clone(),
        source_fingerprint: [1; 32],
        canonical: transfer.clone(),
        relay_digest: [2; 32],
    };
    let candidate = CandidateRecord {
        version: 1,
        session: checkpoint.session,
        destination: checkpoint.destination.clone(),
        source: transfer.clone(),
        credentials: credentials.clone(),
        canonical: transfer.clone(),
        relay_digest: checkpoint.relay_digest,
    };
    for (name, value) in [
        (
            StagedRecord::Candidate.file_name(stage).unwrap(),
            serde_json::to_value(candidate).unwrap(),
        ),
        (
            StagedRecord::Complete.file_name(stage).unwrap(),
            serde_json::to_value(&credentials).unwrap(),
        ),
        (
            "profile-ready.json".into(),
            serde_json::json!({ "version": 1, "session": checkpoint.session, "credentials": credentials, "canonical": transfer }),
        ),
    ] {
        std::fs::write(dir.path().join(name), serde_json::to_vec(&value).unwrap()).unwrap();
    }
    for name in [
        "wallet.db".into(),
        crate::database_staging::file_name(stage).unwrap(),
        crate::database_staging::canonical_file_name(stage).unwrap(),
    ] {
        std::fs::write(dir.path().join(name), database).unwrap();
    }
    (dir, checkpoint)
}

fn verify(path: &Path, checkpoint: &RecoveryCheckpoint) -> Result<()> {
    let accounts = account_instances(std::fs::read_dir(path)?.map(|entry| Ok(entry?.file_name())))?;
    verify_ready(checkpoint, &accounts, |name| {
        Ok(File::open(path.join(name))?)
    })
}

#[test]
fn complete_preparation_matches_all_runtime_and_staged_bytes() {
    let (dir, checkpoint) = fixture();
    verify(dir.path(), &checkpoint).unwrap();
}

#[test]
fn corrupted_preparation_never_verifies() {
    for mutation in 0..10 {
        let (dir, checkpoint) = fixture();
        let path = dir.path();
        match mutation {
            0 => std::fs::write(path.join("key-database"), b"changed").unwrap(),
            1 => {
                std::fs::write(path.join("key-database"), b"changed").unwrap();
                std::fs::write(
                    path.join(
                        StagedRecord::Credential(ServiceCredentialRecord::DatabaseKey)
                            .file_name(checkpoint.stage)
                            .unwrap(),
                    ),
                    b"changed",
                )
                .unwrap();
            }
            2 => std::fs::remove_file(path.join("profile-ready.json")).unwrap(),
            3 => std::fs::write(path.join("profile-ready.json"), vec![b' '; 4097]).unwrap(),
            4 => std::fs::write(path.join("wallet.db"), b"different encrypted database").unwrap(),
            5 => std::fs::write(
                path.join(crate::database_staging::file_name(checkpoint.stage).unwrap()),
                b"changed",
            )
            .unwrap(),
            6 => std::fs::write(
                path.join(crate::database_staging::canonical_file_name(checkpoint.stage).unwrap()),
                b"changed",
            )
            .unwrap(),
            7 => std::fs::write(
                path.join(format!("key-account-{}", Uuid::new_v4())),
                b"extra",
            )
            .unwrap(),
            8 => std::fs::write(path.join("wallet.db-wal"), b"unverified pages").unwrap(),
            _ => {
                let candidate =
                    path.join(StagedRecord::Candidate.file_name(checkpoint.stage).unwrap());
                let mut value: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&candidate).unwrap()).unwrap();
                value["session"] = serde_json::json!(Uuid::new_v4());
                std::fs::write(candidate, serde_json::to_vec(&value).unwrap()).unwrap();
            }
        }
        assert!(verify(path, &checkpoint).is_err(), "mutation {mutation}");
    }
}

#[test]
fn account_names_and_directory_work_are_bounded() {
    for name in [
        "key-account-invalid",
        "key-account-00000000-0000-0000-0000-000000000000",
        "key-account-12345678-ABCD-4000-8000-000000000001",
        "wallet.db-shm",
        "wallet.db-journal",
        "Wallet.DB-WAL",
        "KEY-ACCOUNT-12345678-abcd-4000-8000-000000000001",
    ] {
        assert!(account_instances([Ok(name.into())]).is_err());
    }
    let kelvin_alias = format!(
        "{}ey-account-12345678-abcd-4000-8000-000000000001",
        char::from_u32(0x212a).unwrap()
    );
    assert!(account_instances([Ok(kelvin_alias.into())]).is_err());
    let name = format!("key-account-{}", Uuid::new_v4());
    assert!(account_instances([Ok(name.clone().into()), Ok(name.into())]).is_err());
    assert!(account_instances((0..MAX_ACCOUNTS * 3 + 65).map(|_| Ok("ignored".into()))).is_err());
}
