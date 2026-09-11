use super::*;
use crate::{
    config::WalletMetadata,
    policy_store::{DatabaseKey, PolicyStore},
};
use std::{
    io::Cursor,
    net::{TcpListener, TcpStream},
    time::Duration,
};
use uuid::Uuid;

const KEY: [u8; 32] = [0x43; 32];
const ACCOUNT: [u8; 32] = [0x11; 32];

fn fixture() -> (tempfile::TempDir, ConfigStore, WalletMetadata) {
    let dir = tempfile::tempdir().unwrap();
    let config = ConfigStore::open(dir.path().canonicalize().unwrap(), DatabaseKey::new(KEY));
    let wallet = WalletMetadata {
        instance_id: Uuid::new_v4(),
        id: "source".into(),
        address: alloy::signers::local::PrivateKeySigner::from_slice(&ACCOUNT)
            .unwrap()
            .address(),
        created_at: chrono::DateTime::from_timestamp_millis(1000).unwrap(),
        source: crate::config::WalletSource::Imported,
        exported_at: None,
    };
    config
        .update_for_test(|config| {
            config.wallets = vec![wallet.clone()];
            Ok(())
        })
        .unwrap();
    PolicyStore::open(
        &config.data_dir().join(policy_store::DATABASE_FILE),
        &DatabaseKey::new(KEY),
    )
    .unwrap()
    .register_wallet_without_policy(&wallet)
    .unwrap();
    (dir, config, wallet)
}

fn destination() -> Destination {
    Destination {
        owner: "owner".into(),
        service: "service".into(),
        profile: Uuid::new_v4(),
    }
}

fn streams() -> (TcpStream, TcpStream) {
    // Synthetic codec transport only; production never uses TCP for this channel.
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    for stream in [&client, &server] {
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .unwrap();
    }
    (client, server)
}

#[test]
fn collected_source_stays_fenced_through_checkpoint_until_abort_or_disconnect() {
    for abort in [true, false] {
        let (_dir, config, wallet) = fixture();
        let path = config.data_dir().join(policy_store::DATABASE_FILE);
        let before = std::fs::read(&path).unwrap();
        let destination = destination();
        let target = destination.clone();
        let expected_wallet = wallet.clone();
        let (mut owner, mut installer) = streams();
        let worker = std::thread::spawn(move || {
            let mut reads = Vec::new();
            let result = config.with_lifecycle_lock(|| {
                collect_and_transfer(
                    &mut owner,
                    config.data_dir(),
                    target,
                    |service, user| {
                        reads.push((service.to_owned(), user.to_owned()));
                        Ok(Zeroizing::new(
                            if service == policy_store::KEYRING_SERVICE {
                                KEY
                            } else {
                                ACCOUNT
                            },
                        ))
                    },
                    |_, _| Ok(()),
                )
            });
            assert_eq!(
                reads,
                vec![
                    (
                        policy_store::KEYRING_SERVICE.into(),
                        policy_store::KEYRING_USER.into()
                    ),
                    (
                        crate::custody::KEYRING_SERVICE.into(),
                        expected_wallet.instance_id.to_string()
                    ),
                ]
            );
            result
        });
        let request = migration_transfer::relay_request(
            &mut installer,
            &mut Vec::new(),
            &destination,
            INSTALLER_LIMITS,
        )
        .unwrap();
        assert_eq!(request.wallets(), &[wallet]);
        let (_, relay) =
            crate::custody_envelope::WrappingKey::from_material(Zeroizing::new([0x44; 32]))
                .enroll(
                    crate::custody_envelope::CustodyBinding::new(
                        &destination.owner,
                        &destination.service,
                        destination.profile,
                        Uuid::new_v4(),
                    )
                    .unwrap(),
                )
                .unwrap();
        let reply = serde_json::to_vec(&serde_json::json!({
            "session": request.session(), "stage": Uuid::new_v4(),
            "canonical": request.source(), "relay": hex::encode(relay.as_bytes()),
        }))
        .unwrap();
        let mut service = u32::try_from(reply.len()).unwrap().to_le_bytes().to_vec();
        service.extend(reply);
        request
            .finish(&mut service.as_slice(), &mut installer)
            .unwrap();
        assert!(!worker.is_finished());
        let lifecycle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.parent().unwrap().join("lifecycle.lock"))
            .unwrap();
        assert_eq!(
            fs2::FileExt::try_lock_exclusive(&lifecycle)
                .unwrap_err()
                .raw_os_error(),
            fs2::lock_contended_error().raw_os_error()
        );
        // Inspect from a different process: opening/closing a source descriptor
        // here would itself release SQLite's process-wide POSIX advisory locks.
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "policy_store::migration_database::tests::independent_process_observes_source_fence"])
            .env("EKUBO_TEST_MIGRATION_FENCE_SOURCE", &path).status().unwrap().success());
        if abort {
            installer.write_all(&[0]).unwrap();
        }
        drop(installer);
        assert_eq!(worker.join().unwrap().is_ok(), abort);
        fs2::FileExt::try_lock_exclusive(&lifecycle).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(PolicyStore::open(&path, &DatabaseKey::new(KEY)).unwrap());
    }
}

#[test]
fn missing_database_key_does_not_initialize_source_or_emit_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let mut stream = Cursor::new(Vec::new());
    assert!(
        collect_and_transfer(
            &mut stream,
            dir.path(),
            destination(),
            |service, user| {
                assert_eq!(
                    (service, user),
                    (policy_store::KEYRING_SERVICE, policy_store::KEYRING_USER)
                );
                anyhow::bail!("synthetic missing credential")
            },
            |_, _| panic!("must not persist relay"),
        )
        .is_err()
    );
    assert!(stream.into_inner().is_empty());
    assert!(!dir.path().join(policy_store::DATABASE_FILE).exists());
}

#[test]
fn missing_or_mismatched_account_key_fails_before_transmitting_database_key() {
    let (_dir, config, wallet) = fixture();
    for missing in [true, false] {
        let mut stream = Cursor::new(Vec::new());
        assert!(
            collect_and_transfer(
                &mut stream,
                config.data_dir(),
                destination(),
                |service, user| {
                    if service == policy_store::KEYRING_SERVICE {
                        return Ok(Zeroizing::new(KEY));
                    }
                    assert_eq!(
                        (service, user),
                        (
                            crate::custody::KEYRING_SERVICE,
                            wallet.instance_id.to_string().as_str()
                        )
                    );
                    ensure!(!missing, "synthetic missing account");
                    Ok(Zeroizing::new([0x22; 32]))
                },
                |_, _| panic!("must not persist relay"),
            )
            .is_err()
        );
        assert!(stream.into_inner().is_empty());
    }
}

fn recovery_fixture(
    config: &ConfigStore,
    destination: &Destination,
) -> (
    RecoveryCheckpoint,
    crate::custody_envelope::WrappedDataKey,
    Vec<u8>,
) {
    let mut snapshot = MigrationDatabaseSnapshot::freeze(
        &config.data_dir().join(policy_store::DATABASE_FILE),
        Zeroizing::new(KEY),
    )
    .unwrap();
    let (_, relay) =
        crate::custody_envelope::WrappingKey::from_material(Zeroizing::new([0x44; 32]))
            .enroll(
                crate::custody_envelope::CustodyBinding::new(
                    &destination.owner,
                    &destination.service,
                    destination.profile,
                    Uuid::new_v4(),
                )
                .unwrap(),
            )
            .unwrap();
    let session = Uuid::new_v4();
    let reply = serde_json::to_vec(&serde_json::json!({
        "session": session, "stage": Uuid::new_v4(),
        "canonical": snapshot.transfer().unwrap(), "relay": hex::encode(relay.as_bytes()),
    }))
    .unwrap();
    let mut wire = u32::try_from(reply.len()).unwrap().to_le_bytes().to_vec();
    wire.extend(reply);
    let reply = migration_transfer::read_reply(&mut wire.as_slice(), session).unwrap();
    let checkpoint =
        RecoveryCheckpoint::capture(destination.clone(), &reply, &mut snapshot).unwrap();
    (checkpoint, relay, wire)
}

#[test]
fn source_recovery_refreezes_without_reading_account_keys_and_retains_the_fence() {
    let (_dir, config, wallet) = fixture();
    let path = config.data_dir().join(policy_store::DATABASE_FILE);
    let before = std::fs::read(&path).unwrap();
    let destination = destination();
    let (checkpoint, relay, reply) = recovery_fixture(&config, &destination);
    let target = destination.clone();
    let (mut owner, mut installer) = streams();
    let worker = std::thread::spawn(move || {
        config.with_lifecycle_lock(|| {
            let mut command = [0];
            owner.read_exact(&mut command)?;
            ensure!(command == [1], "expected recovery request");
            let checkpoint = RecoveryCheckpoint::read_source_request(&mut owner, &target)?;
            recover_source(
                &mut owner,
                config.data_dir(),
                target,
                &checkpoint,
                relay,
                |service, user| {
                    assert_eq!(
                        (service, user),
                        (policy_store::KEYRING_SERVICE, policy_store::KEYRING_USER)
                    );
                    Ok(Zeroizing::new(KEY))
                },
            )
        })
    });
    request(&mut installer, Some(&checkpoint)).unwrap();
    let mut forwarded = Vec::new();
    let request = migration_transfer::relay_recovery_request(
        &mut installer,
        &mut forwarded,
        &destination,
        &checkpoint,
        INSTALLER_LIMITS,
    )
    .unwrap();
    assert_eq!(&forwarded[..8], b"EKUBORC1");
    assert_eq!(request.source(), &checkpoint.source);
    assert_eq!(request.wallets(), &[wallet]);
    let (_, recovered) = request
        .finish(&mut reply.as_slice(), &mut installer)
        .unwrap();
    assert_eq!(
        recovered.journal_bytes(&destination).unwrap(),
        checkpoint.journal_bytes(&destination).unwrap()
    );
    assert!(!worker.is_finished());
    assert!(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "policy_store::migration_database::tests::independent_process_observes_source_fence"
            ])
            .env("EKUBO_TEST_MIGRATION_FENCE_SOURCE", &path)
            .status()
            .unwrap()
            .success()
    );
    installer.write_all(&[0]).unwrap();
    worker.join().unwrap().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn source_recovery_refuses_changed_source_missing_key_or_wrong_relay_before_output() {
    for mutation in 0..3 {
        let (_dir, config, _) = fixture();
        let destination = destination();
        let (mut checkpoint, relay, _) = recovery_fixture(&config, &destination);
        if mutation == 0 {
            config
                .update_for_test(|state| {
                    state.wallets[0].id = "changed-after-staging".into();
                    Ok(())
                })
                .unwrap();
        } else if mutation == 2 {
            checkpoint.relay_digest[0] ^= 1;
        }
        let mut output = Cursor::new(Vec::new());
        assert!(
            config
                .with_lifecycle_lock(|| recover_source(
                    &mut output,
                    config.data_dir(),
                    destination,
                    &checkpoint,
                    relay,
                    |_, _| {
                        ensure!(mutation != 1, "synthetic missing database key");
                        Ok(Zeroizing::new(KEY))
                    },
                ))
                .is_err()
        );
        assert!(output.into_inner().is_empty());
    }
}
