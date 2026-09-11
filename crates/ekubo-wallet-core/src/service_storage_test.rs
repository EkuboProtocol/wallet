use super::*;
use crate::custody_envelope::WrappingKey;

#[test]
fn installer_configuration_requires_distinct_nonroot_matching_identities() {
    let valid = serde_json::json!({"owner_uid":1000,"service_uid":2000,
        "profile_id": uuid::Uuid::from_u128(1)});
    let bytes = serde_json::to_vec(&valid).unwrap();
    let configured = decode_configuration(&bytes, 1000).unwrap();
    assert_eq!(configured.service_uid, 2000);
    assert_eq!(configured.profile_id, uuid::Uuid::from_u128(1));
    assert!(decode_configuration(&bytes, 1001).is_err());
    for (field, value) in [
        ("service_uid", serde_json::json!(0)),
        ("service_uid", serde_json::json!(1000)),
        ("owner_uid", serde_json::json!(0)),
        ("profile_id", serde_json::json!(uuid::Uuid::nil())),
        ("bus_address", serde_json::json!("/tmp/fake")),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(decode_configuration(&serde_json::to_vec(&invalid).unwrap(), 1000).is_err());
    }
    assert!(decode_configuration(br#"{"owner_uid":1000,"service_uid":2000}"#, 1000).is_err());
    let mut oversized = bytes;
    oversized.resize(usize::try_from(MAX_CONFIG_BYTES).unwrap() + 1, b' ');
    assert!(decode_configuration(&oversized, 1000).is_err());
}

fn cipher_fixture() -> Arc<DataCipher> {
    let binding = crate::custody_envelope::CustodyBinding::new(
        "linux:uid:1000",
        "linux:uid:2000",
        uuid::Uuid::from_u128(1),
        uuid::Uuid::from_u128(2),
    )
    .unwrap();
    let (cipher, _) = WrappingKey::from_material(Zeroizing::new([0x44; 32]))
        .enroll(binding)
        .unwrap();
    Arc::new(cipher)
}

use std::os::unix::fs::{PermissionsExt as _, symlink};

fn fixture() -> (tempfile::TempDir, Entry) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let handle = File::open(directory.path()).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    validate_directory(&handle, uid, true).unwrap();
    (
        directory,
        Entry {
            directory: Arc::new(handle),
            service_uid: uid,
            name: "key-account-test".to_owned(),
            cipher: cipher_fixture(),
            instance: Some(uuid::Uuid::from_u128(3)),
        },
    )
}

#[test]
fn desktop_identity_is_rejected_before_any_credential_access() {
    assert!(initialize(rustix::process::geteuid().as_raw()).is_err());
    assert!(initialize(0).is_err());
}

#[test]
fn keys_survive_reopening_and_cannot_be_overwritten() {
    let (directory, entry) = fixture();
    entry.set_secret(&[0x11; KEY_BYTES]).unwrap();
    assert!(entry.set_secret(&[0x22; KEY_BYTES]).is_err());
    let reopened = Entry {
        directory: Arc::new(File::open(directory.path()).unwrap()),
        service_uid: entry.service_uid,
        name: entry.name.clone(),
        cipher: entry.cipher.clone(),
        instance: entry.instance,
    };
    assert_eq!(reopened.get_secret().unwrap(), [0x11; KEY_BYTES]);
    assert_eq!(
        std::fs::metadata(directory.path().join(&entry.name))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
    reopened.delete_credential().unwrap();
    assert!(entry.get_secret().is_err());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn concurrent_creators_publish_one_complete_key() {
    let (directory, first) = fixture();
    let second = Entry {
        directory: first.directory.clone(),
        service_uid: first.service_uid,
        name: first.name.clone(),
        cipher: first.cipher.clone(),
        instance: first.instance,
    };
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let other_barrier = barrier.clone();
    let child = std::thread::spawn(move || {
        other_barrier.wait();
        second.set_secret(&[0x22; KEY_BYTES]).is_ok()
    });
    barrier.wait();
    let first_won = first.set_secret(&[0x11; KEY_BYTES]).is_ok();
    assert_ne!(first_won, child.join().unwrap());
    let expected = if first_won { 0x11 } else { 0x22 };
    assert_eq!(first.get_secret().unwrap(), [expected; KEY_BYTES]);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn invalid_lengths_never_create_a_credential() {
    let (directory, entry) = fixture();
    for length in [0, KEY_BYTES - 1, KEY_BYTES + 1] {
        assert!(entry.set_secret(&vec![0; length]).is_err());
    }
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn permissive_files_symlinks_and_hardlinks_are_rejected() {
    let (directory, entry) = fixture();
    let path = directory.path().join(&entry.name);
    entry.set_secret(&[0x11; KEY_BYTES]).unwrap();
    let sealed = std::fs::read(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(entry.get_secret().is_err());
    assert!(entry.delete_credential().is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let other = directory.path().join("other");
    std::fs::hard_link(&path, &other).unwrap();
    assert!(entry.get_secret().is_err());
    assert!(entry.delete_credential().is_err());
    std::fs::remove_file(&path).unwrap();
    symlink(&other, &path).unwrap();
    assert!(entry.get_secret().is_err());
    assert!(entry.delete_credential().is_err());
    assert_eq!(std::fs::read(&other).unwrap(), sealed);
}

#[test]
fn directories_require_private_permissions_and_correct_owner() {
    let (directory, entry) = fixture();
    let file = &entry.directory;
    assert!(validate_directory(file, entry.service_uid.wrapping_add(1), true).is_err());
    for mode in [0o755, 0o750, 0o770, 0o777, 0o1700] {
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(validate_directory(file, entry.service_uid, true).is_err());
    }
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn fifo_and_directory_substitutions_do_not_block_or_expose_data() {
    let (directory, entry) = fixture();
    rustix::fs::mknodat(
        &entry.directory,
        &entry.name,
        rustix::fs::FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert!(entry.get_secret().is_err());
    std::fs::remove_file(directory.path().join(&entry.name)).unwrap();
    std::fs::create_dir(directory.path().join(&entry.name)).unwrap();
    assert!(entry.get_secret().is_err());
}

#[test]
fn missing_credentials_map_to_absence_but_corruption_does_not() {
    let (directory, entry) = fixture();
    let error = crate::credential_store::Entry::Service(entry);
    assert!(matches!(error.get_secret(), Err(keyring::Error::NoEntry)));
    error.set_secret(&[0x11; KEY_BYTES]).unwrap();
    std::fs::write(directory.path().join("key-account-test"), b"short").unwrap();
    assert!(matches!(
        error.get_secret(),
        Err(keyring::Error::PlatformFailure(_))
    ));
}

#[test]
fn profile_lock_excludes_another_authority_until_release() {
    let (_directory, entry) = fixture();
    let first = lock_profile(&entry.directory, entry.service_uid).unwrap();
    assert!(lock_profile(&entry.directory, entry.service_uid).is_err());
    drop(first);
    assert!(lock_profile(&entry.directory, entry.service_uid).is_ok());
}

#[test]
fn open_directory_descriptor_does_not_follow_replaced_paths() {
    let parent = tempfile::tempdir().unwrap();
    let original = parent.path().join("original");
    std::fs::create_dir(&original).unwrap();
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
    let entry = Entry {
        directory: Arc::new(File::open(&original).unwrap()),
        service_uid: rustix::process::geteuid().as_raw(),
        name: "key-account-test".into(),
        cipher: cipher_fixture(),
        instance: Some(uuid::Uuid::from_u128(3)),
    };
    let moved = parent.path().join("moved");
    std::fs::rename(&original, &moved).unwrap();
    std::fs::create_dir(&original).unwrap();
    entry.set_secret(&[0x11; KEY_BYTES]).unwrap();
    assert_eq!(std::fs::read_dir(&original).unwrap().count(), 0);
    assert_eq!(
        std::fs::read(moved.join(&entry.name)).unwrap().len(),
        SEALED_KEY_BYTES
    );
    assert_eq!(entry.get_secret().unwrap(), [0x11; KEY_BYTES]);
}

fn public_root() -> (tempfile::TempDir, File, u32) {
    let root = tempfile::tempdir().unwrap();
    let handle = File::open(root.path()).unwrap();
    (root, handle, rustix::process::geteuid().as_raw())
}

#[test]
fn optional_installation_read_distinguishes_absence_from_invalid_files() {
    let (root, handle, uid) = public_root();
    assert!(find_owner_configuration(&handle, 1000, uid).is_err());
    std::fs::create_dir(root.path().join("etc")).unwrap();
    assert!(
        find_owner_configuration(&handle, 1000, uid)
            .unwrap()
            .is_none()
    );
    let owners = root.path().join("etc/ekubo-wallet/owners");
    std::fs::create_dir_all(&owners).unwrap();
    assert!(
        find_owner_configuration(&handle, 1000, uid)
            .unwrap()
            .is_none()
    );
    let path = owners.join("1000.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "owner_uid":1000,"service_uid":2000,"profile_id":uuid::Uuid::from_u128(1)
        }))
        .unwrap(),
    )
    .unwrap();
    let found = find_owner_configuration(&handle, 1000, uid)
        .unwrap()
        .unwrap();
    assert_eq!(found.service_uid, 2000);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(find_owner_configuration(&handle, 1000, uid).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, b"not json").unwrap();
    assert!(find_owner_configuration(&handle, 1000, uid).is_err());
    std::fs::remove_file(&path).unwrap();
    symlink(owners.join("absent"), &path).unwrap();
    assert!(
        find_owner_configuration(&handle, 1000, uid).is_err(),
        "a dangling link is not an absent installation"
    );
}

#[test]
fn unsafe_ancestors_cannot_hide_behind_missing_configuration() {
    let (root, handle, uid) = public_root();
    let config = root.path().join("etc/ekubo-wallet");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(find_owner_configuration(&handle, 1000, uid).is_err());
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        find_owner_configuration(&handle, 1000, uid)
            .unwrap()
            .is_none()
    );
    std::fs::remove_dir(&config).unwrap();
    symlink(root.path().join("missing"), &config).unwrap();
    assert!(find_owner_configuration(&handle, 1000, uid).is_err());
}

#[tokio::test]
async fn mcp_peer_checks_both_the_installed_uid_and_authenticated_process() {
    let (stream, _peer) = tokio::net::UnixStream::pair().unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let pid = std::process::id();
    validate_agent_peer(&stream, uid, pid).unwrap();
    assert!(validate_agent_peer(&stream, uid.wrapping_add(1), pid).is_err());
    assert!(validate_agent_peer(&stream, uid, pid.wrapping_add(1)).is_err());
    assert!(validate_agent_peer(&stream, uid, 0).is_err());
}

#[tokio::test]
async fn mcp_connects_through_pinned_runtime_and_rejects_substituted_paths() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let (root, handle, uid) = public_root();
    let identity = InstalledServiceIdentity {
        owner_uid: 1000,
        service_uid: uid,
        profile_id: uuid::Uuid::from_u128(1),
    };
    let runtime = root.path().join("run/ekubo-wallet/1000");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o711)).unwrap();
    let socket = runtime.join("mcp.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let mut stream = connect_agent_under(&handle, &identity, std::process::id(), uid)
        .await
        .unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    stream.write_all(b"MCP").await.unwrap();
    let mut bytes = [0; 3];
    server.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, *b"MCP");
    assert!(
        connect_agent_under(&handle, &identity, std::process::id().wrapping_add(1), uid)
            .await
            .is_err()
    );
    std::fs::remove_file(&socket).unwrap();
    let target = runtime.join("different.sock");
    let _different = tokio::net::UnixListener::bind(&target).unwrap();
    symlink(&target, &socket).unwrap();
    assert!(
        connect_agent_under(&handle, &identity, std::process::id(), uid)
            .await
            .is_err()
    );
    std::fs::remove_file(&socket).unwrap();
    std::fs::write(&socket, b"not a socket").unwrap();
    assert!(
        connect_agent_under(&handle, &identity, std::process::id(), uid)
            .await
            .is_err()
    );
}

#[test]
fn custody_stage_records_use_private_immutable_names_and_leave_active_custody_untouched() {
    use crate::custody_staging::{ServiceCredentialRecord, StagedRecord};
    let (directory, entry) = fixture();
    entry.set_secret(&[0x11; KEY_BYTES]).unwrap();
    let name = StagedRecord::Credential(ServiceCredentialRecord::WrappingKey)
        .file_name(uuid::Uuid::new_v4())
        .unwrap();
    publish_stage_record(&entry.directory, entry.service_uid, &name, &[0x77; 32]).unwrap();
    assert_eq!(
        read_stage_record(&entry.directory, entry.service_uid, &name)
            .unwrap()
            .as_slice(),
        [0x77; 32]
    );
    assert!(publish_stage_record(&entry.directory, entry.service_uid, &name, &[0x88; 32]).is_err());
    assert_eq!(entry.get_secret().unwrap(), [0x11; KEY_BYTES]);
    assert_eq!(
        std::fs::metadata(directory.path().join(&name))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
    let linked = StagedRecord::Complete
        .file_name(uuid::Uuid::new_v4())
        .unwrap();
    symlink(&name, directory.path().join(&linked)).unwrap();
    assert!(publish_stage_record(&entry.directory, entry.service_uid, &linked, b"{}").is_err());
    assert!(read_stage_record(&entry.directory, entry.service_uid, &linked).is_err());
}

#[test]
fn pending_storage_stages_without_becoming_an_active_profile() {
    use crate::custody_staging::{
        CredentialStagingStore as _, ServiceCredentialRecord, StagedRecord,
    };
    let (root, handle, uid) = public_root();
    let owner = if uid == 1000 { 1001 } else { 1000 };
    let profile = uuid::Uuid::new_v4();
    let pending = root.path().join("etc/ekubo-wallet/pending");
    std::fs::create_dir_all(&pending).unwrap();
    let config = pending.join(format!("{owner}.json"));
    let bytes = serde_json::to_vec(
        &serde_json::json!({"owner_uid":owner,"service_uid":uid,"profile_id":profile}),
    )
    .unwrap();
    std::fs::write(&config, &bytes).unwrap();
    let private = root
        .path()
        .join(format!("var/lib/ekubo-wallet/pending/{profile}"));
    std::fs::create_dir_all(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        find_owner_configuration(&handle, owner, uid)
            .unwrap()
            .is_none()
    );
    let staging = open_pending_storage(&handle, owner, uid).unwrap();
    assert_eq!(
        staging.identity(),
        (
            format!("linux:uid:{owner}"),
            format!("linux:uid:{uid}"),
            profile
        )
    );
    assert!(
        open_pending_storage(&handle, owner, uid).is_err(),
        "pending profile must retain its singleton lock"
    );
    let stage = uuid::Uuid::new_v4();
    let record = StagedRecord::Credential(ServiceCredentialRecord::WrappingKey);
    staging.create_new(stage, record, &[0x77; 32]).unwrap();
    assert_eq!(staging.read(stage, record).unwrap().as_slice(), [0x77; 32]);
    assert!(
        find_owner_configuration(&handle, owner, uid)
            .unwrap()
            .is_none()
    );
    assert!(!private.join("wrapping.key").exists());
    drop(staging);
    drop(open_pending_storage(&handle, owner, uid).unwrap());
    let active = root.path().join("etc/ekubo-wallet/owners");
    std::fs::create_dir_all(&active).unwrap();
    let active = active.join(format!("{owner}.json"));
    std::fs::write(&active, &bytes).unwrap();
    assert!(open_pending_storage(&handle, owner, uid).is_err());
    std::fs::write(&active, b"invalid").unwrap();
    assert!(
        open_pending_storage(&handle, owner, uid).is_err(),
        "invalid active metadata must not permit pending fallback"
    );
}

#[test]
fn pending_configuration_requires_protected_valid_metadata() {
    let (root, handle, uid) = public_root();
    let pending = root.path().join("etc/ekubo-wallet/pending");
    std::fs::create_dir_all(&pending).unwrap();
    assert!(pending_configuration(&handle, 1000, uid).is_err());
    let path = pending.join("1000.json");
    std::fs::write(&path,br#"{"owner_uid":1000,"service_uid":2000,"profile_id":"00000000-0000-0000-0000-000000000001"}"#).unwrap();
    assert!(pending_configuration(&handle, 1000, uid).is_ok());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(pending_configuration(&handle, 1000, uid).is_err());
    std::fs::remove_file(&path).unwrap();
    symlink("absent", &path).unwrap();
    assert!(pending_configuration(&handle, 1000, uid).is_err());
    assert!(
        find_owner_configuration(&handle, 1000, uid)
            .unwrap()
            .is_none()
    );
}

#[test]
fn protected_database_receive_publishes_only_complete_verified_frames() {
    use crate::database_staging::{DatabaseStagingStore as _, DatabaseTransfer};
    let (directory, entry) = fixture();
    let pending = PendingCredentialStorage(CredentialStagingRoot {
        directory: entry.directory.clone(),
        owner_uid: if entry.service_uid == 1001 {
            1002
        } else {
            1001
        },
        service_uid: entry.service_uid,
        profile_id: uuid::Uuid::new_v4(),
        _lock: Some(lock_profile(&entry.directory, entry.service_uid).unwrap()),
    });
    let payload = vec![0x77; 100_003];
    let transfer = DatabaseTransfer::describe(&mut payload.as_slice()).unwrap();
    let stage = uuid::Uuid::new_v4();
    pending
        .receive_database(stage, &transfer, &mut payload.as_slice())
        .unwrap();
    let mut file = pending.open_staged_database(stage).unwrap();
    assert_eq!(DatabaseTransfer::describe(&mut file).unwrap(), transfer);
    assert!(
        pending
            .receive_database(stage, &transfer, &mut payload.as_slice())
            .is_err()
    );
    assert!(!directory.path().join("wallet.db").exists());
    for mut input in [&payload[..40_000], &vec![0x33; payload.len()][..]] {
        let failed = uuid::Uuid::new_v4();
        assert!(
            pending
                .receive_database(failed, &transfer, &mut input)
                .is_err()
        );
        assert!(
            !directory
                .path()
                .join(crate::database_staging::file_name(failed).unwrap())
                .exists()
        );
    }
    assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".key-stage-")
    }));
}

#[test]
fn encrypted_source_snapshot_transfers_into_pending_storage_and_reopens_with_original_key() {
    use crate::custody_staging::CredentialStagingStore as _;
    use crate::database_staging::{DatabaseStagingStore as _, DatabaseTransfer};
    use crate::policy_store::{
        DatabaseKey, PolicyStore, migration_database::MigrationDatabaseSnapshot,
    };
    use std::io::{Seek as _, SeekFrom};
    let (directory, entry) = fixture();
    let pending = PendingCredentialStorage(CredentialStagingRoot {
        directory: entry.directory.clone(),
        owner_uid: if entry.service_uid == 1001 {
            1002
        } else {
            1001
        },
        service_uid: entry.service_uid,
        profile_id: uuid::Uuid::new_v4(),
        _lock: Some(lock_profile(&entry.directory, entry.service_uid).unwrap()),
    });
    let source_dir = tempfile::tempdir().unwrap();
    let source = source_dir.path().join("source.db");
    let raw_key = [0x44; 32];
    let wallet = crate::config::WalletMetadata {
        instance_id: uuid::Uuid::new_v4(),
        id: "migrated".into(),
        address: alloy::signers::local::PrivateKeySigner::from_slice(&[0x22; 32])
            .unwrap()
            .address(),
        created_at: chrono::Utc::now(),
        source: crate::config::WalletSource::Imported,
        exported_at: None,
    };
    let account = || crate::custody_provisioning::MigrationAccount {
        wallet: wallet.clone(),
        key: Zeroizing::new([0x22; 32]),
    };
    let mut source_store = PolicyStore::open(&source, &DatabaseKey::new(raw_key)).unwrap();
    source_store
        .register_wallet_without_policy(&wallet)
        .unwrap();
    let config = crate::config::WalletConfig {
        version: 3,
        wallets: vec![wallet.clone()],
        networks: vec![],
    };
    source_store
        .connection
        .execute(
            "INSERT INTO application_settings(key,value_json,updated_at) VALUES(?1,?2,0)",
            rusqlite::params![
                crate::config::WALLET_CONFIGURATION_SETTING,
                serde_json::to_string(&config).unwrap()
            ],
        )
        .unwrap();
    drop(source_store);
    let mut snapshot = MigrationDatabaseSnapshot::freeze(&source, Zeroizing::new(raw_key)).unwrap();
    let transfer = snapshot.transfer().unwrap();
    let mut stream = tempfile::tempfile().unwrap();
    snapshot.write_to(&mut stream).unwrap();
    stream.seek(SeekFrom::Start(0)).unwrap();
    let (owner, service, profile) = pending.identity();
    let prepared = crate::custody_provisioning::PreparedServiceCredentials::prepare(
        &owner,
        &service,
        profile,
        Zeroizing::new(raw_key),
        std::slice::from_ref(&wallet),
        vec![account()],
    )
    .unwrap();
    let credentials = prepared.stage(&pending).unwrap();
    let stage = credentials.id();
    pending
        .receive_database(stage, &transfer, &mut stream)
        .unwrap();
    prepared
        .verify_staged_inventory(&pending, &credentials)
        .unwrap();
    let abandoned_stage = uuid::Uuid::new_v4();
    let abandoned = pending.create_canonical_database(abandoned_stage).unwrap();
    let temporary_path = abandoned.path().to_owned();
    assert!(temporary_path.exists());
    drop(abandoned);
    assert!(!temporary_path.exists());
    assert!(pending.canonical_database(abandoned_stage).is_err());
    let canonical_transfer = prepared
        .rebuild_staged_database(&pending, &credentials)
        .unwrap();
    let canonical = pending.canonical_database(stage).unwrap();
    assert_eq!(canonical.transfer().unwrap(), canonical_transfer);
    assert!(
        prepared
            .rebuild_staged_database(&pending, &credentials)
            .is_err()
    );
    assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".database-build-")
    }));
    let limits = crate::migration_transfer::TransferLimits {
        accounts: 10,
        metadata_bytes: 4096,
        total_metadata_bytes: 40960,
        database_bytes: 64 * 1024 * 1024,
    };
    let (owner, service, profile) = pending.identity();
    let mut wire = Zeroizing::new(Vec::new());
    let mut rejected_output = Vec::new();
    assert!(
        crate::migration_transfer::send(
            &mut rejected_output,
            crate::migration_transfer::Destination {
                owner: owner.clone(),
                service: service.clone(),
                profile
            },
            Zeroizing::new(raw_key),
            std::slice::from_ref(&wallet),
            vec![account()],
            &mut snapshot,
            crate::migration_transfer::TransferLimits {
                total_metadata_bytes: 1,
                ..limits
            },
        )
        .is_err()
    );
    assert!(rejected_output.is_empty());
    let session = crate::migration_transfer::send(
        &mut *wire,
        crate::migration_transfer::Destination {
            owner,
            service,
            profile,
        },
        Zeroizing::new(raw_key),
        std::slice::from_ref(&wallet),
        vec![account()],
        &mut snapshot,
        limits,
    )
    .unwrap();
    let canonical_count = || {
        std::fs::read_dir(directory.path())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with("-canonical.db")
            })
            .count()
    };
    let before_interruption = canonical_count();
    assert!(
        crate::migration_transfer::receive(&pending, &mut &wire[..wire.len() - 1], limits).is_err()
    );
    assert_eq!(
        canonical_count(),
        before_interruption,
        "truncated transfer cannot publish a candidate"
    );
    wire.extend_from_slice(b"next protocol frame");
    let mut input = wire.as_slice();
    let candidate = crate::migration_transfer::receive(&pending, &mut input, limits).unwrap();
    assert_eq!(candidate.session(), session);
    assert_eq!(input, b"next protocol frame");
    assert_ne!(candidate.stage(), stage);
    assert_eq!(
        pending
            .canonical_database(candidate.stage())
            .unwrap()
            .transfer()
            .unwrap(),
        *candidate.canonical()
    );
    assert_eq!(
        candidate.relay().as_bytes().len(),
        crate::custody_envelope::SEALED_KEY_BYTES
    );
    let mut received = pending.open_staged_database(stage).unwrap();
    assert_eq!(DatabaseTransfer::describe(&mut received).unwrap(), transfer);
    received.seek(SeekFrom::Start(0)).unwrap();
    let imported = source_dir.path().join("imported.db");
    let mut output = std::fs::File::create(&imported).unwrap();
    std::io::copy(&mut received, &mut output).unwrap();
    drop(output);
    drop(PolicyStore::open(&imported, &DatabaseKey::new(raw_key)).unwrap());
    assert!(PolicyStore::open(&imported, &DatabaseKey::new([0x55; 32])).is_err());
    assert!(!directory.path().join("wallet.db").exists());
}
