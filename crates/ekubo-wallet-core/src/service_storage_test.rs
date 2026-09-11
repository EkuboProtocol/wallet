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
