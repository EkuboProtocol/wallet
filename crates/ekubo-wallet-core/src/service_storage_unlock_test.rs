use super::*;
use crate::custody_envelope::{CustodyBinding, CustodyEnrollment, WrappingKey};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use uuid::Uuid;

struct Fixture {
    directory: tempfile::TempDir,
    storage: Storage,
    wrapped: WrappedDataKey,
}

fn open_storage(path: &Path, owner_uid: u32, profile_id: Uuid) -> Storage {
    let directory = Arc::new(File::open(path).unwrap());
    let service_uid = rustix::process::geteuid().as_raw();
    Storage {
        _lock: lock_profile(&directory, service_uid).unwrap(),
        directory,
        owner_uid,
        profile_id,
        service_uid,
        data_dir: path.to_owned(),
        custody: ServiceCustody::default(),
    }
}

fn enroll(storage: &Storage) -> (CustodyEnrollment, WrappedDataKey) {
    let generation = Uuid::new_v4();
    let binding = CustodyBinding::new(
        &format!("linux:uid:{}", storage.owner_uid),
        &format!("linux:uid:{}", storage.service_uid),
        storage.profile_id,
        generation,
    )
    .unwrap();
    let (_, wrapped) = WrappingKey::from_material(Zeroizing::new([0x44; 32]))
        .enroll(binding)
        .unwrap();
    (
        CustodyEnrollment::new(generation, &wrapped).unwrap(),
        wrapped,
    )
}

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let owner = if uid == 1000 { 1001 } else { 1000 };
    let storage = open_storage(directory.path(), owner, Uuid::new_v4());
    let (enrollment, wrapped) = enroll(&storage);
    private_file(&directory.path().join("wrapping.key"), &[0x44; 32]);
    private_file(
        &directory.path().join("custody.json"),
        &serde_json::to_vec(&enrollment).unwrap(),
    );
    Fixture {
        directory,
        storage,
        wrapped,
    }
}

#[test]
fn custody_stays_locked_until_the_exact_enrolled_ciphertext_is_supplied() {
    let fixture = fixture();
    assert!(
        fixture
            .storage
            .entry("org.ekubo.wallet.db", "default")
            .is_err()
    );
    let (_, wrong) = enroll(&fixture.storage);
    assert!(fixture.storage.unlock(&wrong).is_err());
    assert!(
        fixture
            .storage
            .entry("org.ekubo.wallet.db", "default")
            .is_err()
    );
    assert!(!fixture.directory.path().join("key-database").exists());
    fixture.storage.unlock(&fixture.wrapped).unwrap();
    let database = fixture
        .storage
        .entry("org.ekubo.wallet.db", "default")
        .unwrap();
    database.set_secret(&[0x11; 32]).unwrap();
    assert_eq!(database.get_secret().unwrap(), [0x11; 32]);
    fixture.storage.unlock(&fixture.wrapped).unwrap();
    assert_eq!(database.get_secret().unwrap(), [0x11; 32]);
    let bytes = std::fs::read(fixture.directory.path().join("key-database")).unwrap();
    assert_eq!(bytes.len(), SEALED_KEY_BYTES);
    assert_eq!(&bytes[..8], b"EKUBOKEY");
    assert_eq!(
        std::fs::read_dir(fixture.directory.path()).unwrap().count(),
        4
    );
}

#[test]
fn reopening_requires_unlock_and_preserves_encrypted_database_and_account_keys() {
    let Fixture {
        directory,
        storage,
        wrapped,
    } = fixture();
    storage.unlock(&wrapped).unwrap();
    let instance = Uuid::new_v4().to_string();
    storage
        .entry("org.ekubo.wallet.db", "default")
        .unwrap()
        .set_secret(&[0x11; 32])
        .unwrap();
    storage
        .entry("org.ekubo.wallet.private-key.instance", &instance)
        .unwrap()
        .set_secret(&[0x22; 32])
        .unwrap();
    let (owner, profile) = (storage.owner_uid, storage.profile_id);
    drop(storage);
    let reopened = open_storage(directory.path(), owner, profile);
    assert!(reopened.entry("org.ekubo.wallet.db", "default").is_err());
    reopened.unlock(&wrapped).unwrap();
    assert_eq!(
        reopened
            .entry("org.ekubo.wallet.db", "default")
            .unwrap()
            .get_secret()
            .unwrap(),
        [0x11; 32]
    );
    assert_eq!(
        reopened
            .entry("org.ekubo.wallet.private-key.instance", &instance)
            .unwrap()
            .get_secret()
            .unwrap(),
        [0x22; 32]
    );
}

#[test]
fn ciphertext_substitution_and_legacy_plaintext_do_not_become_missing_key_fallbacks() {
    let fixture = fixture();
    fixture.storage.unlock(&fixture.wrapped).unwrap();
    let first = fixture
        .storage
        .entry(
            "org.ekubo.wallet.private-key.instance",
            &Uuid::new_v4().to_string(),
        )
        .unwrap();
    let second = fixture
        .storage
        .entry(
            "org.ekubo.wallet.private-key.instance",
            &Uuid::new_v4().to_string(),
        )
        .unwrap();
    first.set_secret(&[0x11; 32]).unwrap();
    second.set_secret(&[0x22; 32]).unwrap();
    let copied = std::fs::read(fixture.directory.path().join(&first.name)).unwrap();
    let second_path = fixture.directory.path().join(&second.name);
    std::fs::write(&second_path, copied).unwrap();
    let entry = crate::credential_store::Entry::Service(second);
    assert!(matches!(
        entry.get_secret(),
        Err(keyring::Error::PlatformFailure(_))
    ));
    std::fs::write(&second_path, [0x22; 32]).unwrap();
    assert!(matches!(
        entry.get_secret(),
        Err(keyring::Error::PlatformFailure(_))
    ));
    assert!(entry.set_secret(&[0x33; 32]).is_err());
    assert_eq!(std::fs::read(second_path).unwrap(), [0x22; 32]);
}

#[test]
fn enrollment_changes_cannot_replace_an_active_cipher() {
    let fixture = fixture();
    fixture.storage.unlock(&fixture.wrapped).unwrap();
    let entry = fixture
        .storage
        .entry("org.ekubo.wallet.db", "default")
        .unwrap();
    entry.set_secret(&[0x11; 32]).unwrap();
    let (updated, wrapped) = enroll(&fixture.storage);
    std::fs::write(
        fixture.directory.path().join("custody.json"),
        serde_json::to_vec(&updated).unwrap(),
    )
    .unwrap();
    assert!(fixture.storage.unlock(&wrapped).is_err());
    assert_eq!(entry.get_secret().unwrap(), [0x11; 32]);
}

#[test]
fn wrapping_and_enrollment_files_require_private_permissions_and_valid_binding() {
    let mut fixture = fixture();
    for name in ["wrapping.key", "custody.json"] {
        let path = fixture.directory.path().join(name);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(fixture.storage.unlock(&fixture.wrapped).is_err());
        assert!(fixture.storage.custody.cipher().is_err());
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fixture.storage.profile_id = Uuid::new_v4();
    assert!(fixture.storage.unlock(&fixture.wrapped).is_err());
    assert!(fixture.storage.custody.cipher().is_err());
}
