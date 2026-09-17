use super::*;
use std::os::unix::fs::{PermissionsExt as _, symlink};

fn fixture() -> (tempfile::TempDir, PendingCredentialStorage) {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = Arc::new(File::open(temp.path()).unwrap());
    let service_uid = rustix::process::geteuid().as_raw();
    let lock = lock_profile(&directory, service_uid).unwrap();
    (
        temp,
        PendingCredentialStorage(CredentialStagingRoot {
            directory,
            owner_uid: service_uid + 1,
            service_uid,
            profile_id: uuid::Uuid::new_v4(),
            _lock: Some(lock),
        }),
    )
}

#[test]
fn configuration_rejects_same_identity_root_and_extra_fields() {
    let valid =
        serde_json::json!({"owner_uid":1000,"service_uid":2000,"profile_id":uuid::Uuid::new_v4()});
    assert!(decode_configuration(&serde_json::to_vec(&valid).unwrap(), 1000).is_ok());
    for (field, value) in [
        ("service_uid", serde_json::json!(0)),
        ("service_uid", serde_json::json!(1000)),
        ("owner_uid", serde_json::json!(0)),
        ("profile_id", serde_json::json!(uuid::Uuid::nil())),
        ("path", serde_json::json!("/tmp/hostile")),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(decode_configuration(&serde_json::to_vec(&invalid).unwrap(), 1000).is_err());
    }
}

#[test]
fn discovery_ignores_v1_metadata_and_rejects_damaged_v2_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let legacy = temp.path().join("etc/ekubo-wallet/owners");
    std::fs::create_dir_all(&legacy).unwrap();
    let sentinel = legacy.join("1000.json");
    std::fs::write(&sentinel, b"untouched v1 metadata").unwrap();
    let root = File::open(temp.path()).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    assert!(
        find_installation_configuration(&root, 1000, uid)
            .unwrap()
            .is_none()
    );
    let v2 = temp.path().join("etc/ekubo-wallet-v2/owners");
    std::fs::create_dir_all(&v2).unwrap();
    std::fs::write(v2.join("1000.json"), b"damaged v2").unwrap();
    assert!(find_installation_configuration(&root, 1000, uid).is_err());
    assert_eq!(std::fs::read(sentinel).unwrap(), b"untouched v1 metadata");
}

#[test]
fn fresh_enrollment_is_empty_encrypted_and_never_replaces_keys() {
    use crate::{
        custody_envelope::{CustodyEnrollment, WrappingKey},
        custody_staging::CredentialStagingStore as _,
    };
    let (temp, pending) = fixture();
    let relay = crate::custody_provisioning::enroll(&pending).unwrap();
    let wrapping =
        read_fixed::<32>(&pending.0.directory, "wrapping.key", pending.0.service_uid).unwrap();
    let enrollment = std::fs::read(temp.path().join("custody.json")).unwrap();
    let (owner, service, profile) = pending.identity();
    let cipher = CustodyEnrollment::from_bytes(&enrollment)
        .unwrap()
        .unlock(
            &WrappingKey::from_material(wrapping),
            &owner,
            &service,
            profile,
            &relay,
        )
        .unwrap();
    let sealed = std::fs::read(temp.path().join("key-database")).unwrap();
    let key = cipher.open_database_key(&sealed).unwrap();
    let database = temp.path().join("wallet.db");
    let config =
        crate::config::ConfigStore::open(temp.path(), crate::policy_store::DatabaseKey::new(*key))
            .load()
            .unwrap();
    assert!(config.wallets.is_empty());
    let bytes = std::fs::read(&database).unwrap();
    assert!(!bytes.starts_with(b"SQLite format 3"));
    let db = crate::policy_store::PolicyStore::open(
        &database,
        &crate::policy_store::DatabaseKey::new(*key),
    )
    .unwrap();
    db.assert_schema_current().unwrap();
    drop(db);
    assert!(!std::fs::read_dir(temp.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("key-account-")
    }));
    let before = std::fs::read(temp.path().join("wrapping.key")).unwrap();
    assert!(crate::custody_provisioning::enroll(&pending).is_err());
    assert_eq!(
        before,
        std::fs::read(temp.path().join("wrapping.key")).unwrap()
    );
    assert_eq!(bytes, std::fs::read(database).unwrap());
    assert!(std::fs::read_dir(temp.path()).unwrap().all(|entry| {
        let path = entry.unwrap().path();
        std::fs::metadata(path).unwrap().mode() & 0o7777 == 0o600
    }));
}

#[test]
fn private_storage_refuses_symlinks_hardlinks_and_permissions() {
    let (temp, pending) = fixture();
    let parent = &pending.0.directory;
    let uid = pending.0.service_uid;
    publish_private_record(parent, "record", b"immutable").unwrap();
    assert!(publish_private_record(parent, "record", b"replacement").is_err());
    symlink(temp.path().join("record"), temp.path().join("link")).unwrap();
    assert!(open_regular(parent, "link", uid, true).is_err());
    std::fs::hard_link(temp.path().join("record"), temp.path().join("hard")).unwrap();
    assert!(open_regular(parent, "record", uid, true).is_err());
    std::fs::remove_file(temp.path().join("hard")).unwrap();
    std::fs::set_permissions(
        temp.path().join("record"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(open_regular(parent, "record", uid, true).is_err());
    assert!(open_regular(parent, "record", uid + 1, false).is_err());
}

#[test]
fn pending_lock_excludes_another_setup_and_identity_cannot_activate_itself() {
    let (_temp, pending) = fixture();
    assert!(lock_profile(&pending.0.directory, pending.0.service_uid).is_err());
    assert!(initialize(pending.0.service_uid).is_err());
    assert!(initialize(0).is_err());
}

#[test]
fn interrupted_key_publication_cannot_be_reenrolled() {
    let (temp, pending) = fixture();
    publish_private_record(&pending.0.directory, "wrapping.key", &[0x55; 32]).unwrap();
    assert!(crate::custody_provisioning::enroll(&pending).is_err());
    assert_eq!(
        std::fs::read(temp.path().join("wrapping.key")).unwrap(),
        [0x55; 32]
    );
    assert!(!temp.path().join("wallet.db").exists());
}
