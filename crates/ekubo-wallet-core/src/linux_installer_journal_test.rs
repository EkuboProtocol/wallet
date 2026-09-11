use super::*;
use std::os::unix::fs::{PermissionsExt as _, symlink};

#[test]
fn checkpoint_publication_is_durable_immutable_and_bound_to_pending_identity() {
    let root = tempfile::tempdir().unwrap();
    let pending = root.path().join("etc/ekubo-wallet/pending");
    std::fs::create_dir_all(&pending).unwrap();
    let owner = 1000;
    let uid = rustix::process::geteuid().as_raw();
    let profile = uuid::Uuid::new_v4();
    let config = serde_json::json!({"owner_uid":owner,"service_uid":2000,"profile_id":profile});
    std::fs::write(
        pending.join("1000.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let checkpoint: RecoveryCheckpoint = serde_json::from_value(serde_json::json!({
        "version":1,"destination":{"owner":"linux:uid:1000","service":"linux:uid:2000","profile":profile},
        "session":uuid::Uuid::new_v4(),"stage":uuid::Uuid::new_v4(),
        "source":{"bytes":1024,"sha256":([0u8;32])},"source_fingerprint":([0u8;32]),
        "canonical":{"bytes":1024,"sha256":([1u8;32])},"relay_digest":([2u8;32])
    })).unwrap();
    let handle = File::open(root.path()).unwrap();
    save_under(&handle, owner, uid, &checkpoint).unwrap();
    let path = pending.join("1000.checkpoint.json");
    let original = std::fs::read(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    save_under(&handle, owner, uid, &checkpoint).unwrap();
    let mut changed = serde_json::to_value(&checkpoint).unwrap();
    changed["stage"] = serde_json::json!(uuid::Uuid::new_v4());
    assert!(
        save_under(
            &handle,
            owner,
            uid,
            &serde_json::from_value(changed).unwrap()
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), original);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(save_under(&handle, owner, uid, &checkpoint).is_err());
    std::fs::remove_file(&path).unwrap();
    let outside = root.path().join("outside");
    std::fs::write(&outside, b"retained").unwrap();
    symlink(&outside, &path).unwrap();
    assert!(save_under(&handle, owner, uid, &checkpoint).is_err());
    assert_eq!(std::fs::read(&outside).unwrap(), b"retained");
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, vec![b' '; 4097]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(save_under(&handle, owner, uid, &checkpoint).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir_all(root.path().join("etc/ekubo-wallet/owners")).unwrap();
    std::fs::write(
        root.path().join("etc/ekubo-wallet/owners/1000.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    assert!(save_under(&handle, owner, uid, &checkpoint).is_err());
    assert!(!path.exists());
}
