use super::*;
use std::os::unix::fs::{PermissionsExt as _, symlink};

#[test]
fn profile_move_never_replaces_even_an_empty_directory_or_dangling_link() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let target = root.path().join("target");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&target).unwrap();
    let source_parent = File::open(&source).unwrap();
    let target_parent = File::open(&target).unwrap();
    std::fs::create_dir(source.join("profile")).unwrap();
    std::fs::write(source.join("profile/data"), b"original").unwrap();
    std::fs::create_dir(target.join("profile")).unwrap();
    assert!(move_new(&source_parent, "profile", &target_parent, "profile").is_err());
    std::fs::remove_dir(target.join("profile")).unwrap();
    symlink(root.path().join("missing"), target.join("profile")).unwrap();
    assert!(move_new(&source_parent, "profile", &target_parent, "profile").is_err());
    std::fs::remove_file(target.join("profile")).unwrap();
    std::fs::write(target.join("profile"), b"retained").unwrap();
    assert!(move_new(&source_parent, "profile", &target_parent, "profile").is_err());
    assert_eq!(std::fs::read(target.join("profile")).unwrap(), b"retained");
    std::fs::remove_file(target.join("profile")).unwrap();
    move_new(&source_parent, "profile", &target_parent, "profile").unwrap();
    assert!(!source.join("profile").exists());
    assert_eq!(
        std::fs::read(target.join("profile/data")).unwrap(),
        b"original"
    );
}

#[test]
fn an_opposite_location_must_be_absent_not_a_file_directory_or_dangling_link() {
    let root = tempfile::tempdir().unwrap();
    let handle = File::open(root.path()).unwrap();
    let path = root.path().join("profile");
    assert!(require_absent(&handle, "profile").is_ok());
    std::fs::write(&path, b"unrelated").unwrap();
    assert!(require_absent(&handle, "profile").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"unrelated");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(require_absent(&handle, "profile").is_err());
    std::fs::remove_dir(&path).unwrap();
    symlink(root.path().join("missing"), &path).unwrap();
    assert!(require_absent(&handle, "profile").is_err());
}

#[test]
fn cutover_identity_blocks_fallback_and_pending_bootstrap_until_matching_activation() {
    let root = tempfile::tempdir().unwrap();
    let wallet = root.path().join("etc/ekubo-wallet");
    let pending = wallet.join("pending");
    std::fs::create_dir_all(&pending).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let configured = OwnerConfiguration {
        owner_uid: 1000,
        service_uid: 2000,
        profile_id: uuid::Uuid::new_v4(),
    };
    let bytes = serde_json::to_vec(&configured).unwrap();
    std::fs::write(pending.join("1000.json"), &bytes).unwrap();
    let handle = File::open(root.path()).unwrap();
    assert!(
        find_installation_configuration(&handle, 1000, uid)
            .unwrap()
            .is_none()
    );
    record_cutover_under(&handle, &configured, uid).unwrap();
    record_cutover_under(&handle, &configured, uid).unwrap();
    let marker = wallet.join("committed/1000.json");
    assert_eq!(std::fs::read(&marker).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(&marker).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert!(find_installation_configuration(&handle, 1000, uid).is_err());
    assert!(super::super::require_uncommitted(&handle, 1000, uid).is_err());
    assert!(open_pending_storage(&handle, 1000, uid).is_err());
    assert!(pending_configuration(&handle, 1000, uid).unwrap() == configured);
    let changed = OwnerConfiguration {
        profile_id: uuid::Uuid::new_v4(),
        ..configured.clone()
    };
    std::fs::write(
        pending.join("1000.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(record_cutover_under(&handle, &changed, uid).is_err());
    assert!(pending_configuration(&handle, 1000, uid).is_err());
    assert_eq!(std::fs::read(&marker).unwrap(), bytes);
    std::fs::create_dir(wallet.join("owners")).unwrap();
    std::fs::write(
        wallet.join("owners/1000.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(find_installation_configuration(&handle, 1000, uid).is_err());
    std::fs::write(wallet.join("owners/1000.json"), &bytes).unwrap();
    assert!(find_installation_configuration(&handle, 1000, uid).unwrap() == Some(configured));
    std::fs::write(&marker, b"invalid").unwrap();
    assert!(find_installation_configuration(&handle, 1000, uid).is_err());
}

#[test]
fn cutover_publication_rejects_links_and_unsafe_directories_without_repair() {
    let root = tempfile::tempdir().unwrap();
    let wallet = root.path().join("etc/ekubo-wallet");
    std::fs::create_dir_all(wallet.join("pending")).unwrap();
    std::fs::create_dir(wallet.join("committed")).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let configured = OwnerConfiguration {
        owner_uid: 1000,
        service_uid: 2000,
        profile_id: uuid::Uuid::new_v4(),
    };
    let bytes = serde_json::to_vec(&configured).unwrap();
    std::fs::write(wallet.join("pending/1000.json"), &bytes).unwrap();
    let handle = File::open(root.path()).unwrap();
    let outside = root.path().join("outside");
    std::fs::write(&outside, &bytes).unwrap();
    let marker = wallet.join("committed/1000.json");
    symlink(&outside, &marker).unwrap();
    assert!(record_cutover_under(&handle, &configured, uid).is_err());
    std::fs::remove_file(&marker).unwrap();
    std::fs::hard_link(&outside, &marker).unwrap();
    assert!(record_cutover_under(&handle, &configured, uid).is_err());
    std::fs::remove_file(&marker).unwrap();
    std::fs::set_permissions(
        wallet.join("committed"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(record_cutover_under(&handle, &configured, uid).is_err());
    assert!(!marker.exists());
    assert_eq!(std::fs::read(&outside).unwrap(), bytes);
}

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

#[test]
fn intent_is_private_immutable_and_rejects_a_checkpoint_for_another_attempt() {
    let root = tempfile::tempdir().unwrap();
    let pending = root.path().join("etc/ekubo-wallet/pending");
    std::fs::create_dir_all(&pending).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let destination = Destination {
        owner: "linux:uid:1000".into(),
        service: "linux:uid:2000".into(),
        profile: uuid::Uuid::new_v4(),
    };
    std::fs::write(
        pending.join("1000.json"),
        serde_json::to_vec(&serde_json::json!({
            "owner_uid":1000,"service_uid":2000,"profile_id":destination.profile,
        }))
        .unwrap(),
    )
    .unwrap();
    let intent = TransferIntent {
        version: 1,
        destination: destination.clone(),
        session: uuid::Uuid::new_v4(),
        source: crate::database_staging::DatabaseTransfer {
            bytes: 1024,
            sha256: [0; 32],
        },
    };
    let handle = File::open(root.path()).unwrap();
    save_intent_under(&handle, 1000, uid, &intent).unwrap();
    save_intent_under(&handle, 1000, uid, &intent).unwrap();
    let path = pending.join("1000.intent.json");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let before = std::fs::read(&path).unwrap();
    let mut changed = intent.clone();
    changed.session = uuid::Uuid::new_v4();
    assert!(save_intent_under(&handle, 1000, uid, &changed).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let mut checkpoint = RecoveryCheckpoint {
        version: 1,
        destination,
        session: changed.session,
        stage: uuid::Uuid::new_v4(),
        source: intent.source.clone(),
        source_fingerprint: [0; 32],
        canonical: intent.source.clone(),
        relay_digest: [0; 32],
    };
    assert!(save_under(&handle, 1000, uid, &checkpoint).is_err());
    assert!(!pending.join("1000.checkpoint.json").exists());
    checkpoint.session = intent.session;
    save_under(&handle, 1000, uid, &checkpoint).unwrap();
    let (parent, destination) = journal_parent(&handle, 1000, uid).unwrap();
    assert_eq!(
        read_intent(&parent, 1000, uid, &destination)
            .unwrap()
            .unwrap()
            .journal_bytes(&destination)
            .unwrap(),
        before
    );
    std::fs::write(&path, changed.journal_bytes(&destination).unwrap()).unwrap();
    assert!(read(&parent, 1000, uid, &destination).is_err());
    std::fs::write(&path, &before).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(save_under(&handle, 1000, uid, &checkpoint).is_err());
}

#[test]
fn installer_lease_excludes_other_processes_and_preserves_its_rendezvous_file() {
    let root = tempfile::tempdir().unwrap();
    let pending = root.path().join("etc/ekubo-wallet/pending");
    std::fs::create_dir_all(&pending).unwrap();
    let handle = File::open(root.path()).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let path = pending.join("installer.lock");
    let lease = acquire_under(&handle, uid).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(acquire_under(&handle, uid).is_err());
    let probe = |expected| {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "service_profile_lock::tests::child_probe",
                "--ignored",
            ])
            .env("EKUBO_TEST_SERVICE_LOCK_PATH", &path)
            .env("EKUBO_TEST_SERVICE_LOCK_EXPECTED", expected)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    };
    probe("locked");
    drop(lease);
    assert!(path.exists());
    probe("available");
    drop(acquire_under(&handle, uid).unwrap());
    assert!(std::fs::read(path).unwrap().is_empty());
}

#[test]
fn installer_lease_rejects_unsafe_objects_without_repairing_them() {
    let root = tempfile::tempdir().unwrap();
    let pending = root.path().join("etc/ekubo-wallet/pending");
    std::fs::create_dir_all(&pending).unwrap();
    let handle = File::open(root.path()).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let path = pending.join("installer.lock");
    std::fs::write(&path, b"not a PID lease").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(acquire_under(&handle, uid).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"not a PID lease");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(acquire_under(&handle, uid).is_err());
    std::fs::remove_file(&path).unwrap();
    let outside = root.path().join("outside");
    std::fs::write(&outside, b"").unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&outside, &path).unwrap();
    assert!(acquire_under(&handle, uid).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::hard_link(&outside, &path).unwrap();
    assert!(acquire_under(&handle, uid).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(acquire_under(&handle, uid).is_err());
    assert!(!path.exists());
}
