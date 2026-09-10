use super::*;
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
    assert_eq!(std::fs::read(&other).unwrap(), [0x11; KEY_BYTES]);
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
    };
    let moved = parent.path().join("moved");
    std::fs::rename(&original, &moved).unwrap();
    std::fs::create_dir(&original).unwrap();
    entry.set_secret(&[0x11; KEY_BYTES]).unwrap();
    assert_eq!(std::fs::read_dir(&original).unwrap().count(), 0);
    assert_eq!(
        std::fs::read(moved.join(&entry.name)).unwrap(),
        [0x11; KEY_BYTES]
    );
}
