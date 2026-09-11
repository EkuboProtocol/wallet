use super::*;
use crate::custody_envelope::{CustodyBinding, DataCipher, WrappingKey};
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;

struct Fixture {
    path: PathBuf,
    parent: File,
    owner: String,
    cipher: DataCipher,
}

impl Fixture {
    fn new() -> Self {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_WRITE,
        };
        let path = std::env::temp_dir().join(format!("ekubo-key-write-{}", Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .open(&path)
            .unwrap();
        let owner = crate::windows_service_identity::current_process_identity()
            .unwrap()
            .user_sid()
            .to_owned();
        let binding = CustodyBinding::new(
            "windows:owner",
            "windows:service",
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .unwrap();
        let (cipher, _) = WrappingKey::from_material(zeroize::Zeroizing::new([0x11; 32]))
            .enroll(binding)
            .unwrap();
        Self {
            path,
            parent,
            owner,
            cipher,
        }
    }

    fn validate(&self, file: &File) -> Result<()> {
        let (owner, entries) = read_security(file.as_handle(), StorageKind::File)?;
        ensure!(owner == self.owner, "unexpected file owner");
        ensure!(entries.len() == 2, "unexpected inherited access entries");
        for entry in entries {
            match entry {
                crate::windows_security::AccessEntry::Allow {
                    sid, inherit_only, ..
                } => {
                    ensure!(
                        !inherit_only && (sid == self.owner || sid == "S-1-5-18"),
                        "untrusted access entry"
                    );
                }
                _ => anyhow::bail!("unexpected access entry"),
            }
        }
        Ok(())
    }

    fn publish(&self, bytes: &[u8; crate::custody_envelope::SEALED_KEY_BYTES]) -> Result<()> {
        publish(&self.parent, "key-database", &self.owner, bytes, |file| {
            self.validate(file)
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn native_encrypted_publication_is_private_and_never_replaces_an_existing_key() {
    let fixture = Fixture::new();
    // Hold the production directory access/sharing mode during publication,
    // including the kernel's relative target lookup for rename.
    let pinned = open_native(
        None,
        &format!("\\??\\{}", fixture.path.display()),
        StorageKind::Directory,
    )
    .unwrap();
    let sealed = fixture.cipher.seal_database_key(&[0x22; 32]).unwrap();
    publish(&pinned, "key-database", &fixture.owner, &sealed, |file| {
        fixture.validate(file)
    })
    .unwrap();
    let stored = std::fs::read(fixture.path.join("key-database")).unwrap();
    assert_eq!(stored, sealed);
    assert_eq!(
        *fixture.cipher.open_database_key(&stored).unwrap(),
        [0x22; 32]
    );
    assert!(
        fixture
            .publish(&fixture.cipher.seal_database_key(&[0x33; 32]).unwrap())
            .is_err()
    );
    assert_eq!(
        std::fs::read(fixture.path.join("key-database")).unwrap(),
        sealed
    );
    assert_eq!(std::fs::read_dir(&fixture.path).unwrap().count(), 1);
}

#[test]
fn native_creation_is_exclusive_and_failed_validation_discards_only_its_temporary_file() {
    let fixture = Fixture::new();
    let file = create(fixture.parent.as_handle(), "held", &fixture.owner).unwrap();
    fixture.validate(&file).unwrap();
    assert!(std::fs::read(fixture.path.join("held")).is_err());
    assert!(create(fixture.parent.as_handle(), "held", &fixture.owner).is_err());
    discard(&file).unwrap();
    drop(file);
    assert!(!fixture.path.join("held").exists());
    let sealed = fixture.cipher.seal_database_key(&[0x22; 32]).unwrap();
    assert!(
        publish(
            &fixture.parent,
            "key-database",
            &fixture.owner,
            &sealed,
            |_| { anyhow::bail!("synthetic validation rejection") }
        )
        .is_err()
    );
    assert_eq!(std::fs::read_dir(&fixture.path).unwrap().count(), 0);
    std::fs::write(fixture.path.join("key-database"), [0x33; 32]).unwrap();
    assert!(fixture.publish(&sealed).is_err());
    assert_eq!(
        std::fs::read(fixture.path.join("key-database")).unwrap(),
        [0x33; 32]
    );
    assert_eq!(std::fs::read_dir(&fixture.path).unwrap().count(), 1);
}

#[test]
fn native_publication_stays_under_the_open_parent_after_its_path_changes() {
    let fixture = Fixture::new();
    let moved = fixture.path.with_extension("moved");
    std::fs::rename(&fixture.path, &moved).unwrap();
    std::fs::create_dir(&fixture.path).unwrap();
    let sealed = fixture.cipher.seal_database_key(&[0x22; 32]).unwrap();
    fixture.publish(&sealed).unwrap();
    assert_eq!(std::fs::read_dir(&fixture.path).unwrap().count(), 0);
    assert_eq!(std::fs::read(moved.join("key-database")).unwrap(), sealed);
    // Release the pinned handle before fixture cleanup of the renamed directory.
    drop(fixture);
    std::fs::remove_dir_all(moved).unwrap();
}

#[test]
fn native_competing_writers_publish_one_complete_encrypted_key() {
    let fixture = Arc::new(Fixture::new());
    let first = fixture.cipher.seal_database_key(&[0x22; 32]).unwrap();
    let second = fixture.cipher.seal_database_key(&[0x33; 32]).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let competing = fixture.clone();
    let start = barrier.clone();
    let thread = std::thread::spawn(move || {
        start.wait();
        competing.publish(&second).is_ok()
    });
    barrier.wait();
    let won = fixture.publish(&first).is_ok();
    assert_ne!(won, thread.join().unwrap());
    let bytes = std::fs::read(fixture.path.join("key-database")).unwrap();
    assert!(bytes == first || bytes == second);
    assert_eq!(std::fs::read_dir(&fixture.path).unwrap().count(), 1);
}

#[test]
fn native_database_handles_allow_writers_but_pin_private_files_against_replacement() {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let fixture = Fixture::new();
    let pin = open_native(
        None,
        &format!("\\??\\{}", fixture.path.display()),
        StorageKind::Directory,
    )
    .unwrap();
    for name in ["wallet.db", "wallet.lock"] {
        let mut first = open_database_file(pin.as_handle(), name, &fixture.owner, |file| {
            fixture.validate(file)
        })
        .unwrap();
        first.write_all(b"synthetic database bytes").unwrap();
        let mut second = open_database_file(pin.as_handle(), name, &fixture.owner, |file| {
            fixture.validate(file)
        })
        .unwrap();
        let mut contents = Vec::new();
        second.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"synthetic database bytes");
        second.seek(SeekFrom::Start(0)).unwrap();
        second.write_all(b"S").unwrap();
        assert!(std::fs::remove_file(fixture.path.join(name)).is_err());
        assert!(std::fs::rename(fixture.path.join(name), fixture.path.join("moved")).is_err());
        drop(first);
        assert!(std::fs::remove_file(fixture.path.join(name)).is_err());
        drop(second);
        std::fs::remove_file(fixture.path.join(name)).unwrap();
    }
}

#[test]
fn native_database_open_does_not_truncate_repair_or_follow_linked_state() {
    let fixture = Fixture::new();
    let path = fixture.path.join("wallet.db");
    let mut file = open_database_file(
        fixture.parent.as_handle(),
        "wallet.db",
        &fixture.owner,
        |file| fixture.validate(file),
    )
    .unwrap();
    file.write_all(b"preserve existing database").unwrap();
    drop(file);
    assert!(
        open_database_file(
            fixture.parent.as_handle(),
            "wallet.db",
            &fixture.owner,
            |_| anyhow::bail!("refused existing descriptor")
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"preserve existing database");
    std::fs::hard_link(&path, fixture.path.join("alias")).unwrap();
    assert!(
        open_database_file(
            fixture.parent.as_handle(),
            "wallet.db",
            &fixture.owner,
            |file| fixture.validate(file)
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"preserve existing database");
}

#[test]
fn native_database_opener_rejects_credential_and_arbitrary_names() {
    let fixture = Fixture::new();
    for name in [
        "wrapping.key",
        "key-database",
        "service.lock",
        "../wallet.db",
        "wallet.db:stream",
    ] {
        assert!(
            open_database_file(
                fixture.parent.as_handle(),
                name,
                &fixture.owner,
                |_| panic!("invalid name reached handle validation")
            )
            .is_err()
        );
    }
    assert_eq!(std::fs::read_dir(&fixture.path).unwrap().count(), 0);
}
