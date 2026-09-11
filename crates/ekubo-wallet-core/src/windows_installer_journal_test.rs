use super::*;

fn grant(sid: &str) -> AccessEntry {
    AccessEntry::Allow {
        sid: sid.into(),
        mask: 0x001f_01ff,
        inherit_only: false,
        object_inherit: false,
    }
}

#[test]
fn checkpoint_policy_rejects_desktop_and_service_access_even_with_admin_owner() {
    let allowed = [grant(ADMINISTRATORS), grant("S-1-5-18")];
    validate_journal_entries(ADMINISTRATORS, &allowed).unwrap();
    for untrusted in ["S-1-1-0", "S-1-5-21-1-2-3-1000", "S-1-5-80-1-2-3-4-5"] {
        assert!(validate_journal_entries(untrusted, &allowed).is_err());
        assert!(
            validate_journal_entries(ADMINISTRATORS, &[grant(ADMINISTRATORS), grant(untrusted)])
                .is_err()
        );
    }
    assert!(validate_journal_entries(ADMINISTRATORS, &[AccessEntry::Unsupported]).is_err());
}

#[test]
fn native_installer_lease_excludes_competitors_and_denies_replacement() {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    // Creating the production BA-owned lock requires elevated installer identity.
    // Disposable Windows CI supplies it; ordinary developer test runs do not.
    if crate::windows_service_identity::verify_installer_process().is_err() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let parent = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(directory.path())
        .unwrap();
    let path = directory.path().join("installer.lock");
    let lease = lock_parent(&parent).unwrap();
    assert!(lock_parent(&parent).is_err());
    assert!(std::fs::remove_file(&path).is_err());
    drop(lease);
    assert!(path.exists());
    drop(lock_parent(&parent).unwrap());
    assert!(std::fs::read(&path).unwrap().is_empty());
    std::fs::write(&path, b"not a PID lease").unwrap();
    assert!(lock_parent(&parent).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"not a PID lease");
}
