use super::*;
use std::os::windows::fs::OpenOptionsExt as _;
use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

#[test]
fn native_move_requires_closed_profile_handles_and_never_replaces_a_destination() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("Source")).unwrap();
    std::fs::create_dir(root.path().join("Target")).unwrap();
    let original_path = root.path().join("Source/profile");
    let moved_path = root.path().join("Target/profile");
    let other_path = root.path().join("Source/other");
    std::fs::create_dir(&original_path).unwrap();
    std::fs::write(original_path.join("data"), b"original").unwrap();
    std::fs::create_dir(&other_path).unwrap();
    std::fs::write(other_path.join("data"), b"replacement").unwrap();
    std::fs::write(root.path().join("Source/file"), b"replacement").unwrap();
    std::fs::write(root.path().join("Target/existing"), b"retained").unwrap();
    let parent = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(root.path())
        .unwrap();
    let source = open_native_shared(
        Some(parent.as_handle()),
        "Source",
        StorageKind::Directory,
        false,
        FILE_SHARE_READ,
    )
    .unwrap();
    let target = open_native_shared(
        Some(parent.as_handle()),
        "Target",
        StorageKind::Directory,
        false,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
    .unwrap();
    let pinned = open_native_shared(
        Some(source.as_handle()),
        "profile",
        StorageKind::Directory,
        false,
        FILE_SHARE_READ,
    )
    .unwrap();
    let original_id = file_id(&pinned).unwrap();
    assert!(move_new(&source, "profile", &target, "profile").is_err());
    assert!(original_path.exists());
    assert!(!moved_path.exists());
    drop(pinned);
    move_new(&source, "profile", &target, "profile").unwrap();
    assert!(!original_path.exists());
    let moved = open_native_shared(
        Some(target.as_handle()),
        "profile",
        StorageKind::Directory,
        false,
        FILE_SHARE_READ,
    )
    .unwrap();
    assert_eq!(file_id(&moved).unwrap(), original_id);
    drop(moved);
    assert!(move_new(&source, "other", &target, "profile").is_err());
    assert!(move_new(&source, "file", &target, "existing").is_err());
    assert_eq!(
        std::fs::read(root.path().join("Target/existing")).unwrap(),
        b"retained"
    );
    assert_eq!(std::fs::read(moved_path.join("data")).unwrap(), b"original");
    assert_eq!(
        std::fs::read(other_path.join("data")).unwrap(),
        b"replacement"
    );
    assert!(move_new(&source, "profile", &target, "../outside").is_err());
}
