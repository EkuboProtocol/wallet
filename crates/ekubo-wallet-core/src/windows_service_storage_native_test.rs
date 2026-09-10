use super::*;
use windows::{
    Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    },
    core::PCWSTR,
};

const SERVICE: &str = "S-1-5-80-1-2-3-4-5";

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("ekubo-relative-open-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn directory_handle(path: &std::path::Path) -> File {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_WRITE,
    };
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .open(path)
        .unwrap()
}

#[test]
fn native_child_open_stays_bound_to_the_directory_handle_after_rename() {
    use std::io::Read as _;
    let dir = Directory::new();
    let original = dir.0.join("original");
    std::fs::create_dir(&original).unwrap();
    std::fs::write(original.join("state"), b"original").unwrap();
    let parent = directory_handle(&original);
    std::fs::rename(&original, dir.0.join("moved")).unwrap();
    std::fs::create_dir(&original).unwrap();
    std::fs::write(original.join("state"), b"replacement").unwrap();
    let mut child = open_relative(parent.as_handle(), "state", StorageKind::File).unwrap();
    let mut contents = String::new();
    child.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "original");
    assert!(open_relative(parent.as_handle(), "missing", StorageKind::File).is_err());
    assert!(!dir.0.join("moved/missing").exists());
    assert!(open_relative(parent.as_handle(), "state", StorageKind::Directory).is_err());
}

#[test]
fn native_child_open_rejects_a_concurrent_writer() {
    let dir = Directory::new();
    let parent = directory_handle(&dir.0);
    let writer = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dir.0.join("state"))
        .unwrap();
    assert!(open_relative(parent.as_handle(), "state", StorageKind::File).is_err());
    drop(writer);
    assert!(open_relative(parent.as_handle(), "state", StorageKind::File).is_ok());
}

fn validate_sddl(sddl: &str) -> Result<()> {
    let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }?;
    let descriptor = Descriptor(descriptor);
    let (owner, entries) = unsafe { crate::windows_security::read_descriptor(descriptor.0) }?;
    validate_security(&owner, &entries, SERVICE)
}

#[test]
fn native_private_descriptor_rejects_public_read_and_unrestricted_acl() {
    assert!(validate_sddl(&format!("O:{SERVICE}D:P(A;;FA;;;{SERVICE})(A;;FA;;;SY)")).is_ok());
    assert!(validate_sddl(&format!("O:{SERVICE}D:(A;;FR;;;BU)")).is_err());
    assert!(validate_sddl(&format!("O:{SERVICE}D:(D;;FR;;;BU)(A;;FA;;;BU)")).is_err());
    assert!(validate_sddl(&format!("O:{SERVICE}D:NO_ACCESS_CONTROL")).is_err());
    assert!(validate_sddl("O:BUD:(A;;FA;;;BU)").is_err());
}

#[test]
fn native_file_checks_reject_desktop_owned_and_hard_linked_state() {
    let dir = std::env::temp_dir().join(format!("ekubo-storage-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("synthetic-state");
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let owned_error = validate_handle(file.as_handle(), SERVICE, StorageKind::File).unwrap_err();
    assert!(owned_error.to_string().contains("not owned by the service"));
    let link = dir.join("synthetic-link");
    std::fs::hard_link(&path, &link).unwrap();
    let link_error = validate_handle(file.as_handle(), SERVICE, StorageKind::File).unwrap_err();
    assert!(link_error.to_string().contains("multiple or no links"));
    drop(file);
    std::fs::remove_file(link).unwrap();
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(dir).unwrap();
}
