use super::*;
use windows::{
    Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    },
    core::PCWSTR,
};

const SERVICE: &str = "S-1-5-80-1-2-3-4-5";

#[test]
fn native_profile_lock_excludes_competitors_and_prevents_lock_file_replacement() {
    let dir = Directory::new();
    let path = dir.0.join("service.lock");
    std::fs::write(&path, b"").unwrap();
    let parent = directory_handle(&dir.0);
    let first = open_relative(parent.as_handle(), "service.lock", StorageKind::File).unwrap();
    let guard = ProfileLock::acquire(first).unwrap();
    let second = open_relative(parent.as_handle(), "service.lock", StorageKind::File).unwrap();
    assert!(ProfileLock::acquire(second).is_err());
    assert!(std::fs::remove_file(&path).is_err());
    drop(guard);
    let next = open_relative(parent.as_handle(), "service.lock", StorageKind::File).unwrap();
    let guard = ProfileLock::acquire(next).unwrap();
    drop(guard);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn native_program_data_ancestors_pass_machine_directory_checks() {
    // Read only OS directory metadata. No Ekubo directory or credential is
    // opened, installed, or modified by this test.
    let trusted = crate::windows_service_config::machine_trustees().unwrap();
    let ancestors = program_data_ancestors(&trusted).unwrap();
    assert!(ancestors.len() >= 2);
}

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

fn attribute_writer(path: &std::path::Path) -> File {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
    };
    std::fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .open(path)
        .unwrap()
}

fn set_junction(handle: &File, target: &std::path::Path) -> windows::core::Result<()> {
    // REPARSE_DATA_BUFFER, MountPointReparseBuffer layout from MS-FSCC 2.1.2.2.
    // These fixed SDK constants avoid adding production features for a test.
    const SET_REPARSE_POINT: u32 = 0x0009_00a4;
    const MOUNT_POINT_TAG: u32 = 0xa000_0003;
    let target = target.to_str().unwrap();
    let substitute: Vec<u16> = format!(r"\??\{target}").encode_utf16().collect();
    let print: Vec<u16> = target.encode_utf16().collect();
    let substitute_bytes = u16::try_from(substitute.len() * 2).unwrap();
    let print_bytes = u16::try_from(print.len() * 2).unwrap();
    let data_length = 8 + substitute_bytes + 2 + print_bytes + 2;
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&MOUNT_POINT_TAG.to_le_bytes());
    for value in [
        data_length,
        0, // reserved
        0, // substitute offset
        substitute_bytes,
        substitute_bytes + 2, // print offset
        print_bytes,
    ] {
        buffer.extend_from_slice(&value.to_le_bytes());
    }
    for unit in substitute.into_iter().chain([0]).chain(print).chain([0]) {
        buffer.extend_from_slice(&unit.to_le_bytes());
    }
    let mut returned = 0;
    // SAFETY: the live synchronous handle and correctly sized input buffer
    // remain borrowed through this call. No output buffer is requested.
    unsafe {
        windows::Win32::System::IO::DeviceIoControl(
            HANDLE(handle.as_raw_handle()),
            SET_REPARSE_POINT,
            Some(buffer.as_ptr().cast()),
            u32::try_from(buffer.len()).unwrap(),
            None,
            0,
            Some(&raw mut returned),
            None,
        )
    }
}

#[test]
fn native_attribute_writer_cannot_redirect_a_directory_with_a_pinned_child() {
    use windows::Win32::Foundation::ERROR_DIR_NOT_EMPTY;
    let dir = Directory::new();
    let target = dir.0.join("target");
    let parent_path = dir.0.join("parent");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("state"), b"redirected state").unwrap();
    std::fs::create_dir(&parent_path).unwrap();
    let writer = attribute_writer(&parent_path);
    let fixture = directory_handle(&dir.0);
    let parent = open_relative(fixture.as_handle(), "parent", StorageKind::Directory).unwrap();
    // Attribute-only handles coexist with the production no-write/delete
    // sharing mode. A retained child must supply the nonempty invariant.
    std::fs::create_dir(parent_path.join("child")).unwrap();
    let child = open_relative(parent.as_handle(), "child", StorageKind::Directory).unwrap();
    assert!(std::fs::remove_dir(parent_path.join("child")).is_err());
    let error = set_junction(&writer, &target).unwrap_err();
    assert_eq!(error.code(), ERROR_DIR_NOT_EMPTY.to_hresult());
    read_security(parent.as_handle(), StorageKind::Directory).unwrap();

    drop(child);
    std::fs::remove_dir(parent_path.join("child")).unwrap();
    // Positive control: the same attribute-only handle and request can redirect
    // an empty parent, even while its production handle remains open.
    set_junction(&writer, &target).unwrap();
    // An attacker can change an ancestor before its child is pinned. Relative
    // lookup must not follow the new junction, even temporarily.
    assert!(open_relative(parent.as_handle(), "state", StorageKind::File).is_err());
    assert!(read_security(parent.as_handle(), StorageKind::Directory).is_err());
    drop(writer);
    drop(parent);
    std::fs::remove_dir(parent_path).unwrap();
}

fn validate_sddl(sddl: &str) -> Result<()> {
    validate_sddl_kind(sddl, StorageKind::File)
}

fn validate_sddl_kind(sddl: &str, kind: StorageKind) -> Result<()> {
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
    validate_security(&owner, &entries, SERVICE)?;
    if matches!(kind, StorageKind::Directory) {
        validate_directory_inheritance(&entries, SERVICE)?;
    }
    Ok(())
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

#[test]
fn native_directory_descriptor_requires_private_file_inheritance() {
    for flags in ["OI", "OICI", "OIIO"] {
        assert!(
            validate_sddl_kind(
                &format!("O:{SERVICE}D:P(A;{flags};FA;;;{SERVICE})(A;;FA;;;SY)"),
                StorageKind::Directory,
            )
            .is_ok()
        );
    }
    for flags in ["", "CI", "CIIO"] {
        assert!(
            validate_sddl_kind(
                &format!("O:{SERVICE}D:P(A;{flags};FA;;;{SERVICE})"),
                StorageKind::Directory,
            )
            .is_err()
        );
    }
    for trustee in ["BU", "WD", "CG"] {
        assert!(
            validate_sddl_kind(
                &format!("O:{SERVICE}D:P(A;OICI;FA;;;{SERVICE})(A;OIIO;FR;;;{trustee})"),
                StorageKind::Directory,
            )
            .is_err()
        );
    }
}

#[test]
fn native_volume_path_resolves_the_held_directory_after_rename() {
    let dir = Directory::new();
    let original = dir.0.join("original");
    std::fs::create_dir(&original).unwrap();
    std::fs::write(original.join("state"), b"pinned profile").unwrap();
    let handle = directory_handle(&original);
    std::fs::rename(&original, dir.0.join("moved")).unwrap();
    std::fs::create_dir(&original).unwrap();
    std::fs::write(original.join("state"), b"replacement").unwrap();
    let resolved = pinned_directory_path(handle.as_handle()).unwrap();
    assert_eq!(
        std::fs::read(resolved.join("state")).unwrap(),
        b"pinned profile"
    );
    assert!(resolved.to_str().unwrap().starts_with(r"\\?\Volume{"));
}
