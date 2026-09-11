use super::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn native_pipe_authenticates_its_object_and_client_without_retaining_impersonation() {
    let sid = crate::windows_service_identity::current_process_identity()
        .unwrap()
        .user_sid()
        .to_owned();
    let pipe_name = name(uuid::Uuid::new_v4()).unwrap();
    let mut server = create(&pipe_name, &sid, &sid, true).unwrap();
    let mut client = open(&pipe_name, &sid, &sid).unwrap();
    server.connect().await.unwrap();
    client.write_all(b"hello").await.unwrap();
    let mut bytes = [0u8; 5];
    server.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, *b"hello");
    assert_eq!(client_sid(HANDLE(server.as_raw_handle())).unwrap(), sid);
    assert_eq!(
        crate::windows_service_identity::current_process_identity()
            .unwrap()
            .user_sid(),
        sid
    );
    server.write_all(b"reply").await.unwrap();
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, *b"reply");
}

#[tokio::test]
async fn native_pipe_refuses_name_squatting_and_wrong_service_ownership() {
    let sid = crate::windows_service_identity::current_process_identity()
        .unwrap()
        .user_sid()
        .to_owned();
    let pipe_name = name(uuid::Uuid::new_v4()).unwrap();
    let _server = create(&pipe_name, &sid, &sid, true).unwrap();
    assert!(create(&pipe_name, &sid, &sid, true).is_err());
    assert!(open(&pipe_name, "S-1-5-80-1-2-3-4-5", &sid).is_err());
}

#[test]
fn native_descriptor_keeps_desktop_data_access_separate_from_server_creation() {
    let service = "S-1-5-80-1-2-3-4-5";
    let desktop = "S-1-5-21-1-2-3-1001";
    let descriptor = descriptor(service, desktop).unwrap();
    // SAFETY: the descriptor guard retains the complete OS-allocated buffer.
    let (owner, entries) =
        unsafe { crate::windows_security::read_descriptor(descriptor.0) }.unwrap();
    validate_security(&owner, &entries, service, desktop).unwrap();
    let grants: Vec<_> = entries
        .iter()
        .filter_map(|entry| match entry {
            crate::windows_security::AccessEntry::Allow { sid, mask, .. } if sid == desktop => {
                Some(*mask)
            }
            _ => None,
        })
        .collect();
    assert_eq!(grants.len(), 1);
    assert_eq!(
        grants[0] & windows::Win32::Storage::FileSystem::FILE_CREATE_PIPE_INSTANCE.0,
        0
    );
    assert_eq!(grants[0] & 3, 3);
}
