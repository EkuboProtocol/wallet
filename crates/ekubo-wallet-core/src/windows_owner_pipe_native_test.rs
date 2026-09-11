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

#[tokio::test]
async fn native_client_waits_for_a_free_instance_before_any_request_is_sent() {
    let sid = crate::windows_service_identity::current_process_identity()
        .unwrap()
        .user_sid()
        .to_owned();
    let pipe_name = name(uuid::Uuid::new_v4()).unwrap();
    let first = create(&pipe_name, &sid, &sid, true).unwrap();
    let _occupied = open(&pipe_name, &sid, &sid).unwrap();
    first.connect().await.unwrap();
    let mut waiting = Box::pin(open_available(&pipe_name, &sid, &sid));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), waiting.as_mut())
            .await
            .is_err()
    );
    let next = create(&pipe_name, &sid, &sid, false).unwrap();
    let _client = waiting.await.unwrap();
    next.connect().await.unwrap();
}

#[tokio::test]
async fn native_installer_pipe_checks_privilege_and_runs_the_shared_io_bridge() {
    use std::io::{Read as _, Write as _};
    let allowed = crate::windows_service_identity::verify_installer_process().is_ok();
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        assert!(
            allowed,
            "GitHub Windows runner must exercise the privileged success path"
        );
    }
    let identity = crate::windows_service_identity::current_process_identity().unwrap();
    let service = identity.user_sid();
    let pipe_name = format!(
        r"\\.\pipe\EkuboWallet.Provision.{}",
        uuid::Uuid::new_v4().simple()
    );
    let mut server = create(&pipe_name, service, "S-1-5-32-544", true).unwrap();
    let mut client = open(&pipe_name, service, "S-1-5-32-544").unwrap();
    server.connect().await.unwrap();
    client
        .write_all(crate::windows_provisioning_pipe::PREFACE)
        .await
        .unwrap();
    let mut preface = [0; 8];
    server.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, crate::windows_provisioning_pipe::PREFACE);
    assert_eq!(authenticate_installer_client(&server).is_ok(), allowed);
    assert_eq!(
        crate::windows_service_identity::current_process_identity()
            .unwrap()
            .user_sid(),
        service
    );
    if !allowed {
        return;
    }
    let (mut stream, _cancel) =
        crate::provisioning_io::bridge(server, std::time::Duration::from_secs(10));
    let worker = tokio::task::spawn_blocking(move || {
        let mut bytes = [0; 3];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"dbx");
        stream.write_all(b"ack").unwrap();
    });
    client.write_all(b"dbx").await.unwrap();
    let mut reply = [0; 3];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ack");
    worker.await.unwrap();
}

#[test]
fn native_installer_descriptor_does_not_grant_admin_server_creation() {
    let descriptor = descriptor("S-1-5-80-1-2-3-4-5", "S-1-5-32-544").unwrap();
    // SAFETY: the guard retains the complete native descriptor allocation.
    let (owner, entries) =
        unsafe { crate::windows_security::read_descriptor(descriptor.0) }.unwrap();
    validate_security(&owner, &entries, "S-1-5-80-1-2-3-4-5", "S-1-5-32-544").unwrap();
    let allowed: Vec<_> = entries
        .iter()
        .filter_map(|entry| match entry {
            crate::windows_security::AccessEntry::Allow { sid, mask, .. }
                if sid == "S-1-5-32-544" =>
            {
                Some(*mask)
            }
            _ => None,
        })
        .collect();
    assert_eq!(allowed, vec![CLIENT_ACCESS]);
    assert_eq!(
        allowed[0] & windows::Win32::Storage::FileSystem::FILE_CREATE_PIPE_INSTANCE.0,
        0
    );
}

#[tokio::test]
async fn cancellation_wakes_a_blocking_read_on_a_native_windows_pipe() {
    use std::io::Read as _;
    let identity = crate::windows_service_identity::current_process_identity().unwrap();
    let sid = identity.user_sid();
    let pipe_name = name(uuid::Uuid::new_v4()).unwrap();
    let server = create(&pipe_name, sid, sid, true).unwrap();
    let _client = open(&pipe_name, sid, sid).unwrap();
    server.connect().await.unwrap();
    let (mut stream, cancel) =
        crate::provisioning_io::bridge(server, std::time::Duration::from_secs(60));
    let (started, ready) = tokio::sync::oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || {
        started.send(()).unwrap();
        stream.read_exact(&mut [0; 1]).unwrap_err().kind()
    });
    ready.await.unwrap();
    drop(cancel);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap(),
        std::io::ErrorKind::ConnectionAborted
    );
}
