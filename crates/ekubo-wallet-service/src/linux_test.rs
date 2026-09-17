use super::*;
use tokio::net::UnixStream;

#[tokio::test]
async fn peer_identity_is_taken_from_the_kernel() {
    let (client, server) = UnixStream::pair().unwrap();
    let actual = rustix::process::geteuid().as_raw();
    assert!(peer_is_owner(&server, actual));
    assert!(!peer_is_owner(&server, actual.wrapping_add(1)));
    drop(client);
}

#[tokio::test]
async fn socket_is_reachable_through_its_installed_path() {
    let directory = tempfile::tempdir().unwrap();
    let handle = File::open(directory.path()).unwrap();
    let listener = bind_listener(&handle).unwrap();
    let path = directory.path().join("mcp.sock");
    let client = UnixStream::connect(&path).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    assert!(peer_is_owner(&server, rustix::process::geteuid().as_raw()));
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o666);
    drop(client);
}

#[tokio::test]
async fn stale_path_cleanup_cannot_delete_a_regular_file_or_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let handle = File::open(directory.path()).unwrap();
    let path = directory.path().join("mcp.sock");
    std::fs::write(&path, b"unrelated").unwrap();
    assert!(bind_listener(&handle).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"unrelated");
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("missing", &path).unwrap();
    assert!(bind_listener(&handle).is_err());
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
