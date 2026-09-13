use super::*;

#[test]
fn relay_endpoint_names_are_local_fixed_and_cannot_accept_paths() {
    assert!(name(uuid::Uuid::nil()).is_err());
    let endpoint = uuid::Uuid::from_u128(1);
    assert_eq!(
        name(endpoint).unwrap(),
        r"\\.\pipe\EkuboWalletV2.InstallerRelay.00000000000000000000000000000001"
    );
    assert_ne!(
        name(endpoint).unwrap(),
        name(uuid::Uuid::from_u128(2)).unwrap()
    );
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn relay_listener_rejects_an_obsolete_source_preface_before_token_admission() {
    use tokio::io::AsyncWriteExt as _;
    let listener = OwnerRelayListener::bind().unwrap();
    let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(name(listener.endpoint_id()).unwrap())
        .unwrap();
    let connected = listener.accept().await.unwrap();
    let _reserved = connected.reserve_next().unwrap();
    client.write_all(b"EKUBOSC1").await.unwrap();
    assert!(connected.authenticate().await.is_err());
}
