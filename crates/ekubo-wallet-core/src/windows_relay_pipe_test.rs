use super::*;

#[test]
fn relay_endpoint_names_are_local_fixed_and_cannot_accept_paths() {
    assert!(name(uuid::Uuid::nil()).is_err());
    let endpoint = uuid::Uuid::from_u128(1);
    assert_eq!(
        name(endpoint).unwrap(),
        r"\\.\pipe\EkuboWallet.InstallerRelay.00000000000000000000000000000001"
    );
    assert_ne!(
        name(endpoint).unwrap(),
        name(uuid::Uuid::from_u128(2)).unwrap()
    );
}

#[test]
fn source_and_relay_protocols_cannot_share_a_name_or_preface() {
    let endpoint = uuid::Uuid::from_u128(1);
    assert!(source_name(uuid::Uuid::nil()).is_err());
    assert_eq!(
        source_name(endpoint).unwrap(),
        r"\\.\pipe\EkuboWallet.InstallerSource.00000000000000000000000000000001"
    );
    assert_ne!(source_name(endpoint).unwrap(), name(endpoint).unwrap());
    assert_ne!(SOURCE_PREFACE, PREFACE);
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn source_listener_rejects_a_relay_preface_before_token_admission() {
    use tokio::io::AsyncWriteExt as _;
    let listener = OwnerRelayListener::bind_source().unwrap();
    let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(source_name(listener.endpoint_id()).unwrap())
        .unwrap();
    let connected = listener.accept().await.unwrap();
    let _reserved = connected.reserve_next().unwrap();
    client.write_all(PREFACE).await.unwrap();
    assert!(connected.authenticate().await.is_err());
}
