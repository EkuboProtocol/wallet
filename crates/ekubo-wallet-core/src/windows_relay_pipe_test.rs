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
