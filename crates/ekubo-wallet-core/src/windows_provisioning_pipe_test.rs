use super::*;

#[test]
fn provisioning_names_are_profile_bound_and_separate_from_owner_dispatch() {
    assert!(name(uuid::Uuid::nil()).is_err());
    let first = uuid::Uuid::new_v4();
    let second = uuid::Uuid::new_v4();
    assert_eq!(
        name(first).unwrap(),
        format!(r"\\.\pipe\EkuboWallet.Provision.{}", first.simple())
    );
    assert_ne!(name(first).unwrap(), name(second).unwrap());
    assert!(!name(first).unwrap().contains(".Owner."));
}
