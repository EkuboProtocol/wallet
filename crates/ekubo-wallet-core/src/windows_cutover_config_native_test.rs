use super::super::tests::RegistryFixture;
use super::*;

#[test]
fn committed_identity_is_immutable_and_publication_never_replaces_a_leaf() {
    // BA-owned creation requires an elevated token. CI's native Windows tests
    // run elevated; an ordinary local developer cannot provision this ACL.
    if crate::windows_service_identity::verify_installer_process().is_err() {
        eprintln!("cutover registry publication requires an elevated test process");
        return;
    }
    let registry = RegistryFixture::new();
    drop(registry.create(r"SOFTWARE\EkuboWallet"));
    let configured = super::super::super::Configuration {
        owner_sid: "S-1-5-21-1-2-3-1001".into(),
        service_sid: "S-1-5-80-1-2-3-4-5".into(),
        profile_id: uuid::Uuid::new_v4(),
    };
    record_under(registry.root.0, &configured, &registry.trusted).unwrap();
    record_under(registry.root.0, &configured, &registry.trusted).unwrap();
    let parent = registry.create(r"SOFTWARE\EkuboWallet\Committed");
    let leaf = open_component(parent.0, &configured.owner_sid, &registry.trusted)
        .unwrap()
        .unwrap();
    let original = read_profile_value(leaf.0).unwrap();
    let changed = super::super::super::Configuration {
        profile_id: uuid::Uuid::new_v4(),
        ..configured
    };
    assert!(record_under(registry.root.0, &changed, &registry.trusted).is_err());
    assert!(
        publish(&parent, &changed, &registry.trusted).is_err(),
        "native rename must not replace the final leaf"
    );
    assert_eq!(read_profile_value(leaf.0).unwrap(), original);
}
