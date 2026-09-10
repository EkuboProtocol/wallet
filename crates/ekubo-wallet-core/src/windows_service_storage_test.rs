use super::*;
const SERVICE: &str = "S-1-5-80-1-2-3-4-5";

#[test]
fn child_names_cannot_select_paths_streams_or_dos_devices() {
    for name in [
        "",
        ".",
        "..",
        "../key",
        "a\\key",
        "C:key",
        "key:stream",
        "key.",
        "key ",
        "a\0b",
        "CON",
        "nul.key",
        "com1",
        "LPT9.db",
        "é",
    ] {
        assert!(validate_component(name).is_err(), "{name:?}");
    }
    assert!(validate_component(&"a".repeat(129)).is_err());
    for name in [
        "database.key",
        ".lock",
        "profile-01",
        "account_123",
        "com10",
        "a",
    ] {
        assert!(validate_component(name).is_ok(), "{name:?}");
    }
}

fn allow(sid: &str, mask: u32, inherit_only: bool) -> AccessEntry {
    AccessEntry::Allow {
        sid: sid.into(),
        mask,
        inherit_only,
    }
}

#[test]
fn private_state_rejects_readers_as_well_as_writers() {
    let trusted = [
        allow(SERVICE, u32::MAX, false),
        allow("S-1-5-18", u32::MAX, false),
    ];
    assert!(validate_security(SERVICE, &trusted, SERVICE).is_ok());
    for mask in [1, 2, 0x20000, 0x8000_0000, 0x4000_0000, u32::MAX] {
        assert!(
            validate_security(SERVICE, &[allow("S-1-5-32-545", mask, false)], SERVICE).is_err()
        );
    }
    assert!(validate_security("S-1-5-32-545", &trusted, SERVICE).is_err());
    assert!(validate_security(SERVICE, &trusted, "S-1-5-18").is_err());
}

#[test]
fn deny_does_not_mask_an_untrusted_allow() {
    assert!(
        validate_security(
            SERVICE,
            &[AccessEntry::Deny, allow("S-1-1-0", 1, false)],
            SERVICE
        )
        .is_err()
    );
    assert!(validate_security(SERVICE, &[AccessEntry::Unsupported], SERVICE).is_err());
    assert!(validate_security(SERVICE, &[allow("S-1-3-0", u32::MAX, true)], SERVICE).is_ok());
    assert!(validate_security(SERVICE, &[], SERVICE).is_ok());
}

#[test]
fn rejects_reparse_points_wrong_types_and_linked_files() {
    assert!(validate_metadata(0, 1, StorageKind::File).is_ok());
    assert!(validate_metadata(0x10, 1, StorageKind::Directory).is_ok());
    for attributes in [0x400, 0x410] {
        assert!(validate_metadata(attributes, 1, StorageKind::File).is_err());
        assert!(validate_metadata(attributes, 1, StorageKind::Directory).is_err());
    }
    for links in [0, 2, u32::MAX] {
        assert!(validate_metadata(0, links, StorageKind::File).is_err());
    }
    assert!(validate_metadata(0x10, 1, StorageKind::File).is_err());
    assert!(validate_metadata(0, 1, StorageKind::Directory).is_err());
}
