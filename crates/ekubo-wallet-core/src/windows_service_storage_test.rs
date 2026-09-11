use super::*;
const SERVICE: &str = "S-1-5-80-1-2-3-4-5";

#[test]
fn machine_paths_reject_remote_relative_and_ambiguous_names() {
    assert_eq!(
        machine_path(r"c:\ProgramData").unwrap(),
        (r"C:\".into(), vec!["ProgramData"])
    );
    assert!(machine_path(r"D:\Données\ProgramData").is_ok());
    for path in [
        r"\\server\share",
        r"\\?\C:\ProgramData",
        r"C:ProgramData",
        r"C:/ProgramData",
        r"C:\a\..\b",
        r"C:\a\b:stream",
        r"C:\a.\b",
        r"C:\a \b",
        "C:\\a\0b",
        r"C:\\ProgramData",
    ] {
        assert!(machine_path(path).is_err(), "{path:?}");
    }
}

#[test]
fn machine_ancestors_allow_siblings_but_not_replacement_or_security_changes() {
    let trusted = vec!["S-1-5-18".to_owned(), "S-1-5-32-544".to_owned()];
    let reader = [allow("S-1-5-32-545", 0x0012_00a9, false)];
    assert!(validate_machine_security("S-1-5-18", &reader, &trusted, false).is_ok());
    let creator = [allow("S-1-5-32-545", 0x6, false)];
    assert!(validate_machine_security("S-1-5-18", &creator, &trusted, true).is_ok());
    assert!(validate_machine_security("S-1-5-18", &creator, &trusted, false).is_err());
    for mask in [0x10, 0x100, 0x116] {
        let shared_os_rights = [allow("S-1-5-32-545", mask, false)];
        assert!(validate_machine_security("S-1-5-18", &shared_os_rights, &trusted, true).is_ok());
        assert!(validate_machine_security("S-1-5-18", &shared_os_rights, &trusted, false).is_err());
    }
    for mask in [0x40, 0x10000, 0x40000, 0x80000, 0x4000_0000, 0x1000_0000] {
        assert!(
            validate_machine_security(
                "S-1-5-18",
                &[allow("S-1-5-32-545", mask, false)],
                &trusted,
                true
            )
            .is_err()
        );
    }
    assert!(validate_machine_security("S-1-5-32-545", &reader, &trusted, true).is_err());
    assert!(
        validate_machine_security("S-1-5-18", &[AccessEntry::Unsupported], &trusted, true).is_err()
    );
}

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
        object_inherit: false,
    }
}

#[test]
fn private_state_rejects_readers_as_well_as_writers() {
    let trusted = [
        allow(SERVICE, u32::MAX, false),
        allow("S-1-5-18", u32::MAX, false),
    ];
    assert!(validate_security(SERVICE, &trusted, SERVICE).is_ok());
    for mask in [
        1,
        2,
        0x10,
        0x100,
        0x116,
        0x20000,
        0x8000_0000,
        0x4000_0000,
        u32::MAX,
    ] {
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

#[test]
fn private_state_rejects_untrusted_grants_even_when_only_inherited() {
    for sid in ["S-1-1-0", "S-1-5-32-545", "S-1-3-1"] {
        for object_inherit in [false, true] {
            let grant = AccessEntry::Allow {
                sid: sid.into(),
                mask: 1,
                inherit_only: true,
                object_inherit,
            };
            assert!(validate_security(SERVICE, &[grant], SERVICE).is_err());
        }
    }
    // CREATOR OWNER is safe only as a placeholder on children created inside
    // this already-private directory, never as an effective parent grant.
    assert!(validate_security(SERVICE, &[allow("S-1-3-0", 1, false)], SERVICE).is_err());
}

#[test]
fn directory_requires_full_service_grant_inherited_by_files() {
    assert!(validate_directory_inheritance(&[], SERVICE).is_err());
    for (sid, mask, object_inherit, valid) in [
        (SERVICE, 0x001f_01ff, true, true),
        (SERVICE, 0x1000_0000, true, true),
        (SERVICE, 0x001f_01ff, false, false),
        (SERVICE, 0x0012_0089, true, false),
        ("S-1-5-18", 0x001f_01ff, true, false),
        ("S-1-3-0", 0x001f_01ff, true, false),
    ] {
        let grant = AccessEntry::Allow {
            sid: sid.into(),
            mask,
            inherit_only: true,
            object_inherit,
        };
        assert_eq!(
            validate_directory_inheritance(&[grant], SERVICE).is_ok(),
            valid
        );
    }
}
