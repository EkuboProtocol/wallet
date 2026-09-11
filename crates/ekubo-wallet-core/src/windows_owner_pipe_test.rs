use super::*;
const SERVICE: &str = "S-1-5-80-1-2-3-4-5";
const DESKTOP: &str = "S-1-5-21-1-2-3-1001";

fn allow(sid: &str, mask: u32) -> AccessEntry {
    AccessEntry::Allow {
        sid: sid.into(),
        mask,
        inherit_only: false,
        object_inherit: false,
    }
}

#[test]
fn desktop_pipe_rights_cannot_create_servers_or_change_security() {
    assert!(
        validate_security(
            SERVICE,
            &[allow(SERVICE, u32::MAX), allow(DESKTOP, CLIENT_ACCESS)],
            SERVICE,
            DESKTOP
        )
        .is_ok()
    );
    for mask in [
        4,
        0x10,  // FILE_WRITE_EA
        0x100, // FILE_WRITE_ATTRIBUTES
        0x4000_0000,
        0x1000_0000,
        0x40000,
        0x80000,
        0x10000,
        0x0012_0116,
    ] {
        assert!(
            validate_security(
                SERVICE,
                &[allow(DESKTOP, CLIENT_ACCESS | mask)],
                SERVICE,
                DESKTOP
            )
            .is_err()
        );
    }
    assert!(validate_security(DESKTOP, &[allow(SERVICE, u32::MAX)], SERVICE, DESKTOP).is_err());
    assert!(validate_security(SERVICE, &[allow("S-1-1-0", 1)], SERVICE, DESKTOP).is_err());
    assert!(validate_security(SERVICE, &[AccessEntry::Unsupported], SERVICE, DESKTOP).is_err());
}

#[test]
fn pipe_names_use_only_the_protected_non_nil_profile() {
    let id = uuid::Uuid::new_v4();
    assert_eq!(
        name(id).unwrap(),
        format!(r"\\.\pipe\EkuboWallet.Owner.{}", id.simple())
    );
    assert!(name(uuid::Uuid::nil()).is_err());
}
