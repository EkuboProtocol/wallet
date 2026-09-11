use super::*;

fn grant(sid: &str) -> AccessEntry {
    AccessEntry::Allow {
        sid: sid.into(),
        mask: 0x001f_01ff,
        inherit_only: false,
        object_inherit: false,
    }
}

#[test]
fn checkpoint_policy_rejects_desktop_and_service_access_even_with_admin_owner() {
    let allowed = [grant(ADMINISTRATORS), grant("S-1-5-18")];
    validate_journal_entries(ADMINISTRATORS, &allowed).unwrap();
    for untrusted in ["S-1-1-0", "S-1-5-21-1-2-3-1000", "S-1-5-80-1-2-3-4-5"] {
        assert!(validate_journal_entries(untrusted, &allowed).is_err());
        assert!(
            validate_journal_entries(ADMINISTRATORS, &[grant(ADMINISTRATORS), grant(untrusted)])
                .is_err()
        );
    }
    assert!(validate_journal_entries(ADMINISTRATORS, &[AccessEntry::Unsupported]).is_err());
}
