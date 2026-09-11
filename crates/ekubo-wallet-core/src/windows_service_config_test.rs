use super::*;

const OWNER: &str = "S-1-5-21-1-2-3-1001";
const SERVICE: &str = "S-1-5-80-1-2-3-4-5";

fn config() -> serde_json::Value {
    serde_json::json!({"owner_sid": OWNER, "service_sid": SERVICE, "profile_id": "b74236a2-bc21-4c35-8424-c9846c069d51"})
}

#[test]
fn configuration_binds_owner_service_and_fixed_name() {
    let identity = decode(&serde_json::to_vec(&config()).unwrap(), OWNER).unwrap();
    assert_eq!(identity.owner_sid(), OWNER);
    assert_eq!(identity.service_sid(), SERVICE);
    assert!(!identity.profile_id().is_nil());
    assert_eq!(
        identity.service_name(),
        "EkuboWallet-b74236a2bc214c358424c9846c069d51"
    );
}

#[test]
fn configuration_rejects_unbound_or_ambiguous_metadata() {
    for (field, value) in [
        ("owner_sid", "S-1-5-21-9-8-7-1001"),
        ("service_sid", OWNER),
        ("profile_id", "00000000-0000-0000-0000-000000000000"),
        ("storage_path", "C:\\wallet"),
    ] {
        let mut input = config();
        input[field] = value.into();
        assert!(decode(&serde_json::to_vec(&input).unwrap(), OWNER).is_err());
    }
    assert!(decode(&vec![b' '; MAX_CONFIG_BYTES + 1], OWNER).is_err());
    for owner in [
        "S-1-5-21\\other",
        "S-1-5-21/other",
        "S-1-5-21\0",
        "S-1-5-18",
        SERVICE,
    ] {
        assert!(validate_owner_component(owner).is_err());
    }
}

fn allow(mask: u32, inherit_only: bool) -> RegistryAce {
    RegistryAce::Allow {
        sid: OWNER.into(),
        mask,
        inherit_only,
        object_inherit: false,
    }
}

#[test]
fn registry_requires_trusted_owner_and_restricted_dacl() {
    let trusted = vec!["S-1-5-18".to_owned()];
    assert!(validate_registry_security(OWNER, Some(&[]), &trusted).is_err());
    assert!(validate_registry_security(&trusted[0], None, &trusted).is_err());
    assert!(validate_registry_security(&trusted[0], Some(&[]), &trusted).is_ok());
    assert!(
        validate_registry_security(&trusted[0], Some(&[allow(0xa002_0019, false)]), &trusted)
            .is_ok()
    );
    assert!(
        validate_registry_security(&trusted[0], Some(&[RegistryAce::Unsupported]), &trusted)
            .is_err()
    );
}

#[test]
fn creator_owner_placeholder_does_not_trust_a_resolved_untrusted_child() {
    let trusted = vec!["S-1-5-18".to_owned()];
    let placeholder = RegistryAce::Allow {
        sid: "S-1-3-0".into(),
        mask: 0x000f_003f,
        inherit_only: false,
        object_inherit: false,
    };
    assert!(
        validate_registry_security(
            &trusted[0],
            Some(std::slice::from_ref(&placeholder)),
            &trusted
        )
        .is_ok()
    );
    assert!(
        validate_registry_security(OWNER, Some(std::slice::from_ref(&placeholder)), &trusted)
            .is_err()
    );
    // Inheritance resolves the placeholder to a concrete creator. Neither a
    // changed owner nor an ordinary creator's effective write ACE is trusted.
    assert!(
        validate_registry_security(&trusted[0], Some(&[allow(0x000f_003f, false)]), &trusted)
            .is_err()
    );
    for sid in ["S-1-3-1", "S-1-3-4", "S-1-1-0"] {
        let entry = RegistryAce::Allow {
            sid: sid.into(),
            mask: 0x000f_003f,
            inherit_only: false,
            object_inherit: false,
        };
        assert!(validate_registry_security(&trusted[0], Some(&[entry]), &trusted).is_err());
    }
}

#[test]
fn public_write_grants_fail_even_with_deny_entries() {
    let trusted = vec!["S-1-5-18".to_owned()];
    for mask in [
        2,
        4,
        0x20,
        0x10000,
        0x40000,
        0x80000,
        0x1000_0000,
        0x4000_0000,
    ] {
        assert!(
            validate_registry_security(
                &trusted[0],
                Some(&[RegistryAce::Deny, allow(mask, false)]),
                &trusted
            )
            .is_err()
        );
        assert!(
            validate_registry_security(&trusted[0], Some(&[allow(mask, true)]), &trusted).is_ok()
        );
    }
    let system = RegistryAce::Allow {
        sid: trusted[0].clone(),
        mask: u32::MAX,
        inherit_only: false,
        object_inherit: false,
    };
    assert!(validate_registry_security(&trusted[0], Some(&[system]), &trusted).is_ok());
}
