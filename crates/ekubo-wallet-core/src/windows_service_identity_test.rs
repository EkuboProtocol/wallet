use super::*;

#[test]
fn installer_authority_requires_enabled_administrators_and_high_or_system_integrity() {
    for integrity in ["S-1-16-12288", "S-1-16-16384"] {
        assert!(require_installer_context(true, integrity).is_ok());
        assert!(require_installer_context(false, integrity).is_err());
    }
    for integrity in [
        "S-1-16-0",
        "S-1-16-4096",
        "S-1-16-8192",
        "S-1-16-8448",
        "S-1-16-12288-extra",
        "S-1-16-99999",
        "S-1-5-18",
    ] {
        assert!(require_installer_context(true, integrity).is_err());
    }
}

const SERVICE: &str = "S-1-5-80-123-456-789-10-11";

#[test]
fn only_the_exact_virtual_account_in_session_zero_matches() {
    let service = ProcessIdentity {
        user_sid: SERVICE.into(),
        session_id: 0,
    };
    service.verify_service(SERVICE).unwrap();
    assert!(
        service
            .verify_service("S-1-5-80-123-456-789-10-12")
            .is_err()
    );
    let interactive = ProcessIdentity {
        session_id: 1,
        ..service
    };
    assert!(interactive.verify_service(SERVICE).is_err());
    for user in ["S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-21-1-2-3-1000"] {
        let ordinary = ProcessIdentity {
            user_sid: user.into(),
            session_id: 0,
        };
        assert!(ordinary.verify_service(SERVICE).is_err());
        assert!(ordinary.verify_service(user).is_err());
    }
}

#[test]
fn service_identifiers_are_complete_and_canonical() {
    for invalid in [
        "S-1-5-80",
        "S-1-5-80-0",
        "S-1-5-80-1-2-3-4",
        "S-1-5-80-1-2-3-4-5-6",
        "S-1-5-80-01-2-3-4-5",
        "S-1-5-80-+1-2-3-4-5",
        "S-1-5-80-1-2-3-4-4294967296",
        "S-1-5-80-1-2-3-4-5\0",
        "s-1-5-80-1-2-3-4-5",
    ] {
        assert!(!is_virtual_service_sid(invalid), "{invalid:?}");
    }
    assert!(is_virtual_service_sid(SERVICE));
}

#[cfg(target_os = "windows")]
#[test]
fn native_primary_token_is_read_without_accessing_credentials() {
    let identity = current_process_identity().unwrap();
    assert!(identity.user_sid().starts_with("S-1-"));
    // CI runs as an ordinary account, not this synthetic service identity.
    assert!(verify_service_process(SERVICE).is_err());
}

#[cfg(target_os = "windows")]
#[test]
// Exercise the native impersonation guard on this test thread only.
#[allow(unsafe_code)]
fn native_identity_rejects_thread_impersonation() {
    use windows::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // SAFETY: this guard runs on the thread that called ImpersonateSelf.
            unsafe { RevertToSelf() }.expect("restore the test thread's token");
        }
    }
    // SAFETY: impersonate only this test thread's own process identity.
    unsafe { ImpersonateSelf(SecurityImpersonation) }.unwrap();
    let revert = Revert;
    let error = current_process_identity().unwrap_err();
    assert!(error.to_string().contains("impersonating"));
    drop(revert);
    current_process_identity().unwrap();
}
