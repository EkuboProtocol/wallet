use super::*;
use windows::Win32::Security::{
    CREATE_RESTRICTED_TOKEN_FLAGS, CreateRestrictedToken, ImpersonateSelf, RevertToSelf,
    SID_AND_ATTRIBUTES,
};

#[test]
fn installer_queries_require_the_exact_native_context() {
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // SAFETY: the guard remains on the test thread that impersonates itself.
            unsafe { RevertToSelf() }.expect("restore the test thread token");
        }
    }
    let process_allowed = verify_installer_process().is_ok();
    assert!(
        verify_installer_thread().is_err(),
        "missing thread token is not process fallback"
    );
    // SAFETY: impersonate only this thread's own process, never another account.
    unsafe { ImpersonateSelf(SecurityIdentification) }.unwrap();
    let revert = Revert;
    assert_eq!(verify_installer_thread().is_ok(), process_allowed);
    assert!(
        verify_installer_process().is_err(),
        "primary-process check rejects impersonation"
    );
    drop(revert);
    assert_eq!(verify_installer_process().is_ok(), process_allowed);
}

#[test]
fn a_deny_only_administrator_sid_is_not_installer_authority() {
    let mut handle = HANDLE::default();
    // SAFETY: only read/duplicate this test process's token; no global token changes.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &raw mut handle,
        )
    }
    .unwrap();
    let original = Token(handle);
    let mut storage = [0u32; 17];
    let admin = PSID(storage.as_mut_ptr().cast());
    let mut bytes = u32::try_from(size_of_val(&storage)).unwrap();
    // SAFETY: initialized aligned buffer covers the supplied SID capacity.
    unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            None,
            Some(admin),
            &raw mut bytes,
        )
    }
    .unwrap();
    let disable = [SID_AND_ATTRIBUTES {
        Sid: admin,
        Attributes: 0,
    }];
    let mut restricted = HANDLE::default();
    // SAFETY: this creates a separate less-privileged token. It is never assigned
    // to a process/thread; the SID allocation remains live through this call.
    unsafe {
        CreateRestrictedToken(
            original.0,
            CREATE_RESTRICTED_TOKEN_FLAGS(0),
            Some(&disable),
            None,
            None,
            &raw mut restricted,
        )
    }
    .unwrap();
    let restricted = Token(restricted);
    let mut query = HANDLE::default();
    // SAFETY: duplicate only the restricted token for membership inspection.
    unsafe {
        DuplicateTokenEx(
            restricted.0,
            TOKEN_QUERY,
            None,
            SecurityIdentification,
            TokenImpersonation,
            &raw mut query,
        )
    }
    .unwrap();
    let query = Token(query);
    assert!(!administrator_enabled(&query).unwrap());
    assert!(verify_token(&query).is_err());
}
