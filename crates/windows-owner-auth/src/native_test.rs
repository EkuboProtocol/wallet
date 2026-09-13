use super::*;
use windows::Win32::{
    Foundation::ERROR_ACCESS_DENIED,
    Security::{
        AccessCheck, CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, GENERIC_MAPPING,
        ImpersonateLoggedOnUser, PRIVILEGE_SET, RevertToSelf, SecurityImpersonation,
        TokenImpersonation,
    },
    System::{
        RemoteDesktop::WTSGetActiveConsoleSessionId,
        Threading::{
            GetProcessId, GetThreadId, OpenProcess, OpenThread, PROCESS_ACCESS_RIGHTS,
            THREAD_ACCESS_RIGHTS,
        },
    },
};
use windows::core::BOOL;

#[test]
fn ordinary_process_cannot_invoke_system_launcher() {
    if token_sid(process_token().unwrap().0).unwrap() == "S-1-5-18" {
        return;
    }
    let challenge = Challenge {
        nonce: "a".repeat(64),
        operation_digest: "b".repeat(64),
        reason: "fixture".into(),
    };
    assert!(launch("S-1-5-21-1-2-3-4", 1, [0, 0], &challenge).is_err());
}

struct Revert;
impl Drop for Revert {
    fn drop(&mut self) {
        if unsafe { RevertToSelf() }.is_err() {
            std::process::abort();
        }
    }
}

/// Explicitly executed under SYSTEM on the disposable CI VM. The collector is
/// NEVER resumed: no Hello UI, account mutation, or biometric operation occurs.
#[test]
#[ignore = "requires disposable Windows CI SYSTEM context and an interactive session"]
fn system_created_collector_denies_owner_mutation_from_birth() {
    assert_eq!(token_sid(process_token().unwrap().0).unwrap(), "S-1-5-18");
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    assert!(
        session != 0 && session != u32::MAX,
        "CI needs an interactive fixture session"
    );
    let mut raw = HANDLE::default();
    unsafe { WTSQueryUserToken(session, &raw mut raw) }.unwrap();
    let owner = Handle(raw);
    let sid = token_sid(owner.0).unwrap();
    let (_, logon) = logon_identity(owner.0).unwrap();
    let challenge = Challenge {
        nonce: "a".repeat(64),
        operation_digest: "b".repeat(64),
        reason: "isolated native boundary fixture".into(),
    };
    assert!(collector_token("S-1-5-21-1-2-3-4", session, logon).is_err());
    assert!(collector_token(&sid, session, [logon[0] ^ 1, logon[1]]).is_err());
    let (mut process, thread) = create_suspended(
        &std::env::current_exe().unwrap(),
        &sid,
        session,
        logon,
        &challenge,
    )
    .unwrap();
    let mut primary = HANDLE::default();
    unsafe { OpenProcessToken(process.process.0, TOKEN_QUERY, &raw mut primary) }.unwrap();
    let primary = Handle(primary);
    assert_eq!(token_sid(primary.0).unwrap(), sid);
    assert_eq!(logon_identity(primary.0).unwrap(), (session, logon));
    let pid = unsafe { GetProcessId(process.process.0) };
    let tid = unsafe { GetThreadId(thread.0) };
    let mut restricted = HANDLE::default();
    unsafe {
        CreateRestrictedToken(
            owner.0,
            DISABLE_MAX_PRIVILEGE,
            None,
            None,
            None,
            &raw mut restricted,
        )
    }
    .unwrap();
    let restricted = Handle(restricted);
    unsafe { ImpersonateLoggedOnUser(restricted.0) }.unwrap();
    {
        let _revert = Revert;
        // Try each separately: one denied right must not conceal a different
        // independently granted route to token theft, injection or forged exit.
        for mask in [
            0x0001,
            0x0002,
            0x0020,
            0x0040,
            0x0200,
            0x1000,
            0x0004_0000,
            0x0008_0000,
        ] {
            let error =
                unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(mask), false, pid) }.unwrap_err();
            assert_eq!(
                error.code(),
                ERROR_ACCESS_DENIED.to_hresult(),
                "process right {mask:#x}"
            );
        }
        for mask in [0x0010, 0x0002, 0x0004_0000, 0x0008_0000] {
            let error = unsafe { OpenThread(THREAD_ACCESS_RIGHTS(mask), false, tid) }.unwrap_err();
            assert_eq!(
                error.code(),
                ERROR_ACCESS_DENIED.to_hresult(),
                "thread right {mask:#x}"
            );
        }
    }
    assert_default_acl_denies_owner_write_dac(
        &sid,
        &collector_token(&sid, session, logon).unwrap(),
        &restricted,
    );
    process.deadline = Instant::now();
    assert!(
        process.poll().is_err(),
        "expired collector remained consumable"
    );
    let mut observed = HANDLE::default();
    unsafe {
        windows::Win32::Foundation::DuplicateHandle(
            GetCurrentProcess(),
            process.process.0,
            GetCurrentProcess(),
            &raw mut observed,
            0,
            false,
            windows::Win32::Foundation::DUPLICATE_SAME_ACCESS,
        )
    }
    .unwrap();
    let observed = Handle(observed);
    // Dropping an unconsumed collector terminates the suspended process.
    drop(process);
    assert_eq!(
        unsafe { WaitForSingleObject(observed.0, 5_000) },
        WAIT_OBJECT_0
    );
}

fn assert_default_acl_denies_owner_write_dac(sid: &str, token: &Handle, attacker: &Handle) {
    use windows::Win32::Security::{
        InitializeSecurityDescriptor, SECURITY_DESCRIPTOR, SetSecurityDescriptorDacl,
        SetSecurityDescriptorGroup, SetSecurityDescriptorOwner,
    };
    let default_acl = data(token.0, TokenDefaultDacl).unwrap();
    let default_acl = unsafe { &*default_acl.as_ptr().cast::<TOKEN_DEFAULT_DACL>() };
    // A future thread's owner will be TokenOwner (the user), not SYSTEM. Verify
    // that OWNER RIGHTS suppresses the implicit WRITE_DAC grant even then.
    let owner_data = data(attacker.0, TokenUser).unwrap();
    let user = unsafe { &*owner_data.as_ptr().cast::<TOKEN_USER>() };
    assert_eq!(token_sid(attacker.0).unwrap(), sid);
    let mut sd = SECURITY_DESCRIPTOR::default();
    let sd_ptr = PSECURITY_DESCRIPTOR((&raw mut sd).cast());
    unsafe { InitializeSecurityDescriptor(sd_ptr, 1) }.unwrap();
    unsafe { SetSecurityDescriptorOwner(sd_ptr, Some(user.User.Sid), false) }.unwrap();
    unsafe { SetSecurityDescriptorGroup(sd_ptr, Some(user.User.Sid), false) }.unwrap();
    unsafe { SetSecurityDescriptorDacl(sd_ptr, true, Some(default_acl.DefaultDacl), false) }
        .unwrap();
    let mut impersonation = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            attacker.0,
            TOKEN_QUERY,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut impersonation,
        )
    }
    .unwrap();
    let impersonation = Handle(impersonation);
    let mapping = GENERIC_MAPPING::default();
    let mut privileges = [0usize; 128];
    let mut bytes = u32::try_from(size_of_val(&privileges)).unwrap();
    let mut granted = 0;
    let mut allowed = BOOL::default();
    unsafe {
        AccessCheck(
            sd_ptr,
            impersonation.0,
            0x0004_0000,
            &raw const mapping,
            Some(privileges.as_mut_ptr().cast::<PRIVILEGE_SET>()),
            &raw mut bytes,
            &raw mut granted,
            &raw mut allowed,
        )
    }
    .unwrap();
    assert!(
        !allowed.as_bool(),
        "owner can replace the default thread DACL"
    );
}
