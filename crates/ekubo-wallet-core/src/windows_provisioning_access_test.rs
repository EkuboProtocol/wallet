//! Synthetic SCM fixture only: exercise raw filesystem access with the installer's
//! administrator SID made deny-only and all removable privileges disabled.
use anyhow::{Result, ensure};
use std::path::Path;
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{
        CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE, ImpersonateLoggedOnUser,
        PSID, RevertToSelf, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_QUERY,
        WinBuiltinAdministratorsSid,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: this guard exclusively owns a successfully opened token.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct Revert;
impl Drop for Revert {
    fn drop(&mut self) {
        // SAFETY: the synchronous fixture stays on its impersonating thread.
        if unsafe { RevertToSelf() }.is_err() {
            std::process::abort();
        }
    }
}

pub fn ordinary_access_is_denied(path: &Path, expected: &[u8]) -> Result<()> {
    // Establish that this is the actual synthetic service-created file, so a
    // nonexistent path cannot make the negative access test pass.
    ensure!(
        std::fs::read(path)? == expected,
        "fixture staged bytes changed"
    );
    let token = restricted_token()?;
    // SAFETY: only impersonate a less-privileged duplicate of this process's own
    // primary token; no async yield occurs before the same-thread revert guard.
    unsafe { ImpersonateLoggedOnUser(token.0) }?;
    let revert = Revert;
    for result in [
        std::fs::File::open(path),
        std::fs::OpenOptions::new().write(true).open(path),
    ] {
        ensure!(
            result
                .err()
                .is_some_and(|error| error.raw_os_error() == Some(5)),
            "ordinary token could open protected storage, or failed for a reason other than access denial"
        );
    }
    drop(revert);
    ensure!(
        std::fs::read(path)? == expected,
        "fixture staged file changed during denial checks"
    );
    Ok(())
}

fn restricted_token() -> Result<Token> {
    let mut handle = HANDLE::default();
    // SAFETY: query/duplicate only this process's own primary token.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &raw mut handle,
        )
    }?;
    let original = Token(handle);
    let mut storage = [0_u32; 17];
    let admin = PSID(storage.as_mut_ptr().cast());
    let mut bytes = u32::try_from(size_of_val(&storage))?;
    // SAFETY: live aligned storage covers the declared SID capacity.
    unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            None,
            Some(admin),
            &raw mut bytes,
        )
    }?;
    let disable = [SID_AND_ATTRIBUTES {
        Sid: admin,
        Attributes: 0,
    }];
    let mut restricted = HANDLE::default();
    // SAFETY: creates a separate restricted token; the SID storage stays alive.
    unsafe {
        CreateRestrictedToken(
            original.0,
            DISABLE_MAX_PRIVILEGE,
            Some(&disable),
            None,
            None,
            &raw mut restricted,
        )
    }?;
    Ok(Token(restricted))
}
