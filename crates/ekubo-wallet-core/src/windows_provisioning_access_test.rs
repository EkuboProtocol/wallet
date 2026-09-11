//! Synthetic SCM fixture only: exercise raw filesystem access with the installer's
//! administrator SID made deny-only and all removable privileges disabled.
use anyhow::{Context as _, Result, ensure};
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

pub fn ordinary_access_is_denied(path: &Path) -> Result<()> {
    // The service verifies the bytes before replying. The elevated fixture can
    // enumerate its private directory (BA grant), but the published file itself
    // grants only service/SYSTEM access. Prove the exact file exists without
    // weakening that DACL or confusing a missing path with access denial.
    require_fixture_file(path)?;
    let token = restricted_token().context("creating restricted fixture token")?;
    // SAFETY: only impersonate a less-privileged duplicate of this process's own
    // primary token; no async yield occurs before the same-thread revert guard.
    unsafe { ImpersonateLoggedOnUser(token.0) }
        .context("impersonating restricted fixture token")?;
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
    require_fixture_file(path)?;
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

fn require_fixture_file(path: &Path) -> Result<()> {
    let parent = path.parent().context("missing fixture parent")?;
    let name = path.file_name().context("missing fixture file name")?;
    for entry in std::fs::read_dir(parent).context("enumerating fixture private directory")? {
        let entry = entry?;
        if entry.file_name() == name {
            ensure!(entry.file_type()?.is_file(), "fixture entry is not a file");
            return Ok(());
        }
    }
    anyhow::bail!("service-created fixture file is absent")
}
