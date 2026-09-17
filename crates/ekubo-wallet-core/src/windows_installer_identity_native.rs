//! Installer authority from native token state, never an account-name assertion.
use super::{Token, ensure_not_impersonating, require_installer_context, sid_in_data, token_data};
use anyhow::Result;
use std::mem::size_of;
use windows::{
    Win32::{
        Foundation::HANDLE,
        Security::{
            CheckTokenMembership, CreateWellKnownSid, DuplicateTokenEx, PSID,
            SecurityIdentification, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
            TokenImpersonation, TokenIntegrityLevel, WinBuiltinAdministratorsSid,
        },
        System::Threading::{
            GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
        },
    },
    core::BOOL,
};

/// The installer must already run elevated. This does not elevate, prompt,
/// access a credential, or grant a wallet owner-authorization capability.
pub fn verify_installer_process() -> Result<()> {
    ensure_not_impersonating()?;
    verify_token(&primary_query_token()?)
}

fn primary_query_token() -> Result<Token> {
    let mut handle = HANDLE::default();
    // SAFETY: query/duplicate only this process's existing primary token.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &raw mut handle,
        )
    }?;
    let primary = Token(handle);
    let mut query = HANDLE::default();
    // SAFETY: CheckTokenMembership requires an impersonation token. This copy
    // has query access only and is never installed on a thread or process.
    unsafe {
        DuplicateTokenEx(
            primary.0,
            TOKEN_QUERY,
            None,
            SecurityIdentification,
            TokenImpersonation,
            &raw mut query,
        )
    }?;
    Ok(Token(query))
}

/// Query the exact kernel client token selected by the pipe's last read. Call
/// synchronously inside a native impersonation/revert guard, never across await.
/// A missing thread token fails; the service's own primary token is no fallback.
pub fn verify_installer_thread() -> Result<()> {
    let mut handle = HANDLE::default();
    // SAFETY: open this thread's existing context for query only. OpenAsSelf
    // allows an identification-level token to be inspected without using it.
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut handle) }?;
    verify_token(&Token(handle))
}

fn verify_token(token: &Token) -> Result<()> {
    let data = token_data(
        token,
        TokenIntegrityLevel,
        size_of::<TOKEN_MANDATORY_LABEL>(),
    )?;
    // SAFETY: token_data provides an aligned initialized buffer of checked size.
    let label = unsafe { &*data.words.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
    let integrity = sid_in_data(&data, label.Label.Sid)?;
    require_installer_context(administrator_enabled(token)?, &integrity)
}

fn administrator_enabled(token: &Token) -> Result<bool> {
    // SECURITY_MAX_SID_SIZE is 68 bytes. DWORD storage supplies SID alignment.
    let mut storage = [0u32; 17];
    let mut bytes = u32::try_from(size_of_val(&storage))?;
    let admin = PSID(storage.as_mut_ptr().cast());
    // SAFETY: the fixed output buffer is initialized, aligned, and its complete
    // byte length is supplied. The resulting SID remains live through the query.
    unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            None,
            Some(admin),
            &raw mut bytes,
        )
    }?;
    let mut enabled = BOOL::default();
    // SAFETY: the token is an owned impersonation token with TOKEN_QUERY access.
    // This API checks enabled membership AND restricting SIDs, excluding UAC
    // deny-only administrator membership and restricted tokens lacking authority.
    unsafe { CheckTokenMembership(Some(token.0), admin, &raw mut enabled) }?;
    Ok(enabled.as_bool())
}

#[cfg(test)]
#[path = "windows_installer_identity_native_test.rs"]
mod tests;
