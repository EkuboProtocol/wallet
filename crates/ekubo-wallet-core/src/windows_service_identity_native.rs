//! Native primary-token reads. No credentials or wallet state are accessed.

// Win32 token queries require FFI and pointer-backed variable-length records.
// Keep those unsafe operations inside this small native boundary.
#![allow(unsafe_code)]

use super::ProcessIdentity;
use anyhow::{Context as _, Result, bail, ensure};
use std::mem::size_of;
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN, HANDLE, HLOCAL, LocalFree,
        },
        Security::Authorization::ConvertSidToStringSidW,
        Security::{
            GetTokenInformation, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER, TokenSessionId,
            TokenUser,
        },
        System::Threading::{
            GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
        },
    },
    core::{HRESULT, PWSTR},
};

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: this guard owns a token handle returned by Open*Token.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct SidText(PWSTR);
impl Drop for SidText {
    fn drop(&mut self) {
        // SAFETY: ConvertSidToStringSidW allocates this string with LocalAlloc.
        unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
    }
}

fn ensure_not_impersonating() -> Result<()> {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo-handle is current-thread-only and output is writable.
    match unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut token) } {
        Ok(()) => {
            drop(Token(token));
            bail!("wallet identity checks cannot run while impersonating another token");
        }
        Err(error) if error.code() == HRESULT::from_win32(ERROR_NO_TOKEN.0) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

struct TokenData {
    words: Vec<usize>,
    bytes: usize,
}

fn token_data(token: &Token, class: TOKEN_INFORMATION_CLASS, minimum: usize) -> Result<TokenData> {
    let mut bytes = 0;
    // SAFETY: this is the documented size-query call with no output buffer.
    let error = unsafe { GetTokenInformation(token.0, class, None, 0, &raw mut bytes) }
        .err()
        .context("token size query returned no required size")?;
    ensure!(
        error.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0),
        "cannot determine token information size: {error}"
    );
    let capacity = usize::try_from(bytes)?;
    ensure!(
        (minimum..=65_536).contains(&capacity),
        "invalid token information size"
    );
    // Word storage supplies alignment for TOKEN_USER as well as its SID pointer.
    let mut words = vec![0usize; capacity.div_ceil(size_of::<usize>())];
    // SAFETY: the buffer is aligned, initialized, and at least `bytes` long.
    unsafe {
        GetTokenInformation(
            token.0,
            class,
            Some(words.as_mut_ptr().cast()),
            bytes,
            &raw mut bytes,
        )
    }?;
    let bytes = usize::try_from(bytes)?;
    ensure!(
        (minimum..=capacity).contains(&bytes),
        "token information changed size"
    );
    Ok(TokenData { words, bytes })
}

fn user_sid(token: &Token) -> Result<String> {
    let data = token_data(token, TokenUser, size_of::<TOKEN_USER>())?;
    // SAFETY: token_data checked size/alignment; TOKEN_USER is a plain C struct.
    let user = unsafe { &*data.words.as_ptr().cast::<TOKEN_USER>() };
    let base = data.words.as_ptr() as usize;
    let offset = (user.User.Sid.0 as usize)
        .checked_sub(base)
        .context("token SID lies outside its buffer")?;
    // SAFETY: the vector is initialized for at least data.bytes bytes.
    let bytes = unsafe { std::slice::from_raw_parts(data.words.as_ptr().cast::<u8>(), data.bytes) };
    let sid = bytes
        .get(offset..)
        .context("token SID lies outside its buffer")?;
    ensure!(
        sid.len() >= 8 && sid[0] == 1 && sid[1] <= 15,
        "invalid token SID header"
    );
    ensure!(
        sid.len() >= 8 + usize::from(sid[1]) * 4,
        "truncated token SID"
    );
    // SAFETY: the SID is wholly inside the live token buffer and has a valid
    // revision/count. The API validates its contents before allocating text.
    unsafe { sid_string(user.User.Sid) }
}

/// Convert an OS-provided SID without leaking its allocated text.
///
/// # Safety
/// `sid` must point to a complete valid SID for the duration of this call.
pub(crate) unsafe fn sid_string(sid: windows::Win32::Security::PSID) -> Result<String> {
    let mut text = PWSTR::null();
    // SAFETY: the caller guarantees a complete live SID.
    unsafe { ConvertSidToStringSidW(sid, &raw mut text) }?;
    let text = SidText(text);
    // SAFETY: the successful conversion returned an allocated NUL-terminated string.
    Ok(unsafe { text.0.to_string() }?)
}

pub(crate) fn current_thread_user_sid() -> Result<String> {
    let mut handle = HANDLE::default();
    // SAFETY: query the current thread only, using the process token for the
    // access check so an identification-only client context remains queryable.
    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut handle) }?;
    user_sid(&Token(handle))
}

/// Read primary account identity. Thread impersonation is rejected so callers
/// cannot mistake a temporary client context for the host's custody identity.
pub fn current_process_identity() -> Result<ProcessIdentity> {
    ensure_not_impersonating()?;
    let mut handle = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle; output is writable.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut handle) }?;
    let token = Token(handle);
    let user_sid = user_sid(&token)?;
    let session = token_data(&token, TokenSessionId, size_of::<u32>())?;
    // SAFETY: token_data checked alignment and at least one DWORD is present.
    let session_id = unsafe { *session.words.as_ptr().cast::<u32>() };
    Ok(ProcessIdentity {
        user_sid,
        session_id,
    })
}

/// The expected SID must come from protected installer configuration. This
/// checks actual execution identity only and grants no storage or IPC access.
pub fn verify_service_process(expected_service_sid: &str) -> Result<ProcessIdentity> {
    let identity = current_process_identity()?;
    identity.verify_service(expected_service_sid)?;
    Ok(identity)
}
