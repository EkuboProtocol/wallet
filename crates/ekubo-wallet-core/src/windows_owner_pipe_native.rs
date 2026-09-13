//! Native pipe construction, connected-object ACLs, and client token queries.
#![allow(unsafe_code)]

use super::{CLIENT_ACCESS, name, validate_security};
use crate::windows_service_config::InstalledServiceIdentity;
use anyhow::{Context as _, Result, ensure};
use std::{
    mem::size_of,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, IntoRawHandle as _, OwnedHandle},
    sync::Arc,
};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer};
use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                SDDL_REVISION_1, SE_KERNEL_OBJECT,
            },
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            RevertToSelf, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_SHARE_MODE,
            FILE_TYPE_PIPE, GetFileType, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
            SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
        },
        System::Pipes::{
            CreateNamedPipeW, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
    },
    core::PCWSTR,
};

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor APIs allocate the owned result with LocalAlloc.
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

fn descriptor(service: &str, desktop: &str) -> Result<Descriptor> {
    for sid in [service, desktop] {
        ensure!(
            sid.starts_with("S-1-")
                && sid.len() <= 184
                && sid
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'S' | b'-')),
            "invalid pipe trustee SID"
        );
    }
    // IPC must accept the normal medium-integrity desktop. A service-created
    // pipe otherwise inherits system integrity and rejects client writes before
    // its DACL is considered. This label grants no SID access or owner proof;
    // the fixed DACL and kernel client-token checks still govern every request.
    let sddl: Vec<u16> = format!(
        "O:{service}D:P(A;;FA;;;{service})(A;;FA;;;SY)(A;;0x{CLIENT_ACCESS:08x};;;{desktop})S:(ML;;NW;;;ME)"
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: fixed SDDL clauses contain validated SID text; output is owned.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }?;
    Ok(Descriptor(descriptor))
}

fn validate_pipe(handle: HANDLE, service: &str, desktop: &str) -> Result<()> {
    // SAFETY: callers retain the pipe handle for this synchronous inspection.
    ensure!(
        unsafe { GetFileType(handle) } == FILE_TYPE_PIPE,
        "owner endpoint is not a pipe"
    );
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the API allocates a complete descriptor and the guard frees it.
    unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&raw mut descriptor),
        )
    }
    .ok()?;
    let descriptor = Descriptor(descriptor);
    let (owner, entries) = unsafe { crate::windows_security::read_descriptor(descriptor.0) }?;
    validate_security(&owner, &entries, service, desktop)
}

pub(crate) fn create(
    pipe_name: &str,
    service: &str,
    desktop: &str,
    first: bool,
) -> Result<NamedPipeServer> {
    let descriptor = descriptor(service, desktop)?;
    let security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())?,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: false.into(),
    };
    let wide: Vec<u16> = pipe_name.encode_utf16().chain(Some(0)).collect();
    let mut mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    // SAFETY: input buffers remain live; overlapped handles transfer to Tokio.
    // Remote clients are rejected in the kernel and instance count is bounded.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide.as_ptr()),
            mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            64,
            65_536,
            65_536,
            0,
            Some(&raw const security),
        )
    };
    if handle.is_invalid() {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: this successful native handle is newly owned and non-inheritable.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    validate_pipe(HANDLE(handle.as_raw_handle()), service, desktop)?;
    // SAFETY: from_raw_handle consumes ownership, including registration errors.
    Ok(unsafe { NamedPipeServer::from_raw_handle(handle.into_raw_handle()) }?)
}

fn open(pipe_name: &str, service: &str, desktop: &str) -> Result<NamedPipeClient> {
    let wide: Vec<u16> = pipe_name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: NUL-terminated fixed profile name; no inheritable handle. Identify
    // the caller without granting the server authority to act as the desktop.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            CLIENT_ACCESS,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            None,
        )
    }
    .context("opening authenticated wallet pipe")?;
    // SAFETY: take ownership before any validation that can fail.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    validate_pipe(HANDLE(handle.as_raw_handle()), service, desktop)
        .context("validating connected wallet pipe security")?;
    // SAFETY: transfer the verified overlapped handle, including on error.
    Ok(unsafe { NamedPipeClient::from_raw_handle(handle.into_raw_handle()) }?)
}

/// Connect to the protected profile endpoint, waiting briefly when all server
/// instances are occupied. No bytes have been sent during these retries.
pub async fn connect(identity: &InstalledServiceIdentity) -> Result<NamedPipeClient> {
    let current = crate::windows_service_identity::current_process_identity()?;
    ensure!(
        current.user_sid() == identity.owner_sid(),
        "owner pipe belongs to another desktop account"
    );
    open_available(
        &name(identity.profile_id())?,
        identity.service_sid(),
        identity.owner_sid(),
    )
    .await
}

pub(crate) async fn open_available(
    pipe_name: &str,
    service: &str,
    desktop: &str,
) -> Result<NamedPipeClient> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match open(pipe_name, service, desktop) {
                Ok(pipe) => return Ok(pipe),
                Err(error)
                    if error
                        .downcast_ref::<windows::core::Error>()
                        .is_some_and(|error| {
                            error.code()
                                == windows::core::HRESULT::from_win32(
                                    windows::Win32::Foundation::ERROR_PIPE_BUSY.0,
                                )
                        }) =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .context("wallet pipe remained busy")?
}

/// The host must retain at least one instance while creating successors. The
/// first instance refuses a preexisting name; ordinary clients cannot create
/// additional server instances under the verified pipe's ACL.
pub struct OwnerPipeListener {
    pipe: NamedPipeServer,
    identity: Arc<InstalledServiceIdentity>,
}

impl OwnerPipeListener {
    pub fn bind(identity: Arc<InstalledServiceIdentity>, first: bool) -> Result<Self> {
        crate::windows_service_identity::verify_service_process(identity.service_sid())?;
        let pipe = create(
            &name(identity.profile_id())?,
            identity.service_sid(),
            identity.owner_sid(),
            first,
        )?;
        Ok(Self { pipe, identity })
    }

    /// Read a bounded frame, then call `authenticate_request` before dispatch.
    pub async fn accept(self) -> Result<ConnectedOwnerPipe> {
        self.pipe.connect().await?;
        Ok(ConnectedOwnerPipe {
            pipe: self.pipe,
            identity: self.identity,
        })
    }
}

pub struct ConnectedOwnerPipe {
    pipe: NamedPipeServer,
    identity: Arc<InstalledServiceIdentity>,
}

impl ConnectedOwnerPipe {
    pub fn owner_call_context(
        &self,
        request: &[u8],
    ) -> Result<crate::windows_service_presence::OwnerCallContext> {
        self.authenticate_request()?;
        let (session, logon) = with_client(HANDLE(self.pipe.as_raw_handle()), || {
            use windows::Win32::{
                Security::TOKEN_QUERY,
                System::Threading::{GetCurrentThread, OpenThreadToken},
            };
            let mut handle = HANDLE::default();
            // SAFETY: read the impersonated, last-read client token on this
            // thread only. The local handle closes before impersonation ends.
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut handle) }?;
            let token = unsafe { OwnedHandle::from_raw_handle(handle.0) };
            ekubo_wallet_windows_owner_auth::logon_identity(HANDLE(token.as_raw_handle()))
        })?;
        let retained = retain_auth_connection(&self.pipe)?;
        Ok(
            crate::windows_service_presence::OwnerCallContext::from_authenticated_token(
                self.identity.clone(),
                session,
                logon,
                request,
                retained,
            ),
        )
    }

    pub fn stream(&mut self) -> &mut NamedPipeServer {
        &mut self.pipe
    }

    /// Transfer a connection after authenticating its protocol-selection read.
    /// The receiving protocol owns the stream until disconnect; it must never
    /// switch back to owner dispatch without a new authenticated connection.
    #[must_use]
    pub fn into_stream(self) -> NamedPipeServer {
        self.pipe
    }

    /// Verify the kernel client context of the last read. This is synchronous:
    /// impersonation cannot cross an await, task migration, or owner dispatch.
    /// A successful check supplies no human-presence proof.
    pub fn authenticate_request(&self) -> Result<()> {
        crate::windows_service_identity::verify_service_process(self.identity.service_sid())?;
        let sid = client_sid(HANDLE(self.pipe.as_raw_handle()))?;
        ensure!(
            sid == self.identity.owner_sid(),
            "owner pipe client is another account"
        );
        Ok(())
    }
}

struct Revert;
impl Drop for Revert {
    fn drop(&mut self) {
        // SAFETY: this guard stays on the impersonating thread. Continuing as
        // the client after a failed revert is unsafe, including during unwind.
        if unsafe { RevertToSelf() }.is_err() {
            std::process::abort();
        }
    }
}

pub(crate) fn authenticate_installer_client(pipe: &NamedPipeServer) -> Result<()> {
    with_client(
        HANDLE(pipe.as_raw_handle()),
        crate::windows_service_identity::verify_installer_thread,
    )
}

fn client_sid(pipe: HANDLE) -> Result<String> {
    with_client(
        pipe,
        crate::windows_service_identity::current_thread_user_sid,
    )
}

pub(crate) fn authenticate_auth_service(pipe: &NamedPipeServer, expected: &str) -> Result<()> {
    ensure!(
        client_sid(HANDLE(pipe.as_raw_handle()))? == expected,
        "native authentication caller is not the installed wallet service"
    );
    verify_pipe_connection(HANDLE(pipe.as_raw_handle()))
}

pub(crate) fn verify_auth_connection(connection: &OwnedHandle) -> Result<()> {
    verify_pipe_connection(HANDLE(connection.as_raw_handle()))
}

fn verify_pipe_connection(connection: HANDLE) -> Result<()> {
    let mut available = 0;
    // SAFETY: retained overlapped server handle; this consumes no data and does
    // not change the last-read impersonation context. Broken pipes fail.
    unsafe {
        windows::Win32::System::Pipes::PeekNamedPipe(
            connection,
            None,
            0,
            None,
            Some(&raw mut available),
            None,
        )
    }?;
    ensure!(
        available == 0,
        "unexpected traffic on native authorization owner connection"
    );
    Ok(())
}

fn retain_auth_connection(pipe: &NamedPipeServer) -> Result<OwnedHandle> {
    use windows::Win32::{
        Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle},
        System::Threading::GetCurrentProcess,
    };
    let mut retained = HANDLE::default();
    // SAFETY: retain the verified overlapped server endpoint in this process
    // without inheritance. Holding a server handle does not keep its peer alive.
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            HANDLE(pipe.as_raw_handle()),
            GetCurrentProcess(),
            &raw mut retained,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }?;
    let retained = unsafe { OwnedHandle::from_raw_handle(retained.0) };
    verify_auth_connection(&retained)?;
    Ok(retained)
}

fn with_client<T>(pipe: HANDLE, inspect: impl FnOnce() -> Result<T>) -> Result<T> {
    // Reject nested impersonation before changing any thread context.
    crate::windows_service_identity::current_process_identity()?;
    // SAFETY: the server handle is live and its last read selected this client.
    unsafe { ImpersonateNamedPipeClient(pipe) }?;
    let _revert = Revert;
    inspect()
}

#[cfg(test)]
#[path = "windows_owner_pipe_native_test.rs"]
mod tests;
