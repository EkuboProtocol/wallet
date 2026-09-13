//! All process/token FFI for the fixed collector. The broker retains the actual
//! process object, never reopens a PID, and kills the child when its lease drops.
#![allow(unsafe_code)]

use crate::{Challenge, VERIFIED_EXIT};
use anyhow::{Context as _, Result, ensure};
use std::{
    mem::size_of,
    path::Path,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            DuplicateTokenEx, GetSecurityDescriptorDacl, GetTokenInformation, PSECURITY_DESCRIPTOR,
            SECURITY_ATTRIBUTES, SecurityIdentification, SetTokenInformation, TOKEN_ALL_ACCESS,
            TOKEN_DEFAULT_DACL, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
            TOKEN_STATISTICS, TOKEN_USER, TokenDefaultDacl, TokenIntegrityLevel, TokenPrimary,
            TokenSessionId, TokenStatistics, TokenUser,
        },
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            },
            RemoteDesktop::WTSQueryUserToken,
            SystemInformation::GetSystemWindowsDirectoryW,
            Threading::{
                CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
                DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
                GetExitCodeProcess, InitializeProcThreadAttributeList,
                LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, PROCESS_INFORMATION, ResumeThread,
                STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
            },
        },
    },
    core::{PCWSTR, PWSTR},
};

pub(crate) struct Handle(pub HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}
// Kernel handles can be used on any thread; these wrappers never impersonate.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

pub(crate) fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

/// Machine-known installation path; neither environment nor IPC selects code.
pub fn installed_helper_path() -> Result<std::path::PathBuf> {
    use windows::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
    };
    struct Text(PWSTR);
    impl Drop for Text {
        fn drop(&mut self) {
            unsafe { CoTaskMemFree(Some(self.0.0.cast())) };
        }
    }
    let folder = FOLDERID_ProgramFiles;
    let root = Text(unsafe { SHGetKnownFolderPath(&raw const folder, KF_FLAG_DEFAULT, None) }?);
    Ok(std::path::PathBuf::from(unsafe { root.0.to_string() }?)
        .join("Ekubo Wallet 2")
        .join("ekubo-wallet-v2-owner-auth.exe"))
}

fn descriptor(value: &str) -> Result<Descriptor> {
    let value = wide(value);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(value.as_ptr()),
            SDDL_REVISION_1,
            &raw mut sd,
            None,
        )
    }?;
    Ok(Descriptor(sd))
}

fn system_environment() -> Result<Vec<u16>> {
    let mut directory = vec![0u16; 32_768];
    let length = unsafe { GetSystemWindowsDirectoryW(Some(&mut directory)) } as usize;
    ensure!(
        length > 0 && length < directory.len(),
        "cannot determine the system Windows directory"
    );
    let directory = String::from_utf16(&directory[..length])?;
    Ok(format!("SystemRoot={directory}\0WINDIR={directory}\0\0")
        .encode_utf16()
        .collect())
}

fn data(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<usize>> {
    let mut size = 0;
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &raw mut size) };
    ensure!((4..=65_536).contains(&size), "invalid token record size");
    let mut data = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(data.as_mut_ptr().cast()),
            size,
            &raw mut size,
        )
    }?;
    Ok(data)
}

pub(crate) fn token_sid(token: HANDLE) -> Result<String> {
    let data = data(token, TokenUser)?;
    ensure!(
        data.len() * size_of::<usize>() >= size_of::<TOKEN_USER>(),
        "short token user"
    );
    let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut text) }?;
    let result = unsafe { text.to_string() };
    unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    Ok(result?)
}

fn process_token() -> Result<Handle> {
    let mut handle = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut handle) }?;
    Ok(Handle(handle))
}

/// The token LUID is a logon-generation binding, not just a recycled session ID.
pub fn logon_identity(token: HANDLE) -> Result<(u32, [u32; 2])> {
    let session = data(token, TokenSessionId)?;
    let statistics = data(token, TokenStatistics)?;
    ensure!(
        statistics.len() * size_of::<usize>() >= size_of::<TOKEN_STATISTICS>(),
        "short token statistics"
    );
    let statistics = unsafe { &*statistics.as_ptr().cast::<TOKEN_STATISTICS>() };
    Ok((
        unsafe { *session.as_ptr().cast::<u32>() },
        [
            statistics.AuthenticationId.LowPart,
            statistics.AuthenticationId.HighPart.cast_unsigned(),
        ],
    ))
}

fn collector_token(owner: &str, session: u32, logon: [u32; 2]) -> Result<Handle> {
    ensure!(
        token_sid(process_token()?.0)? == "S-1-5-18",
        "only SYSTEM may launch the native collector"
    );
    ensure!(
        session != 0,
        "native collector requires an interactive session"
    );
    let mut original = HANDLE::default();
    unsafe { WTSQueryUserToken(session, &raw mut original) }?;
    let original = Handle(original);
    ensure!(
        token_sid(original.0)? == owner && logon_identity(original.0)? == (session, logon),
        "interactive owner or logon generation changed"
    );
    let security = descriptor("O:SYD:P(A;;GA;;;SY)(A;;0;;;OW)")?;
    // Windows/COM must be able to inspect and duplicate the collector's own
    // primary token through its process pseudo-handle. No other owner process
    // can obtain that handle: the process DACL denies even QUERY_LIMITED, as
    // exercised by the native fixture. Token mutation/WRITE_DAC stay SYSTEM-only.
    let token_security = descriptor(&format!("O:SYD:P(A;;GA;;;SY)(A;;0xa;;;{owner})(A;;0;;;OW)"))?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())?,
        lpSecurityDescriptor: token_security.0.0,
        bInheritHandle: false.into(),
    };
    let mut token = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            original.0,
            TOKEN_ALL_ACCESS,
            Some(&raw const attributes),
            SecurityIdentification,
            TokenPrimary,
            &raw mut token,
        )
    }?;
    let token = Handle(token);
    // CreateProcessAsUser's primary-thread attributes do NOT cover threads later
    // created by COM/WinRT. Their default ACL must also exclude the login owner.
    // OWNER RIGHTS suppresses the otherwise implicit owner WRITE_DAC grant.
    let mut present = false.into();
    let mut defaulted = false.into();
    let mut acl = std::ptr::null_mut();
    unsafe {
        GetSecurityDescriptorDacl(
            security.0,
            &raw mut present,
            &raw mut acl,
            &raw mut defaulted,
        )
    }?;
    let default_acl = TOKEN_DEFAULT_DACL { DefaultDacl: acl };
    unsafe {
        SetTokenInformation(
            token.0,
            TokenDefaultDacl,
            (&raw const default_acl).cast(),
            u32::try_from(size_of::<TOKEN_DEFAULT_DACL>())?,
        )
    }?;
    // UIPI, as well as object ACLs, must separate the collector's HWND from the
    // ordinary medium-integrity desktop. The account and logon ID stay intact.
    let mut high_sid = [1u32, 0x1000_0000, 0x3000];
    // SID revision=1, count=1, authority=16, RID=HIGH (little-endian SID bytes).
    high_sid[0] = 0x101;
    let label = TOKEN_MANDATORY_LABEL {
        Label: windows::Win32::Security::SID_AND_ATTRIBUTES {
            Sid: windows::Win32::Security::PSID(high_sid.as_mut_ptr().cast()),
            Attributes: 0x20, /* SE_GROUP_INTEGRITY */
        },
    };
    unsafe {
        SetTokenInformation(
            token.0,
            TokenIntegrityLevel,
            (&raw const label).cast(),
            u32::try_from(size_of::<TOKEN_MANDATORY_LABEL>())? + 12,
        )
    }?;
    Ok(token)
}

struct Attributes {
    storage: Vec<usize>,
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
}
impl Attributes {
    fn new(mitigation: &u64) -> Result<Self> {
        let mut bytes = 0;
        let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &raw mut bytes) };
        ensure!(
            (1..=65_536).contains(&bytes),
            "invalid process attribute size"
        );
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(pointer), 1, None, &raw mut bytes) }?;
        let result = Self { storage, pointer };
        unsafe {
            UpdateProcThreadAttribute(
                pointer,
                0,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
                Some(std::ptr::from_ref(mitigation).cast()),
                size_of::<u64>(),
                None,
                None,
            )
        }?;
        Ok(result)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.pointer) };
        // Own the allocation for the entire native attribute-list lifetime.
        self.storage.clear();
    }
}

/// A one-use kernel object lease. Drop always ends an outstanding collector;
/// cancelled requests cannot leave a later approval capable of settling a call.
pub struct CollectorProcess {
    process: Handle,
    job: Handle,
    deadline: Instant,
    completed: bool,
    owner: String,
    session: u32,
    logon: [u32; 2],
}
impl CollectorProcess {
    pub fn poll(&mut self) -> Result<Option<bool>> {
        ensure!(!self.completed, "collector result already consumed");
        ensure!(
            Instant::now() < self.deadline,
            "native owner authentication timed out"
        );
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                self.completed = true;
                let mut code = 0;
                unsafe { GetExitCodeProcess(self.process.0, &raw mut code) }?;
                let mut live = HANDLE::default();
                unsafe { WTSQueryUserToken(self.session, &raw mut live) }?;
                let live = Handle(live);
                ensure!(
                    token_sid(live.0)? == self.owner
                        && logon_identity(live.0)? == (self.session, self.logon),
                    "interactive owner logon ended during authentication"
                );
                ensure!(
                    Instant::now() < self.deadline,
                    "native owner authentication expired during final validation"
                );
                Ok(Some(code == VERIFIED_EXIT))
            }
            _ => Err(std::io::Error::last_os_error().into()),
        }
    }
}
impl Drop for CollectorProcess {
    fn drop(&mut self) {
        if !self.completed {
            let _ = unsafe { TerminateProcess(self.process.0, 1) };
            // Drain ordinary cancellation before SCM reports STOPPED, so the
            // installer can replace the mapped helper image without a race.
            let _ = unsafe { WaitForSingleObject(self.process.0, 5_000) };
        }
    }
}

/// Launch only the fixed installed collector. The broker retains its validated
/// image/directory leases until this call returns. No executable or mode can be
/// supplied, and this operation cannot be used outside SYSTEM.
pub fn launch(
    owner: &str,
    session: u32,
    logon: [u32; 2],
    challenge: &Challenge,
) -> Result<CollectorProcess> {
    let (process, thread) =
        create_suspended(&installed_helper_path()?, owner, session, logon, challenge)?;
    ensure!(
        unsafe { ResumeThread(thread.0) } == 1,
        "protected collector left its initial suspended state"
    );
    Ok(process)
}

fn create_suspended(
    installed_helper: &Path,
    owner: &str,
    session: u32,
    logon: [u32; 2],
    challenge: &Challenge,
) -> Result<(CollectorProcess, Handle)> {
    challenge.validate()?;
    let token = collector_token(owner, session, logon)?;
    let descriptor = descriptor("O:SYD:P(A;;GA;;;SY)(A;;0;;;OW)S:(ML;;NW;;;HI)")?;
    let security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())?,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: false.into(),
    };
    // An unnamed, non-inheritable SYSTEM-owned job also ends the collector if
    // the broker crashes before Rust can run the process lease's destructor.
    let job = Handle(unsafe { CreateJobObjectW(Some(&raw const security), None) }?);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())?,
        )
    }?;
    // WinNT.h PROCESS_CREATION_MITIGATION_POLICY_* constants: DEP, bottom-up
    // ASLR, strict handles, extension points off, dynamic code off, Microsoft
    // signed DLLs only, no remote/low-label images, prefer System32.
    let mitigation: u64 = 1
        | (1 << 16)
        | (1 << 24)
        | (1 << 32)
        | (1 << 36)
        | (1 << 44)
        | (1 << 52)
        | (1 << 56)
        | (1 << 60);
    let attributes = Attributes::new(&mitigation)?;
    let executable = wide(
        installed_helper
            .to_str()
            .context("invalid installed helper path")?,
    );
    let cwd = wide(
        installed_helper
            .parent()
            .context("missing installed helper directory")?
            .to_str()
            .context("invalid installed directory")?,
    );
    let serialized = serde_json::to_string(challenge)?;
    let mut command = wide(&format!(
        "{} --verify {}",
        crate::quote_argument(installed_helper.to_str().context("invalid helper path")?),
        crate::quote_argument(&serialized)
    ));
    // No inherited environment, standard handles, or caller-controlled DLL path.
    let environment = system_environment()?;
    let mut desktop = wide("winsta0\\default");
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>())?;
    startup.StartupInfo.lpDesktop = PWSTR(desktop.as_mut_ptr());
    startup.lpAttributeList = attributes.pointer;
    let mut output = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessAsUserW(
            Some(token.0),
            PCWSTR(executable.as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            Some(&raw const security),
            Some(&raw const security),
            false,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            Some(environment.as_ptr().cast()),
            PCWSTR(cwd.as_ptr()),
            &raw const startup.StartupInfo,
            &raw mut output,
        )
    }?;
    let process = CollectorProcess {
        process: Handle(output.hProcess),
        job,
        deadline: Instant::now() + Duration::from_secs(120),
        completed: false,
        owner: owner.into(),
        session,
        logon,
    };
    let thread = Handle(output.hThread);
    unsafe { AssignProcessToJobObject(process.job.0, process.process.0) }?;
    Ok((process, thread))
}

#[cfg(test)]
#[path = "native_test.rs"]
mod tests;
