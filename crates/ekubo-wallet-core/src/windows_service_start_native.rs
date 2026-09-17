//! Local SCM handles stay on one blocking worker. No service creation,
//! configuration, stop, custom controls, or caller-selected start arguments.
#![allow(unsafe_code)]

use super::{Backend, State, activate};
use crate::windows_service_config::InstalledServiceIdentity;
use anyhow::{Context as _, Result, ensure};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::ERROR_SERVICE_ALREADY_RUNNING,
        System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE,
            SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
            SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED, StartServiceW,
        },
    },
    core::{HRESULT, PCWSTR},
};

struct Handle(SC_HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: each successful SCM open transfers its one owned handle here.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

struct Service(Handle);
impl Service {
    fn open(name: &str) -> Result<Self> {
        // SAFETY: null machine/database select only the local active SCM.
        let manager = Handle(unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT) }?);
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: the name comes from protected installed profile metadata.
        // Request only status and start, never configuration or stop rights.
        Ok(Self(Handle(unsafe {
            OpenServiceW(
                manager.0,
                PCWSTR(name.as_ptr()),
                SERVICE_QUERY_STATUS | SERVICE_START,
            )
        }?)))
    }
}

impl Backend for Service {
    fn state(&mut self) -> Result<State> {
        let mut status = SERVICE_STATUS::default();
        // SAFETY: a live service handle and writable status structure.
        unsafe { QueryServiceStatus(self.0.0, &raw mut status) }?;
        Ok(match status.dwCurrentState {
            SERVICE_STOPPED => State::Stopped,
            SERVICE_START_PENDING => State::Starting,
            SERVICE_RUNNING => State::Running,
            _ => State::Unavailable,
        })
    }

    fn start(&mut self) -> Result<()> {
        // SAFETY: owned start-capable handle, no start arguments. Another client
        // can win the race; its running state still has to be observed below.
        match unsafe { StartServiceW(self.0.0, None) } {
            Ok(()) => Ok(()),
            Err(error) if error.code() == HRESULT::from_win32(ERROR_SERVICE_ALREADY_RUNNING.0) => {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

struct Cancel(Arc<AtomicBool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Activate only this user's protected installed service before opening its
/// pipe. The installer must grant the owner `SERVICE_START` and `SERVICE_QUERY_STATUS`.
/// This neither authenticates the endpoint nor grants owner authorization.
/// Cancellation stops subsequent polling/start attempts; an SCM call already
/// in progress may finish, and an accepted start is never undone by stopping it.
pub async fn ensure_running(identity: &InstalledServiceIdentity) -> Result<()> {
    let owner = crate::windows_service_identity::current_process_identity()?;
    ensure!(
        owner.user_sid() == identity.owner_sid(),
        "installed service belongs to another owner"
    );
    let name = identity.service_name();
    let deadline = Instant::now() + Duration::from_secs(10);
    let canceled = Arc::new(AtomicBool::new(false));
    let _cancel = Cancel(canceled.clone());
    let worker = tokio::task::spawn_blocking(move || {
        let active = || !canceled.load(Ordering::Acquire) && Instant::now() < deadline;
        ensure!(active(), "wallet service activation ended or timed out");
        let mut service = Service::open(&name).context("cannot open installed wallet service")?;
        activate(&mut service, active, || {
            std::thread::sleep(Duration::from_millis(50));
        })
    });
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), worker)
        .await
        .context("wallet service activation timed out")??
}

#[cfg(test)]
#[path = "windows_service_start_native_test.rs"]
mod tests;
