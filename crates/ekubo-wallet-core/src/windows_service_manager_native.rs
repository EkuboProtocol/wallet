//! SCM callbacks and handle lifetime. No callback accepts a wallet operation.
// The Windows dispatcher owns callback invocation and argument storage. FFI and
// the status-handle threading guarantee are isolated in this native module.
#![allow(unsafe_code)]

use super::{Control, Phase, Reporter};
use anyhow::{Context as _, Result, anyhow, ensure};
use std::{
    ffi::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Mutex, OnceLock},
};
use tokio::sync::watch;
use windows::{
    Win32::{
        Foundation::{
            ERROR_CALL_NOT_IMPLEMENTED, ERROR_EXCEPTION_IN_SERVICE, ERROR_GEN_FAILURE,
            ERROR_SERVICE_SPECIFIC_ERROR, ERROR_SUCCESS,
        },
        System::Services::{
            RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
            SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
            SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
            SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
            SetServiceStatus, StartServiceCtrlDispatcherW,
        },
    },
    core::{PCWSTR, PWSTR, w},
};

type Host = fn(&str, Running, watch::Receiver<bool>) -> Result<()>;

struct Context {
    owner_sid: String,
    host: Host,
    stop: watch::Sender<bool>,
    control: Mutex<Option<Control<NativeReporter>>>,
    result: Mutex<Option<Result<()>>>,
}

static CONTEXT: OnceLock<Context> = OnceLock::new();

/// A host can announce availability after binding its locked endpoint. It
/// cannot undo an earlier stop request and carries no owner-presence proof.
pub struct Running(());

impl Running {
    pub fn ready(&self) -> Result<()> {
        let context = context()?;
        let mut control = context
            .control
            .lock()
            .map_err(|_| anyhow!("SCM control lock poisoned"))?;
        control
            .as_mut()
            .context("SCM handler is not registered")?
            .running()
    }
}

fn context() -> Result<&'static Context> {
    CONTEXT.get().context("SCM dispatcher is not initialized")
}

/// Run once on the process main thread. A console launch fails at the Windows
/// dispatcher; there is no local-authority fallback. SCM-supplied start
/// arguments cannot select custody: only the fixed owner selector is used,
/// and its protected metadata and actual primary token are validated first.
pub fn run(owner_sid: &str, host: Host) -> Result<()> {
    let (stop, _) = watch::channel(false);
    CONTEXT
        .set(Context {
            owner_sid: owner_sid.to_owned(),
            host,
            stop,
            control: Mutex::new(None),
            result: Mutex::new(None),
        })
        .map_err(|_| anyhow!("SCM dispatcher may only run once per process"))?;
    let table = [
        SERVICE_TABLE_ENTRYW {
            // Windows ignores this name for SERVICE_WIN32_OWN_PROCESS. The real
            // service name comes from ServiceMain and is verified against metadata.
            lpServiceName: PWSTR(w!("EkuboWallet").as_ptr().cast_mut()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: the terminated table lives until this blocking call returns. The
    // static context outlives every callback, including late control requests.
    unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }
        .context("cannot connect wallet service to SCM")?;
    context()?
        .result
        .lock()
        .map_err(|_| anyhow!("SCM result lock poisoned"))?
        .take()
        .context("SCM returned without running the wallet host")?
}

struct NativeReporter(SERVICE_STATUS_HANDLE);
// SAFETY: Microsoft permits SetServiceStatus from any service thread. The
// enclosing control mutex serializes calls and prevents reuse after STOPPED.
unsafe impl Send for NativeReporter {}

impl Reporter for NativeReporter {
    fn report(&mut self, phase: Phase, failed: bool) -> Result<()> {
        let status = status(phase, failed);
        // SAFETY: registration created this handle; Control emits STOPPED at
        // most once and prohibits any later status call. This is not a kernel
        // handle and must not be passed to CloseHandle.
        unsafe { SetServiceStatus(self.0, &raw const status) }.map_err(Into::into)
    }
}

fn status(phase: Phase, failed: bool) -> SERVICE_STATUS {
    let pending = matches!(phase, Phase::Starting | Phase::Stopping);
    SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: match phase {
            Phase::Starting => SERVICE_START_PENDING,
            Phase::Running => SERVICE_RUNNING,
            Phase::Stopping => SERVICE_STOP_PENDING,
            Phase::Stopped => SERVICE_STOPPED,
        },
        dwControlsAccepted: if phase == Phase::Running {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: if failed {
            ERROR_SERVICE_SPECIFIC_ERROR.0
        } else {
            ERROR_SUCCESS.0
        },
        dwServiceSpecificExitCode: u32::from(failed),
        dwCheckPoint: u32::from(pending),
        // No timer fabricates progress. A hung host must remain detectable.
        dwWaitHint: if pending { 30_000 } else { 0 },
    }
}

unsafe extern "system" fn service_main(count: u32, arguments: *mut PWSTR) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        ensure!(
            count >= 1 && !arguments.is_null(),
            "SCM omitted its service name"
        );
        // SAFETY: SCM owns count pointers for the duration of ServiceMain.
        let name = unsafe { *arguments };
        ensure!(
            !name.is_null(),
            "SCM provided an empty service name pointer"
        );
        // SAFETY: the first SCM argument is a NUL-terminated service name. No
        // client-controlled context pointer is retained or dereferenced.
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(PCWSTR(name.as_ptr()), Some(control_handler), None)
        }?;
        run_registered(handle, name)
    }))
    .unwrap_or_else(|_| Err(anyhow!("wallet service host panicked")));
    finish(result);
}

fn run_registered(handle: SERVICE_STATUS_HANDLE, name: PWSTR) -> Result<()> {
    let context = context()?;
    {
        let mut slot = context
            .control
            .lock()
            .map_err(|_| anyhow!("SCM control lock poisoned"))?;
        ensure!(slot.is_none(), "SCM invoked the service host twice");
        *slot = Some(Control::new(NativeReporter(handle), context.stop.clone()));
        slot.as_mut().context("SCM control missing")?.initialize()?;
    }
    let identity = crate::windows_service_config::service_identity(&context.owner_sid)?;
    let expected: Vec<u16> = identity
        .service_name()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: SCM supplies a valid NUL-terminated name. Read no farther than
    // its terminator, and bound comparison by the fixed expected service name.
    ensure!(
        unsafe { name_matches(name, &expected) },
        "SCM service name does not match installed identity"
    );
    (context.host)(&context.owner_sid, Running(()), context.stop.subscribe())
}

unsafe fn name_matches(name: PWSTR, expected: &[u16]) -> bool {
    for (index, expected) in expected.iter().enumerate() {
        // SAFETY: caller guarantees a NUL-terminated Windows string. Return
        // immediately on a mismatch, including an earlier NUL terminator.
        if unsafe { *name.as_ptr().add(index) } != *expected {
            return false;
        }
    }
    true
}

fn finish(result: Result<()>) {
    let Ok(context) = context() else { return };
    let failed = result.is_err();
    // Store the host result before reporting STOPPED: Windows may terminate
    // this process immediately afterward. All host cleanup has already run.
    let Ok(mut outcome) = context.result.lock() else {
        return;
    };
    *outcome = Some(result);
    drop(outcome);
    if let Ok(mut control) = context.control.lock()
        && let Some(control) = control.as_mut()
        && let Err(error) = control.finish(failed)
        && !failed
        && let Ok(mut outcome) = context.result.lock()
    {
        // A failed final status call is not a successful service exit.
        // Never retry the status handle, even on this failure path.
        *outcome = Some(Err(error.context("cannot report service stopped to SCM")));
    }
}

unsafe extern "system" fn control_handler(
    code: u32,
    _: u32,
    _: *mut c_void,
    _: *mut c_void,
) -> u32 {
    catch_unwind(AssertUnwindSafe(|| handle_control(code))).unwrap_or(ERROR_EXCEPTION_IN_SERVICE.0)
}

fn handle_control(code: u32) -> u32 {
    if code == SERVICE_CONTROL_INTERROGATE {
        return ERROR_SUCCESS.0;
    }
    if !matches!(code, SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN) {
        return ERROR_CALL_NOT_IMPLEMENTED.0;
    }
    let Ok(context) = context() else {
        return ERROR_GEN_FAILURE.0;
    };
    let Ok(mut control) = context.control.lock() else {
        context.stop.send_replace(true);
        return ERROR_GEN_FAILURE.0;
    };
    if let Some(control) = control.as_mut() {
        if control.request_stop().is_ok() {
            ERROR_SUCCESS.0
        } else {
            ERROR_GEN_FAILURE.0
        }
    } else {
        // A control delivered during registration must not be lost.
        context.stop.send_replace(true);
        ERROR_SUCCESS.0
    }
}

#[cfg(test)]
#[path = "windows_service_manager_native_test.rs"]
mod tests;
