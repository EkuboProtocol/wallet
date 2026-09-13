//! HWND-owned Windows Hello. This executable is launched only inside the
//! broker-created process boundary; it has no wallet, file, or signing APIs.
#![allow(unsafe_code)]

use crate::Challenge;
use anyhow::{Context as _, Result, ensure};
use std::time::{Duration, Instant};
use windows::{
    Security::Credentials::UI::UserConsentVerificationResult,
    Win32::{
        Foundation::{FreeLibrary, HMODULE, HWND},
        System::{
            LibraryLoader::{
                GET_MODULE_HANDLE_EX_FLAG_PIN, GetModuleHandleExW, GetProcAddress,
                LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW, SetDefaultDllDirectories,
            },
            Registry::{
                HKEY, HKEY_CLASSES_ROOT, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY,
                RegCloseKey, RegDisablePredefinedCacheEx, RegOpenKeyExW, RegOverridePredefKey,
            },
            WinRT::{
                IActivationFactory, IUserConsentVerifierInterop, RO_INIT_MULTITHREADED,
                RoInitialize, RoUninitialize,
            },
        },
        UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, DispatchMessageW, IsWindow, MSG, PM_REMOVE,
            PeekMessageW, SetForegroundWindow, TranslateMessage, WINDOW_EX_STYLE, WM_QUIT,
            WS_CAPTION, WS_SYSMENU, WS_VISIBLE,
        },
    },
    core::{HRESULT, HSTRING, Interface as _, PCWSTR, s, w},
};
use windows_future::{AsyncStatus, IAsyncOperation};

struct Apartment;
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}
struct Window(HWND);
impl Drop for Window {
    fn drop(&mut self) {
        let _ = unsafe { DestroyWindow(self.0) };
    }
}

struct RegistryIsolation {
    classes: HKEY,
}
impl RegistryIsolation {
    fn establish() -> Result<Self> {
        // This is a per-process classes view, not a registry write. Native COM
        // activation must not select a same-user class registration. User data
        // remains available to Windows itself under the actual owner's token.
        unsafe { RegDisablePredefinedCacheEx() }.ok()?;
        let mut classes = HKEY::default();
        unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                w!("SOFTWARE\\Classes"),
                None,
                KEY_READ | KEY_WOW64_64KEY,
                &raw mut classes,
            )
        }
        .ok()?;
        let result = Self { classes };
        unsafe { RegOverridePredefKey(HKEY_CLASSES_ROOT, Some(result.classes)) }.ok()?;
        Ok(result)
    }
}
impl Drop for RegistryIsolation {
    fn drop(&mut self) {
        // Keep the redirected views until every WinRT object/apartment is gone.
        let _ = unsafe { RegOverridePredefKey(HKEY_CLASSES_ROOT, None) };
        let _ = unsafe { RegCloseKey(self.classes) };
    }
}

struct SystemFactoryLibrary(HMODULE);
type Activate =
    unsafe extern "system" fn(*mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> HRESULT;
impl Drop for SystemFactoryLibrary {
    fn drop(&mut self) {
        let _ = unsafe { FreeLibrary(self.0) };
    }
}

fn system_factory() -> Result<(SystemFactoryLibrary, IUserConsentVerifierInterop)> {
    // Pin the OS implementation directly instead of allowing per-user WinRT
    // registration to choose the activation DLL. Never search PATH or cwd.
    let library = SystemFactoryLibrary(unsafe {
        LoadLibraryExW(
            w!("Windows.Security.Credentials.UI.UserConsentVerifier.dll"),
            None,
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }?);
    // Async WinRT work can retain DLL code after local interface references are
    // released. Pin this single fixed OS module until this short-lived process
    // exits instead of racing asynchronous teardown with FreeLibrary.
    let mut pinned = HMODULE::default();
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_PIN,
            w!("Windows.Security.Credentials.UI.UserConsentVerifier.dll"),
            &raw mut pinned,
        )
    }?;
    let address = unsafe { GetProcAddress(library.0, s!("DllGetActivationFactory")) }
        .context("Windows native consent activation export is unavailable")?;
    // SAFETY: the named Windows Runtime export has this documented ABI; HSTRING
    // is the windows crate's transparent native HSTRING representation.
    let activate: Activate = unsafe { std::mem::transmute(address) };
    let class = HSTRING::from("Windows.Security.Credentials.UI.UserConsentVerifier");
    let mut factory = std::ptr::null_mut();
    unsafe { activate(std::mem::transmute_copy(&class), &raw mut factory) }.ok()?;
    ensure!(
        !factory.is_null(),
        "Windows returned an empty native consent factory"
    );
    let factory = unsafe { IActivationFactory::from_raw(factory) };
    let interop = factory.cast::<IUserConsentVerifierInterop>()?;
    Ok((library, interop))
}

#[cfg(test)]
#[path = "hello_test.rs"]
mod tests;

pub fn collect(challenge: &Challenge) -> Result<bool> {
    challenge.validate()?;
    // Startup image-load policy already excludes foreign DLLs before main.
    // Runtime loads use System32 only, without cwd/PATH/application directories.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) }?;
    let _registry = RegistryIsolation::establish()?;
    unsafe { RoInitialize(RO_INIT_MULTITHREADED) }?;
    let _apartment = Apartment;
    let title = crate::native::wide(&format!("Ekubo Wallet 2 — {}", challenge.reason));
    let window = Window(unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("STATIC"),
            PCWSTR(title.as_ptr()),
            WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            100,
            100,
            680,
            160,
            None,
            None,
            None,
            None,
        )
    }?);
    let _ = unsafe { SetForegroundWindow(window.0) };
    let (_library, factory) = system_factory()?;
    let message = HSTRING::from(format!(
        "Ekubo Wallet 2: {}. Operation {}",
        challenge.reason, challenge.operation_digest
    ));
    let operation: IAsyncOperation<UserConsentVerificationResult> =
        unsafe { factory.RequestVerificationForWindowAsync(window.0, &message) }?;
    let deadline = Instant::now() + Duration::from_secs(115);
    while operation.Status()? == AsyncStatus::Started {
        if Instant::now() >= deadline || !unsafe { IsWindow(Some(window.0)) }.as_bool() {
            operation.Cancel()?;
            return Ok(false);
        }
        let mut message = MSG::default();
        while unsafe { PeekMessageW(&raw mut message, None, 0, 0, PM_REMOVE) }.as_bool() {
            if message.message == WM_QUIT {
                operation.Cancel()?;
                return Ok(false);
            }
            unsafe {
                let _ = TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    ensure!(Instant::now() < deadline, "native consent expired");
    Ok(operation.Status()? == AsyncStatus::Completed
        && operation.GetResults()? == UserConsentVerificationResult::Verified)
}
