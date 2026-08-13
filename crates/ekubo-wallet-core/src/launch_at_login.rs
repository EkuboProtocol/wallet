//! Core-enforced current-user launch registration.
//!
//! Enabling persistence expands the wallet's execution and listener surface,
//! so it requires the same sealed authorization that granted agent access.
//! Disabling it only removes authority and is deliberately authorization-free.

use crate::human_presence::{OwnerAuthorization, OwnerAuthorizationScope};
use anyhow::{Context, Result, ensure};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use directories::BaseDirs;
use std::path::Path;
#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::{fs, io::Write as _};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use tempfile::NamedTempFile;

const HIDDEN_STARTUP_ARGUMENT: &str = "--hidden-startup";

/// Install the exact wallet login registration after core verifies the agent
/// access grant that justifies it.
pub fn enable(authorization: &OwnerAuthorization) -> Result<()> {
    authorization.require(OwnerAuthorizationScope::AgentAccess)?;
    let executable = std::env::current_exe().context("could not locate the wallet executable")?;
    ensure!(
        executable.is_absolute(),
        "wallet executable path is not absolute"
    );
    enable_executable(&executable)
}

/// Remove the exact wallet login registration. This is idempotent and never
/// asks for owner authorization because it can only reduce attack surface.
pub fn disable() -> Result<()> {
    disable_registration()
}

#[cfg(target_os = "macos")]
fn registration_path() -> Result<std::path::PathBuf> {
    Ok(BaseDirs::new()
        .context("could not determine the user home directory")?
        .home_dir()
        .join("Library/LaunchAgents/org.ekubo.wallet.plist"))
}

#[cfg(target_os = "linux")]
fn registration_path() -> Result<std::path::PathBuf> {
    Ok(BaseDirs::new()
        .context("could not determine the user config directory")?
        .config_dir()
        .join("autostart/org.ekubo.wallet.desktop"))
}

#[cfg(target_os = "macos")]
fn enable_executable(executable: &Path) -> Result<()> {
    let path = registration_path()?;
    let executable = xml_escape(&executable.to_string_lossy());
    let document = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>org.ekubo.wallet</string><key>ProgramArguments</key><array><string>{executable}</string><string>{HIDDEN_STARTUP_ARGUMENT}</string></array><key>RunAtLoad</key><true/></dict></plist>\n"
    );
    write_atomic(&path, document.as_bytes())
}

#[cfg(target_os = "linux")]
fn enable_executable(executable: &Path) -> Result<()> {
    let path = registration_path()?;
    let executable = desktop_exec_escape(&executable.to_string_lossy());
    let document = format!(
        "[Desktop Entry]\nType=Application\nName=Ekubo Wallet\nComment=Start the Ekubo Wallet tray service\nExec=\"{executable}\" {HIDDEN_STARTUP_ARGUMENT}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
    );
    write_atomic(&path, document.as_bytes())
}

#[cfg(windows)]
fn enable_executable(executable: &Path) -> Result<()> {
    let value = format!(
        "\"{}\" {HIDDEN_STARTUP_ARGUMENT}",
        executable.to_string_lossy()
    );
    let status = Command::new("reg.exe")
        .args([
            "ADD",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "EkuboWallet",
            "/t",
            "REG_SZ",
            "/d",
            &value,
            "/f",
        ])
        .status()
        .context("could not update the current-user startup registry")?;
    ensure!(
        status.success(),
        "Windows rejected the startup registration"
    );
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn disable_registration() -> Result<()> {
    remove_exact_file(&registration_path()?)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn remove_exact_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("could not remove {}", path.display())),
    }
}

#[cfg(windows)]
fn disable_registration() -> Result<()> {
    let query = Command::new("reg.exe")
        .args([
            "QUERY",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "EkuboWallet",
        ])
        .status()
        .context("could not inspect the current-user startup registry")?;
    if !query.success() {
        return Ok(());
    }
    let status = Command::new("reg.exe")
        .args([
            "DELETE",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "EkuboWallet",
            "/f",
        ])
        .status()
        .context("could not remove the current-user startup registry value")?;
    ensure!(status.success(), "Windows rejected startup removal");
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn enable_executable(_executable: &Path) -> Result<()> {
    anyhow::bail!("launch at login is unsupported on this platform")
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn disable_registration() -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("startup registration has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("could not create {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("could not install {}", path.display()))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(any(test, target_os = "linux"))]
fn desktop_exec_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$")
}

#[cfg(test)]
#[path = "launch_at_login_test.rs"]
mod tests;
