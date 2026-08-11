//! Current-user launch-at-login registration for the tray-first desktop app.

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

/// Install an idempotent current-user login registration for this executable.
pub fn enable() -> Result<()> {
    let executable = std::env::current_exe().context("could not locate the wallet executable")?;
    ensure!(
        executable.is_absolute(),
        "wallet executable path is not absolute"
    );
    enable_executable(&executable)
}

#[cfg(target_os = "macos")]
fn enable_executable(executable: &Path) -> Result<()> {
    let base = BaseDirs::new().context("could not determine the user home directory")?;
    let directory = base.home_dir().join("Library/LaunchAgents");
    let path = directory.join("org.ekubo.wallet.plist");
    let executable = xml_escape(&executable.to_string_lossy());
    let document = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>org.ekubo.wallet</string><key>ProgramArguments</key><array><string>{executable}</string><string>{HIDDEN_STARTUP_ARGUMENT}</string></array><key>RunAtLoad</key><true/></dict></plist>\n"
    );
    write_atomic(&path, document.as_bytes())
}

#[cfg(target_os = "linux")]
fn enable_executable(executable: &Path) -> Result<()> {
    let base = BaseDirs::new().context("could not determine the user config directory")?;
    let path = base.config_dir().join("autostart/org.ekubo.wallet.desktop");
    let executable = desktop_exec_escape(&executable.to_string_lossy());
    let document = format!(
        "[Desktop Entry]\nType=Application\nName=Ekubo Wallet\nComment=Start the Ekubo Wallet tray service\nExec=\"{executable}\" {HIDDEN_STARTUP_ARGUMENT}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
    );
    write_atomic(&path, document.as_bytes())
}

#[cfg(target_os = "windows")]
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

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn enable_executable(_executable: &Path) -> Result<()> {
    anyhow::bail!("launch at login is unsupported on this platform")
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

#[cfg(target_os = "linux")]
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
