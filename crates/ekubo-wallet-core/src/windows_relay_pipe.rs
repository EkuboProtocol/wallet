//! Owner-created, installer-authenticated local relay channel. No custody keys.
use anyhow::{Result, ensure};

pub const PREFACE: &[u8; 8] = b"EKUBORL1";
#[cfg(target_os = "windows")]
const ADMINISTRATORS: &str = "S-1-5-32-544";

fn name(endpoint: uuid::Uuid) -> Result<String> {
    ensure!(!endpoint.is_nil(), "invalid relay endpoint");
    Ok(format!(
        r"\\.\pipe\EkuboWallet.InstallerRelay.{}",
        endpoint.simple()
    ))
}

#[cfg(target_os = "windows")]
#[path = "windows_relay_pipe_native.rs"]
mod native;
#[cfg(target_os = "windows")]
pub use native::{ConnectedInstaller, OwnerRelayListener, connect};

#[cfg(test)]
#[path = "windows_relay_pipe_test.rs"]
mod tests;
