//! Installer-only Windows pending endpoint. Ordinary owner RPC never uses it.
use anyhow::{Result, ensure};

pub const PREFACE: &[u8; 8] = b"EKUBOPV1";
#[cfg(target_os = "windows")]
const ADMINISTRATORS: &str = "S-1-5-32-544";

fn name(profile: uuid::Uuid) -> Result<String> {
    ensure!(!profile.is_nil(), "invalid provisioning pipe profile");
    Ok(format!(
        r"\\.\pipe\EkuboWallet.Provision.{}",
        profile.simple()
    ))
}

#[cfg(target_os = "windows")]
#[path = "windows_provisioning_pipe_native.rs"]
mod native;
#[cfg(target_os = "windows")]
pub use native::{ConnectedInstaller, ProvisioningListener};

#[cfg(test)]
#[path = "windows_provisioning_pipe_test.rs"]
mod tests;
