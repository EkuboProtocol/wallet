//! Owner-created, installer-authenticated channels. Source and relay use distinct
//! fixed namespaces and prefaces; this module performs no credential lookup.
use anyhow::{Result, ensure};

pub const PREFACE: &[u8; 8] = b"EKUBORL1";
pub(crate) const SOURCE_PREFACE: &[u8; 8] = b"EKUBOSC1";
#[cfg(target_os = "windows")]
const ADMINISTRATORS: &str = "S-1-5-32-544";

fn name(endpoint: uuid::Uuid) -> Result<String> {
    ensure!(!endpoint.is_nil(), "invalid relay endpoint");
    Ok(format!(
        r"\\.\pipe\EkuboWallet.InstallerRelay.{}",
        endpoint.simple()
    ))
}

fn source_name(endpoint: uuid::Uuid) -> Result<String> {
    ensure!(!endpoint.is_nil(), "invalid source endpoint");
    Ok(format!(
        r"\\.\pipe\EkuboWallet.InstallerSource.{}",
        endpoint.simple()
    ))
}

#[cfg(target_os = "windows")]
#[path = "windows_relay_pipe_native.rs"]
mod native;
#[cfg(target_os = "windows")]
pub(crate) async fn connect_source(
    identity: &crate::windows_service_config::PendingInstallerIdentity,
    endpoint: uuid::Uuid,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    native::connect_source(identity, endpoint).await
}
#[cfg(target_os = "windows")]
pub use native::{ConnectedInstaller, OwnerRelayListener, connect};

#[cfg(test)]
#[path = "windows_relay_pipe_test.rs"]
mod tests;
