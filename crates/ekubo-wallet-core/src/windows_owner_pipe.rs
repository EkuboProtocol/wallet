//! Authenticated local Windows owner-pipe endpoints. This establishes OS peer
//! identity, not human presence or authorization for an owner operation.

use crate::windows_security::AccessEntry;
use anyhow::{Result, ensure};

#[cfg(target_os = "windows")]
#[path = "windows_owner_pipe_native.rs"]
mod native;
#[cfg(target_os = "windows")]
pub use native::{ConnectedOwnerPipe, OwnerPipeListener, connect};
#[cfg(target_os = "windows")]
pub(crate) use native::{
    authenticate_installer_client, create as create_private_pipe,
    open_available as open_private_pipe,
};

// FILE_GENERIC_READ plus FILE_WRITE_DATA: include the standard read-side pipe
// attribute/EA queries. Avoid FILE_GENERIC_WRITE: its FILE_APPEND_DATA bit also
// authorizes server-instance creation. No client attribute/EA/security writes.
const CLIENT_ACCESS: u32 = 0x0012_008b;

fn name(profile: uuid::Uuid) -> Result<String> {
    ensure!(!profile.is_nil(), "invalid owner pipe profile");
    Ok(format!(r"\\.\pipe\EkuboWallet.Owner.{}", profile.simple()))
}

fn validate_security(
    owner: &str,
    entries: &[AccessEntry],
    service: &str,
    desktop: &str,
) -> Result<()> {
    ensure!(
        owner == service,
        "owner pipe is not owned by the installed service"
    );
    for entry in entries {
        match entry {
            AccessEntry::Allow { sid, mask, .. } => ensure!(
                *mask == 0
                    || sid == service
                    || sid == "S-1-5-18"
                    || (sid == desktop && mask & !CLIENT_ACCESS == 0),
                "owner pipe grants untrusted server creation or access"
            ),
            AccessEntry::Deny => {}
            AccessEntry::Unsupported => anyhow::bail!("unsupported owner pipe access entry"),
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "windows_owner_pipe_test.rs"]
mod tests;
