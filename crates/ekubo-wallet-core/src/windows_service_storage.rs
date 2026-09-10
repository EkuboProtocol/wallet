//! Windows private-state validation and relative child reads. These checks do
//! not activate custody; protected root bootstrap, writes, and migration remain.

use crate::windows_security::AccessEntry;
use anyhow::{Result, ensure};

#[cfg(target_os = "windows")]
#[path = "windows_service_storage_native.rs"]
mod native;
#[cfg(target_os = "windows")]
pub use native::{open_private_child, validate_private_handle};

#[derive(Clone, Copy, Debug)]
pub enum StorageKind {
    Directory,
    File,
}

fn validate_component(component: &str) -> Result<()> {
    ensure!(
        !component.is_empty()
            && component.len() <= 128
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            && !component.ends_with('.'),
        "invalid private storage child name"
    );
    let stem = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    ensure!(
        !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            && !(stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9')),
        "reserved private storage child name"
    );
    Ok(())
}

fn validate_security(owner: &str, entries: &[AccessEntry], service_sid: &str) -> Result<()> {
    ensure!(
        crate::windows_service_identity::is_virtual_service_sid(service_sid),
        "private storage requires a dedicated service account"
    );
    ensure!(
        owner == service_sid,
        "private storage is not owned by the service"
    );
    for entry in entries {
        match entry {
            AccessEntry::Allow {
                sid,
                mask,
                inherit_only,
            } => ensure!(
                *inherit_only
                    || *mask == 0
                    || sid == service_sid
                    || matches!(sid.as_str(), "S-1-5-18" | "S-1-5-32-544"),
                "private storage grants access to an untrusted principal"
            ),
            AccessEntry::Deny => {}
            AccessEntry::Unsupported => {
                anyhow::bail!("private storage uses an unsupported access entry")
            }
        }
    }
    Ok(())
}

fn validate_metadata(attributes: u32, links: u32, kind: StorageKind) -> Result<()> {
    const DIRECTORY: u32 = 0x10;
    const REPARSE_POINT: u32 = 0x400;
    ensure!(
        attributes & REPARSE_POINT == 0,
        "private storage is a reparse point"
    );
    ensure!(
        (attributes & DIRECTORY != 0) == matches!(kind, StorageKind::Directory),
        "private storage has an unexpected file type"
    );
    if matches!(kind, StorageKind::File) {
        ensure!(links == 1, "private storage file has multiple or no links");
    }
    Ok(())
}

#[cfg(test)]
#[path = "windows_service_storage_test.rs"]
mod tests;
