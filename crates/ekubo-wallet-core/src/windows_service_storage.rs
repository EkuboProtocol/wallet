//! Windows protected profile bootstrap and relative child reads. These checks
//! do not activate custody; provisioning, writes, and migration remain separate.

use crate::windows_security::AccessEntry;
use anyhow::{Result, ensure};

#[cfg(target_os = "windows")]
#[path = "windows_service_storage_native.rs"]
mod native;
#[cfg(target_os = "windows")]
pub use native::{PrivateStorageRoot, open_private_child, validate_private_handle};

#[derive(Clone, Copy, Debug)]
pub enum StorageKind {
    Directory,
    File,
}

fn machine_path(path: &str) -> Result<(String, Vec<&str>)> {
    let bytes = path.as_bytes();
    ensure!(
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":\\",
        "machine storage requires an absolute local drive path"
    );
    let components: Vec<_> = path[3..].split('\\').collect();
    for component in &components {
        ensure!(
            !component.is_empty()
                && component.encode_utf16().count() <= 255
                && !component.ends_with(['.', ' '])
                && !component
                    .chars()
                    .any(|character| character.is_control() || "<>:\"/\\|?*".contains(character)),
            "invalid machine storage path component"
        );
    }
    Ok((path[..3].to_ascii_uppercase(), components))
}

fn validate_machine_security(
    owner: &str,
    entries: &[AccessEntry],
    trusted: &[String],
    allow_child_creation: bool,
) -> Result<()> {
    ensure!(
        trusted.iter().any(|sid| sid == owner),
        "machine storage directory has an untrusted owner"
    );
    // Shared OS directories may let users create siblings. Existing protected
    // children are checked independently; deletion, ACL/owner changes, and
    // attribute-write rights are never accepted. Native callers
    // retain handles that deny data-write and delete sharing during traversal.
    let permitted =
        0x8000_0000 | 0x2000_0000 | 0x0012_0000 | 0xa9 | if allow_child_creation { 0x6 } else { 0 };
    for entry in entries {
        match entry {
            AccessEntry::Allow {
                sid,
                mask,
                inherit_only,
            } => ensure!(
                *inherit_only
                    || mask & !permitted == 0
                    || trusted.iter().any(|trusted| trusted == sid),
                "machine storage directory grants untrusted mutation rights"
            ),
            AccessEntry::Deny => {}
            AccessEntry::Unsupported => {
                anyhow::bail!("machine storage directory uses an unsupported access entry")
            }
        }
    }
    Ok(())
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
