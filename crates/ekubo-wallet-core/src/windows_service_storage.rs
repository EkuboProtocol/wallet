//! Windows protected profile bootstrap, relative reads, and immutable encrypted
//! key creation after protected enrollment unlock. This object does not switch
//! the application's credential backend; provisioning, deletion, transport
//! integration, and migration remain separate.

use crate::windows_security::AccessEntry;
use anyhow::{Result, ensure};

#[cfg(target_os = "windows")]
#[path = "windows_service_storage_native.rs"]
mod native;
#[cfg(target_os = "windows")]
pub use native::{
    PendingCredentialStorage, PrivateStorageRoot, installer_journal, open_private_child,
    validate_private_handle,
};

#[derive(Clone, Copy, Debug)]
pub enum StorageKind {
    Directory,
    File,
}

/// Fixed mutable files used by `SQLCipher` and its initialization lock.
#[derive(Clone, Copy, Debug)]
pub enum DatabaseFile {
    Database,
    Lock,
    ConfigurationLock,
    LifecycleLock,
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
    shared_os_ancestor: bool,
) -> Result<()> {
    ensure!(
        trusted.iter().any(|sid| sid == owner),
        "machine storage directory has an untrusted owner: {owner}"
    );
    // ProgramData permits child creation and EA/attribute writes. Attribute
    // writers can set reparse points even with no write sharing, so this policy
    // is only one part of the native bootstrap: no-reparse relative opens,
    // retained children that prevent emptying each ancestor, then a final
    // metadata check are required. Never permit deletion or ACL/owner changes.
    // Wallet-owned machine directories do not allow these shared-OS rights.
    let permitted =
        0x8000_0000 | 0x2000_0000 | 0x0012_0000 | 0xa9 | if shared_os_ancestor { 0x116 } else { 0 };
    for entry in entries {
        match entry {
            AccessEntry::Allow {
                sid,
                mask,
                inherit_only,
                ..
            } => ensure!(
                *inherit_only
                    || mask & !permitted == 0
                    || trusted.iter().any(|trusted| trusted == sid),
                "machine storage directory grants untrusted mutation rights: SID {sid}, mask {mask:#010x}"
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
                ..
            } => ensure!(
                (*inherit_only && sid == "S-1-3-0")
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

// SQLite creates transient files using inherited directory permissions. Require
// an explicit service grant for those files; a token's default DACL is not a
// custody policy. validate_security also checks inheritance-only trustees.
fn validate_directory_inheritance(entries: &[AccessEntry], service_sid: &str) -> Result<()> {
    const GENERIC_ALL: u32 = 0x1000_0000;
    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
    ensure!(
        entries.iter().any(|entry| matches!(entry,
            AccessEntry::Allow { sid, mask, object_inherit: true, .. }
                if sid == service_sid
                    && (mask & GENERIC_ALL != 0 || mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS)
        )),
        "private directory lacks an inheritable service file grant"
    );
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
