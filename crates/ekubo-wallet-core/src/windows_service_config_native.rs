//! The registry handles and security descriptors here come only from fixed
//! machine keys. Unsafe code is confined to the Windows API ownership boundary.
#![allow(unsafe_code)]

use std::mem::size_of;

use anyhow::{Context as _, Result, ensure};
use windows::{
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS},
        Security::{
            DACL_SECURITY_INFORMATION, LookupAccountNameW, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE,
        },
        System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_BINARY, REG_OPTION_OPEN_LINK,
            REG_VALUE_TYPE, RegCloseKey, RegGetKeySecurity, RegOpenKeyExW, RegQueryValueExW,
        },
    },
    core::{PCWSTR, PWSTR},
};

use super::{
    InstalledServiceIdentity, MAX_CONFIG_BYTES, decode, validate_owner_component,
    validate_registry_security,
};
use crate::windows_service_identity::{
    current_process_identity, sid_string, verify_service_process,
};

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // This wrapper owns a successful RegOpenKeyExW result.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

pub fn installed_service_identity() -> Result<InstalledServiceIdentity> {
    find_installed_service_identity()?.context("wallet service is not installed")
}

/// Only absence of the protected installation keys means uninstalled. A
/// present owner key with missing, unreadable, or invalid metadata is an error.
pub fn find_installed_service_identity() -> Result<Option<InstalledServiceIdentity>> {
    read_configuration(current_process_identity()?.user_sid())
}

pub fn service_identity(owner_sid: &str) -> Result<InstalledServiceIdentity> {
    let identity = read_configuration(owner_sid)?.context("wallet service is not installed")?;
    verify_service_process(identity.service_sid())?;
    Ok(identity)
}

// Pending identities are confined to the storage bootstrap, never returned to
// desktop discovery or exposed as a public installed-identity constructor.
pub(crate) fn pending_service_identity(owner: &str) -> Result<InstalledServiceIdentity> {
    let identity = pending_configuration_under(HKEY_LOCAL_MACHINE, owner, &machine_trustees()?)?;
    verify_service_process(identity.service_sid())?;
    Ok(identity)
}

/// The caller already has installer authority. No elevation or fallback to an
/// active profile occurs, and the configured service SID/name is checked by the
/// same native registry reader as service bootstrap.
pub fn pending_installer_identity(owner: &str) -> Result<super::PendingInstallerIdentity> {
    crate::windows_service_identity::verify_installer_process()?;
    Ok(super::PendingInstallerIdentity(
        pending_configuration_under(HKEY_LOCAL_MACHINE, owner, &machine_trustees()?)?,
    ))
}

pub(crate) fn pending_owner_identity() -> Result<InstalledServiceIdentity> {
    let current = current_process_identity()?;
    pending_configuration_under(HKEY_LOCAL_MACHINE, current.user_sid(), &machine_trustees()?)
}

fn pending_configuration_under(
    root: HKEY,
    owner: &str,
    trusted: &[String],
) -> Result<InstalledServiceIdentity> {
    ensure!(
        read_configuration_under(root, owner, trusted)?.is_none(),
        "pending bootstrap cannot replace an active service profile"
    );
    read_configuration_at(root, owner, trusted, "Pending")?
        .context("pending service profile is missing")
}

fn account_sid(account: &str) -> Result<String> {
    let account = wide(account);
    let mut bytes = 0;
    let mut domain_chars = 0;
    let mut kind = SID_NAME_USE::default();
    let result = unsafe {
        LookupAccountNameW(
            None,
            PCWSTR(account.as_ptr()),
            None,
            &raw mut bytes,
            None,
            &raw mut domain_chars,
            &raw mut kind,
        )
    };
    ensure!(
        result.is_err_and(|error| error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult()),
        "cannot size service account SID"
    );
    ensure!(
        (8..=68).contains(&bytes) && domain_chars <= 32768,
        "invalid account identity size"
    );
    let mut sid = vec![0u32; (bytes as usize).div_ceil(size_of::<u32>())];
    let mut domain = vec![0u16; domain_chars as usize];
    let pointer = PSID(sid.as_mut_ptr().cast());
    unsafe {
        LookupAccountNameW(
            None,
            PCWSTR(account.as_ptr()),
            Some(pointer),
            &raw mut bytes,
            Some(PWSTR(domain.as_mut_ptr())),
            &raw mut domain_chars,
            &raw mut kind,
        )
    }?;
    // LookupAccountNameW populated this owned, aligned SID buffer.
    unsafe { sid_string(pointer) }
}

fn open_component(parent: HKEY, component: &str, trusted: &[String]) -> Result<Option<Key>> {
    let name = wide(component);
    let mut handle = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            parent,
            PCWSTR(name.as_ptr()),
            Some(REG_OPTION_OPEN_LINK.0),
            KEY_READ | KEY_WOW64_64KEY,
            &raw mut handle,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    status.ok()?;
    let key = Key(handle);
    let link = wide("SymbolicLinkValue");
    let mut size = 0;
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(link.as_ptr()),
            None,
            None,
            None,
            Some(&raw mut size),
        )
    };
    ensure!(
        status == ERROR_FILE_NOT_FOUND,
        "registry links are not supported"
    );
    validate_key(&key, trusted)?;
    Ok(Some(key))
}

pub(crate) fn machine_trustees() -> Result<Vec<String>> {
    Ok(vec![
        "S-1-5-18".to_owned(),
        "S-1-5-32-544".to_owned(),
        account_sid("NT SERVICE\\TrustedInstaller")?,
    ])
}

fn read_configuration(owner: &str) -> Result<Option<InstalledServiceIdentity>> {
    read_configuration_under(HKEY_LOCAL_MACHINE, owner, &machine_trustees()?)
}

// The public reader always uses HKLM. An explicit root permits native tests
// against disposable registry trees without provisioning a machine service.
fn read_configuration_under(
    root: HKEY,
    owner: &str,
    trusted: &[String],
) -> Result<Option<InstalledServiceIdentity>> {
    read_configuration_at(root, owner, trusted, "Owners")
}

fn read_configuration_at(
    root: HKEY,
    owner: &str,
    trusted: &[String],
    collection: &str,
) -> Result<Option<InstalledServiceIdentity>> {
    validate_owner_component(owner)?;
    let mut keys = Vec::new();
    let mut parent = root;
    for component in ["SOFTWARE", "EkuboWallet", collection, owner] {
        let Some(key) = open_component(parent, component, trusted)
            .with_context(|| format!("unsafe service registry component {component}"))?
        else {
            ensure!(
                component != "SOFTWARE",
                "machine software registry is missing"
            );
            return Ok(None);
        };
        parent = key.0;
        keys.push(key);
    }
    let name = wide("Profile");
    let mut kind = REG_VALUE_TYPE::default();
    let mut length = 0;
    unsafe {
        RegQueryValueExW(
            parent,
            PCWSTR(name.as_ptr()),
            None,
            Some(&raw mut kind),
            None,
            Some(&raw mut length),
        )
    }
    .ok()?;
    ensure!(
        kind == REG_BINARY && length as usize <= MAX_CONFIG_BYTES,
        "invalid registry profile value"
    );
    let mut bytes = vec![0u8; length as usize];
    unsafe {
        RegQueryValueExW(
            parent,
            PCWSTR(name.as_ptr()),
            None,
            Some(&raw mut kind),
            Some(bytes.as_mut_ptr()),
            Some(&raw mut length),
        )
    }
    .ok()?;
    ensure!(
        kind == REG_BINARY && length as usize <= bytes.len(),
        "registry profile changed while reading"
    );
    bytes.truncate(length as usize);
    let identity = decode(&bytes, owner)?;
    ensure!(
        account_sid(&format!("NT SERVICE\\{}", identity.service_name()))? == identity.service_sid(),
        "configured service SID does not match its installed name"
    );
    // Keep every validated ancestor open until all metadata has been checked.
    drop(keys);
    Ok(Some(identity))
}

fn validate_key(key: &Key, trusted: &[String]) -> Result<()> {
    let information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut length = 0;
    let status = unsafe { RegGetKeySecurity(key.0, information, None, &raw mut length) };
    ensure!(
        status == ERROR_INSUFFICIENT_BUFFER && (20..=131_072).contains(&length),
        "invalid registry security descriptor size"
    );
    let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    let descriptor = PSECURITY_DESCRIPTOR(buffer.as_mut_ptr().cast());
    let capacity = length;
    let status =
        unsafe { RegGetKeySecurity(key.0, information, Some(descriptor), &raw mut length) };
    ensure!(
        status == ERROR_SUCCESS && length <= capacity,
        "cannot read registry security descriptor"
    );
    // RegGetKeySecurity wrote a self-relative descriptor in the owned buffer.
    unsafe { validate_descriptor(descriptor, trusted) }
}

unsafe fn validate_descriptor(descriptor: PSECURITY_DESCRIPTOR, trusted: &[String]) -> Result<()> {
    // SAFETY: the caller holds the complete OS-provided descriptor buffer.
    let (owner, entries) = unsafe { crate::windows_security::read_descriptor(descriptor) }?;
    validate_registry_security(&owner, Some(&entries), trusted)
}

#[cfg(test)]
#[path = "windows_service_config_native_test.rs"]
mod tests;
