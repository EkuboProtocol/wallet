//! Immutable committed identity in protected machine metadata. This records a
//! decision, not file promotion, active service readiness or cleanup permission.
use super::*;
use windows::Win32::{
    Foundation::{HLOCAL, LocalFree},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    },
    System::Registry::{
        KEY_ALL_ACCESS, REG_CREATE_KEY_DISPOSITION, REG_CREATED_NEW_KEY, REG_OPTION_NON_VOLATILE,
        RegCreateKeyExW, RegDeleteKeyExW, RegFlushKey, RegRenameKey, RegSetValueExW,
    },
};

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

pub(crate) fn record_cutover(owner: &str, expected_profile: uuid::Uuid) -> Result<()> {
    let identity = pending_installer_identity(owner)?;
    ensure!(
        identity.profile_id() == expected_profile,
        "cutover pending identity changed"
    );
    record_under(
        HKEY_LOCAL_MACHINE,
        &super::super::Configuration {
            owner_sid: identity.owner_sid().into(),
            service_sid: identity.service_sid().into(),
            profile_id: identity.profile_id(),
        },
        &machine_trustees()?,
    )
}

fn record_under(
    root: HKEY,
    configured: &super::super::Configuration,
    trusted: &[String],
) -> Result<()> {
    let software = open_component_access(root, "SOFTWARE", trusted, KEY_ALL_ACCESS)?
        .context("machine software registry is missing")?;
    let wallet = open_component_access(software.0, "EkuboWallet", trusted, KEY_ALL_ACCESS)?
        .context("wallet registry is missing")?;
    let parent =
        if let Some(key) = open_component_access(wallet.0, "Committed", trusted, KEY_ALL_ACCESS)? {
            key
        } else {
            create_new(wallet.0, "Committed", trusted)?
        };
    if let Some(existing) =
        open_component_access(parent.0, &configured.owner_sid, trusted, KEY_ALL_ACCESS)?
    {
        let identity = decode(&read_profile_value(existing.0)?, &configured.owner_sid)?;
        ensure!(
            identity.0 == *configured,
            "cutover decision conflicts with existing evidence"
        );
        unsafe { RegFlushKey(existing.0) }.ok()?;
    } else {
        publish(&parent, configured, trusted)?;
    }
    unsafe { RegFlushKey(parent.0) }.ok()?;
    unsafe { RegFlushKey(wallet.0) }.ok()?;
    let stored = open_component(parent.0, &configured.owner_sid, trusted)?
        .context("cutover decision is missing")?;
    ensure!(
        decode(&read_profile_value(stored.0)?, &configured.owner_sid)?.0 == *configured,
        "cutover decision readback mismatch"
    );
    Ok(())
}

fn create_new(parent: HKEY, component: &str, trusted: &[String]) -> Result<Key> {
    // These metadata identities contain no keys or private checkpoint payload.
    // Everyone may read; only Administrators and SYSTEM may modify the record.
    let sddl = wide("O:BAD:P(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KR;;;WD)");
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }?;
    let descriptor = Descriptor(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())?,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: false.into(),
    };
    let mut key = HKEY::default();
    let mut disposition = REG_CREATE_KEY_DISPOSITION::default();
    let name = wide(component);
    unsafe {
        RegCreateKeyExW(
            parent,
            PCWSTR(name.as_ptr()),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS | KEY_WOW64_64KEY,
            Some(&raw const attributes),
            &raw mut key,
            Some(&raw mut disposition),
        )
    }
    .ok()?;
    let key = Key(key);
    ensure!(
        disposition == REG_CREATED_NEW_KEY,
        "cutover registry creation raced an existing key"
    );
    validate_key(&key, trusted)?;
    Ok(key)
}

fn publish(
    parent: &Key,
    configured: &super::super::Configuration,
    trusted: &[String],
) -> Result<()> {
    let temporary = format!(".cutover-{}", uuid::Uuid::new_v4());
    let key = create_new(parent.0, &temporary, trusted)?;
    let name = wide("Profile");
    let temporary = wide(&temporary);
    let owner = wide(&configured.owner_sid);
    let bytes = serde_json::to_vec(configured)?;
    ensure!(
        bytes.len() <= MAX_CONFIG_BYTES,
        "cutover record is oversized"
    );
    let mut published = false;
    let result = (|| {
        unsafe { RegSetValueExW(key.0, PCWSTR(name.as_ptr()), None, REG_BINARY, Some(&bytes)) }
            .ok()?;
        unsafe { RegFlushKey(key.0) }.ok()?;
        ensure!(
            read_profile_value(key.0)? == bytes,
            "cutover temporary readback mismatch"
        );
        unsafe { RegRenameKey(parent.0, PCWSTR(temporary.as_ptr()), PCWSTR(owner.as_ptr())) }
            .ok()?;
        published = true;
        unsafe { RegFlushKey(parent.0) }.ok()?;
        Ok(())
    })();
    if result.is_err() && !published {
        // Delete only this invocation's unfinished leaf, never the final owner key.
        let _ = unsafe {
            RegDeleteKeyExW(
                parent.0,
                PCWSTR(temporary.as_ptr()),
                KEY_WOW64_64KEY.0,
                None,
            )
        };
    }
    result
}

#[cfg(test)]
#[path = "windows_cutover_config_native_test.rs"]
mod tests;
