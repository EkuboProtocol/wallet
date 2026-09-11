//! Public installer metadata for one Windows owner. Only the native protected
//! machine-registry reader can construct an installed identity. No key, storage
//! path, owner authorization, or custody activation is carried by this type.

use anyhow::{Result, ensure};
use serde::Deserialize;
use uuid::Uuid;

#[cfg(target_os = "windows")]
#[path = "windows_service_config_native.rs"]
mod native;
#[cfg(target_os = "windows")]
pub use native::{
    find_installed_service_identity, installed_service_identity, pending_installer_identity,
    service_identity,
};
#[cfg(target_os = "windows")]
pub(crate) use native::{machine_trustees, pending_owner_identity, pending_service_identity};

/// Read protected pending metadata for the actual primary-token owner. The
/// identity reader rejects thread impersonation; service SIDs are not owners.
#[cfg(target_os = "windows")]
pub fn pending_owner_profile() -> Result<Uuid> {
    Ok(pending_owner_identity()?.profile_id())
}

const MAX_CONFIG_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    owner_sid: String,
    service_sid: String,
    profile_id: Uuid,
}

#[derive(Debug)]
pub struct InstalledServiceIdentity(Configuration);

/// Protected pending metadata for a privileged installer. This cannot be passed
/// to desktop discovery, active storage initialization, or the owner pipe.
#[derive(Debug)]
pub struct PendingInstallerIdentity(InstalledServiceIdentity);

impl PendingInstallerIdentity {
    #[must_use]
    pub fn owner_sid(&self) -> &str {
        self.0.owner_sid()
    }
    #[must_use]
    pub fn service_sid(&self) -> &str {
        self.0.service_sid()
    }
    #[must_use]
    pub const fn profile_id(&self) -> Uuid {
        self.0.profile_id()
    }
}

impl InstalledServiceIdentity {
    #[must_use]
    pub fn owner_sid(&self) -> &str {
        &self.0.owner_sid
    }
    #[must_use]
    pub fn service_sid(&self) -> &str {
        &self.0.service_sid
    }
    #[must_use]
    pub const fn profile_id(&self) -> Uuid {
        self.0.profile_id
    }
    #[must_use]
    pub fn service_name(&self) -> String {
        format!("EkuboWallet-{}", self.0.profile_id.simple())
    }
}

pub(crate) fn validate_owner_component(owner: &str) -> Result<()> {
    // This is only a safe registry component check. Client identity originates
    // in the primary token, and service callers must match protected metadata.
    ensure!(
        owner.starts_with("S-1-")
            && owner.len() <= 184
            && owner
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "invalid owner SID registry component"
    );
    ensure!(
        !matches!(owner, "S-1-5-18" | "S-1-5-19" | "S-1-5-20") && !owner.starts_with("S-1-5-80-"),
        "a service account cannot be a wallet owner"
    );
    Ok(())
}

fn decode(bytes: &[u8], expected_owner: &str) -> Result<InstalledServiceIdentity> {
    validate_owner_component(expected_owner)?;
    ensure!(
        bytes.len() <= MAX_CONFIG_BYTES,
        "service configuration is oversized"
    );
    let config: Configuration = serde_json::from_slice(bytes)?;
    ensure!(
        config.owner_sid == expected_owner,
        "service configuration belongs to another owner"
    );
    ensure!(
        crate::windows_service_identity::is_virtual_service_sid(&config.service_sid)
            && config.service_sid != config.owner_sid
            && !config.profile_id.is_nil(),
        "invalid configured Windows service identity"
    );
    Ok(InstalledServiceIdentity(config))
}

use crate::windows_security::AccessEntry as RegistryAce;

fn validate_registry_security(
    owner: &str,
    entries: Option<&[RegistryAce]>,
    trusted: &[String],
) -> Result<()> {
    const READ_ONLY: u32 = 0x8000_0000 | 0x2000_0000 | 0x0002_0000 | 0x19;
    ensure!(
        trusted.iter().any(|sid| sid == owner),
        "registry key has an untrusted owner"
    );
    let entries =
        entries.ok_or_else(|| anyhow::anyhow!("registry key has an unrestricted DACL"))?;
    // GENERIC_READ, GENERIC_EXECUTE, READ_CONTROL, and query/enumerate/notify.
    // Any other permission granted to an untrusted principal is rejected,
    // including deletion, creation, value writes, and ownership/ACL changes.
    for entry in entries {
        match entry {
            RegistryAce::Allow {
                sid,
                mask,
                inherit_only,
                ..
            } => ensure!(
                *inherit_only
                    // CREATOR OWNER is an inheritance placeholder, not a
                    // principal in an access token. Its resolved child ACE is
                    // checked independently when we open that child. The key's
                    // actual owner must still be a machine trustee above.
                    || sid == "S-1-3-0"
                    || mask & !READ_ONLY == 0
                    || trusted.iter().any(|writer| writer == sid),
                "registry key grants mutation rights to untrusted principal {sid} (mask {mask:#010x})"
            ),
            RegistryAce::Deny => {}
            RegistryAce::Unsupported => {
                anyhow::bail!("registry key uses an unsupported access entry")
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "windows_service_config_test.rs"]
mod tests;
