//! Narrow privileged publication of an empty, relay-confirmed fresh profile.
use super::*;

pub struct InstallerLease {
    _lock: ProfileLock,
}

pub fn acquire_installer() -> Result<InstallerLease> {
    ensure!(
        rustix::process::getuid().as_raw() == 0 && rustix::process::geteuid().as_raw() == 0,
        "fresh installation requires root"
    );
    let root = root_directory()?;
    let etc = directory(&root, "etc", 0, false)?;
    let wallet = directory(&etc, "ekubo-wallet-v2", 0, false)?;
    Ok(InstallerLease {
        _lock: lock_profile(&wallet, 0)?,
    })
}

impl InstallerLease {
    /// Caller must first deliver the exact ciphertext and verify its receipt.
    /// Stop provisioning before publication. Existing active metadata/storage is
    /// never replaced, including an incomplete installation awaiting readiness.
    pub fn publish(
        &self,
        owner_uid: u32,
        relay: &WrappedDataKey,
        receipt: &crate::custody_relay::RelayReceipt,
    ) -> Result<()> {
        let identity = pending_installer_identity(owner_uid)?;
        receipt.verify_relay(identity.profile_id(), relay)?;
        write_configuration(&identity.configured, "relay-confirmed")?;
        self.resume(owner_uid)
    }

    /// Resume only an exact durable relay-confirmed fresh setup. No key is read,
    /// generated, transferred, or replaced. A published identity is immutable.
    pub fn resume(&self, owner_uid: u32) -> Result<()> {
        let root = root_directory()?;
        let configured = find_configuration_at(&root, owner_uid, 0, "relay-confirmed")?
            .context("fresh setup has no durable owner-relay confirmation")?;
        ensure!(
            find_configuration_at(&root, owner_uid, 0, "pending")? == Some(configured.clone()),
            "pending setup differs from relay confirmation"
        );
        if let Some(active) = find_owner_configuration(&root, owner_uid, 0)? {
            ensure!(
                active == configured,
                "installed profile differs from fresh setup"
            );
            return write_configuration(&configured, "owners");
        }
        let var = directory(&root, "var", 0, false)?;
        let lib = directory(&var, "lib", 0, false)?;
        let parent = directory(&lib, "ekubo-wallet-v2", 0, false)?;
        let pending = directory(&parent, "pending", 0, false)?;
        let name = configured.profile_id.to_string();
        let original = open_optional(
            &pending,
            &name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        )?;
        let moved = original.is_none();
        let profile = match original {
            Some(profile) => profile,
            None => directory(
                &parent,
                &owner_uid.to_string(),
                configured.service_uid,
                true,
            )?,
        };
        validate_directory(&profile, configured.service_uid, true)?;
        let _lock = ProfileLock::acquire(open_regular(
            &profile,
            "service.lock",
            configured.service_uid,
            true,
        )?)?;
        let ready = read_stage_record(&profile, configured.service_uid, "fresh-profile-ready")?;
        ensure!(
            ready.as_slice() == name.as_bytes(),
            "fresh profile is not ready"
        );
        if !moved {
            rustix::fs::renameat_with(
                &pending,
                &name,
                &parent,
                owner_uid.to_string(),
                RenameFlags::NOREPLACE,
            )?;
        }
        parent.sync_all()?;
        pending.sync_all()?;
        write_configuration(&configured, "owners")
    }
}

fn write_configuration(configured: &OwnerConfiguration, collection: &str) -> Result<()> {
    let root = root_directory()?;
    let etc = directory(&root, "etc", 0, false)?;
    let wallet = directory(&etc, "ekubo-wallet-v2", 0, false)?;
    let owners = directory(&wallet, collection, 0, false)?;
    if let Some(existing) = find_configuration_at(&root, configured.owner_uid, 0, collection)? {
        ensure!(existing == *configured, "fresh setup configuration changed");
        open_regular(&owners, &format!("{}.json", configured.owner_uid), 0, false)?.sync_all()?;
        owners.sync_all()?;
        return Ok(());
    }
    let bytes = serde_json::to_vec(configured)?;
    publish_private_with(&owners, &format!("{}.json", configured.owner_uid), |file| {
        rustix::fs::fchmod(&*file, Mode::from_raw_mode(0o644))?;
        file.write_all(&bytes)?;
        Ok(())
    })
}
