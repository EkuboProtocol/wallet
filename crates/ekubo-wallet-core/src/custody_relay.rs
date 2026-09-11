//! Desktop access to the opaque service data-key envelope. This namespace never
//! contains an account key, database key, or service wrapping key.

use crate::custody_envelope::WrappedDataKey;
use anyhow::{Result, ensure};
use uuid::Uuid;

pub(crate) const SERVICE: &str = "org.ekubo.wallet.custody-envelope";

/// The caller obtains this profile from protected installer configuration after
/// authenticating its service. There is no filesystem cache or fallback. This
/// read grants no signing rights and performs no enrollment or credential write.
pub fn load(profile: Uuid) -> Result<WrappedDataKey> {
    ensure!(!profile.is_nil(), "invalid custody relay profile");
    let bytes = zeroize::Zeroizing::new(
        crate::credential_store::entry(SERVICE, &profile.to_string())?.get_secret()?,
    );
    WrappedDataKey::from_bytes(&bytes)
}

/// Persist only the opaque relay for this process owner's protected pending
/// profile. The installer must deliver it over an authenticated handoff and
/// verify its receipt before activation. This never writes an account/database
/// key, changes signing policy, or supplies an owner-authorization proof.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn persist_pending(profile: Uuid, relay: &WrappedDataKey) -> Result<()> {
    #[cfg(target_os = "linux")]
    let pending = crate::service_storage::pending_owner_profile()?;
    #[cfg(target_os = "windows")]
    let pending = crate::windows_service_config::pending_owner_profile()?;
    ensure!(
        pending == profile && !profile.is_nil(),
        "relay does not belong to this owner's pending profile"
    );
    let entry = crate::credential_store::entry(SERVICE, &profile.to_string())?;
    ensure!(
        matches!(&entry, crate::credential_store::Entry::Platform(_)),
        "custody relay requires the owner's platform credential store"
    );
    persist_with(
        relay,
        || entry.get_secret(),
        |bytes| entry.set_secret(bytes),
    )
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn persist_with(
    relay: &WrappedDataKey,
    mut read: impl FnMut() -> keyring::Result<Vec<u8>>,
    write: impl FnOnce(&[u8]) -> keyring::Result<()>,
) -> Result<()> {
    match read() {
        Ok(bytes) => {
            let bytes = zeroize::Zeroizing::new(bytes);
            ensure!(
                bytes.as_slice() == relay.as_bytes(),
                "pending relay conflicts with an existing credential"
            );
            return Ok(());
        }
        Err(keyring::Error::NoEntry) => {}
        Err(error) => return Err(error.into()),
    }
    // The user's credential store is mutable by that OS user. Readback detects
    // failures/races; this does not claim an atomic compare-and-set keyring API.
    write(relay.as_bytes())?;
    let stored = zeroize::Zeroizing::new(read()?);
    ensure!(
        stored.as_slice() == relay.as_bytes(),
        "pending relay readback mismatch"
    );
    Ok(())
}

#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
#[path = "custody_relay_test.rs"]
mod tests;
