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
