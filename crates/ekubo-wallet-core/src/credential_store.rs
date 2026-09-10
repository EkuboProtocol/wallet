//! Platform credential entries, with a fresh Linux Secret Service session.
//!
//! keyring's v1 facade caches its store (and even initialization failure) for
//! the lifetime of the process. A Secret Service restart invalidates that
//! store's DH session: every subsequent database/key read then fails with
//! `NoSession` until the wallet restarts. Construct a new Linux store per entry
//! instead. No secrets are cached and no credential writes are retried.

pub(crate) enum Entry {
    Platform(keyring::Entry),
    #[cfg(target_os = "linux")]
    Service(crate::service_storage::Entry),
}

impl Entry {
    pub(crate) fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        match self {
            Self::Platform(entry) => entry.get_secret(),
            #[cfg(target_os = "linux")]
            Self::Service(entry) => entry.get_secret().map_err(service_error),
        }
    }

    pub(crate) fn set_secret(&self, bytes: &[u8]) -> keyring::Result<()> {
        match self {
            Self::Platform(entry) => entry.set_secret(bytes),
            #[cfg(target_os = "linux")]
            Self::Service(entry) => entry.set_secret(bytes).map_err(service_error),
        }
    }

    pub(crate) fn delete_credential(&self) -> keyring::Result<()> {
        match self {
            Self::Platform(entry) => entry.delete_credential(),
            #[cfg(target_os = "linux")]
            Self::Service(entry) => entry.delete_credential().map_err(service_error),
        }
    }
}

#[cfg(target_os = "linux")]
fn service_error(error: anyhow::Error) -> keyring::Error {
    if error.downcast_ref::<rustix::io::Errno>() == Some(&rustix::io::Errno::NOENT) {
        keyring::Error::NoEntry
    } else {
        keyring::Error::PlatformFailure(error.into_boxed_dyn_error())
    }
}

pub(crate) fn entry(service: &str, user: &str) -> keyring::Result<Entry> {
    #[cfg(target_os = "linux")]
    if let Some(entry) = crate::service_storage::entry(service, user) {
        // An active service never falls back to the desktop credential store,
        // including missing files, invalid permissions, and I/O failures.
        return entry.map(Entry::Service).map_err(service_error);
    }
    #[cfg(target_os = "linux")]
    {
        use keyring_core::api::CredentialStoreApi as _;

        let store = zbus_secret_service_keyring_store::Store::new()?;
        let inner = store.build(service, user, None)?;
        Ok(Entry::Platform(keyring::Entry { inner }))
    }
    #[cfg(not(target_os = "linux"))]
    keyring::Entry::new(service, user).map(Entry::Platform)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "credential_store_test.rs"]
mod tests;
