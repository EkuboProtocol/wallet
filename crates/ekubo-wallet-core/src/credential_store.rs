//! Platform credential entries, with a fresh Linux Secret Service session.
//!
//! keyring's v1 facade caches its store (and even initialization failure) for
//! the lifetime of the process. A Secret Service restart invalidates that
//! store's DH session: every subsequent database/key read then fails with
//! `NoSession` until the wallet restarts. Construct a new Linux store per entry
//! instead. No secrets are cached and no credential writes are retried.

pub(crate) fn entry(service: &str, user: &str) -> keyring::Result<keyring::Entry> {
    #[cfg(target_os = "linux")]
    {
        use keyring_core::api::CredentialStoreApi as _;

        let store = zbus_secret_service_keyring_store::Store::new()?;
        let inner = store.build(service, user, None)?;
        Ok(keyring::Entry { inner })
    }
    #[cfg(not(target_os = "linux"))]
    keyring::Entry::new(service, user)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "credential_store_test.rs"]
mod tests;
