//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::human_presence::{HumanPresenceError, TestHumanPresence};

/// A presence check that runs an action while the owner is "authenticating".
/// Every race `remove` has to survive lives in exactly that window, because
/// it is the one point where the call awaits without holding any lock.
struct PresenceThen<F>(F);

// A test backend is still a backend, so it carries the seal like the real
// ones. That this file *can* write this impl, and the presentation crate
// cannot, is the seal working as intended rather than an obstacle to it.
impl<F> crate::sealed::SealedHumanPresence for PresenceThen<F> {}

#[async_trait::async_trait]
impl<F: Fn() + Send + Sync> HumanPresence for PresenceThen<F> {
    async fn confirm(&self, _request: &PresenceRequest) -> Result<(), HumanPresenceError> {
        (self.0)();
        Ok(())
    }
}

fn service(
    allow: bool,
) -> (
    tempfile::TempDir,
    CustodyService<MemoryKeyStore, TestHumanPresence>,
) {
    let directory = tempfile::tempdir().unwrap();
    let service = CustodyService::new(
        ConfigStore::new(directory.path()),
        Arc::new(MemoryKeyStore::default()),
        Arc::new(TestHumanPresence { allow }),
    );
    (directory, service)
}

#[tokio::test]
async fn a_refused_creation_still_clears_the_key_it_inserted() {
    // The rollback the post-commit guard must not swallow. The id is taken
    // by a different address, so the metadata write never happened and the
    // credential just inserted is garbage — deleting it is correct, and
    // only a row naming *this* address may keep its key.
    let (_directory, service) = service(true);
    let first = service.create("primary").unwrap();
    service
        .config
        .update(|config| {
            config.wallets.retain(|wallet| wallet.id != "primary");
            Ok(())
        })
        .unwrap();
    service.keys.delete("primary").unwrap();
    service
        .config
        .update(|config| {
            config.wallets.push(WalletMetadata {
                id: "primary".into(),
                address: alloy::primitives::Address::repeat_byte(9),
                created_at: Utc::now(),
                source: WalletSource::Imported,
                exported_at: None,
            });
            Ok(())
        })
        .unwrap();
    assert_ne!(first.address, alloy::primitives::Address::repeat_byte(9));

    assert!(service.create("primary").is_err());
    assert!(service.keys.load("primary").is_err());
}

#[tokio::test]
async fn export_records_a_timestamp() {
    let (_directory, service) = service(true);
    let wallet = service.create("primary").unwrap();
    assert!(wallet.exported_at.is_none());
    let exported = service.export("primary").await.unwrap();
    assert_eq!(exported.len(), 66);
    assert!(
        service
            .config
            .wallet("primary")
            .unwrap()
            .exported_at
            .is_some()
    );
}

#[tokio::test]
async fn re_export_keeps_the_first_timestamp() {
    let (_directory, service) = service(true);
    service.create("primary").unwrap();
    service.export("primary").await.unwrap();
    let first = service.config.wallet("primary").unwrap().exported_at;
    service.export("primary").await.unwrap();
    assert_eq!(service.config.wallet("primary").unwrap().exported_at, first);
}

#[tokio::test]
async fn denial_does_not_record_an_export() {
    let (_directory, service) = service(false);
    service.create("primary").unwrap();
    assert!(service.export("primary").await.is_err());
    assert!(
        service
            .config
            .wallet("primary")
            .unwrap()
            .exported_at
            .is_none()
    );
}

#[test]
fn imports_record_their_external_origin() {
    let (_directory, service) = service(true);
    let key = PrivateKeyMaterial::from_hex(
        "0x0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let wallet = service.import("imported", key).unwrap();
    assert_eq!(wallet.source, WalletSource::Imported);
    // An import is externally known from the start, but that is `source`'s
    // job to say. `exported_at` records only this tool's own disclosures.
    assert!(wallet.exported_at.is_none());
}

#[tokio::test]
async fn an_unreadable_configuration_never_destroys_the_key() {
    // The removal fails *and* the re-read that follows it fails, which is the
    // shape that used to delete a live wallet's only key: `wallet(..).is_ok()`
    // is false for an unreadable configuration exactly as it is for an absent
    // row, so "cannot tell" was being read as "already removed".
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_path_buf();
    let keys = Arc::new(MemoryKeyStore::default());
    let seed = CustodyService::new(
        ConfigStore::new(&path),
        Arc::clone(&keys),
        Arc::new(TestHumanPresence { allow: true }),
    );
    let wallet = seed.create("primary").unwrap();

    let corrupt = path.join("config.json");
    let service = CustodyService::new(
        ConfigStore::new(&path),
        Arc::clone(&keys),
        Arc::new(PresenceThen(move || {
            std::fs::write(&corrupt, b"{ not json").unwrap();
        })),
    );

    assert!(service.remove("primary").await.is_err());
    assert_eq!(
        keys.load("primary").unwrap().signer().address(),
        wallet.address,
        "the key must survive a removal that could not confirm its row was gone"
    );
}

#[tokio::test]
async fn a_replacement_wallet_keeps_its_key() {
    // The owner authorizes removing one wallet; another process replaces it
    // with a different key under the same name before the authorization
    // returns. Acting on the name alone would spend that approval on the
    // replacement and destroy a key nobody agreed to remove.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_path_buf();
    let keys = Arc::new(MemoryKeyStore::default());
    let seed = CustodyService::new(
        ConfigStore::new(&path),
        Arc::clone(&keys),
        Arc::new(TestHumanPresence { allow: true }),
    );
    let original = seed.create("primary").unwrap();

    let swap_path = path.clone();
    let swap_keys = Arc::clone(&keys);
    let service = CustodyService::new(
        ConfigStore::new(&path),
        Arc::clone(&keys),
        Arc::new(PresenceThen(move || {
            let other = CustodyService::new(
                ConfigStore::new(&swap_path),
                Arc::clone(&swap_keys),
                Arc::new(TestHumanPresence { allow: true }),
            );
            other
                .config
                .update(|config| {
                    config.wallets.retain(|wallet| wallet.id != "primary");
                    Ok(())
                })
                .unwrap();
            swap_keys.delete("primary").unwrap();
            other.create("primary").unwrap();
        })),
    );

    assert!(service.remove("primary").await.is_err());
    let replacement = ConfigStore::new(&path).wallet("primary").unwrap();
    assert_ne!(replacement.address, original.address);
    assert_eq!(
        keys.load("primary").unwrap().signer().address(),
        replacement.address,
        "the replacement wallet's key must outlive an approval given for its predecessor"
    );
}
