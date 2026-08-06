//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::human_presence::TestHumanPresence;

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
