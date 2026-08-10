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
    service
        .keys
        .delete_matching("primary", first.address)
        .unwrap();
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
    let exported = service.export("primary", wallet.address).await.unwrap();
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
    let wallet = service.create("primary").unwrap();
    service.export("primary", wallet.address).await.unwrap();
    let first = service.config.wallet("primary").unwrap().exported_at;
    service.export("primary", wallet.address).await.unwrap();
    assert_eq!(service.config.wallet("primary").unwrap().exported_at, first);
}

#[tokio::test]
async fn denial_does_not_record_an_export() {
    let (_directory, service) = service(false);
    let wallet = service.create("primary").unwrap();
    assert!(service.export("primary", wallet.address).await.is_err());
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
            swap_keys
                .delete_matching("primary", original.address)
                .unwrap();
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

/// A key store that answers `delete_matching` however the test needs, over a
/// real [`MemoryKeyStore`] that holds the actual material. Every failure below
/// is a credential store that reported an error without saying what it did,
/// which is the only thing the removal path cannot observe for itself.
struct FlakyKeyStore {
    inner: MemoryKeyStore,
    /// Run instead of the real deletion. Returns the error to report.
    on_delete: Box<dyn Fn(&MemoryKeyStore) -> anyhow::Error + Send + Sync>,
    /// Fail `address_of` too, so the removal cannot tell what happened.
    blind: bool,
}

impl crate::sealed::SealedKeyStore for FlakyKeyStore {}

impl KeyStore for FlakyKeyStore {
    fn insert_new(&self, wallet_id: &str, key: &PrivateKeyMaterial) -> Result<()> {
        self.inner.insert_new(wallet_id, key)
    }

    fn load(&self, wallet_id: &str) -> Result<PrivateKeyMaterial> {
        self.inner.load(wallet_id)
    }

    fn address_of(&self, wallet_id: &str) -> Result<Option<Address>> {
        ensure!(!self.blind, "credential store is unreachable");
        self.inner.address_of(wallet_id)
    }

    fn delete_matching(&self, _wallet_id: &str, _expected: Address) -> Result<Deletion> {
        Err((self.on_delete)(&self.inner))
    }
}

fn flaky(
    on_delete: impl Fn(&MemoryKeyStore) -> anyhow::Error + Send + Sync + 'static,
    blind: bool,
) -> (
    tempfile::TempDir,
    Arc<FlakyKeyStore>,
    CustodyService<FlakyKeyStore, TestHumanPresence>,
) {
    let directory = tempfile::tempdir().unwrap();
    let keys = Arc::new(FlakyKeyStore {
        inner: MemoryKeyStore::default(),
        on_delete: Box::new(on_delete),
        blind,
    });
    let service = CustodyService::new(
        ConfigStore::new(directory.path()),
        Arc::clone(&keys),
        Arc::new(TestHumanPresence { allow: true }),
    );
    (directory, keys, service)
}

#[tokio::test]
async fn a_deletion_that_destroyed_the_key_before_failing_does_not_relist_the_wallet() {
    // The shape that listed a wallet nobody could sign with. `delete` reported
    // an error *after* the credential was gone, and the rollback restored the
    // row on the strength of the error alone — an inventory entry that reads
    // as available and can never produce a signature.
    let (directory, keys, service) = flaky(
        |inner| {
            let address = inner.address_of("primary").unwrap().unwrap();
            inner.delete_matching("primary", address).unwrap();
            anyhow::anyhow!("credential store failed after deleting")
        },
        false,
    );
    service.create("primary").unwrap();

    // The removal the owner asked for did happen, so it is not an error.
    service.remove("primary").await.unwrap();
    assert!(
        keys.address_of("primary").unwrap().is_none(),
        "the credential really is gone"
    );
    assert!(
        ConfigStore::new(directory.path())
            .wallet("primary")
            .is_err(),
        "a wallet whose key was destroyed must not be restored to the inventory"
    );
}

#[tokio::test]
async fn a_deletion_that_kept_the_key_restores_the_row() {
    // The other half of the same question, and the reason the rollback exists
    // at all: the credential is still there, so the row has to come back or a
    // reachable key is orphaned with nothing naming it.
    let (directory, keys, service) = flaky(
        |_| anyhow::anyhow!("credential store failed before deleting"),
        false,
    );
    let wallet = service.create("primary").unwrap();

    assert!(service.remove("primary").await.is_err());
    assert_eq!(
        keys.address_of("primary").unwrap(),
        Some(wallet.address),
        "the key survived"
    );
    assert_eq!(
        ConfigStore::new(directory.path())
            .wallet("primary")
            .unwrap()
            .address,
        wallet.address,
        "so the row naming it must survive too"
    );
}

#[tokio::test]
async fn an_unreadable_credential_store_does_not_relist_the_wallet() {
    // "Cannot tell" is not "the key survived". Restoring here is a coin flip
    // on whether the row can ever sign again, so the removal says what it does
    // not know instead of guessing.
    let (directory, _keys, service) = flaky(
        |_| anyhow::anyhow!("credential store failed at an unknown point"),
        true,
    );
    service.create("primary").unwrap();

    let error = format!("{:#}", service.remove("primary").await.unwrap_err());
    assert!(
        error.contains("could not be re-read"),
        "the owner is told the state is indeterminate: {error}"
    );
    assert!(
        ConfigStore::new(directory.path())
            .wallet("primary")
            .is_err(),
        "an indeterminate credential must not produce a row that claims to be usable"
    );
}

#[test]
fn deletion_is_addressed_by_key_rather_than_by_name() {
    // The invariant the trait exists to enforce. A wallet id is reusable, so
    // every historical way this went wrong — a removal landing on the wallet
    // that replaced its target, a losing creation clearing the winner's key —
    // reduces to a deletion that named an id and accepted whatever answered.
    // There is no method that can express that any more; this is the refusal.
    let keys = MemoryKeyStore::default();
    let mine = PrivateKeyMaterial::from_bytes(
        alloy::signers::local::PrivateKeySigner::random()
            .to_bytes()
            .as_slice(),
    )
    .unwrap();
    let theirs = PrivateKeyMaterial::from_bytes(
        alloy::signers::local::PrivateKeySigner::random()
            .to_bytes()
            .as_slice(),
    )
    .unwrap();
    let mine_address = mine.address();
    keys.insert_new("primary", &theirs).unwrap();

    assert_eq!(
        keys.delete_matching("primary", mine_address).unwrap(),
        Deletion::Mismatched(theirs.address()),
        "a credential belonging to another wallet is reported, not deleted"
    );
    assert_eq!(
        keys.address_of("primary").unwrap(),
        Some(theirs.address()),
        "and it is still there"
    );
    assert_eq!(
        keys.delete_matching("absent", mine_address).unwrap(),
        Deletion::Absent
    );
}

#[tokio::test]
async fn a_creation_that_loses_the_configuration_race_keeps_the_winners_key() {
    // Two creations of the same id. The lifecycle lock is what makes this
    // impossible to reach concurrently now, but the loser's rollback is
    // addressed by key as well, so even a lock that failed to serialize them
    // cannot turn the loser's cleanup into the winner's key loss.
    let directory = tempfile::tempdir().unwrap();
    let keys = Arc::new(MemoryKeyStore::default());
    let service = CustodyService::new(
        ConfigStore::new(directory.path()),
        Arc::clone(&keys),
        Arc::new(TestHumanPresence { allow: true }),
    );
    let winner = service.create("primary").unwrap();

    // A second creation under the same id: the credential store refuses the
    // insert, so nothing is deleted and the winner is untouched.
    assert!(service.create("primary").is_err());
    assert_eq!(
        keys.load("primary").unwrap().signer().address(),
        winner.address,
        "the first wallet's key is still the one stored under its id"
    );
    assert_eq!(
        ConfigStore::new(directory.path())
            .wallet("primary")
            .unwrap()
            .address,
        winner.address
    );
}

#[test]
fn a_write_that_reported_an_error_is_classified_by_what_the_store_holds() {
    // `set_secret` returning an error was read as "nothing was written", so
    // `add` returned before writing metadata or running any rollback. A key
    // the backend had committed was left in the credential store with no row
    // naming it -- invisible to `account list`, and enough to make the next
    // creation of that wallet fail as a duplicate.
    assert!(matches!(
        classify_failed_write(Ok(Some(true))),
        FailedWrite::Committed
    ));
    assert!(matches!(
        classify_failed_write(Ok(None)),
        FailedWrite::NotWritten
    ));
    assert!(matches!(
        classify_failed_write(Ok(Some(false))),
        FailedWrite::Conflicting
    ));
    assert!(matches!(
        classify_failed_write(Err(anyhow::anyhow!("unreachable"))),
        FailedWrite::Unknown(_)
    ));
}

/// The export twin of `a_replacement_wallet_keeps_its_key`.
///
/// The owner reads "reveal the raw private key for 0xabc…" and authenticates.
/// Another process removes that wallet and creates a different one under the
/// same name before the authentication returns. Resolving by name alone hands
/// back the replacement's key — an address that was never on the screen the
/// owner agreed to, and the one thing in this tool that cannot be undone.
///
/// The check that used to be here compared the loaded credential against the
/// loaded metadata. That is a real check of a different thing: both are read
/// after the review, so they agree with each other and with nothing the owner
/// saw.
#[tokio::test]
async fn an_export_reveals_only_the_key_that_was_reviewed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_path_buf();
    let keys = Arc::new(MemoryKeyStore::default());
    let seed = CustodyService::new(
        ConfigStore::new(&path),
        Arc::clone(&keys),
        Arc::new(TestHumanPresence { allow: true }),
    );
    let reviewed = seed.create("primary").unwrap();

    let swap_path = path.clone();
    let swap_keys = Arc::clone(&keys);
    let reviewed_address = reviewed.address;
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
            swap_keys
                .delete_matching("primary", reviewed_address)
                .unwrap();
            other.create("primary").unwrap();
        })),
    );

    let error = format!(
        "{:#}",
        service
            .export("primary", reviewed.address)
            .await
            .expect_err("the reviewed wallet is gone; nothing may be revealed")
    );
    assert!(error.contains("was replaced"), "{error}");

    // And the disclosure is not attributed to the wallet that took the name.
    assert!(
        service
            .config
            .wallet("primary")
            .unwrap()
            .exported_at
            .is_none(),
        "a key that never left must not be marked as having left, on any row"
    );
}

/// The other half: the wallet is still the reviewed one, so the export is the
/// export it always was. Without this, refusing every export would pass above.
#[tokio::test]
async fn an_unchanged_wallet_exports_as_before() {
    let (_directory, service) = service(true);
    let wallet = service.create("primary").unwrap();
    let exported = service.export("primary", wallet.address).await.unwrap();
    assert_eq!(exported.len(), 66);
    assert!(
        service
            .config
            .wallet("primary")
            .unwrap()
            .exported_at
            .is_some()
    );

    // A caller naming an address this id does not hold is refused, which is
    // the same refusal from the other direction.
    let stranger = service.export("primary", Address::repeat_byte(0x99)).await;
    assert!(stranger.is_err());
}
