//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::policy_store::DatabaseKey;

fn open(directory: &Path) -> AddressBookStore {
    AddressBookStore::new(
        PolicyStore::open(&directory.join("policies.db"), &DatabaseKey::new([6; 32])).unwrap(),
    )
}

#[test]
fn an_alias_that_would_be_refused_today_can_still_be_deleted() {
    // A malformed row must stay removable. Enforcing a write-time rule on
    // the way out leaves the owner able to see an entry and unable to remove it.
    let directory = tempfile::tempdir().unwrap();
    let mut store = open(directory.path());
    store
        .database
        .connection
        .execute(
            "INSERT INTO address_book(chain_id, alias, address, note, added_at, updated_at)
                 VALUES (1, 'not a valid alias!', ?1, NULL, 0, 0)",
            rusqlite::params![crate::sql::Blob(Address::repeat_byte(0x11))],
        )
        .unwrap();

    // The write-time rule still refuses it as input.
    assert!(store.get(1, "not a valid alias!").is_err());
    assert_eq!(
        store
            .get_for_removal(1, "not a valid alias!")
            .unwrap()
            .unwrap()
            .alias,
        "not a valid alias!",
        "the removal review must be able to show the exact stored row"
    );
    // Removal reaches it anyway, and returns what it deleted.
    let removed = store.remove(1, "not a valid alias!").unwrap();
    assert_eq!(removed.alias, "not a valid alias!");
    assert!(store.remove(1, "not a valid alias!").is_err());
}

fn store() -> (tempfile::TempDir, AddressBookStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = open(directory.path());
    (directory, store)
}

#[test]
fn upsert_replaces_and_remove_deletes() {
    let (_directory, mut store) = store();
    let first = Address::repeat_byte(0x11);
    let second = Address::repeat_byte(0x22);
    let entry = store.upsert(1, "alice", first, Some("payroll")).unwrap();
    assert_eq!(entry.address, first.to_checksum(None));
    assert_eq!(entry.note.as_deref(), Some("payroll"));

    let replaced = store.upsert(1, "alice", second, None).unwrap();
    assert_eq!(replaced.address, second.to_checksum(None));
    assert_eq!(replaced.note, None);
    assert_eq!(replaced.added_at, entry.added_at);
    assert_eq!(store.count(None).unwrap(), 1);

    // Same alias on another chain is a distinct entry.
    store.upsert(8453, "alice", first, None).unwrap();
    assert_eq!(store.count(None).unwrap(), 2);
    assert_eq!(store.count(Some(1)).unwrap(), 1);

    let removed = store.remove(1, "alice").unwrap();
    assert_eq!(removed.address, second.to_checksum(None));
    assert!(store.get(1, "alice").unwrap().is_none());
    assert!(store.remove(1, "alice").is_err());
}

#[test]
fn listing_is_deterministic_and_scoped() {
    let (_directory, mut store) = store();
    store
        .upsert(1, "bob", Address::repeat_byte(0xB0), None)
        .unwrap();
    store
        .upsert(1, "alice", Address::repeat_byte(0xA0), None)
        .unwrap();
    let listed = store.list(Some(1), 10, 0).unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].alias, "alice");
    assert!(store.list(Some(2), 10, 0).unwrap().is_empty());
    assert_eq!(store.list(None, 1, 1).unwrap().len(), 1);
}

#[test]
fn hostile_aliases_and_notes_are_rejected() {
    let (_directory, mut store) = store();
    let address = Address::repeat_byte(0x33);
    assert!(store.upsert(1, "bad\nalias", address, None).is_err());
    assert!(store.upsert(1, "", address, None).is_err());
    assert!(
        store
            .upsert(1, "ok", address, Some("note\u{1b}[31m"))
            .is_err()
    );
    assert!(
        store
            .upsert(1, "ok", address, Some(&"x".repeat(300)))
            .is_err()
    );
    assert!(store.upsert(0, "ok", address, None).is_err());
}

#[test]
fn reopening_preserves_rows() {
    let directory = tempfile::tempdir().unwrap();
    {
        let mut store = open(directory.path());
        store
            .upsert(10, "vault", Address::repeat_byte(0x44), None)
            .unwrap();
    }
    let store = open(directory.path());
    assert_eq!(store.count(None).unwrap(), 1);
    assert_eq!(
        store.get(10, "vault").unwrap().unwrap().address,
        Address::repeat_byte(0x44).to_checksum(None)
    );
}
