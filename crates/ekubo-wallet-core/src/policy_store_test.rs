//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
};

fn key(byte: u8) -> DatabaseKey {
    DatabaseKey::new([byte; 32])
}

/// Build a database in the shape schema 9 left behind: every queue still
/// carries `expires_at`, and some rows are already terminally `expired`.
fn write_schema_9_database(path: &Path, key: &DatabaseKey) {
    let connection = Connection::open(path).unwrap();
    key.with_sqlcipher_literal(|literal| connection.pragma_update(None, "key", literal))
        .unwrap();
    let statements = [
        "CREATE TABLE schema_metadata (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 version INTEGER NOT NULL
             ) STRICT",
        "INSERT INTO schema_metadata(singleton, version) VALUES (1, 9)",
        "CREATE TABLE pending_transactions (
                 request_id TEXT PRIMARY KEY NOT NULL,
                 wallet_id TEXT NOT NULL,
                 network_name TEXT NOT NULL,
                 chain_id TEXT NOT NULL,
                 plan_json TEXT NOT NULL,
                 plan_digest TEXT NOT NULL,
                 policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
                 status TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 expires_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 approved_at TEXT,
                 rejected_at TEXT,
                 serialized_transaction TEXT,
                 signed_transaction_hash TEXT,
                 broadcast_transaction_hash TEXT,
                 block_number TEXT,
                 approval_required INTEGER NOT NULL DEFAULT 1,
                 review_digest TEXT,
                 cancel_serialized_transaction TEXT,
                 cancel_transaction_hashes TEXT
             ) STRICT",
        "CREATE TABLE pending_typed_data (
                 request_id TEXT PRIMARY KEY NOT NULL,
                 wallet_id TEXT NOT NULL,
                 chain_id TEXT NOT NULL,
                 typed_data_json TEXT NOT NULL,
                 digest TEXT NOT NULL,
                 status TEXT NOT NULL,
                 approval_required INTEGER NOT NULL DEFAULT 1,
                 policy_revision INTEGER,
                 created_at TEXT NOT NULL,
                 expires_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 approved_at TEXT,
                 rejected_at TEXT,
                 signature TEXT
             ) STRICT",
        "CREATE TABLE pending_messages (
                 request_id TEXT PRIMARY KEY NOT NULL,
                 wallet_id TEXT NOT NULL,
                 chain_id TEXT NOT NULL,
                 message_hex TEXT NOT NULL,
                 message_encoding TEXT NOT NULL,
                 digest TEXT NOT NULL,
                 status TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 expires_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 approved_at TEXT,
                 rejected_at TEXT,
                 signature TEXT
             ) STRICT",
        // One request the old rule had already closed, and one that never
        // reached its deadline, in each queue that has one.
        "INSERT INTO pending_transactions(
                 request_id, wallet_id, network_name, chain_id, plan_json, plan_digest,
                 policy_revision, status, created_at, expires_at, updated_at
             ) VALUES ('lapsed', 'primary', 'ethereum', '1', '{}', '0xaa', 1,
                       'expired', 't0', 't1', 't1')",
        "INSERT INTO pending_transactions(
                 request_id, wallet_id, network_name, chain_id, plan_json, plan_digest,
                 policy_revision, status, created_at, expires_at, updated_at,
                 serialized_transaction, signed_transaction_hash, broadcast_transaction_hash,
                 block_number
             ) VALUES ('mined', 'primary', 'ethereum', '1', '{}', '0xbb', 1,
                       'confirmed', 't0', 't1', 't2', '0x0102', '0xcc', '0xcc', '17')",
        "INSERT INTO pending_typed_data(
                 request_id, wallet_id, chain_id, typed_data_json, digest, status,
                 created_at, expires_at, updated_at
             ) VALUES ('td-lapsed', 'primary', '1', '{}', '0xdd', 'expired', 't0', 't1', 't1')",
        "INSERT INTO pending_messages(
                 request_id, wallet_id, chain_id, message_hex, message_encoding, digest,
                 status, created_at, expires_at, updated_at
             ) VALUES ('msg-queued', 'primary', '', '0x6869', 'text', '0xee',
                       'awaiting_approval', 't0', 't1', 't1')",
    ];
    for statement in statements {
        connection.execute_batch(statement).unwrap();
    }
    drop(connection);
}

#[test]
fn a_network_suggestion_waits_and_the_latest_one_prevails() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let mut store = PolicyStore::open(&path, &key(9)).unwrap();
    let mut profile = crate::config::default_networks().remove(0);

    store.put_network_proposal(&profile).unwrap();
    assert_eq!(store.count_network_proposals().unwrap(), 1);

    // An agent that changed its mind has not left two decisions to make,
    // so the newer suggestion for a chain replaces the older one.
    profile.rpc_url = "https://second.example.invalid/rpc".parse().unwrap();
    store.put_network_proposal(&profile).unwrap();
    assert_eq!(store.count_network_proposals().unwrap(), 1);
    assert_eq!(
        store
            .network_proposal(profile.chain_id)
            .unwrap()
            .unwrap()
            .rpc_url
            .as_str(),
        "https://second.example.invalid/rpc"
    );

    // A suggestion is not a network. Nothing here reaches the
    // configuration; the queue is the whole of its effect.
    assert_eq!(store.network_proposals().unwrap().len(), 1);
    assert!(store.discard_network_proposal(profile.chain_id).unwrap());
    assert_eq!(store.count_network_proposals().unwrap(), 0);
    assert!(!store.discard_network_proposal(profile.chain_id).unwrap());
}

#[test]
fn network_suggestions_cannot_grow_without_bound() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let mut store = PolicyStore::open(&path, &key(10)).unwrap();
    let template = crate::config::default_networks().remove(0);
    for index in 0..MAX_PENDING_NETWORK_PROPOSALS {
        let mut profile = template.clone();
        profile.chain_id = 100_000 + index;
        profile.name = format!("chain-{index}");
        profile.aliases = Vec::new();
        store.put_network_proposal(&profile).unwrap();
    }
    let mut overflow = template.clone();
    overflow.chain_id = 999_999;
    overflow.name = "one-too-many".into();
    overflow.aliases = Vec::new();
    let error = store
        .put_network_proposal(&overflow)
        .unwrap_err()
        .to_string();
    assert!(error.contains("await review"), "{error}");

    // Replacing an existing suggestion still works at the ceiling: the
    // owner has that decision either way, and refusing the correction
    // would strand them with the worse of two profiles.
    let mut revised = template.clone();
    revised.chain_id = 100_000;
    revised.name = "chain-0".into();
    revised.aliases = Vec::new();
    revised.rpc_url = "https://revised.example.invalid/rpc".parse().unwrap();
    store.put_network_proposal(&revised).unwrap();
}

#[test]
fn purging_a_wallet_leaves_nothing_for_the_next_one_to_inherit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let mut store = PolicyStore::open(&path, &key(5)).unwrap();
    store
        .put("primary", &WalletPolicy::allow_all_with_approval(), None)
        .unwrap();
    store
        .put_proposal(
            "primary",
            1,
            &WalletPolicy::require_approval_for_everything(),
            "widen it",
        )
        .unwrap();
    for statement in [
        "INSERT INTO pending_transactions(
                 request_id, wallet_id, network_name, chain_id, plan_json, plan_digest,
                 policy_revision, status, created_at, updated_at
             ) VALUES ('tx', 'primary', 'mainnet', '1', '{}', '0xaa', 1,
                       'awaiting_approval', 't0', 't0')",
        "INSERT INTO pending_typed_data(
                 request_id, wallet_id, chain_id, typed_data_json, digest, status,
                 created_at, updated_at
             ) VALUES ('td', 'primary', '1', '{}', '0xbb', 'awaiting_approval', 't0', 't0')",
        "INSERT INTO pending_messages(
                 request_id, wallet_id, chain_id, message_hex, message_encoding, digest,
                 status, created_at, updated_at
             ) VALUES ('msg', 'primary', '1', '0x6869', 'text', '0xcc',
                       'awaiting_approval', 't0', 't0')",
    ] {
        store.connection.execute_batch(statement).unwrap();
    }

    store.purge("primary").unwrap();

    assert!(store.get("primary").unwrap().is_none());
    assert!(store.proposal("primary").unwrap().is_none());
    for table in [
        "pending_transactions",
        "pending_typed_data",
        "pending_messages",
    ] {
        let remaining: i64 = store
            .connection
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE wallet_id = 'primary'"),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0, "{table} kept a row across a purge");
    }

    // The next wallet to take this name starts at revision 1 with the
    // policy it was given. Revisions restarting is exactly why a stale
    // proposal used to apply: it recorded source_revision 1 and found a 1.
    let restarted = store
        .put(
            "primary",
            &WalletPolicy::require_approval_for_everything(),
            None,
        )
        .unwrap();
    assert_eq!(restarted.revision, 1);
}

#[test]
fn any_other_schema_is_refused_and_left_untouched() {
    // There is one schema. A database carrying any other version is not
    // upgraded in place — it is refused, and the refusal writes nothing,
    // so whatever wrote the file still has it byte for byte.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    write_schema_9_database(&path, &key(11));
    let before = std::fs::read(&path).unwrap();

    let error = PolicyStore::open(&path, &key(11))
        .err()
        .expect("a foreign schema must be refused")
        .to_string();
    assert!(
        error.contains("schema 9 is newer than the schema"),
        "{error}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn a_schema_from_a_newer_build_is_refused() {
    // Fails closed rather than being written through a stale
    // understanding of its shape.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    {
        let store = PolicyStore::open(&path, &key(7)).unwrap();
        store
            .connection
            .execute("UPDATE schema_metadata SET version = version + 1", [])
            .unwrap();
    }
    let error = PolicyStore::open(&path, &key(7))
        .err()
        .expect("a newer schema must be refused")
        .to_string();
    assert!(error.contains("is newer than the schema"), "{error}");
}

#[test]
fn a_fresh_database_is_created_at_the_only_schema_there_is() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let store = PolicyStore::open(&path, &key(3)).unwrap();
    assert_eq!(
        schema_version(&store.connection).unwrap(),
        Some(SCHEMA_VERSION)
    );
    // Every table the build expects exists from creation; nothing arrives
    // by later upgrade.
    for table in [
        "wallet_policies",
        "pending_transactions",
        "pending_typed_data",
        "pending_messages",
        "policy_proposals",
        "tokens",
        "token_proposals",
        "address_book",
        "legal_acceptance",
    ] {
        store
            .connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or_else(|error| panic!("{table} missing from a fresh database: {error}"));
    }
}

#[test]
fn schema_change_underneath_a_live_connection_is_refused() {
    // A long-running server re-checks the version on every request; once
    // another process migrates the database, every request fails with a
    // restart instruction instead of writing through the old shape.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let store = PolicyStore::open(&path, &key(3)).unwrap();
    store.assert_schema_current().unwrap();
    store
        .connection
        .execute("UPDATE schema_metadata SET version = version + 1", [])
        .unwrap();
    let error = store.assert_schema_current().unwrap_err().to_string();
    assert!(
        error.contains("restart the ekubo-wallet MCP server"),
        "{error}"
    );
}

#[test]
fn stores_only_current_policy_with_optimistic_revision() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let mut store = PolicyStore::open(&path, &key(7)).unwrap();
    let first = store
        .put("primary", &WalletPolicy::allow_all_with_approval(), None)
        .unwrap();
    assert_eq!(first.revision, 1);
    assert!(store.put("primary", &first.policy, None).is_err());
    let second = store
        .put("primary", &first.policy, Some(first.revision))
        .unwrap();
    assert_eq!(second.revision, 2);
    assert_eq!(store.get("primary").unwrap().unwrap(), second);
}

#[test]
fn single_proposal_per_wallet_binds_the_source_revision_and_latest_prevails() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let mut store = PolicyStore::open(&path, &key(9)).unwrap();
    let active = store
        .put(
            "primary",
            &WalletPolicy::require_approval_for_everything(),
            None,
        )
        .unwrap();

    // A proposal against a revision the agent has not read fails.
    assert!(
        store
            .put_proposal(
                "primary",
                active.revision + 1,
                &WalletPolicy::allow_all_with_approval(),
                "widen",
            )
            .is_err()
    );
    // Rationale is required.
    assert!(
        store
            .put_proposal(
                "primary",
                active.revision,
                &WalletPolicy::allow_all_with_approval(),
                "   ",
            )
            .is_err()
    );

    let first = store
        .put_proposal(
            "primary",
            active.revision,
            &WalletPolicy::allow_all_with_approval(),
            "enable automatic signing",
        )
        .unwrap();
    assert_eq!(first.source_revision, active.revision);
    let replacement = store
        .put_proposal(
            "primary",
            active.revision,
            &WalletPolicy::require_approval_for_everything(),
            "narrower follow-up proposal",
        )
        .unwrap();
    // The latest proposal prevails: one row per wallet.
    let stored = store.proposal("primary").unwrap().unwrap();
    assert_eq!(stored.rationale, replacement.rationale);
    assert_eq!(store.list_proposals().unwrap().len(), 1);

    // Applying with the bound revision succeeds exactly once.
    let applied = store
        .put("primary", &stored.policy, Some(stored.source_revision))
        .unwrap();
    assert_eq!(applied.revision, active.revision + 1);
    assert!(store.delete_proposal("primary").unwrap());
    assert!(!store.delete_proposal("primary").unwrap());
    assert!(store.proposal("primary").unwrap().is_none());
}

#[test]
fn a_proposal_replaced_during_review_is_refused_not_discarded() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let mut store = PolicyStore::open(&path, &key(11)).unwrap();
    let active = store
        .put(
            "primary",
            &WalletPolicy::require_approval_for_everything(),
            None,
        )
        .unwrap();
    let reviewed = store
        .put_proposal(
            "primary",
            active.revision,
            &WalletPolicy::allow_all_with_approval(),
            "the one a human is looking at",
        )
        .unwrap();

    // The active revision never moves while a proposal is pending, so the
    // revision check cannot see this. Without matching the row itself, the
    // reviewed policy applied and the newer one was deleted unseen.
    store
        .put_proposal(
            "primary",
            active.revision,
            &WalletPolicy::require_approval_for_everything(),
            "arrived while the screen was up",
        )
        .unwrap();
    assert!(store.consume_proposal(&reviewed).is_err());

    // Nothing was applied and nothing was consumed: the newer proposal is
    // still there to be reviewed on its own terms.
    assert_eq!(
        store.get("primary").unwrap().unwrap().revision,
        active.revision
    );
    let pending = store.proposal("primary").unwrap().unwrap();
    assert_eq!(pending.rationale, "arrived while the screen was up");

    // And the ordinary path still applies and consumes in one step.
    let applied = store.consume_proposal(&pending).unwrap();
    assert_eq!(applied.revision, active.revision + 1);
    assert!(store.proposal("primary").unwrap().is_none());
}

#[test]
fn wrong_key_cannot_open_existing_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    drop(PolicyStore::open(&path, &key(1)).unwrap());
    assert!(PolicyStore::open(&path, &key(2)).is_err());
}

#[test]
fn plaintext_sqlite_header_is_not_present() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    drop(PolicyStore::open(&path, &key(3)).unwrap());
    let bytes = fs::read(path).unwrap();
    assert!(!bytes.starts_with(b"SQLite format 3\0"));
}

#[test]
fn authenticated_page_corruption_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let mut store = PolicyStore::open(&path, &key(4)).unwrap();
    store
        .put("primary", &WalletPolicy::allow_all_with_approval(), None)
        .unwrap();
    drop(store);

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(file.metadata().unwrap().len() > 4_224);
    file.seek(SeekFrom::Start(4_224)).unwrap();
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0x80;
    file.seek(SeekFrom::Start(4_224)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();
    drop(file);

    assert!(PolicyStore::open(&path, &key(4)).is_err());
}

#[test]
fn committed_state_does_not_depend_on_a_persistent_wal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let mut store = PolicyStore::open(&path, &key(5)).unwrap();
    store
        .put("primary", &WalletPolicy::allow_all_with_approval(), None)
        .unwrap();
    drop(store);
    assert!(!path.with_extension("db-wal").exists());
    assert!(
        PolicyStore::open(&path, &key(5))
            .unwrap()
            .get("primary")
            .unwrap()
            .is_some()
    );
}
