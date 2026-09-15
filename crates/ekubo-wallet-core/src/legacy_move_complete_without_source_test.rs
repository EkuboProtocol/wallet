use super::*;
use crate::human_presence::{OwnerAuthorization, OwnerAuthorizationScope};

fn owner() -> OwnerAuthorization {
    OwnerAuthorization::for_test(OwnerAuthorizationScope::LegacyMove)
}

fn wallet(id: u128, key: u8) -> WalletMetadata {
    WalletMetadata {
        id: format!("recovery-wallet-{id}"),
        instance_id: Uuid::from_u128(id),
        address: PrivateKeySigner::from_slice(&[key; 32]).unwrap().address(),
        created_at: chrono::Utc::now(),
        source: crate::config::WalletSource::Imported,
        exported_at: None,
    }
}

fn binding() -> String {
    // Platform-absolute without touching the filesystem: the recovery path
    // never opens the source, but binding validation requires absoluteness
    // and a Unix-style literal is not absolute on Windows.
    let source = std::env::temp_dir().join("deleted-legacy-source");
    assert!(source.is_absolute());
    serde_json::to_string(&MoveBinding {
        profile: Uuid::new_v4(),
        source,
        preserved_profiles: vec![],
        retained_shared_accounts: vec![],
        retirement: None,
    })
    .unwrap()
}

/// A destination with a committed import and a pending receipt, as if the
/// move verified and retired the source and then the 1.x directory was
/// deleted before completion. Returns the directory, the receipt digest, and
/// the stored binding.
fn pending_destination(wallets: &[WalletMetadata]) -> (tempfile::TempDir, [u8; 32], String) {
    let source = tempfile::tempdir().unwrap();
    crate::policy_store::register_test_database_key(source.path(), [0x71; 32]).unwrap();
    crate::config::ConfigStore::open(source.path(), DatabaseKey::new([0x71; 32]))
        .update_for_test(|config| {
            config.wallets = wallets.to_vec();
            Ok(())
        })
        .unwrap();
    let mut store = crate::policy_store::PolicyStore::production(source.path()).unwrap();
    for wallet in wallets {
        store.register_wallet_without_policy(wallet).unwrap();
    }
    drop(store);
    let connection = database::open_source(
        &source.path().join("wallet.db"),
        &DatabaseKey::new([0x71; 32]),
    )
    .unwrap();
    let snapshot = database::capture(&connection, false).unwrap();
    drop(connection);
    let destination = tempfile::tempdir().unwrap();
    crate::policy_store::register_test_database_key(destination.path(), [0x72; 32]).unwrap();
    crate::config::ConfigStore::open(destination.path(), DatabaseKey::new([0x72; 32]))
        .load()
        .unwrap();
    database::initialize_baseline(destination.path()).unwrap();
    let binding = binding();
    let digest =
        database::import_bound(destination.path(), &snapshot, &binding, |_| Ok(())).unwrap();
    assert!(require_cleanup_finished(destination.path()).is_err());
    (destination, digest, binding)
}

#[test]
fn recovery_refuses_without_owner_authorization() {
    let (destination, _, _) = pending_destination(&[]);
    let wrong_scope = OwnerAuthorization::for_test(OwnerAuthorizationScope::TokenMetadata);
    assert!(
        complete_move_without_source(&wrong_scope, destination.path(), Uuid::new_v4()).is_err()
    );
    let expired = crate::human_presence::OwnerAuthorization::expired_for_test(
        OwnerAuthorizationScope::LegacyMove,
    );
    assert!(complete_move_without_source(&expired, destination.path(), Uuid::new_v4()).is_err());
    assert!(complete_move_without_source(&owner(), destination.path(), Uuid::nil()).is_err());
    // Every refusal leaves the pending receipt untouched: sessions stay blocked.
    let state = database::move_state(destination.path()).unwrap();
    assert!(state.receipt.is_some());
    assert!(!state.complete);
    assert!(require_cleanup_finished(destination.path()).is_err());
}

#[test]
fn recovery_refuses_when_destination_keys_fail_verification() {
    // The destination holds one account whose sealed key was never installed,
    // so the decrypt/unlock re-verification must fail closed.
    let (destination, _, _) = pending_destination(&[wallet(11, 11)]);
    assert!(complete_move_without_source(&owner(), destination.path(), Uuid::new_v4()).is_err());
    let state = database::move_state(destination.path()).unwrap();
    assert!(state.receipt.is_some());
    assert!(!state.complete);
    assert!(require_cleanup_finished(destination.path()).is_err());
}

#[test]
fn recovery_succeeds_when_destination_verifies_and_unblocks_sessions() {
    let (destination, digest, _) = pending_destination(&[]);
    let nonce = Uuid::new_v4();
    let receipt = complete_move_without_source(&owner(), destination.path(), nonce).unwrap();
    assert!(matches!(receipt.phase, ReceiptPhase::Complete));
    assert_eq!(receipt.digest, digest);
    assert_eq!(receipt.nonce, nonce);
    assert!(receipt.binding.is_some());
    assert!(database::move_state(destination.path()).unwrap().complete);
    require_cleanup_finished(destination.path()).unwrap();
    // Completion is terminal: it must not replay.
    assert!(complete_move_without_source(&owner(), destination.path(), Uuid::new_v4()).is_err());
}

#[test]
fn recovery_wire_operation_carries_the_complete_phase() {
    let nonce = Uuid::new_v4();
    let command = ServiceCommand::CompleteWithoutSource { nonce };
    assert_eq!(command.phase(), ReceiptPhase::Complete);
    let encoded = serde_json::to_value(&command).unwrap();
    assert_eq!(
        encoded,
        serde_json::json!({ "operation": "complete_without_source", "nonce": nonce })
    );
    let decoded: ServiceCommand = serde_json::from_value(encoded).unwrap();
    assert!(matches!(
        decoded,
        ServiceCommand::CompleteWithoutSource { .. }
    ));
}
