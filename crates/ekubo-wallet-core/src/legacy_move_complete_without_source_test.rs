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

fn binding_for(source: std::path::PathBuf) -> String {
    // Platform-absolute without touching the filesystem: the recovery path
    // never opens the source, but binding validation requires absoluteness
    // and a Unix-style literal is not absolute on Windows.
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
    pending_destination_with_source(wallets, std::env::temp_dir().join("deleted-legacy-source"))
}

fn pending_destination_with_source(
    wallets: &[WalletMetadata],
    bound_source: std::path::PathBuf,
) -> (tempfile::TempDir, [u8; 32], String) {
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
    let binding = binding_for(bound_source);
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

#[test]
fn recovery_refuses_while_the_bound_source_database_is_live() {
    // A unique source directory so parallel tests sharing the default deleted
    // path cannot interfere: only this test's bound source exists.
    let source = tempfile::tempdir().unwrap();
    let live = source.path().join("live-legacy-source");
    std::fs::create_dir(&live).unwrap();
    std::fs::write(live.join("wallet.db"), b"still a live 1.x database").unwrap();
    let (destination, _, _) = pending_destination_with_source(&[], live.clone());
    let error = complete_move_without_source(&owner(), destination.path(), Uuid::new_v4())
        .map(|_| ())
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("still present"),
        "unexpected refusal: {error:#}"
    );
    assert!(
        format!("{error:#}").contains(&live.join("wallet.db").display().to_string()),
        "refusal must name the live source: {error:#}"
    );
    // The refusal changes nothing: cleanup stays pending and sessions blocked.
    let state = database::move_state(destination.path()).unwrap();
    assert!(state.receipt.is_some());
    assert!(!state.complete);
    assert!(require_cleanup_finished(destination.path()).is_err());
}

#[cfg(unix)]
#[test]
fn recovery_refuses_a_dangling_source_symlink_without_dereferencing() {
    let source = tempfile::tempdir().unwrap();
    let live = source.path().join("linked-legacy-source");
    std::fs::create_dir(&live).unwrap();
    std::os::unix::fs::symlink("nowhere.db", live.join("wallet.db")).unwrap();
    let (destination, _, _) = pending_destination_with_source(&[], live);
    // symlink_metadata succeeds on the dangling link itself, so the source
    // counts as present and recovery refuses rather than treating it as gone.
    assert!(complete_move_without_source(&owner(), destination.path(), Uuid::new_v4()).is_err());
    let state = database::move_state(destination.path()).unwrap();
    assert!(state.receipt.is_some());
    assert!(!state.complete);
}

#[test]
fn recovery_retires_unshared_credentials_and_keeps_shared_ones() {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    // Mirrors the normal-completion fixtures: three moved accounts, the third
    // shared with a preserved profile, and the legacy global database key.
    let wallets = vec![wallet(1, 1), wallet(2, 2), wallet(3, 3)];
    let source = std::env::temp_dir().join("recovered-legacy-source");
    let binding = MoveBinding {
        profile: Uuid::new_v4(),
        source,
        preserved_profiles: vec![],
        retained_shared_accounts: vec![Uuid::from_u128(3)],
        retirement: Some(retirement::Identity {
            database_key_hash: retirement::hash(&[7; 32]),
            source_file_hash: [9; 32],
        }),
    };
    let accounts = RefCell::new(BTreeMap::from([
        (Uuid::from_u128(1), vec![1; 32]),
        (Uuid::from_u128(2), vec![2; 32]),
        (Uuid::from_u128(3), vec![3; 32]),
    ]));
    let global = RefCell::new(Some(vec![7; 32]));
    let read = |wallet: &WalletMetadata| {
        Ok(accounts
            .borrow()
            .get(&wallet.instance_id)
            .cloned()
            .map(Zeroizing::new))
    };
    let remove = |wallet: &WalletMetadata, expected: &[u8]| {
        let mut accounts = accounts.borrow_mut();
        assert_eq!(accounts.get(&wallet.instance_id).unwrap(), expected);
        accounts.remove(&wallet.instance_id);
        Ok(())
    };
    let report = retire_recovered_with(
        &binding,
        &wallets,
        read,
        remove,
        || Ok(global.borrow().clone().map(Zeroizing::new)),
        || {
            global.borrow_mut().take();
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        report.deleted_account_credentials,
        vec![Uuid::from_u128(1), Uuid::from_u128(2)]
    );
    assert!(report.already_absent.is_empty());
    assert_eq!(report.retained_shared_accounts, vec![Uuid::from_u128(3)]);
    assert!(!report.shared_database_credential_retained);
    assert_eq!(
        accounts.borrow().keys().collect::<Vec<_>>(),
        [&Uuid::from_u128(3)]
    );
    assert!(global.borrow().is_none());
    // Repeating after completion only confirms absence, exactly like the
    // normal path replaying after a crash before the receipt transaction.
    let deletions = Cell::new(0);
    let repeated = retire_recovered_with(
        &binding,
        &wallets,
        |wallet: &WalletMetadata| {
            Ok(accounts
                .borrow()
                .get(&wallet.instance_id)
                .cloned()
                .map(Zeroizing::new))
        },
        |_, _| {
            deletions.set(deletions.get() + 1);
            panic!("no further key should be removed")
        },
        || Ok(global.borrow().clone().map(Zeroizing::new)),
        || {
            deletions.set(deletions.get() + 1);
            panic!("no further key should be removed")
        },
    )
    .unwrap();
    assert_eq!(
        repeated.already_absent,
        vec![Uuid::from_u128(1), Uuid::from_u128(2)]
    );
    assert!(!repeated.shared_database_credential_retained);
    assert_eq!(deletions.get(), 0);
}

#[test]
fn recovery_retains_credentials_shared_with_preserved_profiles() {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    let wallets = vec![wallet(1, 1), wallet(3, 3)];
    let preserved = std::env::temp_dir().join("preserved-legacy-source");
    let binding = MoveBinding {
        profile: Uuid::new_v4(),
        source: std::env::temp_dir().join("recovered-legacy-source"),
        preserved_profiles: vec![preserved],
        retained_shared_accounts: vec![Uuid::from_u128(3)],
        retirement: Some(retirement::Identity {
            database_key_hash: retirement::hash(&[7; 32]),
            source_file_hash: [9; 32],
        }),
    };
    let accounts = RefCell::new(BTreeMap::from([
        (Uuid::from_u128(1), vec![1; 32]),
        (Uuid::from_u128(3), vec![3; 32]),
    ]));
    let global = RefCell::new(Some(vec![7; 32]));
    let report = retire_recovered_with(
        &binding,
        &wallets,
        |wallet: &WalletMetadata| {
            Ok(accounts
                .borrow()
                .get(&wallet.instance_id)
                .cloned()
                .map(Zeroizing::new))
        },
        |wallet: &WalletMetadata, expected: &[u8]| {
            let mut accounts = accounts.borrow_mut();
            assert_eq!(accounts.get(&wallet.instance_id).unwrap(), expected);
            accounts.remove(&wallet.instance_id);
            Ok(())
        },
        || Ok(global.borrow().clone().map(Zeroizing::new)),
        || panic!("preserved global key deleted"),
    )
    .unwrap();
    assert_eq!(report.deleted_account_credentials, vec![Uuid::from_u128(1)]);
    assert!(report.shared_database_credential_retained);
    assert!(accounts.borrow().contains_key(&Uuid::from_u128(3)));
    assert!(global.borrow().is_some());
}

#[test]
fn recovery_without_retirement_identity_retains_the_global_key() {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    // Older receipts predate resumable retirement identity: the global key
    // cannot be verified, so it is retained rather than deleted blindly.
    let wallets = vec![wallet(1, 1)];
    let binding = MoveBinding {
        profile: Uuid::new_v4(),
        source: std::env::temp_dir().join("recovered-legacy-source"),
        preserved_profiles: vec![],
        retained_shared_accounts: vec![],
        retirement: None,
    };
    let accounts = RefCell::new(BTreeMap::from([(Uuid::from_u128(1), vec![1; 32])]));
    let report = retire_recovered_with(
        &binding,
        &wallets,
        |wallet: &WalletMetadata| {
            Ok(accounts
                .borrow()
                .get(&wallet.instance_id)
                .cloned()
                .map(Zeroizing::new))
        },
        |wallet: &WalletMetadata, _: &[u8]| {
            accounts.borrow_mut().remove(&wallet.instance_id);
            Ok(())
        },
        || Ok(None),
        || panic!("unverifiable global key deleted"),
    )
    .unwrap();
    assert_eq!(report.deleted_account_credentials, vec![Uuid::from_u128(1)]);
    assert!(report.shared_database_credential_retained);
}
