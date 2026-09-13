use super::*;
use std::{cell::RefCell, collections::BTreeMap};

async fn synchronous_platform_runtime_phase() {
    let value = blocking_phase("platform runtime regression", || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(runtime.block_on(async { 17 }))
    })
    .await
    .unwrap();
    assert_eq!(value, 17);
    let error = blocking_phase::<()>("credential read regression", || {
        anyhow::bail!("native backend failure")
    })
    .await
    .unwrap_err();
    assert!(
        format!("{error:#}")
            .contains("legacy move credential read regression: native backend failure")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_platform_phases_support_current_thread_callers() {
    synchronous_platform_runtime_phase().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_platform_phases_support_multithread_cli_callers() {
    synchronous_platform_runtime_phase().await;
}

#[test]
fn legacy_platform_phases_support_desktop_worker_block_on() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let handle = runtime.handle().clone();
    runtime.block_on(async move {
        tokio::task::spawn_blocking(move || handle.block_on(synchronous_platform_runtime_phase()))
            .await
            .unwrap();
    });
}

#[test]
fn move_owner_request_uses_the_shared_protocol_envelope() {
    let nonce = Uuid::new_v4();
    let request =
        serde_json::to_value(OwnerRequest::LegacyMove(&ServiceCommand::Inspect { nonce })).unwrap();
    assert_eq!(
        request,
        serde_json::json!({ "method": "legacy_move", "params": { "operation": "inspect", "nonce": nonce } })
    );
}

#[tokio::test]
async fn unknown_profile_inventory_cannot_start_a_retirement() {
    assert!(
        LegacySource::review(PathBuf::from("/does-not-exist"), ProfileInventory::Unknown)
            .await
            .is_err()
    );
}

fn wallet(id: u128, key: u8) -> WalletMetadata {
    WalletMetadata {
        id: format!("wallet-{id}"),
        instance_id: Uuid::from_u128(id),
        address: PrivateKeySigner::from_slice(&[key; 32]).unwrap().address(),
        created_at: chrono::Utc::now(),
        source: crate::config::WalletSource::Imported,
        exported_at: None,
    }
}
fn summary() -> MoveSummary {
    MoveSummary {
        source: PathBuf::from("/synthetic/legacy"),
        accounts: vec![wallet(1, 1), wallet(2, 2), wallet(3, 3)],
        tables: vec![],
        retained_shared_accounts: vec![Uuid::from_u128(3)],
        preserved_profiles: vec![PathBuf::from("/synthetic/unmigrated")],
    }
}

#[test]
fn cleanup_resumes_after_partial_failure_and_retains_shared_credentials() {
    let summary = summary();
    let source = tempfile::tempdir().unwrap();
    crate::policy_store::register_test_database_key(source.path(), [0x61; 32]).unwrap();
    let config = crate::config::ConfigStore::open(source.path(), DatabaseKey::new([0x61; 32]));
    config
        .update_for_test(|config| {
            config.wallets = summary.accounts.clone();
            Ok(())
        })
        .unwrap();
    let mut store = crate::policy_store::PolicyStore::production(source.path()).unwrap();
    for wallet in &summary.accounts {
        store.register_wallet_without_policy(wallet).unwrap();
    }
    drop(store);
    let connection = database::open_source(
        &source.path().join("wallet.db"),
        &DatabaseKey::new([0x61; 32]),
    )
    .unwrap();
    let snapshot = database::capture(&connection, false).unwrap();
    let destination = tempfile::tempdir().unwrap();
    crate::policy_store::register_test_database_key(destination.path(), [0x62; 32]).unwrap();
    crate::config::ConfigStore::open(destination.path(), DatabaseKey::new([0x62; 32]))
        .load()
        .unwrap();
    database::initialize_baseline(destination.path()).unwrap();
    assert!(
        database::move_state(destination.path())
            .unwrap()
            .receipt
            .is_none()
    );
    let binding = serde_json::to_string(&MoveBinding {
        profile: Uuid::new_v4(),
        source: summary.source.clone(),
        preserved_profiles: summary.preserved_profiles.clone(),
        retained_shared_accounts: summary.retained_shared_accounts.clone(),
        retirement: None,
    })
    .unwrap();
    let digest =
        database::import_bound(destination.path(), &snapshot, &binding, |_| Ok(())).unwrap();
    assert_eq!(
        database::verify(destination.path(), digest).unwrap().len(),
        3
    );
    assert!(require_cleanup_finished(destination.path()).is_err());
    let keys = RefCell::new(BTreeMap::from([
        (Uuid::from_u128(1), vec![1; 32]),
        (Uuid::from_u128(2), vec![2; 32]),
        (Uuid::from_u128(3), vec![3; 32]),
    ]));
    let read = |wallet: &WalletMetadata| {
        Ok(keys
            .borrow()
            .get(&wallet.instance_id)
            .cloned()
            .map(Zeroizing::new))
    };
    let remove = |wallet: &WalletMetadata, expected: &[u8]| {
        if wallet.instance_id == Uuid::from_u128(2) {
            anyhow::bail!("interrupted cleanup");
        }
        let mut keys = keys.borrow_mut();
        assert_eq!(keys.get(&wallet.instance_id).unwrap(), expected);
        keys.remove(&wallet.instance_id);
        Ok(())
    };
    assert!(cleanup_with(&summary, read, remove).is_err());
    assert!(!keys.borrow().contains_key(&Uuid::from_u128(1)));
    // Reopen after committed import and partial cleanup. Accounts are present,
    // but the durable pending state must still prohibit execution.
    let pending = database::move_state(destination.path()).unwrap();
    assert_eq!(pending.receipt, Some(digest));
    assert!(!pending.complete);
    assert_eq!(pending.binding.as_deref(), Some(binding.as_str()));
    assert!(
        database::import_bound(destination.path(), &snapshot, "another-source", |_| panic!(
            "wrong source must not reach keys"
        ))
        .is_err()
    );
    database::import_bound(destination.path(), &snapshot, &binding, |_| Ok(())).unwrap();
    let report = cleanup_with(&summary, read, |wallet, expected| {
        let mut keys = keys.borrow_mut();
        assert_eq!(keys.get(&wallet.instance_id).unwrap(), expected);
        keys.remove(&wallet.instance_id);
        Ok(())
    })
    .unwrap();
    assert_eq!(report.already_absent, vec![Uuid::from_u128(1)]);
    assert_eq!(report.deleted_account_credentials, vec![Uuid::from_u128(2)]);
    assert!(report.shared_database_credential_retained);
    assert_eq!(keys.borrow().len(), 1);
    assert!(keys.borrow().contains_key(&Uuid::from_u128(3)));
    // Crash after all eligible deletions but before completion: replay is an
    // explicit same-source verification, and already-absent keys are accepted.
    assert!(!database::move_state(destination.path()).unwrap().complete);
    assert!(require_cleanup_finished(destination.path()).is_err());
    database::import_bound(destination.path(), &snapshot, &binding, |_| Ok(())).unwrap();
    let resumed = cleanup_with(&summary, read, |_, _| {
        panic!("no further key should be removed")
    })
    .unwrap();
    assert_eq!(resumed.already_absent.len(), 2);
    assert_eq!(resumed.retained_shared_accounts, vec![Uuid::from_u128(3)]);
    assert!(resumed.shared_database_credential_retained);
    database::verify(destination.path(), digest).unwrap();
    assert!(database::finish_cleanup(destination.path(), digest, "another-source").is_err());
    database::finish_cleanup(destination.path(), digest, &binding).unwrap();
    assert!(database::move_state(destination.path()).unwrap().complete);
    require_cleanup_finished(destination.path()).unwrap();
    assert!(
        database::import_bound(destination.path(), &snapshot, &binding, |_| panic!(
            "completed cleanup must not replay"
        ))
        .is_err()
    );
}

#[test]
fn any_source_key_mismatch_prevents_cleanup_admission() {
    let summary = summary();
    assert!(
        cleanup_with(
            &summary,
            |_| Ok(Some(Zeroizing::new(vec![9; 32]))),
            |_, _| panic!("mismatched credentials must not be removed")
        )
        .is_err()
    );
}

#[test]
fn the_same_account_under_another_profile_uuid_is_not_reported_as_retired() {
    assert_eq!(
        shared_accounts(&[wallet(1, 1)], &[wallet(99, 1)]),
        vec![Uuid::from_u128(1)]
    );
    assert!(shared_accounts(&[wallet(1, 1)], &[wallet(99, 2)]).is_empty());
}
