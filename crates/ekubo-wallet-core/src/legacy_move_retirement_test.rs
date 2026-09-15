use super::*;
use std::cell::{Cell, RefCell};

#[cfg(target_os = "linux")]
#[test]
fn hashing_source_keeps_sqlite_read_lock() {
    const CHILD: &str = "EKUBO_SQLITE_HASH_LOCK_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let writer = rusqlite::Connection::open(path).unwrap();
        writer
            .busy_timeout(std::time::Duration::from_millis(50))
            .unwrap();
        let result = writer.execute("INSERT INTO locks VALUES(1)", []);
        if std::env::var_os("EKUBO_SQLITE_HASH_ALLOW_WRITE").is_some() {
            assert_eq!(result.unwrap(), 1);
        } else {
            assert!(
                matches!(result, Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DatabaseBusy)
            );
        }
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lock-check.db");
    let setup = rusqlite::Connection::open(&path).unwrap();
    setup
        .execute_batch("CREATE TABLE locks(value INTEGER)")
        .unwrap();
    drop(setup);
    let pin = File::open(&path).unwrap();
    let reader = rusqlite::Connection::open(&path).unwrap();
    reader.execute_batch("BEGIN; SELECT * FROM locks;").unwrap();
    file_hash(&pin).unwrap();
    let run_writer = |allow: bool| {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "legacy_move::retirement::tests::hashing_source_keeps_sqlite_read_lock",
            ])
            .env(CHILD, &path);
        if allow {
            command.env("EKUBO_SQLITE_HASH_ALLOW_WRITE", "1");
        }
        assert!(command.status().unwrap().success());
    };
    run_writer(false);
    drop(reader);
    run_writer(true);
}

fn identity() -> Identity {
    Identity {
        database_key_hash: hash(&[7; 32]),
        source_file_hash: hash(b"encrypted history"),
    }
}

#[test]
fn database_key_retirement_is_idempotent_after_crash_before_completion() {
    let key = RefCell::new(Some(vec![7; 32]));
    let deletes = Cell::new(0);
    let read = || Ok(key.borrow().clone().map(Zeroizing::new));
    let remove = || {
        deletes.set(deletes.get() + 1);
        key.borrow_mut().take();
        Ok(())
    };
    assert!(!retire_key_with(&identity(), false, read, remove).unwrap());
    assert!(!retire_key_with(&identity(), false, read, remove).unwrap());
    assert_eq!(deletes.get(), 1);
}

#[test]
fn preserved_profiles_keep_global_key_and_absence_is_an_error() {
    assert!(
        retire_key_with(
            &identity(),
            true,
            || Ok(Some(Zeroizing::new(vec![7; 32]))),
            || panic!("preserved key deleted")
        )
        .unwrap()
    );
    assert!(
        retire_key_with(
            &identity(),
            true,
            || Ok(None),
            || panic!("missing key deleted")
        )
        .is_err()
    );
}

#[test]
fn replacement_or_unconfirmed_database_key_is_never_reported_retired() {
    assert!(
        retire_key_with(
            &identity(),
            false,
            || Ok(Some(Zeroizing::new(vec![8; 32]))),
            || panic!("new authority deleted")
        )
        .is_err()
    );
    let reads = Cell::new(0);
    assert!(
        retire_key_with(
            &identity(),
            false,
            || {
                reads.set(reads.get() + 1);
                Ok(Some(Zeroizing::new(vec![
                    if reads.get() == 1 {
                        7
                    } else {
                        8
                    };
                    32
                ])))
            },
            || panic!("replacement deleted")
        )
        .is_err()
    );
    assert!(
        retire_key_with(
            &identity(),
            false,
            || Ok(Some(Zeroizing::new(vec![7; 32]))),
            || Ok(())
        )
        .is_err()
    );
}

fn source() -> (tempfile::TempDir, Frozen, MoveBinding) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap();
    std::fs::write(path.join("wallet.db"), b"encrypted history").unwrap();
    let mut locks = Vec::new();
    for name in ["application.lock", "lifecycle.lock"] {
        let file = File::create(path.join(name)).unwrap();
        fs2::FileExt::try_lock_exclusive(&file).unwrap();
        locks.push(file);
    }
    let frozen = Frozen {
        connection: None,
        pin: open_legacy_file(&path.join("wallet.db"), false).unwrap(),
        _locks: locks,
        root: path.clone(),
        digest: [1; 32],
    };
    let binding = MoveBinding {
        profile: Uuid::new_v4(),
        source: path,
        preserved_profiles: vec![],
        retained_shared_accounts: vec![],
        retirement: Some(identity()),
    };
    (root, frozen, binding)
}

fn receipt(binding: MoveBinding) -> Receipt {
    Receipt {
        phase: super::super::ReceiptPhase::Inspected,
        selection_digest: None,
        profile: binding.profile,
        binding: Some(binding),
        digest: [1; 32],
        nonce: Uuid::new_v4(),
        accounts: vec![],
        wallets: vec![],
    }
}

#[test]
fn tombstone_keeps_encrypted_history_and_resumes_without_old_database_key() {
    let (_root, mut frozen, binding) = source();
    frozen.retire(&binding).unwrap();
    let tombstone = std::fs::read(binding.source.join("wallet.db")).unwrap();
    assert_eq!(tombstone, marker(&binding).unwrap());
    assert_eq!(
        std::fs::read(binding.source.join("wallet.db.retired-v2-backup")).unwrap(),
        b"encrypted history"
    );
    assert!(
        database::open_source(
            &binding.source.join("wallet.db"),
            &DatabaseKey::new([7; 32])
        )
        .is_err()
    );
    drop(frozen);
    // Crash after DB-key removal, before the service completion transaction.
    let mut resumed = LegacySource::resume_with_key(receipt(binding.clone()), None).unwrap();
    assert!(resumed.snapshot.is_none());
    resumed.frozen[0].retire(&binding).unwrap();
    assert_eq!(
        std::fs::read(binding.source.join("wallet.db")).unwrap(),
        tombstone
    );
}

#[test]
fn backup_published_before_crash_can_be_reused_without_overwrite() {
    let (_root, mut frozen, binding) = source();
    drop(backup(&binding.source, &frozen.pin, &identity()).unwrap());
    frozen.retire(&binding).unwrap();
    frozen.retire(&binding).unwrap();
}

#[test]
fn mismatched_backup_source_and_receipt_fail_closed() {
    let (_root, mut frozen, binding) = source();
    std::fs::write(
        binding.source.join("wallet.db.retired-v2-backup"),
        b"other history",
    )
    .unwrap();
    assert!(frozen.retire(&binding).is_err());
    assert_eq!(
        std::fs::read(binding.source.join("wallet.db")).unwrap(),
        b"encrypted history"
    );
    drop(frozen);
    assert!(LegacySource::resume_with_key(receipt(binding.clone()), None).is_err());
    assert!(
        LegacySource::resume_with_key(receipt(binding), Some(Zeroizing::new(vec![8; 32]))).is_err()
    );
}

#[test]
fn tombstone_cannot_be_reused_for_another_destination() {
    let (_root, mut frozen, mut binding) = source();
    frozen.retire(&binding).unwrap();
    drop(frozen);
    binding.profile = Uuid::new_v4();
    assert!(LegacySource::resume_with_key(receipt(binding), None).is_err());
}

#[test]
fn account_cleanup_and_keyless_resume_cover_every_deletion_crash_boundary() {
    for crash_after in 0..=3 {
        let (_root, mut frozen, binding) = source();
        frozen.retire(&binding).unwrap();
        drop(frozen);
        let wallets: Vec<_> = (1_u8..=2)
            .map(|id| WalletMetadata {
                id: format!("wallet-{id}"),
                instance_id: Uuid::from_u128(u128::from(id)),
                address: PrivateKeySigner::from_slice(&[id; 32]).unwrap().address(),
                created_at: chrono::Utc::now(),
                source: crate::config::WalletSource::Imported,
                exported_at: None,
            })
            .collect();
        let accounts = RefCell::new(std::collections::BTreeMap::from([
            (wallets[0].instance_id, vec![1; 32]),
            (wallets[1].instance_id, vec![2; 32]),
        ]));
        let global = RefCell::new(Some(vec![7; 32]));
        let summary = MoveSummary {
            source: binding.source.clone(),
            accounts: wallets.clone(),
            tables: vec![],
            retained_shared_accounts: vec![],
            preserved_profiles: vec![],
        };
        let read = |wallet: &WalletMetadata| {
            Ok(accounts
                .borrow()
                .get(&wallet.instance_id)
                .cloned()
                .map(Zeroizing::new))
        };
        let deletions = Cell::new(0);
        let interrupted = cleanup_with(&summary, read, |wallet, _| {
            if deletions.get() == crash_after {
                anyhow::bail!("injected crash");
            }
            accounts.borrow_mut().remove(&wallet.instance_id);
            deletions.set(deletions.get() + 1);
            Ok(())
        });
        if crash_after < 2 {
            assert!(interrupted.is_err());
        } else {
            interrupted.unwrap();
        }
        if crash_after == 3 {
            retire_key_with(
                &identity(),
                false,
                || Ok(global.borrow().clone().map(Zeroizing::new)),
                || {
                    global.borrow_mut().take();
                    Ok(())
                },
            )
            .unwrap();
        }
        // Reacquire the tombstone's exact old locks and reconstruct the cleanup
        // inventory solely from the protected destination's public receipt.
        let mut receipt = receipt(binding.clone());
        receipt.accounts = wallets.iter().map(|wallet| wallet.instance_id).collect();
        receipt.wallets = wallets;
        let mut resumed =
            LegacySource::resume_with_key(receipt, global.borrow().clone().map(Zeroizing::new))
                .unwrap();
        resumed.frozen[0].retire(&binding).unwrap();
        cleanup_with(&resumed.summary, read, |wallet, expected| {
            assert_eq!(
                accounts.borrow().get(&wallet.instance_id).unwrap(),
                expected
            );
            accounts.borrow_mut().remove(&wallet.instance_id);
            Ok(())
        })
        .unwrap();
        retire_key_with(
            &identity(),
            false,
            || Ok(global.borrow().clone().map(Zeroizing::new)),
            || {
                global.borrow_mut().take();
                Ok(())
            },
        )
        .unwrap();
        assert!(accounts.borrow().is_empty());
        assert!(global.borrow().is_none());
    }
}
