//! Hooks are confined to constructing the compiled, released-schema source.
//! Credentials are real entries on the fixture owner's isolated Secret Service.
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Result, ensure};
use ekubo_wallet_core::{
    config::{ConfigStore, WalletMetadata, WalletSource},
    core::policy::WalletPolicy,
    human_presence::{OwnerAuthorization, OwnerAuthorizationScope},
    policy_store::{DatabaseKey, PolicyStore, register_test_database_key},
};
use keyring_core::api::CredentialStoreApi as _;
use sha2::{Digest as _, Sha256};
use std::{
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::PathBuf,
};

const DATABASE_KEY: [u8; 32] = [0x63; 32];
const ACCOUNT_KEY: [u8; 32] = [0x64; 32];

fn entry(service: &str, user: &str) -> keyring::Result<keyring::Entry> {
    let store = zbus_secret_service_keyring_store::Store::new()?;
    Ok(keyring::Entry {
        inner: store.build(service, user, None)?,
    })
}

pub fn run() -> Result<()> {
    let home = PathBuf::from(std::env::var("HOME")?);
    ensure!(
        std::env::var("EKUBO_INSTALLED_ACCEPTANCE").as_deref() == Ok("1")
            && rustix::process::getuid().as_raw() != 0
            && home
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("ewv2-ci-")),
        "source constructor is only for the disposable synthetic owner"
    );
    let source = home.join("legacy-source");
    let expected_path = home.join("move-expected.json");
    match std::env::args().nth(1).as_deref() {
        Some("create") => {
            ensure!(
                !source.try_exists()? && !expected_path.try_exists()?,
                "existing source retained"
            );
            std::fs::DirBuilder::new().mode(0o700).create(&source)?;
            let database_entry = entry("org.ekubo.wallet.db", "default")?;
            ensure!(
                matches!(database_entry.get_secret(), Err(keyring::Error::NoEntry)),
                "old global credential already exists"
            );
            let wallet = WalletMetadata {
                id: "moved-ci".into(),
                instance_id: uuid::Uuid::new_v4(),
                address: PrivateKeySigner::from_slice(&ACCOUNT_KEY)?.address(),
                created_at: chrono::Utc::now(),
                source: WalletSource::Imported,
                exported_at: None,
            };
            let account_entry = entry(
                "org.ekubo.wallet.private-key.instance",
                &wallet.instance_id.to_string(),
            )?;
            ensure!(
                matches!(account_entry.get_secret(), Err(keyring::Error::NoEntry)),
                "old account credential already exists"
            );
            // These hooks are source-construction primitives only. The next
            // process uses the no-hooks client and native owner authorization.
            register_test_database_key(&source, DATABASE_KEY)?;
            let config = ConfigStore::open(&source, DatabaseKey::new(DATABASE_KEY));
            config.update_for_test(|config| {
                config.wallets = vec![wallet.clone()];
                Ok(())
            })?;
            let mut store = PolicyStore::production(&source)?;
            store.register_wallet_without_policy(&wallet)?;
            let authorization =
                OwnerAuthorization::for_test(OwnerAuthorizationScope::PolicySettings);
            // Distinct from the fresh-service baseline: a reset to defaults
            // must not accidentally satisfy the migration policy comparison.
            let source_policy: WalletPolicy = serde_json::from_value(serde_json::json!({
                "version": 1,
                "rules": [{
                    "effect": "deny", "label": "Synthetic legacy native-value denial",
                    "native_value": {"gt": "0"}
                }]
            }))?;
            store.install_policy(
                &wallet.id,
                wallet.address,
                &source_policy,
                None,
                Some(&authorization),
            )?;
            let policy = store.get(&wallet.id)?.expect("source policy installed");
            store.assert_schema_current()?;
            drop(store);
            drop(config);
            // A released desktop creates these persistent lock files. The
            // fixture constructs its database directly rather than opening a UI.
            for name in ["application.lock", "lifecycle.lock"] {
                let lock = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .open(source.join(name))?;
                fs2::FileExt::try_lock_exclusive(&lock)?;
            }
            database_entry.set_secret(&DATABASE_KEY)?;
            account_entry.set_secret(&ACCOUNT_KEY)?;
            let file_hash = hex::encode(Sha256::digest(std::fs::read(source.join("wallet.db"))?));
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(expected_path)?
                .write_all(&serde_json::to_vec(&serde_json::json!({
                    "accounts": [wallet], "policy": policy, "source_file_hash": file_hash
                }))?)?;
        }
        Some("verify") => {
            let expected: serde_json::Value =
                serde_json::from_slice(&std::fs::read(expected_path)?)?;
            ensure!(
                hex::encode(Sha256::digest(std::fs::read(source.join("wallet.db"))?))
                    == expected["source_file_hash"],
                "unmigrated source changed"
            );
            ensure!(
                zeroize::Zeroizing::new(entry("org.ekubo.wallet.db", "default")?.get_secret()?)
                    .as_slice()
                    == DATABASE_KEY,
                "unmigrated database credential changed"
            );
            let instance = expected["accounts"][0]["instance_id"]
                .as_str()
                .expect("fixture instance");
            ensure!(
                zeroize::Zeroizing::new(
                    entry("org.ekubo.wallet.private-key.instance", instance)?.get_secret()?
                )
                .as_slice()
                    == ACCOUNT_KEY,
                "unmigrated account credential changed"
            );
        }
        _ => anyhow::bail!("expected create or verify"),
    }
    println!("Synthetic legacy source fixture verified (no secrets printed).");
    Ok(())
}
