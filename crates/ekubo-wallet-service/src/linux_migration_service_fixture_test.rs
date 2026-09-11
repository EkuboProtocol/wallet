//! Disposable CI fixture: explicit synthetic keys, never login keyring reads.
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_core::{
    config::{ConfigStore, WalletMetadata, WalletSource},
    custody_provisioning::MigrationAccount,
    linux_provisioning_client,
    policy_store::{DatabaseKey, PolicyStore, migration_database::MigrationDatabaseSnapshot},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub fn run() -> Result<()> {
    ensure!(
        std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && std::env::var("RUNNER_OS").as_deref() == Ok("Linux"),
        "disposable Linux CI only"
    );
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 2, "expected service|client <owner UID>");
    let owner = args[1].parse()?;
    match args[0].as_str() {
        "service" => runtime()?.block_on(ekubo_wallet_service::linux_provisioning::run(owner)),
        "client" => client(owner),
        _ => anyhow::bail!("unknown fixture mode"),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

fn client(owner: u32) -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let source = temporary.path().canonicalize()?;
    let database = source.join("wallet.db");
    let key = [0x43; 32];
    let account_key = [0x11; 32];
    let wallet = WalletMetadata {
        instance_id: Uuid::new_v4(),
        id: "migration-fixture".into(),
        // Public address of the fixed synthetic [0x11; 32] key.
        address: alloy::primitives::address!("19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"),
        created_at: chrono::DateTime::from_timestamp_millis(1000)
            .context("invalid fixture time")?,
        source: WalletSource::Imported,
        exported_at: None,
    };
    let config = ConfigStore::open(&source, DatabaseKey::new(key));
    config.update_for_test(|state| {
        state.wallets = vec![wallet.clone()];
        state.networks.clear();
        Ok(())
    })?;
    let mut policies = PolicyStore::open(&database, &DatabaseKey::new(key))?;
    policies.register_wallet_without_policy(&wallet)?;
    drop(policies);
    let runtime = runtime()?;
    config.with_lifecycle_lock(|| {
        let snapshot = MigrationDatabaseSnapshot::freeze(&database, Zeroizing::new(key))?;
        let staged = runtime.block_on(linux_provisioning_client::transfer(
            owner,
            Zeroizing::new(key),
            vec![wallet.clone()],
            vec![MigrationAccount {
                wallet: wallet.clone(),
                key: Zeroizing::new(account_key),
            }],
            snapshot,
        ))?;
        ensure!(!staged.reply().stage().is_nil(), "missing staging identity");
        ensure!(
            staged.reply().canonical().bytes > 0,
            "missing canonical database"
        );
        let staged = runtime.block_on(staged.recover(owner, vec![wallet.clone()]))?;
        // Keep the source fence and lifecycle lock through reply validation.
        // No activation or deletion is performed by this fixture.
        drop(staged);
        Ok(())
    })?;
    ensure!(
        config.load()?.wallets == vec![wallet],
        "source wallet metadata changed"
    );
    println!(
        "Full encrypted Linux migration staged, rebuilt and recovered across service identities"
    );
    Ok(())
}
