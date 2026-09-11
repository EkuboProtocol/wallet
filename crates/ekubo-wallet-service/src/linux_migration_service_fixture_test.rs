//! Disposable CI fixture: synthetic keys and an explicitly isolated login keyring.
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
    ensure!(
        args.len() == 2,
        "expected service|client|relay-owner <owner UID>"
    );
    let owner = args[1].parse()?;
    match args[0].as_str() {
        "service" => runtime()?.block_on(ekubo_wallet_service::linux_provisioning::run(owner)),
        "client" => client(owner),
        "relay-owner" => relay_owner(owner),
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
        let mut staged = runtime.block_on(linux_provisioning_client::transfer(
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
        let recipient = std::env::var("EKUBO_FIXTURE_RELAY_RECIPIENT")?.try_into()?;
        let profile =
            ekubo_wallet_core::service_storage::pending_installer_identity(owner)?.profile_id();
        runtime.block_on(ekubo_wallet_core::linux_relay_handoff::deliver(
            owner,
            recipient,
            profile,
            staged.reply().relay(),
        ))?;
        ekubo_wallet_core::service_storage::installer_journal::save_checkpoint(
            owner,
            &staged.checkpoint()?,
        )?;
        let relay = staged.reply().relay().clone();
        drop(staged);
        let snapshot = MigrationDatabaseSnapshot::freeze(&database, Zeroizing::new(key))?;
        let checkpoint =
            ekubo_wallet_core::service_storage::installer_journal::load_checkpoint(owner)?
                .context("fixture checkpoint is missing")?;
        let staged = runtime.block_on(linux_provisioning_client::resume(
            owner,
            checkpoint,
            snapshot,
            relay,
            vec![wallet.clone()],
        ))?;
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

fn relay_owner(owner: u32) -> Result<()> {
    use std::io::Write as _;
    ensure!(
        owner != 0 && rustix::process::getuid().as_raw() == owner,
        "incorrect fixture owner"
    );
    let isolated = std::path::PathBuf::from(std::env::var("EKUBO_FIXTURE_ISOLATED_RELAY")?);
    ensure!(
        std::env::var_os("XDG_DATA_HOME").as_deref() == Some(isolated.join("data").as_os_str())
            && std::env::var_os("XDG_RUNTIME_DIR").as_deref()
                == Some(isolated.join("runtime").as_os_str())
            && std::env::var("DBUS_SESSION_BUS_ADDRESS")?
                .starts_with(&format!("unix:path={}/bus", isolated.display())),
        "fixture keyring is not isolated"
    );
    let runtime = runtime()?;
    let endpoint =
        runtime.block_on(ekubo_wallet_core::linux_relay_handoff::OwnerRelayEndpoint::bind())?;
    runtime.block_on(reject_ordinary_relay_caller(endpoint.unique_name()?))?;
    println!("{}", endpoint.unique_name()?);
    std::io::stdout().flush()?;
    let mut command = String::new();
    std::io::stdin().read_line(&mut command)?;
    ensure!(
        command == "finish\n",
        "fixture owner did not receive completion"
    );
    let profile = ekubo_wallet_core::service_storage::pending_owner_profile()?;
    ekubo_wallet_core::custody_relay::load(profile)?;
    runtime.block_on(endpoint.close())
}

async fn reject_ordinary_relay_caller(recipient: zbus::names::OwnedUniqueName) -> Result<()> {
    let connection = zbus::connection::Builder::unix_stream(
        ekubo_wallet_core::service_storage::system_bus_stream().await?,
    )
    .build()
    .await?;
    let proxy = zbus::Proxy::new(
        &connection,
        recipient.as_str(),
        "/org/ekubo/Wallet/InstallerRelay",
        "org.ekubo.Wallet.InstallerRelay1",
    )
    .await?;
    let result: zbus::Result<String> = proxy
        .call(
            "Persist",
            &(
                Uuid::new_v4().to_string(),
                Uuid::new_v4().to_string(),
                Vec::<u8>::new(),
            ),
        )
        .await;
    ensure!(
        matches!(result, Err(zbus::Error::MethodError(ref name, _, _)) if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied"),
        "ordinary owner reached relay persistence"
    );
    Ok(())
}
