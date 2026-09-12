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
    ensure!(args.len() == 2, "expected fixture mode and owner UID");
    let owner = args[1].parse()?;
    match args[0].as_str() {
        "service" => runtime()?.block_on(ekubo_wallet_service::linux_provisioning::run(owner)),
        "client" => client(owner),
        "relay-owner" => relay_owner(owner),
        "source-owner" => source_owner(owner),
        "source-client" => source_client(owner),
        "source-recover" => source_recover(owner),
        "source-recover-cutover" => source_recover_cutover(owner),
        "verify-prepared" => verify_prepared(owner),
        "verify-promoted" => verify_promoted(owner),
        "verify-promoted-conflict" => {
            ensure!(
                ekubo_wallet_core::service_storage::installer_journal::acquire_installer()?
                    .verify_promoted(owner)
                    .is_err(),
                "duplicate locations were accepted"
            );
            Ok(())
        }
        _ => anyhow::bail!("unknown fixture mode"),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

fn verify_prepared(owner: u32) -> Result<()> {
    let installer = ekubo_wallet_core::service_storage::installer_journal::acquire_installer()?;
    let prepared = installer.verify_prepared(owner)?;
    ensure!(
        installer.verify_prepared(owner).is_err(),
        "prepared verifier released the service lock"
    );
    prepared.begin_cutover()?;
    drop(prepared);
    drop(installer.verify_prepared(owner)?);
    println!("Quiescent Linux runtime files match the protected checkpoint");
    Ok(())
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

fn source_client(owner: u32) -> Result<()> {
    let runtime = runtime()?;
    let recipient = std::env::var("EKUBO_FIXTURE_SOURCE_RECIPIENT")?.try_into()?;
    let staged = runtime.block_on(linux_provisioning_client::forward_from_owner(
        owner, recipient,
    ))?;
    ensure!(!staged.reply().stage().is_nil(), "missing forwarded stage");
    ensure!(
        ekubo_wallet_core::service_storage::installer_journal::acquire_installer().is_err(),
        "forwarded source released installer exclusion"
    );
    ensure!(
        ekubo_wallet_core::service_storage::installer_journal::load_intent(owner)?.is_some(),
        "forwarding did not persist intent"
    );
    let stored = ekubo_wallet_core::service_storage::installer_journal::load_checkpoint(owner)?
        .context("forwarded checkpoint was not persisted")?;
    ensure!(
        serde_json::to_vec(&stored)? == serde_json::to_vec(staged.checkpoint())?,
        "forwarded checkpoint changed"
    );
    ekubo_wallet_core::service_storage::installer_journal::save_checkpoint(
        owner,
        staged.checkpoint(),
    )?;
    // Source credentials and snapshot were never supplied to this process. The
    // retained channel closes here; this is an abort of retention, not cutover.
    drop(staged);
    drop(ekubo_wallet_core::service_storage::installer_journal::acquire_installer()?);
    println!("Authenticated owner-keyring source staged through the Linux service");
    Ok(())
}

fn source_owner(owner: u32) -> Result<()> {
    use keyring_core::api::CredentialStoreApi as _;
    use std::io::Write as _;
    ensure!(
        owner != 0 && rustix::process::getuid().as_raw() == owner,
        "incorrect source fixture owner"
    );
    let isolated = std::path::PathBuf::from(std::env::var("EKUBO_FIXTURE_ISOLATED_RELAY")?);
    ensure!(
        std::env::var_os("XDG_DATA_HOME").as_deref() == Some(isolated.join("data").as_os_str())
            && std::env::var_os("XDG_RUNTIME_DIR").as_deref()
                == Some(isolated.join("runtime").as_os_str())
            && std::env::var_os("EKUBO_WALLET_HOME").as_deref()
                == Some(isolated.join("wallet").as_os_str())
            && std::env::var("DBUS_SESSION_BUS_ADDRESS")?
                .starts_with(&format!("unix:path={}/bus", isolated.display())),
        "source fixture is not isolated"
    );
    let config = ConfigStore::production()?;
    let explicit = ConfigStore::open(config.data_dir(), DatabaseKey::new([0x43; 32]));
    let wallet = WalletMetadata {
        instance_id: Uuid::new_v4(),
        id: "source-fixture".into(),
        address: alloy::primitives::address!("19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"),
        created_at: chrono::DateTime::from_timestamp_millis(1000).context("fixture time")?,
        source: WalletSource::Imported,
        exported_at: None,
    };
    explicit.update_for_test(|state| {
        state.wallets = vec![wallet.clone()];
        state.networks.clear();
        Ok(())
    })?;
    let database = config.data_dir().join("wallet.db");
    PolicyStore::open(&database, &DatabaseKey::new([0x43; 32]))?
        .register_wallet_without_policy(&wallet)?;
    let before = std::fs::read(&database)?;
    // Only synthetic credentials on this invocation's private session bus. Use
    // the same native backend as production, without adding core test overrides.
    let store = zbus_secret_service_keyring_store::Store::new()?;
    let database_key = store.build("org.ekubo.wallet.db", "default", None)?;
    database_key.set_secret(&[0x43; 32])?;
    let account_key = store.build(
        "org.ekubo.wallet.private-key.instance",
        &wallet.instance_id.to_string(),
        None,
    )?;
    account_key.set_secret(&[0x11; 32])?;
    let runtime = runtime()?;
    for expected in ["recover\n", "recover-cutover\n", "finish\n"] {
        let endpoint = runtime
            .block_on(ekubo_wallet_core::linux_source_handoff::OwnerSourceEndpoint::bind())?;
        println!("{}", endpoint.unique_name()?);
        std::io::stdout().flush()?;
        let mut command = String::new();
        std::io::stdin().read_line(&mut command)?;
        ensure!(
            command == expected,
            "source fixture did not receive completion"
        );
        runtime.block_on(endpoint.close())?;
        // Retire the old endpoint and wait out its source fence before binding
        // the recovery endpoint. No arbitrary sleep or automatic replay.
        explicit.with_lifecycle_lock(|| Ok(()))?;
    }
    // Wait for the collector to release its lifecycle/SQLite fence before any
    // same-process source descriptor is reopened for validation.
    explicit.with_lifecycle_lock(|| {
        ensure!(
            std::fs::read(&database)? == before,
            "legacy source bytes changed"
        );
        ensure!(
            explicit.load()?.wallets == vec![wallet],
            "legacy inventory changed"
        );
        // Staging and abort preserve the keys needed to reopen legacy custody.
        let database_secret = Zeroizing::new(database_key.get_secret()?);
        let account_secret = Zeroizing::new(account_key.get_secret()?);
        ensure!(
            database_secret.as_slice() == [0x43; 32],
            "legacy database key changed during staging"
        );
        ensure!(
            account_secret.as_slice() == [0x11; 32],
            "legacy account key changed during staging"
        );
        let profile = ekubo_wallet_core::service_storage::pending_owner_profile()?;
        ekubo_wallet_core::custody_relay::load(profile)?;
        Ok(())
    })
}

fn source_recover(owner: u32) -> Result<()> {
    let runtime = runtime()?;
    let previous = ekubo_wallet_core::service_storage::installer_journal::load_checkpoint(owner)?
        .context("missing original source checkpoint")?;
    let recipient = std::env::var("EKUBO_FIXTURE_SOURCE_RECIPIENT")?.try_into()?;
    let recovered = runtime.block_on(linux_provisioning_client::recover_from_owner(
        owner, recipient,
    ))?;
    ensure!(
        serde_json::to_vec(recovered.checkpoint())? == serde_json::to_vec(&previous)?,
        "native recovery changed the checkpoint"
    );
    ensure!(
        ekubo_wallet_core::service_storage::installer_journal::acquire_installer().is_err(),
        "recovered source released installer exclusion"
    );
    let identity = ekubo_wallet_core::service_storage::pending_installer_identity(owner)?;
    let unit = format!(
        "ekubo-wallet-provision-fixture-{}@{owner}.service",
        identity.profile_id().simple()
    );
    ensure!(
        std::process::Command::new("systemctl")
            .args(["stop", &unit])
            .status()?
            .success(),
        "fixture service stop failed"
    );
    let confirmed = runtime.block_on(recovered.begin_cutover())?;
    ensure!(
        ekubo_wallet_core::service_storage::installer_journal::acquire_installer().is_err(),
        "confirmed source released installer exclusion"
    );
    drop(confirmed.verify_prepared()?);
    drop(confirmed);
    println!("Native owner source confirmed its frozen checkpoint after durable cutover");
    Ok(())
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

fn source_recover_cutover(owner: u32) -> Result<()> {
    let previous = ekubo_wallet_core::service_storage::installer_journal::load_checkpoint(owner)?
        .context("missing cutover checkpoint")?;
    let recipient = std::env::var("EKUBO_FIXTURE_SOURCE_RECIPIENT")?.try_into()?;
    let runtime = runtime()?;
    let recovered = runtime.block_on(linux_provisioning_client::recover_cutover_from_owner(
        owner, recipient,
    ))?;
    ensure!(
        serde_json::to_vec(recovered.checkpoint())? == serde_json::to_vec(&previous)?,
        "committed recovery changed checkpoint"
    );
    drop(recovered.verify_prepared()?);
    ensure!(
        ekubo_wallet_core::service_storage::installer_journal::acquire_installer().is_err(),
        "committed recovery released installer exclusion"
    );
    drop(recovered);
    println!("Committed source recovered without starting the pending service");
    Ok(())
}

fn verify_promoted(owner: u32) -> Result<()> {
    let installer = ekubo_wallet_core::service_storage::installer_journal::acquire_installer()?;
    let promoted = installer.verify_promoted(owner)?;
    ensure!(
        installer.verify_prepared(owner).is_err(),
        "promoted files remained pending"
    );
    ensure!(
        installer.verify_promoted(owner).is_err(),
        "promoted verification released service exclusion"
    );
    ensure!(
        promoted.begin_cutover().is_err(),
        "promoted guard allowed a new decision"
    );
    drop(promoted);
    drop(installer.verify_promoted(owner)?);
    println!("Moved Linux files verified against committed identity and checkpoint");
    Ok(())
}
