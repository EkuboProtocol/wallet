use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_core::{
    config::{ConfigStore, WalletMetadata, WalletSource},
    custody_provisioning::MigrationAccount,
    policy_store::{DatabaseKey, PolicyStore, migration_database::MigrationDatabaseSnapshot},
    windows_provisioning_client, windows_service_manager,
};
use tokio::sync::watch;
use uuid::Uuid;
use zeroize::Zeroizing;

pub fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 2, "expected service|client <owner SID>");
    let result = match args[0].as_str() {
        "service" => windows_service_manager::run_pending(&args[1], host),
        "client" => client(&args[1]),
        _ => anyhow::bail!("unknown fixture mode"),
    };
    if args[0] == "service" {
        let executable = std::env::current_exe()?;
        std::fs::write(
            executable
                .parent()
                .context("missing fixture parent")?
                .join("service-result.txt"),
            format!("{result:?}\n"),
        )?;
    }
    result
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

fn host(
    owner: &str,
    running: windows_service_manager::Running,
    stop: watch::Receiver<bool>,
) -> Result<()> {
    runtime()?.block_on(ekubo_wallet_service::windows_provisioning::run(
        owner,
        move || running.ready(),
        stop,
    ))
}

fn client(owner: &str) -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let source = temporary.path().canonicalize()?;
    let database = source.join("wallet.db");
    let key = [0x43; 32];
    let account_key = [0x11; 32];
    let wallet = WalletMetadata {
        instance_id: Uuid::new_v4(),
        id: "migration-fixture".into(),
        address: PrivateKeySigner::from_slice(&account_key)?.address(),
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
        let staged = runtime.block_on(windows_provisioning_client::transfer(
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
        restart_fixture_service(owner)?;
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
        "Full encrypted Windows migration staged, rebuilt and recovered after service process restart"
    );
    Ok(())
}

fn restart_fixture_service(owner: &str) -> Result<()> {
    let identity = ekubo_wallet_core::windows_service_config::pending_installer_identity(owner)?;
    let executable = std::env::current_exe()?;
    let helper = executable
        .parent()
        .context("missing fixture parent")?
        .join("restart-windows-provisioning-fixture.ps1");
    let system = std::env::var_os("SystemRoot").context("missing fixture SystemRoot")?;
    let powershell =
        std::path::PathBuf::from(system).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let status = std::process::Command::new(powershell)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(helper)
        .arg("-ServiceName")
        .arg(format!("EkuboWallet-{}", identity.profile_id().simple()))
        .arg("-OwnerSid")
        .arg(owner)
        .status()?;
    ensure!(status.success(), "synthetic service restart failed");
    Ok(())
}
