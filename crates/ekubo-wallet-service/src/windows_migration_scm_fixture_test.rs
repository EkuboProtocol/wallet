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

#[path = "windows_source_scm_fixture_test.rs"]
mod source;

pub fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 2, "expected fixture mode and owner SID");
    let result = match args[0].as_str() {
        "service" => windows_service_manager::run_pending(&args[1], host),
        "client" => client(&args[1]),
        "relay-owner" => runtime()?.block_on(relay_owner(&args[1])),
        "source-client" => runtime()?.block_on(source::client(&args[1])),
        "source-owner" => source::owner(&args[1]),
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
    ensure!(
        std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && std::env::var("RUNNER_OS").as_deref() == Ok("Windows"),
        "disposable Windows CI only"
    );

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
        let mut staged = runtime.block_on(windows_provisioning_client::transfer(
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
        ekubo_wallet_core::windows_service_storage::installer_journal::save_checkpoint(
            owner,
            &staged.checkpoint()?,
        )?;
        let relay = runtime.block_on(deliver_owner_relay(owner, staged.reply().relay()))?;
        drop(staged);
        let snapshot = MigrationDatabaseSnapshot::freeze(&database, Zeroizing::new(key))?;
        let checkpoint =
            ekubo_wallet_core::windows_service_storage::installer_journal::load_checkpoint(owner)?
                .context("fixture checkpoint is missing")?;
        let staged = runtime.block_on(windows_provisioning_client::resume(
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

async fn deliver_owner_relay(
    owner: &str,
    relay: &ekubo_wallet_core::custody_envelope::WrappedDataKey,
) -> Result<ekubo_wallet_core::custody_envelope::WrappedDataKey> {
    use ekubo_wallet_core::{custody_relay, windows_relay_handoff, windows_service_config};
    use std::{process::Stdio, time::Duration};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    fixture_owner(owner)?;
    let profile = windows_service_config::pending_installer_identity(owner)?.profile_id();
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .args(["relay-owner", owner])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let result = async {
        let mut stdout = child.stdout.take().context("missing relay owner stdout")?;
        let mut ready = [0; 37];
        tokio::time::timeout(Duration::from_secs(30), stdout.read_exact(&mut ready))
            .await
            .context("relay owner readiness timed out")??;
        ensure!(ready[36] == b'\n', "invalid relay owner readiness frame");
        let endpoint = std::str::from_utf8(&ready[..36])?.parse::<Uuid>()?;
        ensure!(!endpoint.is_nil(), "invalid relay owner endpoint");
        windows_relay_handoff::deliver(owner, endpoint, profile, relay).await?;
        let mut stdin = child.stdin.take().context("missing relay owner stdin")?;
        stdin.write_all(b"finish\n").await?;
        drop(stdin);
        let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
            .await
            .context("relay owner shutdown timed out")??;
        ensure!(status.success(), "relay owner process failed");
        // Reload only after the separate owner process has acknowledged the
        // credential write and exited; no in-memory endpoint state survives.
        custody_relay::load(profile)
    }
    .await;
    if result.is_err() {
        // Terminate/reap only this fixture's child, including readiness errors.
        let _ = child.kill().await;
    }
    result
}

fn fixture_owner(owner: &str) -> Result<()> {
    ensure!(
        std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
            && std::env::var("RUNNER_OS").as_deref() == Ok("Windows"),
        "disposable Windows CI only"
    );
    ensure!(
        ekubo_wallet_core::windows_service_identity::current_process_identity()?.user_sid()
            == owner,
        "fixture must run under its synthetic owner account"
    );
    Ok(())
}

async fn relay_owner(owner: &str) -> Result<()> {
    use ekubo_wallet_core::windows_relay_handoff;
    use std::{io::Write as _, time::Duration};
    use tokio::io::AsyncReadExt as _;
    fixture_owner(owner)?;
    let endpoint = windows_relay_handoff::OwnerRelayEndpoint::bind()?;
    println!("{}", endpoint.endpoint_id());
    std::io::stdout().flush()?;
    let (stop, receiver) = watch::channel(false);
    let serving = tokio::spawn(endpoint.run(receiver));
    let result = tokio::time::timeout(Duration::from_secs(360), async {
        let mut finish = [0; 7];
        tokio::io::stdin().read_exact(&mut finish).await?;
        ensure!(&finish == b"finish\n", "invalid relay owner shutdown frame");
        Ok::<_, anyhow::Error>(())
    })
    .await;
    let _ = stop.send(true);
    serving.await??;
    result.context("relay owner shutdown request timed out")?
}
