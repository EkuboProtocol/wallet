//! Disposable owner-process test of the production Windows source collector.
use super::{fixture_owner, runtime};
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_core::{
    config::{ConfigStore, WalletMetadata, WalletSource},
    custody_relay,
    policy_store::{DatabaseKey, PolicyStore},
    windows_provisioning_client, windows_service_config, windows_service_storage,
    windows_source_handoff,
};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::watch,
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) async fn client(owner: &str) -> Result<()> {
    fixture_owner(owner)?;
    let profile = windows_service_config::pending_installer_identity(owner)?.profile_id();
    let source = tempfile::tempdir()?;
    let directory = source.path().canonicalize()?;
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .args(["source-owner", owner])
        .env("EKUBO_WALLET_HOME", &directory)
        .env("EKUBO_FIXTURE_SOURCE_HOME", &directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let result = async {
        let mut stdout = child.stdout.take().context("missing source stdout")?;
        let endpoint = read_endpoint(&mut stdout).await?;
        // Neither a source snapshot nor its keys are supplied to this adapter.
        let staged = windows_provisioning_client::forward_from_owner(owner, endpoint).await?;
        ensure!(
            windows_service_storage::installer_journal::load_intent(owner)?.is_some(),
            "forwarding did not persist intent"
        );
        let checkpoint = windows_service_storage::installer_journal::load_checkpoint(owner)?
            .context("missing forwarded checkpoint")?;
        ensure!(
            serde_json::to_vec(&checkpoint)? == serde_json::to_vec(staged.checkpoint())?,
            "forwarded checkpoint changed"
        );
        windows_service_storage::installer_journal::save_checkpoint(owner, staged.checkpoint())?;
        let expected = staged.reply().relay().clone();
        drop(staged);
        let mut stdin = child.stdin.take().context("missing source stdin")?;
        stdin.write_all(b"finish\n").await?;
        let endpoint = read_endpoint(&mut stdout).await?;
        super::restart_fixture_service(owner)?;
        let recovered = windows_provisioning_client::recover_from_owner(owner, endpoint).await?;
        ensure!(
            serde_json::to_vec(recovered.checkpoint())? == serde_json::to_vec(&checkpoint)?,
            "native recovery changed the checkpoint"
        );
        drop(recovered);
        stdin.write_all(b"finish\n").await?;
        drop(stdin);
        let status = tokio::time::timeout(Duration::from_secs(15), child.wait()).await??;
        ensure!(status.success(), "source owner failed");
        ensure!(
            custody_relay::load(profile)?.as_bytes() == expected.as_bytes(),
            "owner relay changed after process exit"
        );
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = child.kill().await;
    }
    result
}

async fn read_endpoint(stdout: &mut tokio::process::ChildStdout) -> Result<Uuid> {
    let mut ready = [0; 37];
    tokio::time::timeout(Duration::from_secs(30), stdout.read_exact(&mut ready)).await??;
    ensure!(ready[36] == b'\n', "invalid source readiness frame");
    let endpoint = std::str::from_utf8(&ready[..36])?.parse::<Uuid>()?;
    ensure!(!endpoint.is_nil(), "invalid source endpoint");
    Ok(endpoint)
}

/// Never overwrite an existing entry. Cleanup only matches this fixture's exact
/// synthetic value; it is test teardown, not production migration cleanup.
struct SyntheticCredential {
    entry: keyring::Entry,
    value: Zeroizing<[u8; 32]>,
    created: bool,
}
impl SyntheticCredential {
    fn create(service: &str, user: &str, value: [u8; 32]) -> Result<Self> {
        let entry = keyring::Entry::new(service, user)?;
        match entry.get_secret() {
            Err(keyring::Error::NoEntry) => {}
            Err(error) => return Err(error.into()),
            Ok(bytes) => {
                drop(Zeroizing::new(bytes));
                anyhow::bail!("refusing an existing fixture credential");
            }
        }
        let credential = Self {
            entry,
            value: Zeroizing::new(value),
            created: true,
        };
        credential.entry.set_secret(credential.value.as_slice())?;
        let readback = Zeroizing::new(credential.entry.get_secret()?);
        ensure!(
            readback.as_slice() == credential.value.as_slice(),
            "fixture credential readback failed"
        );
        Ok(credential)
    }

    fn remove(&mut self) -> Result<()> {
        if !self.created {
            return Ok(());
        }
        let bytes = match self.entry.get_secret() {
            Err(keyring::Error::NoEntry) => {
                self.created = false;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
            Ok(bytes) => Zeroizing::new(bytes),
        };
        ensure!(
            bytes.as_slice() == self.value.as_slice(),
            "fixture credential changed; refusing removal"
        );
        self.entry.delete_credential()?;
        self.created = false;
        Ok(())
    }

    fn verify_preserved(&self) -> Result<()> {
        let bytes = Zeroizing::new(self.entry.get_secret()?);
        ensure!(
            bytes.as_slice() == self.value.as_slice(),
            "legacy credential changed during staging"
        );
        Ok(())
    }
}
impl Drop for SyntheticCredential {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

pub(super) fn owner(owner: &str) -> Result<()> {
    fixture_owner(owner)?;
    let directory = std::path::PathBuf::from(
        std::env::var_os("EKUBO_FIXTURE_SOURCE_HOME")
            .context("missing isolated source directory")?,
    );
    let production = ConfigStore::production()?;
    ensure!(
        directory.is_absolute()
            && production.data_dir() == directory.as_path()
            && directory.canonicalize()? == directory,
        "source home is not isolated"
    );
    ensure!(
        !directory.join("wallet.db").exists(),
        "refusing an existing source database"
    );
    let config = ConfigStore::open(&directory, DatabaseKey::new([0x43; 32]));
    let wallet = WalletMetadata {
        instance_id: Uuid::new_v4(),
        id: "source-fixture".into(),
        address: alloy::primitives::address!("19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"),
        created_at: chrono::DateTime::from_timestamp_millis(1000).context("fixture time")?,
        source: WalletSource::Imported,
        exported_at: None,
    };
    let mut database_key =
        SyntheticCredential::create("org.ekubo.wallet.db", "default", [0x43; 32])?;
    let mut account_key = SyntheticCredential::create(
        "org.ekubo.wallet.private-key.instance",
        &wallet.instance_id.to_string(),
        [0x11; 32],
    )?;
    config.update_for_test(|state| {
        state.wallets = vec![wallet.clone()];
        state.networks.clear();
        Ok(())
    })?;
    let path = directory.join("wallet.db");
    PolicyStore::open(&path, &DatabaseKey::new([0x43; 32]))?
        .register_wallet_without_policy(&wallet)?;
    let before = std::fs::read(&path)?;
    runtime()?.block_on(serve())?;
    // Complete cancellation before publishing a fresh recovery endpoint; no
    // timing-based retry can race the previous collector's admission permit.
    config.with_lifecycle_lock(|| Ok(()))?;
    runtime()?.block_on(serve())?;
    // Wait for the blocking collector to release both locks before reopening
    // the source. No test cleanup can race its in-flight credential reads.
    config.with_lifecycle_lock(|| {
        ensure!(
            std::fs::read(&path)? == before,
            "source database bytes changed"
        );
        ensure!(
            config.load()?.wallets == vec![wallet],
            "source inventory changed"
        );
        // Staging and abort must preserve both legacy keys. Teardown accepts
        // already-missing entries, so it cannot establish this invariant.
        account_key.verify_preserved()?;
        database_key.verify_preserved()?;
        account_key.remove()?;
        database_key.remove()
    })
}

async fn serve() -> Result<()> {
    use std::io::Write as _;
    let endpoint = windows_source_handoff::OwnerSourceEndpoint::bind()?;
    let (stop, receiver) = watch::channel(false);
    let id = endpoint.endpoint_id();
    let serving = tokio::spawn(endpoint.run(receiver));
    println!("{id}");
    std::io::stdout().flush()?;
    let result = tokio::time::timeout(Duration::from_secs(360), async {
        let mut finish = [0; 7];
        tokio::io::stdin().read_exact(&mut finish).await?;
        ensure!(&finish == b"finish\n", "invalid source shutdown frame");
        Ok::<_, anyhow::Error>(())
    })
    .await;
    let _ = stop.send(true);
    serving.await??;
    result.context("source owner timed out")?
}
