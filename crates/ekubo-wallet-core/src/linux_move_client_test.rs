//! No hooks: real LegacySource methods, SystemBus peer authentication and Polkit.
use anyhow::{Result, ensure};
use ekubo_wallet_core::legacy_move::{LegacySource, ProfileInventory};
use keyring_core::api::CredentialStoreApi as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

fn credential_absent(service: &str, user: &str) -> Result<()> {
    let store = zbus_secret_service_keyring_store::Store::new()?;
    let entry = keyring::Entry {
        inner: store.build(service, user, None)?,
    };
    ensure!(
        matches!(entry.get_secret(), Err(keyring::Error::NoEntry)),
        "exact legacy credential was not retired"
    );
    Ok(())
}

fn retired(home: &Path, expected: &Value) -> Result<()> {
    credential_absent("org.ekubo.wallet.db", "default")?;
    for wallet in expected["accounts"].as_array().expect("fixture accounts") {
        credential_absent(
            "org.ekubo.wallet.private-key.instance",
            wallet["instance_id"].as_str().expect("fixture instance"),
        )?;
    }
    let source = home.join("legacy-source");
    ensure!(
        std::fs::read(source.join("wallet.db"))?
            .starts_with(b"EKUBO WALLET 1.X PROFILE RETIRED TO V2\n"),
        "source was not tombstoned"
    );
    let backup = std::fs::read(source.join("wallet.db.retired-v2-backup"))?;
    ensure!(
        !backup.starts_with(b"SQLite format 3\0"),
        "backup is not encrypted"
    );
    ensure!(
        hex::encode(Sha256::digest(backup)) == expected["source_file_hash"],
        "encrypted source backup changed"
    );
    Ok(())
}

async fn status() -> Result<Value> {
    use ekubo_wallet_core::service_storage;
    let identity = service_storage::installed_service_identity()?;
    let bus = zbus::connection::Builder::unix_stream(service_storage::system_bus_stream().await?)
        .build()
        .await?;
    let registry = zbus::fdo::DBusProxy::new(&bus).await?;
    let name = format!("org.ekubo.Wallet2.Owner.u{}", identity.owner_uid());
    let service = registry.get_name_owner(name.as_str().try_into()?).await?;
    ensure!(
        registry
            .get_connection_unix_user(service.clone().into())
            .await?
            == identity.service_uid(),
        "unexpected service UID"
    );
    let proxy = zbus::Proxy::new(
        &bus,
        service.as_str(),
        "/org/ekubo/Wallet2/Owner",
        "org.ekubo.Wallet2.Owner1",
    )
    .await?;
    let reply: String = proxy
        .call(
            "Call",
            &(json!({"method":"legacy_move_status"}).to_string(),),
        )
        .await?;
    Ok(serde_json::from_str(&reply)?)
}

pub async fn run() -> Result<()> {
    let home = PathBuf::from(std::env::var("HOME")?);
    ensure!(
        std::env::var("EKUBO_INSTALLED_ACCEPTANCE").as_deref() == Ok("1")
            && rustix::process::getuid().as_raw() != 0
            && home
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("ewv2-ci-")),
        "move driver is only for the disposable synthetic owner"
    );
    let expected: Value = serde_json::from_slice(&std::fs::read(home.join("move-expected.json"))?)?;
    let mode = std::env::args().nth(1).unwrap_or_default();
    ensure!(
        matches!(mode.as_str(), "interrupt" | "resume"),
        "expected interrupt or resume"
    );
    ensure!(
        status().await?["state"]
            == if mode == "interrupt" {
                "baseline"
            } else {
                "pending_cleanup"
            },
        "unexpected pre-move state"
    );
    let reviewed = LegacySource::review(
        home.join("legacy-source"),
        ProfileInventory::ReviewedComplete {
            preserve_profiles: vec![],
        },
    )
    .await?;
    ensure!(
        serde_json::to_value(&reviewed.summary().accounts)? == expected["accounts"],
        "review changed source identity/address"
    );
    let result = reviewed.move_and_cleanup().await;
    if mode == "interrupt" {
        // The disposable rule blocks Complete after source retirement until
        // root kills the actual service. No fake receipt or transport shim is
        // involved. This process exits after checking retirement; the NEW
        // process verifies pending_cleanup after the service restarts/unlocks.
        ensure!(result.is_err(), "expected interrupted completion transport");
    } else {
        let report = result?;
        ensure!(
            !report.shared_database_credential_retained
                && report.retained_shared_accounts.is_empty(),
            "unexpected retained legacy authority"
        );
        ensure!(
            report.deleted_account_credentials.is_empty()
                && report.already_absent.len()
                    == expected["accounts"]
                        .as_array()
                        .expect("fixture accounts")
                        .len(),
            "resume did not recognize already-retired keys"
        );
        ensure!(
            status().await?["state"] == "complete",
            "move did not complete"
        );
    }
    tokio::task::block_in_place(|| retired(&home, &expected))?;
    println!(
        "Native move {mode} verified; exact old credentials absent, tombstone and encrypted backup intact."
    );
    Ok(())
}
