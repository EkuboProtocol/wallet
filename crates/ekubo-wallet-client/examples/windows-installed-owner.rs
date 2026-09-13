//! Standard-user half of contrib/test-windows-installed-acceptance.ps1.
//! Real relay, client, account creation and negative native authorization; no UAC.

#[cfg(windows)]
mod fixture {
    use anyhow::{Context as _, Result, ensure};
    use ekubo_wallet_client::OwnerClient;
    use ekubo_wallet_core::{
        legal::LegalDocument, windows_relay_handoff::OwnerRelayEndpoint, windows_service_config,
        windows_service_identity,
    };
    use serde_json::{Value, json};
    use std::{fs, io::Write as _, path::Path, time::Duration};

    const ACCOUNT: &str = "installed-acceptance";
    const SENTINEL: &[u8] = b"1.x owner data: installed v2 acceptance must not change this\n";

    fn publish(directory: &Path, name: &str, value: &Value) -> Result<()> {
        let temporary = directory.join(format!("{name}.pending"));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(value)?)?;
        file.sync_all()?;
        fs::rename(temporary, directory.join(name))?;
        Ok(())
    }

    async fn command(directory: &Path, name: &str) -> Result<Value> {
        loop {
            match fs::read(directory.join(name)) {
                Ok(bytes) => return Ok(serde_json::from_slice(&bytes)?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn connect(directory: &Path) -> Result<OwnerClient> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        loop {
            match OwnerClient::connect().await {
                Ok(client) => {
                    let _ = fs::remove_file(directory.join("connect-error.txt"));
                    return Ok(client);
                }
                Err(error) if tokio::time::Instant::now() >= deadline => {
                    return Err(error).context("installed owner connection never became ready");
                }
                Err(error) => {
                    // The production installer may time out before this loop.
                    // Keep its actual pending connection error observable then.
                    let _ = fs::write(directory.join("connect-error.txt"), format!("{error:#}"));
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    fn check_denied(paths: &Value) -> Result<usize> {
        let paths = paths.as_array().context("missing raw file checks")?;
        ensure!(
            paths.len() >= 4,
            "coordinator did not supply actual database and key files"
        );
        for path in paths {
            let path = path.as_str().context("invalid raw file path")?;
            for write in [false, true] {
                let result = fs::OpenOptions::new().read(!write).write(write).open(path);
                let error = result
                    .err()
                    .context("standard owner opened protected raw data")?;
                ensure!(
                    error.raw_os_error() == Some(5),
                    "expected ACCESS_DENIED for {path}, got {error}"
                );
            }
        }
        Ok(paths.len())
    }

    async fn run(directory: &Path, phase: &str, expected_sid: &str) -> Result<()> {
        let owner = windows_service_identity::current_process_identity()?;
        ensure!(
            owner.user_sid() == expected_sid,
            "logon did not use the synthetic owner token"
        );
        ensure!(
            windows_service_identity::verify_installer_process().is_err(),
            "owner is an installer/admin"
        );
        let username = std::env::var("USERNAME")?;
        ensure!(
            username.starts_with("ewv2ci_"),
            "fixture requires its synthetic account"
        );
        let profile = std::env::var("USERPROFILE")?;
        let local = std::env::var("LOCALAPPDATA")?;
        ensure!(
            local.to_lowercase().starts_with(&profile.to_lowercase()),
            "owner profile environment is not loaded"
        );
        ensure!(
            std::env::var_os("EKUBO_WALLET_V2_HOME").is_none(),
            "fixture must use production paths"
        );
        let logon = std::process::Command::new("whoami.exe")
            .arg("/logonid")
            .output()?;
        ensure!(logon.status.success(), "cannot read actual token logon SID");
        let logon = String::from_utf8(logon.stdout)?.trim().to_owned();
        ensure!(logon.starts_with("S-1-5-5-"), "unexpected logon SID output");
        // Let the administrator compare the real token report with Windows'
        // SID->profile mapping before touching even the synthetic 1.x sentinel.
        publish(
            directory,
            "identity.json",
            &json!({
                "owner_sid":owner.user_sid(), "session":owner.session_id(),
                "logon":logon, "profile":profile
            }),
        )?;
        command(directory, "begin.json").await?;
        let legacy = Path::new(&local).join("Ekubo/wallet/acceptance-sentinel");
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let relay = if phase == "enroll" {
            ensure!(
                windows_service_config::find_installed_service_identity()?.is_none(),
                "existing v2 profile"
            );
            ensure!(
                !legacy.parent().unwrap().exists(),
                "existing 1.x owner directory"
            );
            fs::create_dir_all(legacy.parent().unwrap())?;
            fs::write(&legacy, SENTINEL)?;
            let endpoint = OwnerRelayEndpoint::bind()?;
            publish(
                directory,
                "relay.json",
                &json!({
                    "owner_sid":owner.user_sid(), "endpoint":endpoint.endpoint_id(),
                    "session":owner.session_id(), "logon":logon, "profile":profile
                }),
            )?;
            Some(tokio::spawn(endpoint.run(receiver)))
        } else {
            None
        };
        ensure!(fs::read(&legacy)? == SENTINEL, "1.x owner sentinel changed");
        let client = connect(directory).await?;
        let session = client.start_desktop_session();
        session.ready().await?;
        let identity = windows_service_config::installed_service_identity()?;
        ensure!(
            identity.owner_sid() == expected_sid,
            "published owner changed"
        );
        let account = if phase == "enroll" {
            ensure!(
                client.accounts().await?.is_empty(),
                "fresh service already has accounts"
            );
            client.create_account(ACCOUNT).await?
        } else {
            client.account(ACCOUNT).await?
        };
        ensure!(
            client.accounts().await? == vec![account.clone()],
            "unexpected account inventory"
        );
        publish(
            directory,
            "ready.json",
            &json!({
                "account":account, "owner_sid":owner.user_sid(), "service_sid":identity.service_sid(),
                "profile_id":identity.profile_id(), "service_name":identity.service_name(),
                "session":owner.session_id(), "logon":logon, "profile":profile
            }),
        )?;
        let checks = command(directory, "checks.json").await?;
        let denied = check_denied(&checks["raw_paths"])?;
        let before = serde_json::to_value(client.legal_status().await?)?;
        let (_, digest) = client.legal_document(LegalDocument::TermsOfService).await?;
        let denial = tokio::time::timeout(
            Duration::from_secs(15),
            client.accept_legal(LegalDocument::TermsOfService, &digest),
        )
        .await
        .context("mismatched logon did not fail before prompting")?
        .err()
        .context("mismatched owner/installer session was authorized")?;
        ensure!(
            denial.to_string().contains("platform owner authentication"),
            "request failed outside native authorization: {denial}"
        );
        ensure!(
            serde_json::to_value(client.legal_status().await?)? == before,
            "denied legal decision mutated state"
        );
        ensure!(
            client.account(ACCOUNT).await? == account,
            "account identity changed"
        );
        ensure!(
            fs::read(&legacy)? == SENTINEL,
            "1.x sentinel changed after owner operations"
        );
        publish(
            directory,
            "checked.json",
            &json!({"raw_files_denied":denied, "auth_denied":denial.to_string(), "legal_unchanged":true, "legacy_unchanged":true}),
        )?;
        command(directory, "finish.json").await?;
        session.close().await?;
        let _ = stop.send(true);
        if let Some(relay) = relay {
            relay.await??;
        }
        Ok(())
    }

    pub async fn main() -> Result<()> {
        let args: Vec<_> = std::env::args().skip(1).collect();
        ensure!(
            args.len() == 3 && matches!(args[0].as_str(), "enroll" | "reconnect"),
            "expected <enroll|reconnect> <exchange-directory> <owner-sid>"
        );
        let directory = Path::new(&args[1]);
        let result =
            tokio::time::timeout(Duration::from_secs(180), run(directory, &args[0], &args[2]))
                .await
                .context("owner acceptance deadline expired")
                .and_then(|value| value);
        if let Err(error) = &result {
            let _ = publish(
                directory,
                "failure.json",
                &json!({"error":format!("{error:#}")}),
            );
        }
        result
    }
}

#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fixture::main().await
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Windows installed-owner acceptance requires Windows")
}
