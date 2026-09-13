//! Small installer coordinator. Never accepts source paths or supplied keys.
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::{Context as _, ensure};
    use ekubo_wallet_core::{linux_provisioning_client, linux_relay_handoff, service_storage};
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--discard-unused") if args.len()==1 => {
            let uid=rustix::process::getuid().as_raw();
            let status=tokio::task::spawn_blocking(move || std::process::Command::new("/usr/bin/pkexec")
                .args(["/usr/lib/ekubo-wallet-v2/install-profile","--discard-unused",&uid.to_string()]).status()).await??;
            ensure!(status.success(),"unused setup was not discarded");
            Ok(())
        }
        Some("--resume-publication") if args.len() == 2 => {
            service_storage::installer_journal::acquire_installer()?.resume(args[1].parse()?)
        }
        Some("--owner" | "--resume-owner") if args.len() == 1 => {
            let resume=args[0]=="--resume-owner";
            let endpoint = linux_relay_handoff::OwnerRelayEndpoint::bind().await?;
            let uid = rustix::process::getuid().as_raw();
            let recipient = endpoint.unique_name()?.to_string();
            let status = tokio::task::spawn_blocking(move || {
                std::process::Command::new("/usr/bin/pkexec")
                    .args(if resume { vec!["/usr/lib/ekubo-wallet-v2/install-profile".to_owned(),"--resume".into(),uid.to_string()] }
                        else { vec!["/usr/lib/ekubo-wallet-v2/install-profile".to_owned(),uid.to_string(),recipient] })
                    .status()
            })
            .await??;
            ensure!(
                status.success(),
                "privileged fresh setup failed; pending profile was retained"
            );
            // This authenticates the active service, loads the owner's ciphertext,
            // and waits for the normal runtime's successful activation reply.
            let connection = ekubo_wallet_client::OwnerClient::connect().await?;
            drop(connection);
            endpoint.close().await?;
            println!("Fresh v2 service connected successfully.");
            Ok(())
        }
        Some("--installer") if args.len() == 3 => {
            let uid = args[1].parse()?;
            let recipient = args[2].as_str().try_into()?;
            let lease = service_storage::installer_journal::acquire_installer()?;
            let profile = service_storage::pending_installer_identity(uid)?.profile_id();
            let relay = linux_provisioning_client::enroll(uid).await?;
            let receipt = linux_relay_handoff::deliver(uid, recipient, profile, &relay).await?;
            let status = std::process::Command::new("/usr/bin/systemctl")
                .args(["stop", &format!("ekubo-wallet-v2-provision@{uid}.service")])
                .status()?;
            ensure!(status.success(), "could not stop pending service");
            lease.publish(uid, &relay, &receipt)
        }
        _ => Err(anyhow::anyhow!(
            "expected --owner, --resume-owner, --discard-unused, or --installer <uid> <owner-unique-bus-name>"
        ))
        .context("fresh v2 enrollment"),
    }
}

#[cfg(target_os = "windows")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--discard-unused"] {
        let owner = ekubo_wallet_core::windows_service_identity::current_process_identity()?
            .user_sid()
            .to_owned();
        tokio::task::spawn_blocking(move || {
            ekubo_wallet_core::windows_fresh_setup::run_elevated(
                &owner,
                uuid::Uuid::new_v4(),
                ekubo_wallet_core::windows_fresh_setup::SetupAction::DiscardUnused,
            )
        })
        .await??;
        println!("Only the unused unpublished v2 attempt was discarded.");
        return Ok(());
    }
    if args == ["--owner"] || args == ["--resume-owner"] {
        let action = if args[0] == "--owner" {
            ekubo_wallet_core::windows_fresh_setup::SetupAction::Install
        } else {
            ekubo_wallet_core::windows_fresh_setup::SetupAction::Resume
        };
        let endpoint = ekubo_wallet_core::windows_relay_handoff::OwnerRelayEndpoint::bind()?;
        let owner = ekubo_wallet_core::windows_service_identity::current_process_identity()?;
        let owner = owner.user_sid().to_owned();
        let endpoint_id = endpoint.endpoint_id();
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let relay = tokio::spawn(endpoint.run(receiver));
        let mut installer = tokio::task::spawn_blocking(move || {
            ekubo_wallet_core::windows_fresh_setup::run_elevated(&owner, endpoint_id, action)
        });
        let activation = tokio::time::timeout(std::time::Duration::from_secs(300), async {
            loop {
                if matches!(
                    ekubo_wallet_core::windows_service_config::find_installed_service_identity(),
                    Ok(Some(_))
                ) && let Ok(client) =
                    ekubo_wallet_client::windows_owner_client::OwnerClient::connect().await
                {
                    drop(client);
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
        tokio::pin!(activation);
        let result: anyhow::Result<()> = async {
            tokio::select! {
                result = &mut installer => { result??; activation.await??; }
                result = &mut activation => { result??; installer.await??; }
            }
            Ok(())
        }
        .await;
        let _ = stop.send(true);
        relay.await??;
        result?;
        println!("Fresh v2 service connected successfully.");
        return Ok(());
    }
    ensure!(
        args.len() == 3 && args[0] == "--installer",
        "expected --installer <owner-sid> <owner-relay-endpoint-uuid>"
    );
    let identity = ekubo_wallet_core::windows_service_config::pending_installer_identity(&args[1])?;
    let relay = ekubo_wallet_core::windows_provisioning_client::enroll(&args[1]).await?;
    ekubo_wallet_core::windows_relay_handoff::deliver(
        &args[1],
        args[2].parse()?,
        identity.profile_id(),
        &relay,
    )
    .await?;
    println!(
        "Fresh v2 ciphertext relay confirmed. Stop provisioning before publishing the profile."
    );
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("protected fresh enrollment is supported on Linux and Windows")
}
