//! Small installer coordinator. Never accepts source paths or supplied keys.
//!
//! Privilege boundary: `--installer` (and, on Linux, `--resume-publication`,
//! invoked only by the fixed `/usr/lib/ekubo-wallet-v2/install-profile`
//! helper as root) are the only privileged entries that handle relay or
//! custody material. Every other mode runs as the ordinary owner and reaches
//! privilege solely through the OS elevation of a fixed installed path:
//! pkexec of that helper (constrained by the dedicated
//! `org.ekubo.wallet.v2.install-profile` polkit action) on Linux, or UAC of
//! the signed enrollment helper / signed recovery script on Windows.
//! Discard and resume refuse any profile that already shows account authority
//! and fail closed; they never delete owner credentials.
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::{Context as _, ensure};
    use ekubo_wallet_core::{linux_provisioning_client, linux_relay_handoff, service_storage};
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--discard-unused") if args.len()==1 => {
            let uid=rustix::process::getuid().as_raw();
            refuse_published_reset(uid)?;
            let status=tokio::task::spawn_blocking(move || std::process::Command::new("/usr/bin/pkexec")
                // Mirror polkit::install_policy: no agent on a controlling
                // terminal the desktop does not have, and no caller SHELL for
                // pkexec to reject before polkit is even consulted.
                .arg("--disable-internal-agent")
                .env_remove("SHELL")
                .args(["/usr/lib/ekubo-wallet-v2/install-profile","--discard-unused",&uid.to_string()]).status()).await??;
            ensure!(status.success(),"unused setup was not discarded");
            Ok(())
        }
        Some("--resume-publication") if args.len() == 2 => {
            let uid: u32 = args[1].parse()?;
            // No zero-account gate here: this entry also serves the idempotent
            // restart of an already-published profile (no pending identity),
            // and InstallerLease::resume is itself fail-closed on the durable
            // relay confirmation plus an exact-identity match that never
            // replaces active metadata. The zero-account gate lives on
            // --installer, the only entry that publishes a new profile.
            service_storage::installer_journal::acquire_installer()?.resume(uid)
        }
        Some("--owner" | "--resume-owner") if args.len() == 1 => {
            // Fail fast when the owner's platform credential store is
            // unreachable: the relay delivery below persists through the
            // session Secret Service, so without it enrollment would fail
            // late, after admin authentication and privileged key generation.
            require_secret_service().await?;
            let resume=args[0]=="--resume-owner";
            let endpoint = linux_relay_handoff::OwnerRelayEndpoint::bind().await?;
            let uid = rustix::process::getuid().as_raw();
            let recipient = endpoint.unique_name()?.to_string();
            // Elevation targets only the fixed installed helper path; the
            // dedicated install-profile polkit action constrains pkexec to
            // that exact executable. The helper re-validates everything.
            let status = tokio::task::spawn_blocking(move || {
                std::process::Command::new("/usr/bin/pkexec")
                    // Mirror polkit::install_policy (see hardening note on the
                    // --discard-unused call above).
                    .arg("--disable-internal-agent")
                    .env_remove("SHELL")
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
            let uid: u32 = args[1].parse()?;
            // The only privileged entry on this platform. The pending profile
            // must still show a zero-account database before publication.
            require_zero_account_pending(uid)?;
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

/// Fail fast when no Secret Service answers on the owner's session bus.
/// The desktop relay persists the installer's ciphertext through the platform
/// credential store (`credential_store::entry` builds a
/// `zbus_secret_service_keyring_store::Store`, whose first Secret Service
/// method call bus-activates this same well-known session-bus name), so
/// requesting activation here reuses that availability signal instead of a new
/// bus mechanism. `GetNameOwner`/`NameHasOwner` never trigger D-Bus
/// activation and would wrongly refuse sessions where the daemon is
/// activatable but not yet owned (Hyprland/sway without a PAM-started
/// keyring); `StartServiceByName` performs the same activation the real
/// store's first call would. This only avoids the late failure after
/// elevation; core's entry construction remains the authoritative check and
/// can still refuse an unusable store.
#[cfg(target_os = "linux")]
async fn require_secret_service() -> anyhow::Result<()> {
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let connection = zbus::Connection::session().await?;
        let registry = zbus::fdo::DBusProxy::new(&connection).await?;
        // Idempotent: returns AlreadyRunning when the daemon is up. Any other
        // reply or an explicit refusal (e.g. ServiceUnknown) fails closed.
        let reply = registry
            .start_service_by_name("org.freedesktop.secrets".try_into()?, 0)
            .await?;
        let _ = zbus::fdo::StartServiceReply::try_from(reply)?;
        Ok::<_, anyhow::Error>(())
    })
    .await;
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(anyhow::anyhow!("no reachable Secret Service: {error:#}")),
        Err(_) => Err(anyhow::anyhow!(
            "no reachable Secret Service: session bus lookup timed out"
        )),
    }
}

/// Refuse to escalate a reset once an installed profile exists for this owner.
/// This only avoids a pointless authorization prompt: the privileged helper
/// re-validates the same condition with pinned descriptors before deleting.
#[cfg(target_os = "linux")]
fn refuse_published_reset(owner_uid: u32) -> anyhow::Result<()> {
    use anyhow::ensure;
    ensure!(owner_uid != 0, "discard requires an ordinary owner");
    ensure!(
        !std::path::Path::new(&format!("/etc/ekubo-wallet-v2/owners/{owner_uid}.json")).exists()
            && !std::path::Path::new(&format!("/var/lib/ekubo-wallet-v2/{owner_uid}")).exists(),
        "an installed v2 profile exists; discard/reset is refused"
    );
    Ok(())
}

/// Admin reset guard: first-time publication requires a zero-account pending
/// profile. Refuse when any `key-account-*` or `setup-complete` record exists,
/// mirroring the Windows pending-profile allowlist. Fail closed, including on
/// unreadable state; no owner credential is read or deleted here.
#[cfg(target_os = "linux")]
fn require_zero_account_pending(owner_uid: u32) -> anyhow::Result<()> {
    use anyhow::{Context as _, ensure};
    use ekubo_wallet_core::service_storage;
    let profile = service_storage::pending_installer_identity(owner_uid)
        .context("pending installer identity is required")?
        .profile_id();
    let directory = std::path::PathBuf::from(format!("/var/lib/ekubo-wallet-v2/pending/{profile}"));
    let entries =
        std::fs::read_dir(&directory).with_context(|| "cannot inspect pending profile")?;
    for entry in entries {
        let name = entry?.file_name().to_string_lossy().into_owned();
        ensure!(
            !name.starts_with("key-account-") && name != "setup-complete",
            "pending profile shows active authority; publication/resume is refused"
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--discard-unused"] {
        // Admin reset guard: never escalate a discard once an installed
        // profile exists. The SYSTEM recovery script re-enforces this with
        // its closed pending-profile allowlist; confirmed or installed
        // profiles can never be discarded.
        if ekubo_wallet_core::windows_service_config::find_installed_service_identity()?.is_some() {
            anyhow::bail!("an installed v2 profile exists; discard is refused");
        }
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
    if args == ["--reset-confirmed"] {
        // Admin-plus-owner reset of a confirmed-but-never-activated profile
        // (forged relay receipt or lost credential entry), including the
        // post-publish stranded state where the installer already created
        // the Owners records before the readiness wait failed. Eligibility
        // turns on activation (setup-complete, account keys, service
        // command), which only SYSTEM can inspect against private storage:
        // the coordinator cannot tell that stranded state apart from an
        // active profile, so it always elevates and the SYSTEM recovery
        // script enforces the zero-account/no-setup-complete allowlist and
        // refuses any profile that ever became usable.
        let owner = ekubo_wallet_core::windows_service_identity::current_process_identity()?
            .user_sid()
            .to_owned();
        tokio::task::spawn_blocking(move || {
            ekubo_wallet_core::windows_fresh_setup::run_elevated(
                &owner,
                uuid::Uuid::new_v4(),
                ekubo_wallet_core::windows_fresh_setup::SetupAction::ResetConfirmed,
            )
        })
        .await??;
        println!("Only the confirmed-but-never-activated v2 attempt was reset.");
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
                ) && let Ok(client) = ekubo_wallet_client::OwnerClient::connect().await
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
    if args.len() == 3 && args[0] == "--launch-install" {
        // Elevation trampoline only: run_elevated UAC-elevates this signed
        // binary so the relay endpoint never travels on a generic host command
        // line. Performs no custody, relay, or publication operation itself.
        ekubo_wallet_core::windows_service_identity::verify_installer_process()?;
        ekubo_wallet_core::windows_fresh_setup::run_install_script(&args[1], args[2].parse()?)?;
        return Ok(());
    }
    ensure!(
        args.len() == 3 && args[0] == "--installer",
        "expected --installer <owner-sid> <owner-relay-endpoint-uuid>"
    );
    // The only privileged enrollment entry on this platform. The relay
    // recipient is bound to the exact pending profile: deliver re-reads the
    // protected pending identity and refuses a mismatched profile, and the
    // install script verifies the durable RelayConfirmed marker before
    // publishing the profile.
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
