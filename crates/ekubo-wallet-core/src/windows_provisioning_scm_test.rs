//! Standalone native fixture, built only by contrib/check-windows-service.py.
//! Runs the production SCM and pipe code under distinct real Windows accounts.
//! It exchanges synthetic bytes only; no wallet storage or credentials are used.
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_native_check::{
    provisioning_io, windows_provisioning_pipe, windows_service_config, windows_service_identity,
    windows_service_manager,
};
use std::{
    io::{Read as _, Write as _},
    time::Duration,
};
use tokio::sync::watch;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 2, "expected service|client <owner SID>");
    let result = match args[0].as_str() {
        "service" => windows_service_manager::run_pending(&args[1], host),
        "client" => runtime()?.block_on(client(&args[1])),
        _ => anyhow::bail!("unknown fixture mode"),
    };
    if args[0] == "service" {
        let executable = std::env::current_exe()?;
        let log = executable
            .parent()
            .expect("fixture has a parent")
            .join("service-result.txt");
        std::fs::write(log, format!("{result:?}\n"))?;
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
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    runtime()?.block_on(async move {
        let listener = windows_provisioning_pipe::ProvisioningListener::bind(owner, true)?;
        running.ready()?;
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(60), async {
                let pipe = listener.accept().await?.authenticate().await?;
                let (mut stream, _cancel) = provisioning_io::bridge(pipe, Duration::from_secs(10));
                tokio::task::spawn_blocking(move || {
                    let mut nonce = [0; 16];
                    stream.read_exact(&mut nonce)?;
                    for byte in &mut nonce { *byte ^= 0xff; }
                    stream.write_all(&nonce)?;
                    Ok::<_, anyhow::Error>(())
                }).await?
            }) => result?,
            _ = stop.changed() => anyhow::bail!("fixture stopped before exchange completed"),
        }
    })
}

async fn client(owner: &str) -> Result<()> {
    let identity = windows_service_config::pending_installer_identity(owner)
        .context("fixture installer metadata authentication")?;
    ensure!(
        identity.service_sid() != windows_service_identity::current_process_identity()?.user_sid(),
        "fixture must use different service and installer accounts"
    );
    let pipe = windows_provisioning_pipe::connect(&identity)
        .await
        .context("fixture installer pipe connection")?;
    let (mut stream, _cancel) = provisioning_io::bridge(pipe, Duration::from_secs(10));
    tokio::task::spawn_blocking(move || {
        let nonce = *uuid::Uuid::new_v4().as_bytes();
        stream
            .write_all(windows_provisioning_pipe::PREFACE)
            .context("fixture preface write")?;
        stream.write_all(&nonce).context("fixture nonce write")?;
        let mut reply = [0; 16];
        stream
            .read_exact(&mut reply)
            .context("fixture reply read")?;
        ensure!(
            reply == nonce.map(|byte| byte ^ 0xff),
            "invalid fixture reply"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    println!("SCM provisioning exchange passed with distinct installer and service SIDs");
    Ok(())
}
