//! Linux service host. All storage/identity checks precede authority creation.

use crate::{authority::ApplicationAuthority, config::ConfigStore, events::DomainEventKind};
use anyhow::{Context as _, Result, ensure};
use std::{
    fs::File,
    os::{
        fd::AsRawFd as _,
        unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    },
    sync::{Arc, atomic::AtomicUsize},
};
use tokio::{net::UnixListener, sync::Semaphore, task::JoinSet};

const MAX_CONNECTIONS: usize = 32;

/// Run a single owner's MCP authority under the installer-provisioned service
/// identity. The desktop remains a client; no user-controlled path, home
/// directory, or credential service can select this process's key storage.
pub async fn run(owner_uid: u32) -> Result<()> {
    let data_dir = ekubo_wallet_core::service_storage::initialize(owner_uid)?;
    let runtime = ekubo_wallet_core::service_storage::runtime_directory()?;
    let listener = bind_listener(&runtime)?;
    let config = ConfigStore::production()?;
    ensure!(
        config.data_dir() == data_dir,
        "service configuration escaped its protected profile"
    );
    let authority = ApplicationAuthority::open(config)?;
    let service = Arc::new(crate::runtime::ServiceRuntime::new(authority));
    let owner_bus = zbus::connection::Builder::unix_stream(
        ekubo_wallet_core::service_storage::system_bus_stream().await?,
    )
    .name(format!("org.ekubo.Wallet.Owner.u{owner_uid}"))?
    .serve_at(
        crate::owner_rpc::OBJECT_PATH,
        crate::owner_rpc::LinuxOwnerInterface::new(service.clone()),
    )?
    .build()
    .await?;
    let events = service.events();
    let mut supervisor = Box::pin(service.supervise());
    events.publish(DomainEventKind::McpStatusChanged { online: true });
    let active = Arc::new(AtomicUsize::new(0));
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let result = loop {
        tokio::select! {
            finished = &mut supervisor => break finished,
            _ = terminate.recv() => break Ok(()),
            signal = tokio::signal::ctrl_c() => break signal.map_err(anyhow::Error::from),
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => break Err(error.into()),
                };
                // Identity comes from the kernel, before any request is read.
                // Harness names in the subsequent hello are only attribution.
                if !peer_is_owner(&stream, owner_uid) {
                    continue;
                }
                let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
                let agent = service.agent_api();
                let active = active.clone();
                let events = events.clone();
                connections.spawn(async move {
                    let _slot = slot;
                    if let Err(error) = crate::mcp_transport::serve_connection(stream, agent, active, events).await {
                        tracing::debug!(%error, "wallet service MCP session ended");
                    }
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    };
    // Cancellation drops the same core execution future used by the desktop.
    // Persisted transaction lifecycle records remain available for recovery.
    drop(supervisor);
    events.publish(DomainEventKind::McpStatusChanged { online: false });
    let reviews_closed = service.close_owner_reviews();
    let owner_closed = owner_bus.close().await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    let dapps_closed = service.shutdown_dapps().await;
    reviews_closed.context("cannot close service transaction reviews")?;
    owner_closed.context("cannot close service owner endpoint")?;
    dapps_closed.context("cannot stop dapp sessions")?;
    result
}

fn bind_listener(runtime: &File) -> Result<UnixListener> {
    let path = format!("/proc/self/fd/{}/mcp.sock", runtime.as_raw_fd());
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_socket()
                    && metadata.uid() == rustix::process::geteuid().as_raw(),
                "refusing to replace an invalid service socket"
            );
            // initialize() holds the profile's exclusive lock. The protected
            // runtime directory prevents a desktop peer replacing this entry.
            std::fs::remove_file(&path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener =
        UnixListener::bind(&path).context("cannot bind protected wallet service socket")?;
    // Connections are authenticated with SO_PEERCRED, not filesystem groups.
    // Other users can connect but are disconnected before reading any bytes.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

fn peer_is_owner(stream: &tokio::net::UnixStream, owner_uid: u32) -> bool {
    stream.peer_cred().is_ok_and(|peer| peer.uid() == owner_uid)
}

#[cfg(test)]
#[path = "linux_test.rs"]
mod tests;
