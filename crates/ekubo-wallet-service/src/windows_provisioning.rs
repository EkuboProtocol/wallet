//! Pending Windows host. It stages custody only, with no active wallet runtime.
use anyhow::Result;
use ekubo_wallet_core::{
    custody_provisioning, provisioning_io, windows_provisioning_pipe::ProvisioningListener,
    windows_service_storage::PendingCredentialStorage,
};
use std::sync::Arc;
use tokio::sync::{Mutex, watch};

pub async fn run(
    owner_sid: &str,
    started: impl FnOnce() -> Result<()>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let pending = Arc::new(Mutex::new(PendingCredentialStorage::open(owner_sid)?));
    let mut listener = ProvisioningListener::bind(owner_sid, true)?;
    started()?;
    while !*stop.borrow() {
        let connected = tokio::select! {
            connection = listener.accept() => connection?,
            _ = stop.changed() => return Ok(()),
        };
        // Keep the accepted pipe alive until the successor reserves the name.
        listener = ProvisioningListener::bind(owner_sid, false)?;
        let pipe = tokio::select! {
            pipe = connected.authenticate() => match pipe { Ok(pipe) => pipe, Err(_) => continue },
            _ = stop.changed() => return Ok(()),
        };
        let owned = pending.clone().lock_owned().await;
        let (mut stream, _cancel) =
            provisioning_io::bridge(pipe, custody_provisioning::INSTALLER_TIMEOUT);
        let worker = tokio::task::spawn_blocking(move || {
            use std::io::Write as _;
            let relay = custody_provisioning::enroll(&*owned)?;
            stream.write_all(&u32::try_from(relay.as_bytes().len())?.to_le_bytes())?;
            stream.write_all(relay.as_bytes())?;
            Ok::<_, anyhow::Error>(())
        });
        tokio::select! {
            result = worker => {
                // Partial immutable stages require recovery. A request error
                // does not activate custody or make a later attempt a replay.
                let _ = result?;
            },
            _ = stop.changed() => return Ok(()),
        }
        // Cancellation closes I/O; a SQLCipher operation retains the root lock
        // until it finishes. The loop admits no overlapping storage worker.
    }
    Ok(())
}
