//! Bounded Windows owner relay delivery. Native pipe authentication precedes
//! all receipt/relay parsing and credential access. No activation or raw keys.
use crate::{
    custody_envelope::WrappedDataKey, custody_relay::RelayReceipt, windows_relay_pipe,
    windows_service_config,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::{
    io::AsyncWriteExt as _,
    sync::{OwnedSemaphorePermit, Semaphore, watch},
};
use uuid::Uuid;

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
use crate::relay_frame::{MAX_BYTES, read_frame, write_frame};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delivery {
    profile: Uuid,
    nonce: Uuid,
    relay: Vec<u8>,
}

pub struct OwnerRelayEndpoint(windows_relay_pipe::OwnerRelayListener);
impl OwnerRelayEndpoint {
    pub fn bind() -> Result<Self> {
        Ok(Self(windows_relay_pipe::OwnerRelayListener::bind()?))
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.0.endpoint_id()
    }

    /// Sequential admission keeps one credential operation in flight. The next
    /// listener retains the namespace while the current request is authenticated.
    pub async fn run(self, mut stop: watch::Receiver<bool>) -> Result<()> {
        let mut listener = self.0;
        let slots = Arc::new(Semaphore::new(1));
        loop {
            let connected = tokio::select! {
                _ = stop.wait_for(|stop| *stop) => return Ok(()),
                result = listener.accept() => result?,
            };
            listener = connected.reserve_next()?;
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                continue;
            };
            tokio::select! {
                _ = stop.wait_for(|stop| *stop) => return Ok(()),
                _ = tokio::time::timeout(TIMEOUT, receive(connected, slot)) => {},
            }
        }
    }
}

async fn receive(
    connected: windows_relay_pipe::ConnectedInstaller,
    slot: OwnedSemaphorePermit,
) -> Result<()> {
    let mut stream = connected.authenticate().await?;
    let delivery: Delivery = serde_json::from_slice(&read_frame(&mut stream).await?)?;
    let relay = WrappedDataKey::from_bytes(&delivery.relay)?;
    let receipt = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        RelayReceipt::persisted(delivery.profile, delivery.nonce, &relay)
    })
    .await??;
    write_frame(&mut stream, &serde_json::to_vec(&receipt)?).await
}

/// No retry after writing the preface. The caller retains the source fence and
/// lifecycle lock; the returned correlation receipt never authorizes activation.
pub async fn deliver(
    owner_sid: &str,
    endpoint: Uuid,
    profile: Uuid,
    relay: &WrappedDataKey,
) -> Result<RelayReceipt> {
    let identity = windows_service_config::pending_installer_identity(owner_sid)?;
    ensure!(
        identity.profile_id() == profile,
        "relay profile differs from protected pending identity"
    );
    tokio::time::timeout(TIMEOUT, async {
        let mut stream = windows_relay_pipe::connect(&identity, endpoint).await?;
        let nonce = Uuid::new_v4();
        let delivery = Delivery {
            profile,
            nonce,
            relay: relay.as_bytes().to_vec(),
        };
        let request = serde_json::to_vec(&delivery)?;
        ensure!(request.len() <= MAX_BYTES, "relay delivery is oversized");
        stream.write_all(windows_relay_pipe::PREFACE).await?;
        write_frame(&mut stream, &request).await?;
        let receipt: RelayReceipt = serde_json::from_slice(&read_frame(&mut stream).await?)?;
        receipt.verify(profile, nonce, relay)?;
        Ok(receipt)
    })
    .await?
}
