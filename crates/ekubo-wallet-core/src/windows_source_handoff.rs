//! Native source endpoint. Core collects legacy credentials only after the pipe
//! verifies the actual elevated installer token. No cutover command is exposed.
use crate::{migration_transfer::INSTALLER_TIMEOUT, provisioning_io, windows_relay_pipe};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{Semaphore, watch};
use uuid::Uuid;

/// Run before starting local wallet authority/workers. Binding reads no keys;
/// pass only this fresh endpoint ID through the privileged launch handoff.
pub struct OwnerSourceEndpoint(windows_relay_pipe::OwnerRelayListener);
impl OwnerSourceEndpoint {
    pub fn bind() -> Result<Self> {
        Ok(Self(windows_relay_pipe::OwnerRelayListener::bind_source()?))
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.0.endpoint_id()
    }

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
            let operation = async {
                let pipe = connected.authenticate().await?;
                let (mut stream, _cancel) = provisioning_io::bridge(pipe, INSTALLER_TIMEOUT);
                tokio::task::spawn_blocking(move || {
                    let _slot = slot;
                    crate::migration_source::serve(&mut stream)
                })
                .await?
            };
            tokio::select! {
                _ = stop.wait_for(|stop| *stop) => return Ok(()),
                _ = tokio::time::timeout(INSTALLER_TIMEOUT, operation) => {},
            }
        }
    }
}
