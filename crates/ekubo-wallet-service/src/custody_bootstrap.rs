//! Shared startup coordination. Platform adapters authenticate the IPC caller
//! before entering this flow and supply their protected custody unlock function.

use anyhow::{Context as _, Result};
use ekubo_wallet_core::custody_envelope::WrappedDataKey;
use tokio::sync::{Semaphore, watch};

pub struct CustodyBootstrap {
    unlocked: watch::Sender<bool>,
    ready: watch::Receiver<bool>,
    slots: Semaphore,
}

pub struct Startup {
    unlocked: watch::Receiver<bool>,
    ready: watch::Sender<bool>,
}

impl CustodyBootstrap {
    #[must_use]
    pub fn new() -> (Self, Startup) {
        let (unlocked, waiting) = watch::channel(false);
        let (ready, readiness) = watch::channel(false);
        (
            Self {
                unlocked,
                ready: readiness,
                slots: Semaphore::new(32),
            },
            Startup {
                unlocked: waiting,
                ready,
            },
        )
    }

    /// Accept only the fixed ciphertext format. Success means the host has
    /// opened authority and published its owner interface, not merely unlocked
    /// a key. No desktop-session lease or signing permission is granted here.
    pub async fn unlock(
        &self,
        bytes: &[u8],
        unlock: impl FnOnce(&WrappedDataKey) -> Result<()>,
    ) -> Result<()> {
        let _slot = self
            .slots
            .try_acquire()
            .context("custody bootstrap is busy")?;
        let wrapped = WrappedDataKey::from_bytes(bytes)?;
        unlock(&wrapped)?;
        self.unlocked.send_replace(true);
        self.ready
            .clone()
            .wait_for(|ready| *ready)
            .await
            .context("wallet service startup ended before becoming ready")?;
        Ok(())
    }
}

impl Startup {
    pub async fn wait_for_unlock(&mut self) -> Result<()> {
        self.unlocked
            .wait_for(|unlocked| *unlocked)
            .await
            .context("wallet custody endpoint closed before unlock")?;
        Ok(())
    }

    pub fn ready(&self) {
        self.ready.send_replace(true);
    }
}

#[cfg(test)]
#[path = "custody_bootstrap_test.rs"]
mod tests;
