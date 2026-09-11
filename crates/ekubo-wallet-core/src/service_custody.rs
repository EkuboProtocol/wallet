//! Shared locked custody state. OS adapters must validate each input handle and
//! obtain identity bindings from protected configuration before calling unlock.
//! This module grants no caller identity or owner-authorization proof.

use crate::custody_envelope::{CustodyEnrollment, DataCipher, WrappedDataKey, WrappingKey};
use anyhow::{Context as _, Result, ensure};
use std::{
    io::Read,
    sync::{Arc, OnceLock},
};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct ServiceCustody(OnceLock<ActiveCustody>);

struct ActiveCustody {
    cipher: Arc<DataCipher>,
    envelope_digest: [u8; 32],
}

impl ServiceCustody {
    pub(crate) fn unlock(
        &self,
        enrollment: impl Read,
        wrapping: impl Read,
        owner: &str,
        service: &str,
        profile: Uuid,
        wrapped: &WrappedDataKey,
    ) -> Result<()> {
        let mut bytes = Vec::new();
        enrollment.take(4097).read_to_end(&mut bytes)?;
        let enrollment = CustodyEnrollment::from_bytes(&bytes)?;
        let wrapping = WrappingKey::from_material(read_fixed(wrapping)?);
        let cipher = enrollment.unlock(&wrapping, owner, service, profile, wrapped)?;
        let active = ActiveCustody {
            cipher: Arc::new(cipher),
            envelope_digest: wrapped.digest(),
        };
        if let Err(active) = self.0.set(active) {
            ensure!(
                self.0.get().expect("already initialized").envelope_digest
                    == active.envelope_digest,
                "service custody cannot change enrollment without restart"
            );
        }
        Ok(())
    }

    pub(crate) fn cipher(&self) -> Result<Arc<DataCipher>> {
        Ok(self
            .0
            .get()
            .context("service custody is locked")?
            .cipher
            .clone())
    }
}

pub(crate) fn read_fixed<const N: usize>(mut reader: impl Read) -> Result<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0; N]);
    reader.read_exact(bytes.as_mut_slice())?;
    ensure!(
        reader.read(&mut [0_u8; 1])? == 0,
        "invalid service credential length"
    );
    Ok(bytes)
}

#[cfg(test)]
#[path = "service_custody_test.rs"]
mod tests;
