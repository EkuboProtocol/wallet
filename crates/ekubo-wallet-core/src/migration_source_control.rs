//! Confirmation over an already authenticated source channel. No key material,
//! signing capability, or durable activation receipt belongs in this protocol.
use crate::migration_transfer::RecoveryCheckpoint;
use anyhow::{Result, ensure};
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};

const PREFACE: &[u8; 8] = b"EKUBOSC2";

fn digest(checkpoint: &RecoveryCheckpoint) -> Result<[u8; 32]> {
    Ok(Sha256::digest(checkpoint.journal_bytes(&checkpoint.destination)?).into())
}

pub(crate) fn confirm(
    stream: &mut (impl Read + Write),
    checkpoint: &RecoveryCheckpoint,
) -> Result<()> {
    let expected = digest(checkpoint)?;
    let nonce = *uuid::Uuid::new_v4().as_bytes();
    stream.write_all(&[1])?;
    stream.write_all(&nonce)?;
    stream.write_all(&expected)?;
    stream.flush()?;
    let mut reply = [0; 56];
    stream.read_exact(&mut reply)?;
    ensure!(
        &reply[..8] == PREFACE && reply[8..24] == nonce && reply[24..] == expected,
        "source confirmation mismatch"
    );
    Ok(())
}

/// Retain the caller's snapshot and lifecycle guard through confirmation and
/// until abort/disconnect/deadline. One confirmation is admitted per connection.
pub(super) fn retain(
    stream: &mut (impl Read + Write),
    checkpoint: &RecoveryCheckpoint,
    verify: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut command = [0; 1];
    stream.read_exact(&mut command)?;
    if command == [0] {
        return Ok(());
    }
    ensure!(command == [1], "unsupported source control command");
    let mut nonce = [0; 16];
    let mut received = [0; 32];
    stream.read_exact(&mut nonce)?;
    stream.read_exact(&mut received)?;
    let expected = digest(checkpoint)?;
    ensure!(
        received == expected,
        "source confirmation checkpoint mismatch"
    );
    verify()?;
    stream.write_all(PREFACE)?;
    stream.write_all(&nonce)?;
    stream.write_all(&expected)?;
    stream.flush()?;
    stream.read_exact(&mut command)?;
    ensure!(command == [0], "unsupported source control command");
    Ok(())
}

#[cfg(test)]
#[path = "migration_source_control_test.rs"]
mod tests;
