//! One request per call connection, plus a separate desktop-lifetime connection.
//! OS adapters authenticate each pipe; these tags confer no authority.

use anyhow::{Context as _, Result, ensure};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    Unlock = 2,
    Hold = 3,
    Call = 4,
    Ok = 5,
    Error = 6,
}

pub struct Frame {
    pub kind: Kind,
    bytes: Zeroizing<Vec<u8>>,
}

impl Frame {
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.bytes[1..]
    }
}

pub async fn read(stream: &mut (impl AsyncRead + Unpin)) -> Result<Option<Frame>> {
    let Some(bytes) = crate::framing::read_sensitive_frame(stream).await? else {
        return Ok(None);
    };
    let kind = match bytes[0] {
        1 => Kind::Hello,
        2 => Kind::Unlock,
        3 => Kind::Hold,
        4 => Kind::Call,
        5 => Kind::Ok,
        6 => Kind::Error,
        _ => anyhow::bail!("invalid owner stream message"),
    };
    Ok(Some(Frame { kind, bytes }))
}

pub async fn write(stream: &mut (impl AsyncWrite + Unpin), kind: Kind, body: &[u8]) -> Result<()> {
    ensure!(
        body.len() < crate::framing::MAX_FRAME_BYTES,
        "owner stream payload exceeds its size limit"
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity(body.len() + 1));
    bytes.push(kind as u8);
    bytes.extend_from_slice(body);
    Ok(crate::framing::write_frame(stream, &bytes).await?)
}

/// Read only after authenticating the endpoint. Pin this identifier for the
/// client lifetime and compare every call connection before sending its body.
pub async fn read_hello(stream: &mut (impl AsyncRead + Unpin)) -> Result<uuid::Uuid> {
    let hello = read(stream)
        .await?
        .context("service closed before its greeting")?;
    ensure!(hello.kind == Kind::Hello, "missing owner service greeting");
    let instance = uuid::Uuid::from_slice(hello.body())?;
    ensure!(!instance.is_nil(), "invalid owner service instance");
    Ok(instance)
}

#[cfg(test)]
#[path = "owner_stream_protocol_test.rs"]
mod tests;
