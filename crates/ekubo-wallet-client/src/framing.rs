//! Bounded framing for the desktop/service connection.
//!
//! This is a transport, not an authorization mechanism. Dispatch must derive
//! the peer identity from the OS transport and authorize each typed operation.
//! A disconnected request is never implicitly retried: it may already have
//! committed a policy change or signature.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// Includes large review documents, while bounding allocation per connection.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAGIC: [u8; 4] = *b"EKWS";
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 12;

/// Clean EOF is returned only between frames. A partial header or payload is
/// an error, so an interrupted operation cannot be mistaken for a response.
pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Vec<u8>>> {
    let Some(length) = read_length(reader).await? else {
        return Ok(None);
    };
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

/// Secret-bearing owner traffic erases partial reads as well as complete frames.
pub async fn read_sensitive_frame(
    reader: &mut (impl AsyncRead + Unpin),
) -> io::Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let Some(length) = read_length(reader).await? else {
        return Ok(None);
    };
    let mut payload = zeroize::Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

async fn read_length(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<usize>> {
    let mut header = [0_u8; HEADER_BYTES];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    if header[..4] != MAGIC || header[4..8] != VERSION.to_be_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incompatible wallet service protocol",
        ));
    }
    let length =
        u32::from_be_bytes(header[8..12].try_into().expect("fixed length header")) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wallet service frame length is outside the permitted range",
        ));
    }
    Ok(Some(length))
}

pub async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "wallet service frame length is outside the permitted range",
        ));
    }
    let mut header = [0_u8; HEADER_BYTES];
    header[..4].copy_from_slice(&MAGIC);
    header[4..8].copy_from_slice(&VERSION.to_be_bytes());
    let length = u32::try_from(payload.len()).expect("frame limit fits u32");
    header[8..].copy_from_slice(&length.to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

#[cfg(test)]
#[path = "framing_test.rs"]
mod tests;
