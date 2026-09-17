//! Bounded relay frames. Peer authentication belongs to the native adapter.
use anyhow::{Result, ensure};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
pub(crate) const MAX_BYTES: usize = 4096;

pub(crate) async fn read_frame(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<Vec<u8>> {
    let length = usize::try_from(stream.read_u32_le().await?)?;
    ensure!(
        length > 0 && length <= MAX_BYTES,
        "invalid relay frame length"
    );
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

pub(crate) async fn write_frame(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    bytes: &[u8],
) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_BYTES,
        "invalid relay frame length"
    );
    stream.write_u32_le(u32::try_from(bytes.len())?).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
#[path = "relay_frame_test.rs"]
mod tests;
