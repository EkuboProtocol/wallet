//! Fresh provisioning over the authenticated installer pipe.
use crate::{custody_envelope::WrappedDataKey, windows_provisioning_pipe, windows_service_config};
use anyhow::{Result, ensure};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

pub async fn enroll(owner_sid: &str) -> Result<WrappedDataKey> {
    let identity = windows_service_config::pending_installer_identity(owner_sid)?;
    tokio::time::timeout(crate::custody_provisioning::INSTALLER_TIMEOUT, async {
        let mut pipe = windows_provisioning_pipe::connect(&identity).await?;
        pipe.write_all(windows_provisioning_pipe::PREFACE).await?;
        let length = pipe.read_u32_le().await? as usize;
        ensure!(length <= 4096, "fresh enrollment reply is oversized");
        let mut bytes = vec![0; length];
        pipe.read_exact(&mut bytes).await?;
        WrappedDataKey::from_bytes(&bytes)
    })
    .await?
}
