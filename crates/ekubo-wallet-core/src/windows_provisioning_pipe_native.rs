use super::{ADMINISTRATORS, PREFACE, name};
use crate::{windows_owner_pipe, windows_service_config::InstalledServiceIdentity};
use anyhow::{Result, ensure};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt as _,
    net::windows::named_pipe::{NamedPipeClient, NamedPipeServer},
};

/// Authenticate the connected pipe's actual owner and ACL before any bytes are
/// written. Identification-only SQOS does not let the service act as installer.
/// Busy-instance retries precede all writes; a connected transfer never retries.
pub async fn connect(
    identity: &crate::windows_service_config::PendingInstallerIdentity,
) -> Result<NamedPipeClient> {
    crate::windows_service_identity::verify_installer_process()?;
    windows_owner_pipe::open_private_pipe(
        &name(identity.profile_id())?,
        identity.service_sid(),
        ADMINISTRATORS,
    )
    .await
}

pub struct ProvisioningListener {
    pipe: NamedPipeServer,
    identity: Arc<InstalledServiceIdentity>,
}

impl ProvisioningListener {
    /// The native pending reader verifies the real virtual service token and
    /// rejects active metadata. Retain an existing instance while binding a
    /// successor; the first instance refuses preexisting names.
    pub fn bind(owner_sid: &str, first: bool) -> Result<Self> {
        let identity = Arc::new(crate::windows_service_config::pending_service_identity(
            owner_sid,
        )?);
        let pipe = windows_owner_pipe::create_private_pipe(
            &name(identity.profile_id())?,
            identity.service_sid(),
            ADMINISTRATORS,
            first,
        )?;
        Ok(Self { pipe, identity })
    }

    pub async fn accept(self) -> Result<ConnectedInstaller> {
        self.pipe.connect().await?;
        Ok(ConnectedInstaller {
            pipe: self.pipe,
            identity: self.identity,
        })
    }
}

pub struct ConnectedInstaller {
    pipe: NamedPipeServer,
    identity: Arc<InstalledServiceIdentity>,
}

impl ConnectedInstaller {
    /// Read only a fixed nonsecret preface before asking the kernel for its
    /// client token. No key bytes reach the shared codec before authentication.
    pub async fn authenticate(mut self) -> Result<NamedPipeServer> {
        let mut preface = [0; 8];
        tokio::time::timeout(Duration::from_secs(10), self.pipe.read_exact(&mut preface)).await??;
        ensure!(&preface == PREFACE, "unsupported provisioning preface");
        crate::windows_service_identity::verify_service_process(self.identity.service_sid())?;
        // Native impersonation and mandatory revert are entirely synchronous.
        windows_owner_pipe::authenticate_installer_client(&self.pipe)?;
        Ok(self.pipe)
    }
}
