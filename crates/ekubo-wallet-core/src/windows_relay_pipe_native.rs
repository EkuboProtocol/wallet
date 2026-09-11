use super::{ADMINISTRATORS, PREFACE, SOURCE_PREFACE, name, source_name};
use crate::{windows_owner_pipe, windows_service_config, windows_service_identity};
use anyhow::{Result, ensure};
use tokio::{
    io::AsyncReadExt as _,
    net::windows::named_pipe::{NamedPipeClient, NamedPipeServer},
};
use uuid::Uuid;

pub struct OwnerRelayListener {
    pipe: NamedPipeServer,
    owner: String,
    endpoint: Uuid,
    source: bool,
}

impl OwnerRelayListener {
    pub fn bind() -> Result<Self> {
        Self::bind_kind(false)
    }

    pub(crate) fn bind_source() -> Result<Self> {
        Self::bind_kind(true)
    }

    fn bind_kind(source: bool) -> Result<Self> {
        let owner = windows_service_identity::current_process_identity()?
            .user_sid()
            .to_owned();
        windows_service_config::validate_owner_component(&owner)?;
        Self::create(owner, Uuid::new_v4(), true, source)
    }

    fn create(owner: String, endpoint: Uuid, first: bool, source: bool) -> Result<Self> {
        ensure!(
            windows_service_identity::current_process_identity()?.user_sid() == owner,
            "relay owner identity changed"
        );
        let pipe = windows_owner_pipe::create_private_pipe(
            &if source {
                source_name(endpoint)?
            } else {
                name(endpoint)?
            },
            &owner,
            ADMINISTRATORS,
            first,
        )?;
        Ok(Self {
            pipe,
            owner,
            endpoint,
            source,
        })
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint
    }

    pub async fn accept(self) -> Result<ConnectedInstaller> {
        self.pipe.connect().await?;
        Ok(ConnectedInstaller(self))
    }
}

pub struct ConnectedInstaller(OwnerRelayListener);
impl ConnectedInstaller {
    /// Reserve the successor while the connected instance still owns the name.
    pub fn reserve_next(&self) -> Result<OwnerRelayListener> {
        OwnerRelayListener::create(self.0.owner.clone(), self.0.endpoint, false, self.0.source)
    }

    pub async fn authenticate(mut self) -> Result<NamedPipeServer> {
        let mut preface = [0; 8];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.0.pipe.read_exact(&mut preface),
        )
        .await??;
        let expected = if self.0.source {
            SOURCE_PREFACE
        } else {
            PREFACE
        };
        ensure!(
            &preface == expected,
            "unsupported installer channel preface"
        );
        ensure!(
            windows_service_identity::current_process_identity()?.user_sid() == self.0.owner,
            "relay owner identity changed"
        );
        // Synchronous impersonation, token inspection, and mandatory revert.
        windows_owner_pipe::authenticate_installer_client(&self.0.pipe)?;
        Ok(self.0.pipe)
    }
}

/// Validate the connected object's owner and DACL before any relay bytes. The
/// installer supplies an endpoint learned from its owner launch handoff.
pub async fn connect(
    identity: &windows_service_config::PendingInstallerIdentity,
    endpoint: Uuid,
) -> Result<NamedPipeClient> {
    connect_kind(identity, endpoint, false).await
}

pub(crate) async fn connect_source(
    identity: &windows_service_config::PendingInstallerIdentity,
    endpoint: Uuid,
) -> Result<NamedPipeClient> {
    connect_kind(identity, endpoint, true).await
}

async fn connect_kind(
    identity: &windows_service_config::PendingInstallerIdentity,
    endpoint: Uuid,
    source: bool,
) -> Result<NamedPipeClient> {
    windows_service_identity::verify_installer_process()?;
    let name = if source {
        source_name(endpoint)?
    } else {
        name(endpoint)?
    };
    windows_owner_pipe::open_private_pipe(&name, identity.owner_sid(), ADMINISTRATORS).await
}
