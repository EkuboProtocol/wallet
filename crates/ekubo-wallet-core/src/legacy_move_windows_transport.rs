//! Uses the existing client wire protocol, shared through core. Never accepts
//! caller-provided receipts or a caller-selected pipe/installed-service identity.
use super::*;
use crate::owner_stream_protocol::{self as wire, Kind};
use anyhow::Context as _;
use tokio::net::windows::named_pipe::NamedPipeClient;

pub(in crate::legacy_move) struct Peer {
    identity: crate::windows_service_config::InstalledServiceIdentity,
    instance: uuid::Uuid,
    // Unlock lifetime only. Moving must not acquire an execution lease.
    _lifetime: NamedPipeClient,
}

impl Peer {
    pub(in crate::legacy_move) fn profile(&self) -> uuid::Uuid {
        self.identity.profile_id()
    }

    pub(in crate::legacy_move) async fn connect() -> Result<Self> {
        tokio::time::timeout(std::time::Duration::from_secs(30), Self::connect_inner())
            .await
            .context("legacy move service connection timed out")?
    }

    async fn connect_inner() -> Result<Self> {
        let identity = crate::windows_service_config::installed_service_identity()?;
        crate::windows_service_manager::ensure_running(&identity).await?;
        let mut stream = crate::windows_owner_pipe::connect(&identity).await?;
        let instance = wire::read_hello(&mut stream).await?;
        let profile = identity.profile_id();
        let wrapped =
            tokio::task::spawn_blocking(move || crate::custody_relay::load(profile)).await??;
        wire::write(&mut stream, Kind::Unlock, wrapped.as_bytes()).await?;
        ensure!(
            reply(&mut stream).await?.body().is_empty(),
            "unexpected unlock response"
        );
        Ok(Self {
            identity,
            instance,
            _lifetime: stream,
        })
    }

    pub(in crate::legacy_move) async fn call(
        &mut self,
        command: &ServiceCommand,
    ) -> Result<Receipt> {
        tokio::time::timeout(std::time::Duration::from_secs(180), self.call_once(command))
            .await
            .context("legacy move service call timed out; inspect before retrying")?
    }

    async fn call_once(&self, command: &ServiceCommand) -> Result<Receipt> {
        let mut stream = crate::windows_owner_pipe::connect(&self.identity).await?;
        ensure!(
            wire::read_hello(&mut stream).await? == self.instance,
            "legacy move service instance changed"
        );
        let request = Zeroizing::new(serde_json::to_vec(
            &super::super::OwnerRequest::LegacyMove(command),
        )?);
        wire::write(&mut stream, Kind::Call, &request).await?;
        let response = reply(&mut stream).await?;
        ensure!(
            response.body().len() <= 1024 * 1024,
            "move receipt is oversized"
        );
        let receipt: Receipt = serde_json::from_slice(response.body())?;
        validate_receipt(command, &receipt, self.profile())?;
        Ok(receipt)
    }
}

async fn reply(stream: &mut NamedPipeClient) -> Result<wire::Frame> {
    let response = wire::read(stream)
        .await?
        .context("move service closed without a reply")?;
    if response.kind == Kind::Error {
        ensure!(response.body().len() <= 2048, "oversized owner error");
        anyhow::bail!("{}", std::str::from_utf8(response.body())?);
    }
    ensure!(
        response.kind == Kind::Ok,
        "unexpected move service response"
    );
    Ok(response)
}
