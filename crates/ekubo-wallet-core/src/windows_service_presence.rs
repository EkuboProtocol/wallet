//! Kernel-authenticated owner-call context and a one-connection native consent
//! exchange. Neither a desktop SID string nor a desktop consent enum is proof.

use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_windows_owner_auth::Challenge;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::{human_presence::PresenceRequest, windows_service_config::InstalledServiceIdentity};

const SYSTEM: &str = "S-1-5-18";
const MAX_FRAME: usize = 8192;
const TIMEOUT: Duration = Duration::from_secs(120);

/// Constructed exclusively from the last-read pipe client's token inside core.
#[derive(Clone)]
pub struct OwnerCallContext {
    identity: Arc<InstalledServiceIdentity>,
    session: u32,
    logon: [u32; 2],
    operation_digest: String,
    connection: Arc<std::os::windows::io::OwnedHandle>,
    transport: Option<crate::owner_call_monitor::OwnerCallBinding>,
}

impl OwnerCallContext {
    /// Attach only the guard owned by the transport's actual AsyncRead monitor.
    pub fn with_transport(
        mut self,
        binding: crate::owner_call_monitor::OwnerCallBinding,
    ) -> Result<Self> {
        ensure!(
            self.transport.is_none(),
            "owner call transport is already bound"
        );
        binding.ensure_live()?;
        self.transport = Some(binding);
        Ok(self)
    }

    pub(crate) fn verify_current(&self) -> Result<()> {
        let current = current_binding()?;
        let transport = self
            .transport
            .as_ref()
            .context("owner authorization has no transport binding")?;
        transport.ensure_live()?;
        ensure!(
            Arc::ptr_eq(&self.connection, &current.connection)
                && self.operation_digest == current.operation_digest
                && current
                    .transport
                    .as_ref()
                    .is_some_and(|other| transport.same_call(other)),
            "owner authorization belongs to a different initiating call"
        );
        Ok(())
    }

    pub(crate) fn from_authenticated_token(
        identity: Arc<InstalledServiceIdentity>,
        session: u32,
        logon: [u32; 2],
        request: &[u8],
        connection: std::os::windows::io::OwnedHandle,
    ) -> Self {
        Self {
            identity,
            session,
            logon,
            operation_digest: hex::encode(Sha256::digest(request)),
            connection: Arc::new(connection),
            transport: None,
        }
    }
}

tokio::task_local! { static OWNER_CALL: Option<OwnerCallContext>; }

pub(crate) fn current_binding() -> Result<OwnerCallContext> {
    let context = OWNER_CALL
        .try_with(Clone::clone)
        .ok()
        .flatten()
        .context("Windows owner call is no longer active")?;
    context
        .transport
        .as_ref()
        .context("Windows owner call has no transport monitor")?
        .ensure_live()?;
    // Additional best-effort kernel check; unread Tokio/Mio bytes are governed
    // by the AsyncRead monitor, not PeekNamedPipe's kernel buffer count.
    crate::windows_owner_pipe::verify_auth_connection(&context.connection)?;
    Ok(context)
}

pub(crate) fn verify_current_call() -> Result<()> {
    current_binding().map(|_| ())
}

/// The scope is the initiating operation future. Its cancellation closes any
/// live broker connection; an authentication cannot escape into another call.
pub async fn scope<F: Future>(context: Option<OwnerCallContext>, operation: F) -> F::Output {
    OWNER_CALL.scope(context, operation).await
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    session: u32,
    logon: [u32; 2],
    challenge: Challenge,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    nonce: String,
    operation_digest: String,
}

impl Receipt {
    fn verify(self, challenge: &Challenge) -> Result<()> {
        ensure!(
            self.nonce == challenge.nonce && self.operation_digest == challenge.operation_digest,
            "native authorization receipt binding mismatch"
        );
        Ok(())
    }
}

fn name(identity: &InstalledServiceIdentity) -> String {
    format!(
        r"\\.\pipe\EkuboWalletV2-auth-{}",
        identity.profile_id().simple()
    )
}

async fn write<T: Serialize>(stream: &mut (impl AsyncWrite + Unpin), value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= MAX_FRAME,
        "native authorization frame is too large"
    );
    stream.write_u32(u32::try_from(bytes.len())?).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn read<T: serde::de::DeserializeOwned>(stream: &mut (impl AsyncRead + Unpin)) -> Result<T> {
    let length = stream.read_u32().await? as usize;
    ensure!(
        (1..=MAX_FRAME).contains(&length),
        "invalid native authorization frame"
    );
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) async fn confirm(request: &PresenceRequest) -> Result<()> {
    verify_current_call()?;
    let context = OWNER_CALL
        .try_with(Clone::clone)
        .ok()
        .flatten()
        .context("Windows owner authentication requires an authenticated owner call")?;
    crate::windows_service_identity::verify_service_process(context.identity.service_sid())?;
    ensure!(
        context.session != 0,
        "native owner authentication requires an interactive session"
    );
    let challenge = Challenge {
        nonce: format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ),
        operation_digest: context.operation_digest,
        reason: request.reason(),
    };
    challenge.validate()?;
    let request = Request {
        session: context.session,
        logon: context.logon,
        challenge,
    };
    tokio::time::timeout(TIMEOUT, async {
        let mut pipe = crate::windows_owner_pipe::open_auth_client(
            &name(&context.identity),
            SYSTEM,
            context.identity.service_sid(),
        )
        .await?;
        write(&mut pipe, &request).await?;
        let receipt: Receipt = read(&mut pipe).await?;
        receipt.verify(&request.challenge)?;
        verify_current_call()?;
        Ok(())
    })
    .await
    .context("native owner authentication timed out")?
}

/// A separate SYSTEM SCM host invokes this with protected owner metadata.
/// One active prompt per profile, bounded requests, and no process-spawn API on
/// the pipe. Ordinary desktop tokens cannot connect or impersonate the service.
pub async fn run_broker(
    owner_sid: &str,
    ready: impl FnOnce() -> Result<()>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let identity = crate::windows_service_config::auth_broker_identity(owner_sid)?;
    ensure!(
        crate::windows_service_identity::current_process_identity()?.user_sid() == SYSTEM,
        "native authentication broker requires SYSTEM"
    );
    let mut pipe = crate::windows_owner_pipe::create_auth_server(
        &name(&identity),
        SYSTEM,
        identity.service_sid(),
        true,
    )?;
    ready()?;
    loop {
        tokio::select! {
            biased;
            _ = stop.wait_for(|value| *value) => return Ok(()),
            connected = pipe.connect() => connected?,
        }
        let next = crate::windows_owner_pipe::create_auth_server(
            &name(&identity),
            SYSTEM,
            identity.service_sid(),
            false,
        )?;
        let operation = tokio::time::timeout(TIMEOUT, broker_request(&identity, &mut pipe));
        tokio::select! {
            biased;
            _ = stop.wait_for(|value| *value) => return Ok(()),
            _ = operation => {},
        }
        pipe = next;
    }
}

async fn broker_request(
    identity: &InstalledServiceIdentity,
    pipe: &mut tokio::net::windows::named_pipe::NamedPipeServer,
) -> Result<()> {
    let request: Request = read(pipe).await?;
    crate::windows_owner_pipe::authenticate_auth_service(pipe, identity.service_sid())?;
    request.challenge.validate()?;
    let (reader, mut writer) = tokio::io::split(pipe);
    let mut monitor = crate::owner_call_monitor::OwnerCallMonitor::new(reader);
    let receipt = monitor
        .run(async {
            let image = crate::windows_auth_image::installed_collector()?;
            let mut process = ekubo_wallet_windows_owner_auth::launch(
                identity.owner_sid(),
                request.session,
                request.logon,
                &request.challenge,
            )?;
            drop(image);
            loop {
                if let Some(verified) = process.poll()? {
                    ensure!(verified, "native owner authentication declined or failed");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok(Receipt {
                nonce: request.challenge.nonce,
                operation_digest: request.challenge.operation_digest,
            })
        })
        .await?;
    monitor.run(write(&mut writer, &receipt)).await
}

#[cfg(test)]
#[path = "windows_service_presence_test.rs"]
mod tests;
