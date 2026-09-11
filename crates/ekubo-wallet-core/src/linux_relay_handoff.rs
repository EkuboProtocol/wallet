//! Root-to-owner relay delivery over pinned system-bus identities. No keys,
//! source paths, service activation or generic credential operations are exposed.
use crate::{custody_envelope::WrappedDataKey, custody_relay::RelayReceipt, service_storage};
use anyhow::{Context as _, Result, ensure};
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;
use zbus::{Connection, fdo::DBusProxy, names::OwnedUniqueName};

const PATH: &str = "/org/ekubo/Wallet/InstallerRelay";
const INTERFACE: &str = "org.ekubo.Wallet.InstallerRelay1";
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Retain while the desktop can receive a pending installer's delivery. The
/// installer must learn this exact unique name through its launch handoff.
pub struct OwnerRelayEndpoint(Connection);
impl OwnerRelayEndpoint {
    pub async fn bind() -> Result<Self> {
        let uid = rustix::process::getuid().as_raw();
        ensure!(
            uid != 0 && uid == rustix::process::geteuid().as_raw(),
            "relay endpoint requires the ordinary desktop owner"
        );
        let connection =
            zbus::connection::Builder::unix_stream(service_storage::system_bus_stream().await?)
                .serve_at(
                    PATH,
                    OwnerInterface {
                        slots: Arc::new(Semaphore::new(1)),
                    },
                )?
                .build()
                .await?;
        Ok(Self(connection))
    }

    pub fn unique_name(&self) -> Result<OwnedUniqueName> {
        Ok(self
            .0
            .unique_name()
            .context("desktop relay connection has no unique name")?
            .to_owned())
    }

    pub async fn close(self) -> Result<()> {
        Ok(self.0.close().await?)
    }
}

struct OwnerInterface {
    slots: Arc<Semaphore>,
}

#[zbus::interface(name = "org.ekubo.Wallet.InstallerRelay1")]
impl OwnerInterface {
    async fn persist(
        &self,
        profile: &str,
        nonce: &str,
        relay: Vec<u8>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> zbus::fdo::Result<String> {
        let sender: OwnedUniqueName = header
            .sender()
            .ok_or_else(|| zbus::fdo::Error::AccessDenied("missing installer identity".into()))?
            .to_owned()
            .into();
        let registry = DBusProxy::new(connection).await?;
        ensure_uid(&registry, &sender, 0).await.map_err(|_| {
            zbus::fdo::Error::AccessDenied(
                "relay delivery requires the privileged installer".into(),
            )
        })?;
        let (profile, nonce, relay) = parse_delivery(profile, nonce, &relay)
            .map_err(|_| zbus::fdo::Error::InvalidArgs("invalid relay delivery".into()))?;
        let slot = self.slots.clone().try_acquire_owned().map_err(|_| {
            zbus::fdo::Error::LimitsExceeded("relay delivery already in progress".into())
        })?;
        let result = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let receipt = RelayReceipt::persisted(profile, nonce, &relay)?;
            serde_json::to_string(&receipt).map_err(anyhow::Error::from)
        })
        .await
        .map_err(|_| zbus::fdo::Error::Failed("relay worker failed".into()))?
        .map_err(|_| zbus::fdo::Error::Failed("relay persistence failed".into()))?;
        ensure_uid(&registry, &sender, 0)
            .await
            .map_err(|_| zbus::fdo::Error::AccessDenied("installer connection was lost".into()))?;
        Ok(result)
    }
}

fn parse_delivery(
    profile: &str,
    nonce: &str,
    bytes: &[u8],
) -> Result<(Uuid, Uuid, WrappedDataKey)> {
    ensure!(
        profile.len() == 36 && nonce.len() == 36,
        "invalid delivery identity length"
    );
    let profile = Uuid::parse_str(profile)?;
    let nonce = Uuid::parse_str(nonce)?;
    ensure!(
        !profile.is_nil() && !nonce.is_nil(),
        "invalid delivery identity"
    );
    Ok((profile, nonce, WrappedDataKey::from_bytes(bytes)?))
}

async fn ensure_uid(registry: &DBusProxy<'_>, name: &OwnedUniqueName, uid: u32) -> Result<()> {
    ensure!(
        registry
            .get_connection_unix_user(name.clone().into())
            .await?
            == uid,
        "relay peer identity mismatch"
    );
    Ok(())
}

/// Authenticate the actual owner before sending even relay ciphertext. Caller
/// must retain the source fence and lifecycle lock; no reconnect/replay occurs.
pub async fn deliver(
    owner_uid: u32,
    recipient: OwnedUniqueName,
    profile: Uuid,
    relay: &WrappedDataKey,
) -> Result<RelayReceipt> {
    let identity = service_storage::pending_installer_identity(owner_uid)?;
    ensure!(
        identity.profile_id() == profile,
        "relay destination differs from protected pending profile"
    );
    tokio::time::timeout(TIMEOUT, async {
        let connection =
            zbus::connection::Builder::unix_stream(service_storage::system_bus_stream().await?)
                .build()
                .await?;
        let registry = DBusProxy::new(&connection).await?;
        ensure_uid(&registry, &recipient, owner_uid).await?;
        let proxy = zbus::Proxy::new(&connection, recipient.as_str(), PATH, INTERFACE).await?;
        let nonce = Uuid::new_v4();
        let response: String = proxy
            .call(
                "Persist",
                &(
                    profile.to_string(),
                    nonce.to_string(),
                    relay.as_bytes().to_vec(),
                ),
            )
            .await?;
        ensure!(response.len() <= 4096, "relay receipt is oversized");
        let receipt: RelayReceipt = serde_json::from_str(&response)?;
        receipt.verify(profile, nonce, relay)?;
        ensure_uid(&registry, &recipient, owner_uid).await?;
        Ok(receipt)
    })
    .await
    .context("relay delivery timed out")?
}

#[cfg(test)]
#[path = "linux_relay_handoff_test.rs"]
mod tests;
