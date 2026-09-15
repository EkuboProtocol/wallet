//! Authentication stays in core: presentation cannot forge a cleanup receipt.
use super::{Receipt, ServiceCommand};
use anyhow::{Result, ensure};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
pub(super) struct Peer {
    bus: zbus::Connection,
    service: zbus::names::OwnedUniqueName,
    profile: uuid::Uuid,
}
#[cfg(target_os = "linux")]
impl Peer {
    pub(super) const fn profile(&self) -> uuid::Uuid {
        self.profile
    }
    pub(super) async fn connect() -> Result<Self> {
        let identity = crate::service_storage::installed_service_identity()?;
        let bus = zbus::connection::Builder::unix_stream(
            crate::service_storage::system_bus_stream().await?,
        )
        .build()
        .await?;
        let registry = zbus::fdo::DBusProxy::new(&bus).await?;
        let name = format!("org.ekubo.Wallet2.Owner.u{}", identity.owner_uid());
        let peer = registry.get_name_owner(name.as_str().try_into()?).await?;
        ensure!(
            registry
                .get_connection_unix_user(peer.clone().into())
                .await?
                == identity.service_uid(),
            "move endpoint is not the installed protected service"
        );
        drop(registry);
        Ok(Self {
            bus,
            service: peer,
            profile: identity.profile_id(),
        })
    }
    pub(super) async fn call(&mut self, command: &ServiceCommand) -> Result<Receipt> {
        let request = Zeroizing::new(serde_json::to_string(command)?);
        let proxy = zbus::Proxy::new(
            &self.bus,
            self.service.as_str(),
            "/org/ekubo/Wallet2/Owner",
            "org.ekubo.Wallet2.Owner1",
        )
        .await?;
        let response: String = tokio::time::timeout(
            std::time::Duration::from_secs(180),
            proxy.call("LegacyMove", &(request.as_str(),)),
        )
        .await??;
        ensure!(response.len() <= 1024 * 1024, "move receipt is oversized");
        let receipt: Receipt = serde_json::from_str(&response)?;
        validate_receipt(command, &receipt, self.profile)?;
        Ok(receipt)
    }
}

#[cfg(target_os = "windows")]
#[path = "legacy_move_windows_transport.rs"]
mod windows;
#[cfg(target_os = "windows")]
pub(super) use windows::Peer;

// Private validation is invoked only on replies read from an authenticated,
// installed service. A deserialized receipt supplied by the UI is never accepted.
fn validate_receipt(
    command: &ServiceCommand,
    receipt: &Receipt,
    profile: uuid::Uuid,
) -> Result<()> {
    ensure!(
        receipt.profile == profile && receipt.phase == command.phase(),
        "move receipt profile or authorization phase mismatch"
    );
    match command {
        ServiceCommand::AuthorizeSource {
            nonce,
            source,
            preserved_profiles,
        } => {
            ensure!(
                !nonce.is_nil()
                    && receipt.nonce == *nonce
                    && receipt.selection_digest
                        == Some(super::selection_digest(
                            profile,
                            source,
                            preserved_profiles
                        )?),
                "source authorization receipt does not match the fresh exact selection"
            );
        }
        ServiceCommand::Inspect { nonce } => {
            ensure!(
                !nonce.is_nil() && receipt.nonce == *nonce && receipt.selection_digest.is_none(),
                "stale inspection receipt"
            );
        }
        ServiceCommand::Verify {
            digest,
            nonce,
            binding,
        }
        | ServiceCommand::Complete {
            digest,
            nonce,
            binding,
        } => {
            ensure!(
                !nonce.is_nil()
                    && receipt.nonce == *nonce
                    && receipt.digest == *digest
                    && receipt.binding.as_ref() == Some(binding)
                    && receipt.selection_digest.is_none(),
                "cleanup authorization receipt does not match the fresh bound phase"
            );
        }
        ServiceCommand::CompleteWithoutSource { nonce } => {
            ensure!(
                !nonce.is_nil()
                    && receipt.nonce == *nonce
                    && receipt.selection_digest.is_none()
                    && receipt.binding.is_some(),
                "cleanup authorization receipt does not match the fresh bound phase"
            );
        }
        ServiceCommand::Import { .. } => {
            ensure!(
                receipt.nonce.is_nil() && receipt.selection_digest.is_none(),
                "invalid import receipt phase"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "legacy_move_transport_test.rs"]
mod tests;
