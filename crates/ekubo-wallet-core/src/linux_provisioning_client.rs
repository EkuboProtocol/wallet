//! Privileged fresh enrollment. The only returned secret-shaped value is ciphertext.
use crate::{custody_envelope::WrappedDataKey, service_storage};
use anyhow::{Result, ensure};
use zbus::fdo::DBusProxy;

pub async fn enroll(owner_uid: u32) -> Result<WrappedDataKey> {
    let identity = service_storage::pending_installer_identity(owner_uid)?;
    tokio::time::timeout(crate::custody_provisioning::INSTALLER_TIMEOUT, async {
        let bus =
            zbus::connection::Builder::unix_stream(service_storage::system_bus_stream().await?)
                .build()
                .await?;
        let registry = DBusProxy::new(&bus).await?;
        let name = format!("org.ekubo.Wallet2.Provision.u{owner_uid}");
        let peer = registry.get_name_owner(name.as_str().try_into()?).await?;
        ensure!(
            registry
                .get_connection_unix_user(peer.clone().into())
                .await?
                == identity.service_uid(),
            "provisioning endpoint is not the installed service"
        );
        let proxy = zbus::Proxy::new(
            &bus,
            peer.as_str(),
            "/org/ekubo/Wallet2/Provision",
            "org.ekubo.Wallet2.Provision1",
        )
        .await?;
        let bytes: Vec<u8> = proxy.call("Enroll", &()).await?;
        WrappedDataKey::from_bytes(&bytes)
    })
    .await?
}
