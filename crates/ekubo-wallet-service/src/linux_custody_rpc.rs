//! Linux adapter for the shared custody startup flow. Only ciphertext enters;
//! protected enrollment and the wrapping key stay inside core service storage.

use crate::custody_bootstrap::CustodyBootstrap;

pub(crate) struct LinuxCustodyInterface(pub(crate) CustodyBootstrap);

#[zbus::interface(name = "org.ekubo.Wallet.Custody1")]
impl LinuxCustodyInterface {
    async fn unlock(
        &self,
        ciphertext: &[u8],
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        if ciphertext.len() != ekubo_wallet_core::custody_envelope::SEALED_KEY_BYTES {
            return Err(zbus::fdo::Error::InvalidArgs(
                "invalid custody envelope length".into(),
            ));
        }
        ekubo_wallet_core::service_presence::with_owner_call(
            connection,
            &header,
            self.0
                .unlock(ciphertext, ekubo_wallet_core::service_storage::unlock),
        )
        .await
        .map_err(|error| zbus::fdo::Error::AccessDenied(error.to_string()))?
        // Do not reflect protected paths, enrollment, or credential errors.
        .map_err(|_| zbus::fdo::Error::Failed("wallet custody startup failed".into()))
    }
}
