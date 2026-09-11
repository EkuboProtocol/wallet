//! Windows service runtime; the SCM adapter supplies status and stop controls.

use crate::{
    authority::ApplicationAuthority, config::ConfigStore, runtime::ServiceRuntime,
    service_host::ServiceHost, windows_owner_rpc::WindowsOwnerEndpoint,
};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::watch;

/// Bind locked custody before announcing availability. Reporting running only
/// after unlock would deadlock a desktop waiting for SCM startup before relay.
/// This host requires installer-provisioned protected identity and storage.
pub async fn run(
    owner_sid: &str,
    started: impl FnOnce() -> Result<()>,
    stop: watch::Receiver<bool>,
) -> Result<()> {
    let (endpoint, publisher, startup) = WindowsOwnerEndpoint::bind(owner_sid)?;
    started()?;
    let (endpoint_stop, endpoint_stopping) = watch::channel(false);
    ServiceHost {
        startup,
        endpoint: endpoint.run(endpoint_stopping),
        endpoint_stop,
        open: || {
            Ok(Arc::new(ServiceRuntime::new(ApplicationAuthority::open(
                ConfigStore::production()?,
            )?)))
        },
        publish: |runtime| publisher.publish(runtime),
    }
    .run(stop)
    .await
}
