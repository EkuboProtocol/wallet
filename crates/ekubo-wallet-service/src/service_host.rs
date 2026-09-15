//! Shared custody startup and ordered runtime shutdown for stream service hosts.

use crate::{custody_bootstrap::Startup, events::DomainEventKind, runtime::ServiceRuntime};
use anyhow::{Context as _, Result, anyhow};
use std::{future::Future, sync::Arc};
use tokio::sync::watch;

pub(crate) struct ServiceHost<E, O, P> {
    pub startup: Startup,
    pub endpoint: E,
    pub endpoint_stop: watch::Sender<bool>,
    pub open: O,
    pub publish: P,
}

impl<E, O, P> ServiceHost<E, O, P>
where
    E: Future<Output = Result<()>>,
    O: FnOnce() -> Result<Arc<ServiceRuntime>>,
    P: FnOnce(Arc<ServiceRuntime>) -> Result<()>,
{
    pub async fn run(self, mut stop: watch::Receiver<bool>) -> Result<()> {
        let Self {
            mut startup,
            endpoint,
            endpoint_stop,
            open,
            publish,
        } = self;
        let mut endpoint = Box::pin(endpoint);
        let mut endpoint_finished = false;
        let mut runtime = None;
        let result = async {
            tokio::select! {
                biased;
                _ = stop.wait_for(|stop| *stop) => return Ok(()),
                result = &mut endpoint => {
                    endpoint_finished = true;
                    return unexpected_endpoint_end(result);
                }
                result = startup.wait_for_unlock() => result?,
            }
            // Retain authority before publication so a publication failure
            // still runs review and dapp cleanup. Never open it while locked.
            let service = open()?;
            runtime = Some(service.clone());
            publish(service.clone())?;
            service
                .events()
                .publish(DomainEventKind::McpStatusChanged { online: true });
            startup.ready();
            tokio::select! {
                biased;
                _ = stop.wait_for(|stop| *stop) => Ok(()),
                result = &mut endpoint => {
                    endpoint_finished = true;
                    unexpected_endpoint_end(result)
                }
                result = service.supervise() => result,
            }
        }
        .await;
        // The supervisor future has dropped before connections are stopped.
        // Dropping readiness also rejects unlock waiters on failed startup.
        drop(startup);
        endpoint_stop.send_replace(true);
        let reviews = runtime.as_ref().map_or(Ok(()), |service| {
            service
                .events()
                .publish(DomainEventKind::McpStatusChanged { online: false });
            service.close_owner_reviews()
        });
        let endpoint_closed = if endpoint_finished {
            Ok(())
        } else {
            endpoint.await
        };
        let dapps = match runtime {
            Some(service) => service.shutdown_dapps().await,
            None => Ok(()),
        };
        // Execute all cleanup, preserving the original failure if there is one.
        result?;
        reviews.context("cannot close service owner reviews")?;
        endpoint_closed.context("cannot stop service owner endpoint")?;
        dapps.context("cannot stop service dapp sessions")
    }
}

fn unexpected_endpoint_end(result: Result<()>) -> Result<()> {
    result.and_then(|()| Err(anyhow!("service owner endpoint stopped unexpectedly")))
}

#[cfg(test)]
#[path = "service_host_test.rs"]
mod tests;
