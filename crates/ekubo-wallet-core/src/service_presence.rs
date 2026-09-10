//! Bind Linux service owner authentication to a live desktop system-bus caller.
//!
//! The service dispatch layer must pass the header supplied by zbus, never a
//! caller-supplied name or approval boolean. Context is task-local: concurrent
//! requests cannot borrow each other's identity and spawned tasks inherit none.

use crate::human_presence::HumanPresenceError;
use futures::StreamExt as _;
use std::{collections::HashMap, future::Future, time::Duration};
use zbus::{Connection, fdo::DBusProxy, message::Header, names::OwnedUniqueName};
use zbus_polkit::policykit1::Subject;

tokio::task_local! {
    static OWNER_CALL: OwnerCall;
}

#[derive(Clone)]
struct OwnerCall {
    bus: Connection,
    sender: OwnedUniqueName,
    owner_uid: u32,
}

impl OwnerCall {
    async fn execute<F: Future>(&self, operation: F) -> Result<F::Output, HumanPresenceError> {
        let registry = DBusProxy::new(&self.bus)
            .await
            .map_err(|error| HumanPresenceError::Unavailable(error.to_string()))?;
        // Install the departure watch before checking identity. Unique names
        // cannot be reused on this pinned connection's bus lifetime.
        let mut departed = tokio::time::timeout(
            Duration::from_secs(10),
            registry.receive_name_owner_changed_with_args(&[(0, self.sender.as_str())]),
        )
        .await
        .map_err(|_| HumanPresenceError::Unavailable("owner connection watch timed out".into()))?
        .map_err(|error| HumanPresenceError::Unavailable(error.to_string()))?;
        self.verify().await?;
        let disconnected = async {
            while let Some(signal) = departed.next().await {
                let args = signal
                    .args()
                    .map_err(|error| HumanPresenceError::Unavailable(error.to_string()))?;
                if args.name().as_str() == self.sender.as_str()
                    && args.new_owner().as_ref().is_none()
                {
                    break;
                }
            }
            Err(HumanPresenceError::Denied(
                "the owner connection is no longer available".into(),
            ))
        };
        // Keep the operation on the receiving task, including native owner
        // authentication. Dropping it releases pending review reservations;
        // this does not roll back mutations that have already committed.
        tokio::select! {
            biased;
            result = disconnected => result,
            result = OWNER_CALL.scope(self.clone(), operation) => Ok(result),
        }
    }

    async fn verify(&self) -> Result<(), HumanPresenceError> {
        let uid = tokio::time::timeout(Duration::from_secs(10), async {
            DBusProxy::new(&self.bus)
                .await?
                .get_connection_unix_user(self.sender.clone().into())
                .await
                .map_err(zbus::Error::from)
        })
        .await
        .map_err(|_| HumanPresenceError::Unavailable("owner identity lookup timed out".into()))?
        .map_err(|_| {
            HumanPresenceError::Denied("the owner connection is no longer available".into())
        })?;
        if uid != self.owner_uid {
            return Err(HumanPresenceError::Denied(
                "the caller does not own this service profile".into(),
            ));
        }
        Ok(())
    }

    fn subject(&self) -> Result<Subject, HumanPresenceError> {
        let name = self
            .sender
            .clone()
            .try_into()
            .map_err(|error: zbus::zvariant::Error| {
                HumanPresenceError::Backend(error.to_string())
            })?;
        Ok(Subject {
            subject_kind: "system-bus-name".into(),
            subject_details: HashMap::from([("name".into(), name)]),
        })
    }
}

/// Scope one service owner operation to its actual system-bus message sender.
/// `bus` and `header` must come from the same zbus system-bus method handler.
/// Keep that connection pinned: opening a new connection after a bus restart
/// could resolve the same textual unique name in a different bus lifetime.
/// This establishes caller identity only. Every protected operation must still
/// invoke core's human-presence checks, which call polkit for this exact sender.
/// The operation is cancelled when its caller or the pinned bus disconnects.
pub async fn with_owner_call<F: Future>(
    bus: &Connection,
    header: &Header<'_>,
    operation: F,
) -> Result<F::Output, HumanPresenceError> {
    let owner_uid = crate::service_storage::owner_uid().ok_or_else(|| {
        HumanPresenceError::Unavailable("protected service storage is not active".into())
    })?;
    let sender = header
        .sender()
        .ok_or_else(|| HumanPresenceError::Denied("owner request has no system-bus sender".into()))?
        .to_owned();
    let call = OwnerCall {
        bus: bus.clone(),
        sender: sender.into(),
        owner_uid,
    };
    call.execute(operation).await
}

fn current(owner_uid: u32) -> Result<OwnerCall, HumanPresenceError> {
    let call = OWNER_CALL.try_with(Clone::clone).map_err(|_| {
        HumanPresenceError::Denied("service owner operation has no authenticated caller".into())
    })?;
    if call.owner_uid != owner_uid {
        return Err(HumanPresenceError::Denied(
            "owner request belongs to a different service profile".into(),
        ));
    }
    Ok(call)
}

pub(crate) async fn authority()
-> Result<Option<zbus_polkit::policykit1::AuthorityProxy<'static>>, HumanPresenceError> {
    let Some(owner_uid) = crate::service_storage::owner_uid() else {
        return Ok(None);
    };
    let call = current(owner_uid)?;
    call.verify().await?;
    zbus_polkit::policykit1::AuthorityProxy::new(&call.bus)
        .await
        .map(Some)
        .map_err(|error| HumanPresenceError::Unavailable(error.to_string()))
}

pub(crate) async fn subject() -> Result<Option<Subject>, HumanPresenceError> {
    let Some(owner_uid) = crate::service_storage::owner_uid() else {
        return Ok(None);
    };
    let call = current(owner_uid)?;
    call.verify().await?;
    call.subject().map(Some)
}

/// Recheck after polkit returns, before core issues an authorization proof.
/// D-Bus unique names are not reusable within a bus lifetime; a disconnected
/// caller cannot hand its pending approval to a replacement process.
pub(crate) async fn verify_after_authentication() -> Result<(), HumanPresenceError> {
    if let Some(owner_uid) = crate::service_storage::owner_uid() {
        current(owner_uid)?.verify().await?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "service_presence_test.rs"]
mod tests;
