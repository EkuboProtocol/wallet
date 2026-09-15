//! Windows native authentication runs through the protected SYSTEM broker,
//! scoped to the kernel-authenticated initiating owner connection.

use super::{HumanPresenceError, PresenceRequest};

pub(super) async fn confirm(request: &PresenceRequest) -> Result<(), HumanPresenceError> {
    crate::windows_service_presence::confirm(request)
        .await
        .map_err(|error| HumanPresenceError::Unavailable(error.to_string()))
}

#[cfg(test)]
#[path = "windows_owner_auth_test.rs"]
mod tests;
