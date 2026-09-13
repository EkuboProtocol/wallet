//! Windows v2 owner-authentication feasibility boundary.
//!
//! There is deliberately no desktop fallback, including before service custody
//! activation. Session-0 consent authenticates the wrong principal; a consent
//! enum received over an owner-SID pipe proves no human decision. See the
//! accompanying feasibility report before enabling any replacement.

use super::{HumanPresenceError, PresenceRequest};

pub(super) fn confirm(_request: &PresenceRequest) -> Result<(), HumanPresenceError> {
    Err(HumanPresenceError::Unavailable(
        "Windows v2 service owner authentication is unavailable: trusted interactive-owner \
         enrollment and service-verified operation-bound proof are not implemented"
            .into(),
    ))
}

#[cfg(test)]
#[path = "windows_owner_auth_test.rs"]
mod tests;
