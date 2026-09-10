//! Windows primary-token identity checks for the isolated service host.
//!
//! A service SID in `TokenGroups` is insufficient: the process must run as the
//! dedicated virtual account itself. This does not attest installer metadata,
//! validate storage ACLs, or activate custody; those checks remain separate.

use anyhow::{Result, ensure};

#[cfg(target_os = "windows")]
#[path = "windows_service_identity_native.rs"]
mod native;
#[cfg(target_os = "windows")]
pub use native::{current_process_identity, verify_service_process};

/// Identity read from the current process's primary token, never an IPC field.
#[derive(Debug)]
pub struct ProcessIdentity {
    user_sid: String,
    session_id: u32,
}

impl ProcessIdentity {
    #[must_use]
    pub fn user_sid(&self) -> &str {
        &self.user_sid
    }

    #[must_use]
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    fn verify_service(&self, expected_service_sid: &str) -> Result<()> {
        ensure!(
            is_virtual_service_sid(expected_service_sid),
            "expected a dedicated Windows virtual service account"
        );
        ensure!(
            self.user_sid == expected_service_sid,
            "process is not running as the configured service account"
        );
        ensure!(
            self.session_id == 0,
            "wallet service must run in the noninteractive service session"
        );
        Ok(())
    }
}

fn is_virtual_service_sid(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("S-1-5-80-") else {
        return false;
    };
    let mut count = 0;
    for part in suffix.split('-') {
        let Ok(number) = part.parse::<u32>() else {
            return false;
        };
        if part != number.to_string() {
            return false;
        }
        count += 1;
    }
    count == 5
}

#[cfg(test)]
#[path = "windows_service_identity_test.rs"]
mod tests;
