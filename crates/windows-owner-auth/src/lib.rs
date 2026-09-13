//! The fixed native Windows Hello collector and its process boundary.
//!
//! Only a service holding the process handle returned by `launch` can consume
//! its result. An independently launched copy has no authority.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub const VERIFIED_EXIT: u32 = 0x4557_3201;
/// Read-only diagnostic completion plus the Windows availability enum (0..=4).
/// This range is deliberately disjoint from every authorization success code.
pub const AVAILABILITY_EXIT_BASE: u32 = 0x4557_3300;
pub const MAX_REASON_BYTES: usize = 1024;

/// Fixed-mode launch input. No executable, DLL, handle, or credential can be
/// selected by this record. The nonce and operation digest originate in core.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub nonce: String,
    pub operation_digest: String,
    pub reason: String,
}

impl Challenge {
    pub fn validate(&self) -> Result<()> {
        for value in [&self.nonce, &self.operation_digest] {
            ensure!(
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "invalid native authorization binding"
            );
        }
        ensure!(
            !self.reason.trim().is_empty()
                && self.reason.len() <= MAX_REASON_BYTES
                && !self.reason.chars().any(char::is_control),
            "invalid native authorization reason"
        );
        Ok(())
    }
}

/// Windows argv quoting (CommandLineToArgvW/CRT rules), including backslashes
/// immediately preceding a quote and trailing backslashes before the delimiter.
#[cfg(any(windows, test))]
fn quote_argument(value: &str) -> String {
    let mut quoted = String::from("\"");
    let mut slashes = 0;
    for character in value.chars() {
        if character == '\\' {
            slashes += 1;
            continue;
        }
        quoted.extend(std::iter::repeat_n(
            '\\',
            if character == '"' {
                slashes * 2 + 1
            } else {
                slashes
            },
        ));
        quoted.push(character);
        slashes = 0;
    }
    quoted.extend(std::iter::repeat_n('\\', slashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{CollectorProcess, installed_helper_path, launch, logon_identity};
#[cfg(windows)]
mod hello;
#[cfg(windows)]
pub use hello::{collect, probe_availability};

#[cfg(test)]
#[path = "lib_test.rs"]
mod tests;
