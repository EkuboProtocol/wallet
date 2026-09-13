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

/// Diagnostic-only tag: stage in bits 24..27 and the lower 24 HRESULT bits.
/// Only HRESULTs with upper byte 0x80 use this lossless encoding; others remain
/// raw failures. The positive 0x7 tag cannot collide with a failing HRESULT or
/// `VERIFIED_EXIT`, making tagged versus raw failures unambiguous.
#[must_use]
pub fn decode_probe_failure(code: u32) -> Option<(&'static str, u32)> {
    const STAGES: [&str; 16] = [
        "unknown",
        "DLL search policy",
        "registry cache",
        "registry open",
        "registry override",
        "native apartment",
        "HWND creation",
        "factory activation/interop QI",
        "statics QI",
        "CheckAvailabilityAsync",
        "async status",
        "async GetResults",
        "async cancellation",
        "availability completion",
        "System32 DLL load",
        "System32 DLL pin",
    ];
    if code & 0xf000_0000 != 0x7000_0000 {
        return None;
    }
    let stage = usize::try_from((code >> 24) & 0xf).ok()?;
    Some((*STAGES.get(stage)?, 0x8000_0000 | (code & 0x00ff_ffff)))
}
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
pub use hello::{collect, probe_availability, probe_failure_exit};

#[cfg(test)]
#[path = "lib_test.rs"]
mod tests;
