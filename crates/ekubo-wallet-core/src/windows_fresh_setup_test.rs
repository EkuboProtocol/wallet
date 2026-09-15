//! Launcher-string backstop for the elevated resume/discard/reset bootstrap.
//! No CI job drives `run_elevated`, so these tests pin the exact properties
//! that distinguish a working launcher from the print-and-exit-0 failure:
//! the verified bootstrap must travel via `-EncodedCommand` (UTF-16LE
//! base64, the recovery path's exact encoding) and never as a bare
//! single-quoted `-Command` payload. The string builder is tested, not
//! elevation.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

const ENCODED_PREFIX: &str = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ";

fn decode_bootstrap(inner: &str) -> String {
    let encoded = inner
        .strip_prefix(ENCODED_PREFIX)
        .expect("launcher carries -EncodedCommand");
    let wide = STANDARD.decode(encoded).expect("valid base64 blob");
    assert_eq!(wide.len() % 2, 0, "UTF-16LE byte length is even");
    let units: Vec<u16> = wide
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).expect("UTF-16LE bootstrap text")
}

#[test]
fn encoded_launcher_has_no_quoted_script_payload() {
    let bootstrap = "$ErrorActionPreference='Stop'; Write-Output 'probe'";
    let inner = encode_bootstrap_command(bootstrap);
    // Working property: the elevated host decodes and executes.
    assert_eq!(decode_bootstrap(&inner), bootstrap);
    // Print-and-exit-0 properties: no `-Command '<script>'` form and no raw
    // script text outside the blob. The base64 alphabet carries neither `'`
    // nor `$`, so any occurrence proves the payload leaked unencoded.
    assert!(
        !inner.contains("-Command '"),
        "launcher must not single-quote -Command: {inner}"
    );
    assert!(
        !inner.contains('\''),
        "encoded launcher must not contain quotes: {inner}"
    );
    assert!(
        !inner.contains('$'),
        "raw script must not appear outside the blob: {inner}"
    );
}

#[test]
fn verified_bootstrap_is_encoded_never_quoted() {
    let bootstrap = verified_script_bootstrap(
        std::path::Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        std::path::Path::new(r"C:\Program Files\Ekubo Wallet 2\recover-windows-v2.ps1"),
        " -OwnerSid 'S-1-5-21-1-2-3-4' -ResetConfirmed",
        "ABCDEF0123456789",
    );
    // The bootstrap itself is PowerShell source carrying signature and hash
    // checks, so quoting it into `-Command` would reproduce the literal bug.
    assert!(bootstrap.contains("Get-AuthenticodeSignature"));
    assert!(bootstrap.contains("Get-FileHash"));
    assert!(bootstrap.contains('\''));
    let inner = encode_bootstrap_command(&bootstrap);
    assert!(inner.starts_with(ENCODED_PREFIX));
    assert_eq!(decode_bootstrap(&inner), bootstrap);
    assert!(!inner.contains('\''));
}
