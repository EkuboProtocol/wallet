//! Launch only the packaged signed code through native UAC. The caller remains
//! the login owner and keeps its authenticated relay endpoint.
//!
//! Elevation hardening: the Install action elevates the signed
//! `ekubo-wallet-v2-enroll.exe` helper path, so the UAC consent prompt names
//! that signed binary and the live relay endpoint travels only on its command
//! line, never on a generic host's elevated command line. Resume carries no
//! relay material and elevates a bootstrap that re-validates the signed
//! recovery script (Authenticode plus exact approved hash) before running it
//! with process-scoped Bypass. Discard and reset-confirmed keep the
//! interactive AllSigned outer invocation whose Run-once approval their
//! SYSTEM task re-validates.
#![allow(unsafe_code)]
use anyhow::{Result, ensure};
use uuid::Uuid;
use windows::{
    Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{
            FOLDERID_ProgramFiles, FOLDERID_System, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
        },
    },
    core::{GUID, PWSTR},
};

fn folder(id: GUID) -> Result<std::path::PathBuf> {
    struct Text(PWSTR);
    impl Drop for Text {
        fn drop(&mut self) {
            unsafe { CoTaskMemFree(Some(self.0.0.cast())) };
        }
    }
    // Fixed machine known-folder IDs; no environment or caller-selected executable.
    let text = Text(unsafe { SHGetKnownFolderPath(&raw const id, KF_FLAG_DEFAULT, None) }?);
    Ok(std::path::PathBuf::from(unsafe { text.0.to_string() }?))
}
fn ps_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Bootstrap template for invoking a fixed installed setup script. The
/// placeholders are replaced with single-quoted literals only; the template
/// itself carries no caller-controlled quoting.
const VERIFIED_SCRIPT_BOOTSTRAP: &str = "$ErrorActionPreference='Stop'; $env:PSModulePath=[IO.Path]::Combine($PSHOME, 'Modules'); $s=__SCRIPT__; if ((Get-AuthenticodeSignature -LiteralPath $s).Status -ne 'Valid') { throw 'Installed setup script signature is not valid.' }; if ((Get-FileHash -LiteralPath $s -Algorithm SHA256).Hash -cne __HASH__) { throw 'Installed setup script changed after approval.' }; & __POWERSHELL__ -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $s__ARGS__; if ($LASTEXITCODE -ne 0) { throw 'Verified setup script failed.' }";

/// SHA256 of the exact installed bytes the operator approved, uppercase hex
/// to match `Get-FileHash`. Fail closed on missing or unreadable state.
fn approved_script_hash(script: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    ensure!(
        script.is_file(),
        "signed setup script is not installed; fresh setup refused"
    );
    let bytes = std::fs::read(script)?;
    Ok(hex::encode(Sha256::digest(&bytes)).to_uppercase())
}

/// Verify Authenticode plus the exact approved hash, then invoke with
/// process-scoped Bypass. Bypass here is NOT signature validation: the two
/// checks above it bind the executed bytes to the installed package the
/// operator approved (UAC consent on the signed helper for install, the
/// owner's own pre-elevation read for resume). Machine/User Group Policy
/// still takes precedence and is never changed; publisher trust is never
/// installed. `-NonInteractive` fails closed on any unexpected prompt
/// instead of hanging: the AllSigned "untrusted publisher" prompt, whose
/// default abort and "Never run" option used to brick enrollment, can never
/// appear.
fn verified_script_bootstrap(
    powershell: &std::path::Path,
    script: &std::path::Path,
    args: &str,
    approved_hash: &str,
) -> String {
    VERIFIED_SCRIPT_BOOTSTRAP
        .replace("__SCRIPT__", &ps_literal(&script.to_string_lossy()))
        .replace("__HASH__", &ps_literal(approved_hash))
        .replace("__POWERSHELL__", &ps_literal(&powershell.to_string_lossy()))
        .replace("__ARGS__", args)
}

#[derive(Clone, Copy)]
pub enum SetupAction {
    Install,
    Resume,
    DiscardUnused,
    /// Admin-plus-owner reset of a confirmed-but-never-activated pending
    /// profile (forged relay receipt or lost credential entry). The SYSTEM
    /// recovery script enforces the zero-account/no-setup-complete allowlist
    /// and refuses any installed or activated state.
    ResetConfirmed,
}

/// Blocking: run in a background worker while the owner serves its relay and
/// connects/unlocks the published service. UAC denial is an ordinary error.
///
/// Install elevates only the signed enrollment helper (see `--launch-install`
/// in enroll_main): the relay endpoint is passed to that signed binary, not to
/// a generic elevated host. The helper performs no custody, relay, or
/// publication operation itself; it only re-executes the signed install script
/// in the elevated context.
pub fn run_elevated(owner_sid: &str, endpoint: Uuid, action: SetupAction) -> Result<()> {
    crate::windows_service_config::validate_owner_component(owner_sid)?;
    ensure!(
        !endpoint.is_nil()
            && crate::windows_service_identity::current_process_identity()?.user_sid() == owner_sid,
        "fresh setup must be launched by the actual owner"
    );
    if matches!(action, SetupAction::Install) {
        let enroll = folder(FOLDERID_ProgramFiles)?
            .join("Ekubo Wallet 2")
            .join("ekubo-wallet-v2-enroll.exe");
        ensure!(
            enroll.is_file(),
            "signed enrollment helper is not installed; fresh setup refused"
        );
        let expression = format!(
            "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath {} -Verb RunAs -ArgumentList {},{},{} -Wait -PassThru; exit $p.ExitCode",
            ps_literal(&enroll.to_string_lossy()),
            ps_literal("--launch-install"),
            ps_literal(owner_sid),
            ps_literal(&endpoint.to_string())
        );
        return elevate(expression);
    }
    let powershell = folder(FOLDERID_System)?.join(r"WindowsPowerShell\v1.0\powershell.exe");
    // Resume carries no relay material. It elevates a verified Bypass
    // bootstrap of the signed recovery script: Authenticode Valid plus the
    // owner-approved hash captured below, re-checked elevated before
    // execution. Discard and reset keep the interactive AllSigned outer
    // invocation below: that Run-once approval is the parent binding their
    // SYSTEM task re-validates.
    if matches!(action, SetupAction::Resume) {
        let script = folder(FOLDERID_ProgramFiles)?
            .join("Ekubo Wallet 2")
            .join("recover-windows-v2.ps1");
        let approved = approved_script_hash(&script)?;
        let bootstrap = verified_script_bootstrap(
            &powershell,
            &script,
            &format!(" -OwnerSid {}", ps_literal(owner_sid)),
            &approved,
        );
        let inner = format!(
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command {}",
            ps_literal(&bootstrap)
        );
        let expression = format!(
            "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath {} -Verb RunAs -ArgumentList {} -Wait -PassThru; if ($null -eq $p.ExitCode) {{ exit 1 }}; exit $p.ExitCode",
            ps_literal(&powershell.to_string_lossy()),
            ps_literal(&inner)
        );
        return elevate(expression);
    }
    // Install returns above; resume returns above; discard and reset carry no
    // relay material and keep elevating the signed recovery script.
    let script = folder(FOLDERID_ProgramFiles)?
        .join("Ekubo Wallet 2")
        .join("recover-windows-v2.ps1");
    let option: String = match action {
        SetupAction::DiscardUnused => " -DiscardUnused".into(),
        SetupAction::ResetConfirmed => " -ResetConfirmed".into(),
        SetupAction::Install | SetupAction::Resume => {
            unreachable!("install and resume elevate above")
        }
    };
    // AllSigned can prompt for a valid but not-yet-trusted publisher. The
    // elevated console must allow the operator to choose Run once; do not
    // import a publisher certificate or answer Always run on their behalf.
    // The outer command-only launcher remains noninteractive below.
    let arguments = format!(
        "-NoProfile -ExecutionPolicy AllSigned -File \"{}\" -OwnerSid {owner_sid}{option}",
        script.display()
    );
    let expression = format!(
        "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath {} -Verb RunAs -ArgumentList {} -Wait -PassThru; exit $p.ExitCode",
        ps_literal(&powershell.to_string_lossy()),
        ps_literal(&arguments)
    );
    elevate(expression)
}

/// Elevated trampoline for enroll `--launch-install`. The caller must already
/// be the elevated installer; this only re-executes the signed install script
/// in that context. No custody, relay, registry, or publication operation
/// occurs here: the only privileged enrollment entry remains `--installer`,
/// invoked by the install script once the pending service is provisioned.
pub fn run_install_script(owner_sid: &str, endpoint: Uuid) -> Result<()> {
    crate::windows_service_identity::verify_installer_process()?;
    crate::windows_service_config::validate_owner_component(owner_sid)?;
    ensure!(
        !endpoint.is_nil(),
        "an explicit live relay endpoint is required"
    );
    let powershell = folder(FOLDERID_System)?.join(r"WindowsPowerShell\v1.0\powershell.exe");
    let script = folder(FOLDERID_ProgramFiles)?
        .join("Ekubo Wallet 2")
        .join("install-windows-v2.ps1");
    ensure!(
        script.is_file(),
        "signed fresh installer is not installed; fresh setup refused"
    );
    let modules = powershell
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing system PowerShell directory"))?
        .join("Modules");
    // The caller is already the UAC-elevated installer (verified above), so
    // no publisher prompt may appear here: verify Authenticode plus the exact
    // approved bytes, then invoke with process-scoped Bypass and
    // -NonInteractive. The nested auth-registration call inside the install
    // script follows the same pattern, so neither of the two prompts that
    // used to brick enrollment on "Never run" can appear.
    let approved = approved_script_hash(&script)?;
    let bootstrap = verified_script_bootstrap(
        &powershell,
        &script,
        &format!(
            " -OwnerSid {} -RelayEndpoint {}",
            ps_literal(owner_sid),
            ps_literal(&endpoint.to_string())
        ),
        &approved,
    );
    let status = std::process::Command::new(&powershell)
        .env("PSModulePath", &modules)
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(&bootstrap)
        .status()?;
    ensure!(
        status.success(),
        "fresh setup was declined or failed; existing profile state was retained"
    );
    Ok(())
}

/// Run an already-built elevation expression through the noninteractive,
/// command-only system launcher with a constrained module path.
fn elevate(expression: String) -> Result<()> {
    let powershell = folder(FOLDERID_System)?.join(r"WindowsPowerShell\v1.0\powershell.exe");
    let modules = powershell
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing system PowerShell directory"))?
        .join("Modules");
    let status = std::process::Command::new(powershell)
        .env("PSModulePath", modules)
        .args(["-NoProfile", "-NonInteractive", "-Command", &expression])
        .status()?;
    ensure!(
        status.success(),
        "fresh setup was declined or failed; existing profile state was retained"
    );
    Ok(())
}
