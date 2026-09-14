//! Launch only the packaged signed code through native UAC. The caller remains
//! the login owner and keeps its authenticated relay endpoint.
//!
//! Elevation hardening: the Install action elevates the signed
//! `ekubo-wallet-v2-enroll.exe` helper path, so the UAC consent prompt names
//! that signed binary and the live relay endpoint travels only on its command
//! line, never on a generic host's elevated command line. Resume and discard
//! carry no relay material and keep elevating the signed recovery script.
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

#[derive(Clone, Copy)]
pub enum SetupAction {
    Install,
    Resume,
    DiscardUnused,
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
    // Install returns above; resume and discard carry no relay material and
    // keep elevating the signed recovery script.
    let script = folder(FOLDERID_ProgramFiles)?
        .join("Ekubo Wallet 2")
        .join("recover-windows-v2.ps1");
    let option = match action {
        SetupAction::Resume => String::new(),
        SetupAction::DiscardUnused => " -DiscardUnused".into(),
        SetupAction::Install => unreachable!("install elevates the signed helper above"),
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
    // Mirror the interactive AllSigned invocation previously used for direct
    // elevation: the elevated console stays interactive so the operator can
    // choose Run once for a valid but not-yet-trusted publisher. Publisher
    // trust is never installed on their behalf.
    let status = std::process::Command::new(&powershell)
        .env("PSModulePath", &modules)
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("AllSigned")
        .arg("-File")
        .arg(&script)
        .arg("-OwnerSid")
        .arg(owner_sid)
        .arg("-RelayEndpoint")
        .arg(endpoint.to_string())
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
