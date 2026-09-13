//! Launch only the packaged signed fresh installer through native UAC. The
//! caller remains the login owner and keeps its authenticated relay endpoint.
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
pub fn run_elevated(owner_sid: &str, endpoint: Uuid, action: SetupAction) -> Result<()> {
    crate::windows_service_config::validate_owner_component(owner_sid)?;
    ensure!(
        !endpoint.is_nil()
            && crate::windows_service_identity::current_process_identity()?.user_sid() == owner_sid,
        "fresh setup must be launched by the actual owner"
    );
    let powershell = folder(FOLDERID_System)?.join(r"WindowsPowerShell\v1.0\powershell.exe");
    let filename = match action {
        SetupAction::Install => "install-windows-v2.ps1",
        _ => "recover-windows-v2.ps1",
    };
    let script = folder(FOLDERID_ProgramFiles)?
        .join("Ekubo Wallet 2")
        .join(filename);
    let option = match action {
        SetupAction::Install => format!(" -RelayEndpoint {endpoint}"),
        SetupAction::Resume => String::new(),
        SetupAction::DiscardUnused => " -DiscardUnused".into(),
    };
    let arguments = format!(
        "-NoProfile -NonInteractive -ExecutionPolicy AllSigned -File \"{}\" -OwnerSid {owner_sid}{option}",
        script.display()
    );
    let expression = format!(
        "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath {} -Verb RunAs -ArgumentList {} -Wait -PassThru; exit $p.ExitCode",
        ps_literal(&powershell.to_string_lossy()),
        ps_literal(&arguments)
    );
    let status = std::process::Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-Command", &expression])
        .status()?;
    ensure!(
        status.success(),
        "fresh setup was declined or failed; existing profile state was retained"
    );
    Ok(())
}
