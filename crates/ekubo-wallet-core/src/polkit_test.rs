//! Tests for [`super`].

use super::*;
use std::os::unix::process::ExitStatusExt;

#[test]
fn the_shipped_definition_declares_the_action_the_backend_asks_for() {
    assert!(
        POLICY_DOCUMENT.contains(&format!("<action id=\"{ACTION_ID}\">")),
        "human_presence.rs and contrib/polkit must name the same action"
    );
    assert!(
        POLICY_DOCUMENT.contains("<allow_active>auth_self</allow_active>"),
        "owner authentication is the owner's own password, not an administrator's"
    );
}

#[test]
fn a_workspace_build_finds_and_verifies_its_own_source_file() {
    let path = bundled_policy().expect("the workspace checkout ships the policy");
    assert!(path.is_absolute());
    assert_eq!(path.file_name().unwrap(), POLICY_FILE_NAME);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), POLICY_DOCUMENT);
}

#[test]
fn a_bundled_file_that_differs_from_this_build_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(POLICY_FILE_NAME);
    std::fs::write(&path, format!("{POLICY_DOCUMENT}\n<!-- edited -->")).unwrap();
    assert!(matches!(
        verify_bundled_policy(&path),
        Err(SetupError::BundleMismatch(_))
    ));
    std::fs::write(&path, POLICY_DOCUMENT).unwrap();
    assert!(verify_bundled_policy(&path).is_ok());
}

#[test]
fn the_manual_command_installs_the_same_file_to_the_same_place() {
    let command = manual_install_command(Path::new("/opt/ekubo wallet/lib/it's.policy"));
    assert_eq!(
        command,
        "sudo install -m 644 '/opt/ekubo wallet/lib/it'\\''s.policy' \
         /usr/share/polkit-1/actions/com.ekubo.wallet.policy"
    );
    assert_eq!(
        manual_install_command(Path::new("/usr/lib/ekubo-wallet/com.ekubo.wallet.policy")),
        "sudo install -m 644 /usr/lib/ekubo-wallet/com.ekubo.wallet.policy \
         /usr/share/polkit-1/actions/com.ekubo.wallet.policy"
    );
}

#[test]
fn pkexec_exit_codes_map_to_what_the_owner_did() {
    let status = |code: i32| ExitStatus::from_raw(code << 8);
    assert!(classify(status(0), "").is_ok());
    assert!(matches!(
        classify(status(126), ""),
        Err(SetupError::Dismissed)
    ));
    let no_agent = classify(
        status(127),
        "Error executing command as another user: No authentication agent found.\n",
    );
    match no_agent {
        Err(SetupError::NotAuthorized(detail)) => {
            assert!(detail.contains("No authentication agent found"));
        }
        other => panic!("unexpected {other:?}"),
    }
    match classify(status(1), "install: cannot create regular file\x1b[31m!\n") {
        Err(SetupError::InstallFailed(detail)) => {
            assert!(detail.starts_with("install: cannot create"));
            assert!(!detail.contains('\x1b'), "stderr is quoted into the UI");
        }
        other => panic!("unexpected {other:?}"),
    }
    match classify(status(1), "") {
        Err(SetupError::InstallFailed(detail)) => assert!(detail.contains("exit")),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn readiness_never_panics_without_a_bus() {
    // CI runners and containers may have no system bus at all; the answer
    // then is `Unreachable`, which the settings pane renders as a sentence.
    let state = readiness().await;
    assert!(!matches!(state, Readiness::Ready) || std::path::Path::new(ACTIONS_DIR).is_dir());
}
