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
fn the_exported_copy_is_this_builds_document_and_root_readable() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let nested = directory.path().join("state");
    let path = export_policy(&nested).expect("a fresh directory is created on the way");
    assert!(path.is_absolute());
    assert_eq!(path.file_name().unwrap(), POLICY_FILE_NAME);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), POLICY_DOCUMENT);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );

    std::fs::write(&path, "stale").unwrap();
    export_policy(&nested).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        POLICY_DOCUMENT,
        "an older build's copy is replaced, not kept"
    );
}

#[test]
fn the_manual_command_installs_the_exported_file_to_the_same_place() {
    let command = manual_install_command(Path::new("/home/o wner/.local/state/it's.policy"));
    assert_eq!(
        command,
        "sudo install -m 644 '/home/o wner/.local/state/it'\\''s.policy' \
         /usr/share/polkit-1/actions/com.ekubo.wallet.policy"
    );
    assert_eq!(
        manual_install_command(Path::new(
            "/home/owner/.local/share/ekubo-wallet/com.ekubo.wallet.policy"
        )),
        "sudo install -m 644 /home/owner/.local/share/ekubo-wallet/com.ekubo.wallet.policy \
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

#[test]
fn a_failed_poll_does_not_outrank_an_answer_polkit_already_gave() {
    let lost = || Readiness::Unreachable("lost".into());
    assert_eq!(prefer(None, lost()), lost());
    assert_eq!(
        prefer(None, Readiness::PolicyMissing),
        Readiness::PolicyMissing
    );
    assert_eq!(
        prefer(Some(Readiness::PolicyMissing), lost()),
        Readiness::PolicyMissing
    );
    assert_eq!(
        prefer(Some(lost()), Readiness::PolicyMissing),
        Readiness::PolicyMissing
    );
    assert_eq!(prefer(Some(Readiness::Ready), lost()), Readiness::Ready);
    assert_eq!(
        prefer(Some(lost()), Readiness::Unreachable("again".into())),
        Readiness::Unreachable("again".into())
    );
}

#[tokio::test]
async fn readiness_never_panics_without_a_bus() {
    // CI runners and containers may have no system bus at all; the answer
    // then is `Unreachable`, which the settings pane renders as a sentence.
    let state = readiness().await;
    assert!(!matches!(state, Readiness::Ready) || std::path::Path::new(ACTIONS_DIR).is_dir());
}
