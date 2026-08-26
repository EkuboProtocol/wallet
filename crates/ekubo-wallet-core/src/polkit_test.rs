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
fn the_exported_copy_is_this_builds_document_and_replaces_a_stale_one() {
    let directory = tempfile::tempdir().unwrap();
    let nested = directory.path().join("state");
    let path = export_policy(&nested).expect("a fresh directory is created on the way");
    assert!(path.is_absolute());
    assert_eq!(path.file_name().unwrap(), POLICY_FILE_NAME);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), POLICY_DOCUMENT);

    std::fs::write(&path, format!("{POLICY_DOCUMENT}{POLICY_DOCUMENT}")).unwrap();
    export_policy(&nested).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        POLICY_DOCUMENT,
        "an older or longer copy is replaced whole, not overwritten in place"
    );
}

#[test]
fn a_link_planted_at_the_export_name_is_refused_not_followed() {
    let directory = tempfile::tempdir().unwrap();
    let victim = directory.path().join("wallet.db");
    std::fs::write(&victim, "precious").unwrap();
    std::os::unix::fs::symlink(&victim, directory.path().join(POLICY_FILE_NAME)).unwrap();

    let refused = export_policy(directory.path());
    assert!(
        matches!(refused, Err(SetupError::ExportFailed(_))),
        "{refused:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "precious",
        "the link's target must be untouched"
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
fn the_innermost_mount_decides_whether_the_actions_directory_is_writable() {
    const ORDINARY: &str = "\
/dev/mapper/root / btrfs rw,relatime,compress=zstd:3 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
";
    const SILVERBLUE: &str = "\
composefs / overlay ro,relatime,seclabel 0 0
/dev/nvme0n1p3 /sysroot btrfs rw,seclabel,relatime 0 0
/dev/nvme0n1p3 /usr overlay ro,seclabel,relatime,lowerdir=/usr 0 0
/dev/nvme0n1p3 /var btrfs rw,seclabel,relatime 0 0
";
    const REMOUNTED: &str = "\
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda1 /usr ext4 ro,relatime 0 0
/dev/sda1 /usr ext4 rw,relatime 0 0
";
    const SPACED: &str = "\
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sdb1 /usr/share\\040extra ext4 ro 0 0
/dev/sdc1 /usr/shar ext4 ro 0 0
";
    assert!(!mounted_read_only(ORDINARY, ACTIONS_DIR));
    assert!(mounted_read_only(SILVERBLUE, ACTIONS_DIR));
    assert!(
        !mounted_read_only(SILVERBLUE, "/var/lib/thing"),
        "the read-only root must not shadow a writable mount beneath it"
    );
    assert!(
        !mounted_read_only(REMOUNTED, ACTIONS_DIR),
        "the later mount on the same point is the one on top"
    );
    assert!(
        !mounted_read_only(SPACED, ACTIONS_DIR),
        "neither a sibling with a space nor a prefix that is not a path component counts"
    );
    assert!(mounted_read_only(SPACED, "/usr/share extra/file"));
    assert!(!mounted_read_only("", ACTIONS_DIR));
}

#[tokio::test]
async fn readiness_never_panics_without_a_bus() {
    // CI runners and containers may have no system bus at all; the answer
    // then is `Unreachable`, which the settings pane renders as a sentence.
    let state = readiness().await;
    assert!(!matches!(state, Readiness::Ready) || std::path::Path::new(ACTIONS_DIR).is_dir());
}
