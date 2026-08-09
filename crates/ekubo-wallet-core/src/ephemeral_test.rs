//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default.
//!
//! None of these touch [`super::ENABLED`]. It is process-global, and these
//! tests share a process with every other test in the crate — including the
//! custody ones that assert the credential store *is* reached.
//!
//! Identity is asserted through the key file rather than through
//! `DatabaseKey`, which has neither a public accessor nor `Debug`. Both are
//! deliberate, and a test is not a reason to widen either.

use super::*;

fn key_bytes(data_dir: &Path) -> Vec<u8> {
    std::fs::read(data_dir.join(KEY_FILE)).expect("the key file")
}

#[test]
fn a_session_is_ordinary_unless_it_was_enabled() {
    // The default, and the only state any other test in this process sees.
    assert!(!is_enabled());
    let directory = tempfile::tempdir().expect("a temporary directory");
    assert!(
        database_key(directory.path(), false)
            .expect("an ordinary session answers rather than failing")
            .is_none()
    );
    // Nothing was created merely by asking.
    assert!(!directory.path().join(KEY_FILE).exists());
}

#[test]
fn a_fresh_directory_gets_a_key_that_persists() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    assert!(key_in_dir(directory.path(), false).is_ok());
    let first = key_bytes(directory.path());
    assert_eq!(first.len(), 32);

    // The next command in the same session has to open the same database, so
    // the key must come back rather than be regenerated.
    assert!(key_in_dir(directory.path(), true).is_ok());
    assert_eq!(first, key_bytes(directory.path()));
}

#[test]
fn two_directories_do_not_share_a_key() {
    // The isolation the credential store cannot give: one machine-wide entry
    // means every data directory shares one key.
    let one = tempfile::tempdir().expect("a temporary directory");
    let two = tempfile::tempdir().expect("a temporary directory");
    assert!(key_in_dir(one.path(), false).is_ok());
    assert!(key_in_dir(two.path(), false).is_ok());
    assert_ne!(key_bytes(one.path()), key_bytes(two.path()));
}

#[test]
fn the_key_is_not_readable_by_anyone_else() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    assert!(key_in_dir(directory.path(), false).is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(directory.path().join(KEY_FILE))
            .expect("the key file")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "the key file is group- or world-accessible"
        );
    }
}

#[test]
fn a_database_whose_key_is_gone_fails_closed() {
    // Matching the credential-store path: generating a fresh key here would
    // report a working empty wallet over a database nothing can read.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let Err(error) = key_in_dir(directory.path(), true) else {
        panic!("a database with no key must not silently get a new one");
    };
    let message = format!("{error:#}");
    assert!(message.contains(KEY_FILE), "{message}");
    assert!(message.contains("delete the directory"), "{message}");
}

#[test]
fn a_truncated_key_file_is_refused_rather_than_padded() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    std::fs::write(directory.path().join(KEY_FILE), [7_u8; 16]).expect("a short key file");
    let Err(error) = key_in_dir(directory.path(), true) else {
        panic!("a 16-byte key must not be accepted as a 32-byte one");
    };
    assert!(format!("{error:#}").contains("not a 32-byte key"));
}
