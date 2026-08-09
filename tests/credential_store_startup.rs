//! Every credential-store touch in `crates/ekubo-wallet-core` (the database
//! key in `policy_store.rs`, private keys in `custody.rs`) must run inside
//! `tokio::task::block_in_place` -- see `load_or_create_database_key`'s doc
//! comment. Without it, `keyring`'s Linux backend connects to D-Bus through
//! a *blocking* API that starts its own runtime on first use, and Tokio
//! panics rather than nest one runtime inside another. That panic used to
//! fire on every credential-store-touching command, unconditionally --
//! before this environment's own D-Bus reachability was ever checked. This
//! test can't assert *success*, since a Secret Service may genuinely be
//! unavailable wherever it runs; it asserts the wallet never crashes finding
//! that out.

use assert_cmd::Command;

fn cli() -> Command {
    Command::cargo_bin("ekubo-wallet").expect("ekubo-wallet binary builds")
}

#[test]
fn credential_store_access_never_panics_the_runtime() {
    let commands: [&[&str]; 2] = [&["status"], &["legal", "accept"]];
    for args in commands {
        let data_dir = tempfile::tempdir().unwrap();
        let output = cli()
            .arg("--data-dir")
            .arg(data_dir.path())
            .args(args)
            .write_stdin("")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("Cannot start a runtime from within a runtime"),
            "{args:?} nested a Tokio runtime while reaching the credential store: {stderr}"
        );
        assert!(
            !stderr.contains("panicked at"),
            "{args:?} panicked reaching the credential store: {stderr}"
        );
    }
}
