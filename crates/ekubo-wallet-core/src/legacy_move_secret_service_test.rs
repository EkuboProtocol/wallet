//! Real synchronous Secret Service adapter on a private bus, never the user's.
use super::*;
use std::{
    io::{BufRead as _, BufReader},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const CHILD_HOME: &str = "EKUBO_LEGACY_MOVE_PRIVATE_BUS_HOME";
const TEST_NAME: &str = "legacy_move::retirement::secret_service_tests::legacy_credentials_from_async_runtimes_on_private_bus";

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires dbus-daemon and gnome-keyring-daemon; uses an isolated bus and keyring"]
fn legacy_credentials_from_async_runtimes_on_private_bus() {
    if let Some(home) = std::env::var_os(CHILD_HOME) {
        let home = PathBuf::from(home);
        assert_eq!(
            std::env::var("DBUS_SESSION_BUS_ADDRESS")
                .unwrap()
                .split(',')
                .next()
                .unwrap(),
            format!("unix:path={}/bus", home.display())
        );
        exercise(&home);
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join("bus.conf");
    std::fs::write(&config, format!(r#"<busconfig><type>session</type><listen>unix:path={}/bus</listen><auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/></policy></busconfig>"#, home.path().display())).unwrap();
    let mut bus = Process(
        Command::new("dbus-daemon")
            .args(["--nofork", "--print-address=1", "--config-file"])
            .arg(config)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut address = String::new();
    BufReader::new(bus.0.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    let data = home.path().join("data");
    let runtime = home.path().join("runtime");
    std::fs::create_dir(&data).unwrap();
    std::fs::create_dir(&runtime).unwrap();
    let mut child = Process(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--ignored", "--nocapture"])
            .env(CHILD_HOME, home.path())
            .env("HOME", home.path())
            .env("DBUS_SESSION_BUS_ADDRESS", address.trim())
            .env("XDG_DATA_HOME", data)
            .env("XDG_RUNTIME_DIR", runtime)
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env_remove("GNOME_KEYRING_CONTROL")
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "private legacy credential regression timed out"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn exercise(home: &Path) {
    let mut daemon = Process(
        Command::new("gnome-keyring-daemon")
            .args([
                "--foreground",
                "--components=secrets",
                "--unlock",
                "--control-directory",
            ])
            .arg(home.join("control"))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    daemon
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"private-legacy-test-password")
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while read_database_key().is_err() {
        assert!(daemon.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(25));
    }
    for multithread in [false, true] {
        let mut builder = if multithread {
            tokio::runtime::Builder::new_multi_thread()
        } else {
            tokio::runtime::Builder::new_current_thread()
        };
        let runtime = builder.enable_all().build().unwrap();
        runtime.block_on(async {
            blocking_phase("private Secret Service regression", || {
                let identity = Identity {
                    database_key_hash: hash(&[7; 32]),
                    source_file_hash: [0; 32],
                };
                let entry =
                    crate::credential_store::legacy_entry("org.ekubo.wallet.db", "default")?;
                entry.set_secret(&[7; 32])?;
                drop(entry);
                exercise_account_credential()?;
                check_database_key(&identity, true)?;
                assert!(retire_database_key(&identity, true)?);
                assert!(!retire_database_key(&identity, false)?);
                assert!(!retire_database_key(&identity, false)?);
                assert!(read_database_key()?.is_none());
                Ok(())
            })
            .await
            .unwrap();
        });
    }
}

fn exercise_account_credential() -> Result<()> {
    let wallet = WalletMetadata {
        id: "private-bus-fixture".into(),
        instance_id: Uuid::new_v4(),
        address: PrivateKeySigner::from_slice(&[7; 32])?.address(),
        source: crate::config::WalletSource::Imported,
        created_at: chrono::Utc::now(),
        exported_at: None,
    };
    let entry = crate::credential_store::legacy_entry(
        "org.ekubo.wallet.private-key.instance",
        &wallet.instance_id.to_string(),
    )?;
    entry.set_secret(&[7; 32])?;
    drop(entry);
    let summary = MoveSummary {
        source: PathBuf::from("/private-bus-fixture"),
        accounts: vec![wallet],
        tables: vec![],
        retained_shared_accounts: vec![],
        preserved_profiles: vec![],
    };
    let report = cleanup_with(&summary, legacy_key, |wallet, expected| {
        let entry = crate::credential_store::legacy_entry(
            "org.ekubo.wallet.private-key.instance",
            &wallet.instance_id.to_string(),
        )?;
        let current = Zeroizing::new(entry.get_secret()?);
        ensure!(
            current.as_slice() == expected,
            "private fixture key changed"
        );
        entry.delete_credential()?;
        Ok(())
    })?;
    assert_eq!(report.deleted_account_credentials.len(), 1);
    assert!(legacy_key(&summary.accounts[0])?.is_none());
    Ok(())
}
