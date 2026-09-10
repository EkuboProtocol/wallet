use std::{
    io::{BufRead as _, BufReader, Write as _},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const TEST_NAME: &str =
    "credential_store::tests::recovers_after_secret_service_startup_and_restart";
const CHILD_HOME: &str = "EKUBO_TEST_SECRET_SERVICE_HOME";
const SERVICE: &str = "org.ekubo.wallet.test.credential-reconnect";
const USER: &str = "test-only";
const SECRET: &[u8] = b"isolated-test-secret-not-a-wallet-key";

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// This test creates its own bus and credential daemon and only ever kills
/// those child processes. It cannot read or change the desktop's keyring.
#[test]
#[ignore = "requires dbus-daemon and gnome-keyring-daemon; creates an isolated test bus"]
fn recovers_after_secret_service_startup_and_restart() {
    if let Some(home) = std::env::var_os(CHILD_HOME) {
        exercise_restart(Path::new(&home));
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join("bus.conf");
    let address = format!("unix:path={}/bus", home.path().display());
    // No service directories: failed connects cannot auto-activate the
    // desktop's keyring daemon or hide the initial unavailable condition.
    std::fs::write(
        &config,
        format!(
            r#"<busconfig>
        <type>session</type><listen>{address}</listen><auth>EXTERNAL</auth>
        <policy context="default">
            <allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/>
        </policy>
    </busconfig>"#
        ),
    )
    .unwrap();
    let mut bus = Process(
        Command::new("dbus-daemon")
            .arg("--nofork")
            .arg("--print-address=1")
            .arg("--config-file")
            .arg(&config)
            .stdout(Stdio::piped())
            .spawn()
            .expect("dbus-daemon is required"),
    );
    let mut bus_address = String::new();
    BufReader::new(bus.0.stdout.take().unwrap())
        .read_line(&mut bus_address)
        .unwrap();
    assert!(bus_address.starts_with(&address));
    let data = home.path().join("data");
    let runtime = home.path().join("runtime");
    std::fs::create_dir(&data).unwrap();
    std::fs::create_dir(&runtime).unwrap();
    let mut child = Process(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--ignored", "--nocapture"])
            .env(CHILD_HOME, home.path())
            .env("DBUS_SESSION_BUS_ADDRESS", bus_address.trim())
            .env("XDG_DATA_HOME", &data)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env_remove("GNOME_KEYRING_CONTROL")
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "isolated Secret Service regression failed"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "isolated Secret Service regression timed out"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn start_keyring(home: &Path) -> Process {
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
            .expect("gnome-keyring-daemon is required"),
    );
    daemon
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"isolated-test-keyring-password")
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if super::entry(SERVICE, USER).is_ok() {
            return daemon;
        }
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "test keyring exited during startup"
        );
        assert!(Instant::now() < deadline, "test keyring did not start");
        thread::sleep(Duration::from_millis(25));
    }
}

fn exercise_restart(home: &Path) {
    use crate::{
        custody::{KeyStore as _, OsKeyStore, PrivateKeyMaterial},
        policy_store::PolicyStore,
    };

    // Initial unavailability must not poison every future entry construction.
    assert!(super::entry(SERVICE, USER).is_err());
    let database = home.join("wallet-data");
    assert!(PolicyStore::production(&database).is_err());
    let daemon = start_keyring(home);
    PolicyStore::production(&database)
        .unwrap()
        .assert_schema_current()
        .unwrap();
    let instance = uuid::Uuid::new_v4();
    let key = PrivateKeyMaterial::from_hex(&"11".repeat(32)).unwrap();
    OsKeyStore.insert_new(instance, &key).unwrap();
    let old = super::entry(SERVICE, USER).unwrap();
    assert!(matches!(old.get_secret(), Err(keyring::Error::NoEntry)));
    old.set_secret(SECRET).unwrap();
    assert_eq!(old.get_secret().unwrap(), SECRET);
    drop(daemon);
    let _restarted = start_keyring(home);
    // Prove this really invalidated the old session, then show that the
    // wallet's next operation recovers without recreating or replacing keys.
    assert!(
        old.get_secret().is_err(),
        "old Secret Service session unexpectedly survived restart"
    );
    let fresh = super::entry(SERVICE, USER).unwrap();
    assert_eq!(fresh.get_secret().unwrap(), SECRET);
    // Exercise both production call sites, not just the entry factory: MCP
    // startup must reopen its existing database, and custody must still read
    // the same account key after the daemon loses its sessions.
    PolicyStore::production(&database)
        .unwrap()
        .assert_schema_current()
        .unwrap();
    assert_eq!(OsKeyStore.load(instance).unwrap().address(), key.address());
    fresh.delete_credential().unwrap();
    assert!(matches!(fresh.get_secret(), Err(keyring::Error::NoEntry)));
}
