use super::*;

/// Only an isolated test daemon; never the installed system bus or wallet data.
#[tokio::test]
#[ignore = "requires dbus-daemon; launches an isolated test bus"]
async fn installer_identity_comes_from_live_bus_credentials() {
    use std::io::{BufRead as _, BufReader};
    use std::process::{Command, Stdio};
    struct Bus(std::process::Child);
    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut daemon = Bus(Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap());
    let mut address = String::new();
    BufReader::new(daemon.0.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    let service = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let caller = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let registry = DBusProxy::new(&service).await.unwrap();
    let sender = caller.unique_name().unwrap().clone();
    let result = installer_process(&registry, &sender).await;
    if rustix::process::geteuid().as_raw() == 0 {
        assert_eq!(result.unwrap(), std::process::id());
    } else {
        assert!(
            result.is_err(),
            "an ordinary desktop caller is not an installer"
        );
    }
    caller.close().await.unwrap();
    assert!(installer_process(&registry, &sender).await.is_err());
    let missing = zbus::names::UniqueName::try_from(":1.999999").unwrap();
    assert!(installer_process(&registry, &missing).await.is_err());
}
