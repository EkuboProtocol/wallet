use super::*;

#[tokio::test]
#[ignore = "requires dbus-daemon; launches an isolated test bus"]
async fn recipient_authentication_rejects_wrong_uid_and_does_not_follow_replacement() {
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
    let installer = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let name = "org.ekubo.Wallet.Provision.u1000";
    let service = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .name(name)
        .unwrap()
        .build()
        .await
        .unwrap();
    let registry = DBusProxy::new(&installer).await.unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let pinned = authenticate(&registry, name, uid).await.unwrap();
    assert_eq!(&pinned, service.unique_name().unwrap());
    assert!(
        authenticate(&registry, name, uid.wrapping_add(1))
            .await
            .is_err()
    );
    assert!(authenticate(&registry, ":1.999999", uid).await.is_err());
    service.close().await.unwrap();
    let replacement = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .name(name)
        .unwrap()
        .build()
        .await
        .unwrap();
    assert_ne!(replacement.unique_name().unwrap(), &pinned);
    assert!(authenticate(&registry, pinned.as_str(), uid).await.is_err());
    assert_eq!(
        authenticate(&registry, name, uid).await.unwrap(),
        *replacement.unique_name().unwrap()
    );
}
