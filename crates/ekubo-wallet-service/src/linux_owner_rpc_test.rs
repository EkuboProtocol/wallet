use super::*;

#[test]
fn zeroizing_owner_reply_keeps_the_existing_dbus_string_signature() {
    use zbus::zvariant::{LE, Type, serialized::Context, to_bytes};
    let text = "{\"accounts\":[]}";
    let response = OwnerResponse(zeroize::Zeroizing::new(text.into()));
    assert_eq!(OwnerResponse::SIGNATURE, String::SIGNATURE);
    let encoded = to_bytes(Context::new_dbus(LE, 0), &response).unwrap();
    let (decoded, _): (String, _) = encoded.deserialize().unwrap();
    assert_eq!(decoded, text);
}

/// This exercises connection lifetime on a private bus. Owner UID authorization
/// is a separate core check at the real interface, before `hold` is invoked.
#[tokio::test]
#[ignore = "requires dbus-daemon; launches an isolated test bus"]
async fn desktop_disconnect_releases_its_execution_session() {
    use std::io::{BufRead as _, BufReader};
    use std::process::{Command, Stdio};
    use std::time::Duration;
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
    let desktop = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let sender = desktop.unique_name().unwrap().clone();
    let service_name = service.unique_name().unwrap().clone();
    let proxy = zbus::Proxy::new(
        &desktop,
        service_name.as_str(),
        ekubo_wallet_client::owner_protocol::OBJECT_PATH,
        "org.ekubo.Wallet.Owner1",
    )
    .await
    .unwrap();
    let mut ready = proxy.receive_signal("DesktopSessionReady").await.unwrap();
    let sessions = crate::desktop_sessions::DesktopSessions::default();
    let activity = sessions.activity();
    let reservation = sessions.reserve().unwrap();
    let nonce = uuid::Uuid::new_v4().to_string();
    let expected_nonce = nonce.clone();
    let lease =
        tokio::spawn(async move { hold_desktop(reservation, &service, &sender, &nonce).await });
    let signal = tokio::time::timeout(Duration::from_secs(5), ready.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(signal.header().sender(), Some(service_name.inner()));
    assert_eq!(
        signal.body().deserialize::<(String,)>().unwrap().0,
        expected_nonce
    );
    assert_eq!(
        *activity.borrow(),
        1,
        "readiness must follow lease activation"
    );
    drop(ready);
    drop(proxy);
    desktop.close().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), lease)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(*activity.borrow(), 0);
    assert!(sessions.reserve().is_ok());
}
