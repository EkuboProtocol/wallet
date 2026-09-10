use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Endpoint {
    calls: Arc<AtomicUsize>,
}

#[zbus::interface(name = "org.ekubo.Wallet.Owner1")]
impl Endpoint {
    fn call(&self, request: &str) -> String {
        assert!(matches!(
            serde_json::from_str::<Request>(request).unwrap(),
            Request::Accounts
        ));
        self.calls.fetch_add(1, Ordering::SeqCst);
        "[]".into()
    }
}

/// No real service, keys, or system-bus configuration are involved. The UID
/// mismatch and name replacement exercise actual private-bus peer lookups.
#[tokio::test]
#[ignore = "requires dbus-daemon; launches an isolated test bus"]
async fn client_checks_uid_pins_service_and_does_not_replay_after_disconnect() {
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
    let name = "org.ekubo.Wallet.Owner.Test";
    let original_calls = Arc::new(AtomicUsize::new(0));
    let original = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .name(name)
        .unwrap()
        .serve_at(
            OBJECT_PATH,
            Endpoint {
                calls: original_calls.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let desktop = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let uid = rustix::process::geteuid().as_raw();
    assert!(
        OwnerClient::on_bus(desktop.clone(), name, uid.wrapping_add(1))
            .await
            .is_err()
    );
    assert_eq!(original_calls.load(Ordering::SeqCst), 0);
    let client = OwnerClient::on_bus(desktop, name, uid).await.unwrap();
    assert!(client.accounts().await.unwrap().is_empty());
    original.release_name(name).await.unwrap();
    let replacement_calls = Arc::new(AtomicUsize::new(0));
    let replacement = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .name(name)
        .unwrap()
        .serve_at(
            OBJECT_PATH,
            Endpoint {
                calls: replacement_calls.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    client.accounts().await.unwrap();
    assert_eq!(original_calls.load(Ordering::SeqCst), 2);
    assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);
    original.close().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), client.accounts())
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);
    replacement.close().await.unwrap();
}
