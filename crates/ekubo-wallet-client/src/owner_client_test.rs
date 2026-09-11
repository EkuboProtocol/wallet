struct Bus(std::process::Child);
impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn private_bus() -> (Bus, String) {
    use std::io::{BufRead as _, BufReader};
    use std::process::{Command, Stdio};

    let mut daemon = Bus(Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap());
    let mut address = String::new();
    BufReader::new(daemon.0.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    (daemon, address)
}

use super::*;
use crate::owner_protocol::Request;
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

struct CustodyEndpoint {
    expected: Vec<u8>,
    entered: tokio::sync::watch::Sender<usize>,
    ready: tokio::sync::watch::Receiver<bool>,
}

#[zbus::interface(name = "org.ekubo.Wallet.Custody1")]
impl CustodyEndpoint {
    async fn unlock(&self, ciphertext: &[u8]) -> zbus::fdo::Result<()> {
        assert_eq!(ciphertext, self.expected);
        self.entered.send_modify(|count| *count += 1);
        self.ready
            .clone()
            .wait_for(|ready| *ready)
            .await
            .map_err(|_| zbus::fdo::Error::Failed("startup failed".into()))?;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires dbus-daemon; launches an isolated test bus"]
async fn custody_relay_waits_for_readiness_and_stays_on_the_authenticated_service() {
    use ekubo_wallet_core::custody_envelope::{CustodyBinding, WrappingKey};
    use uuid::Uuid;

    let (_daemon, address) = private_bus();
    let name = "org.ekubo.Wallet.Owner.CustodyTest";
    let binding =
        CustodyBinding::new("owner", "service", Uuid::from_u128(1), Uuid::from_u128(2)).unwrap();
    let (_, wrapped) = WrappingKey::from_material(zeroize::Zeroizing::new([0x11; 32]))
        .enroll(binding)
        .unwrap();
    let (entered, mut received) = tokio::sync::watch::channel(0);
    let (ready, waiting) = tokio::sync::watch::channel(false);
    let original = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .name(name)
        .unwrap()
        .serve_at(
            crate::owner_protocol::CUSTODY_OBJECT_PATH,
            CustodyEndpoint {
                expected: wrapped.as_bytes().to_vec(),
                entered,
                ready: waiting,
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
        LinuxOwnerTransport::authenticate(desktop.clone(), name, uid.wrapping_add(1))
            .await
            .is_err()
    );
    assert_eq!(*received.borrow(), 0);
    let transport = LinuxOwnerTransport::authenticate(desktop, name, uid)
        .await
        .unwrap();
    assert_eq!(transport.process, std::process::id());
    original.release_name(name).await.unwrap();
    let (replaced, replacement_calls) = tokio::sync::watch::channel(0);
    let replacement = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .name(name)
        .unwrap()
        .serve_at(
            crate::owner_protocol::CUSTODY_OBJECT_PATH,
            CustodyEndpoint {
                expected: wrapped.as_bytes().to_vec(),
                entered: replaced,
                ready: ready.subscribe(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut relay = Box::pin(transport.unlock(&wrapped));
    tokio::select! {
        result = relay.as_mut() => panic!("reply preceded readiness: {result:?}"),
        result = received.wait_for(|count| *count == 1) => { result.unwrap(); },
        () = tokio::time::sleep(Duration::from_secs(5)) => panic!("relay never reached pinned service"),
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(10), relay.as_mut())
            .await
            .is_err()
    );
    ready.send_replace(true);
    relay.await.unwrap();
    assert_eq!(*replacement_calls.borrow(), 0);
    original.close().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), transport.unlock(&wrapped))
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(*replacement_calls.borrow(), 0);
    replacement.close().await.unwrap();
}

/// No real service, keys, or system-bus configuration are involved. The UID
/// mismatch and name replacement exercise actual private-bus peer lookups.
#[tokio::test]
#[ignore = "requires dbus-daemon; launches an isolated test bus"]
async fn client_checks_uid_pins_service_and_does_not_replay_after_disconnect() {
    let (_daemon, address) = private_bus();
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

struct SessionEndpoint {
    calls: Arc<AtomicUsize>,
    started: tokio::sync::watch::Sender<bool>,
}

#[zbus::interface(name = "org.ekubo.Wallet.Owner1")]
impl SessionEndpoint {
    fn call(&self, request: &str) -> String {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(matches!(
            serde_json::from_str::<Request>(request).unwrap(),
            Request::Accounts
        ));
        "[]".into()
    }
    async fn hold_desktop_session(&self) {
        self.started.send_replace(true);
        std::future::pending::<()>().await;
    }
}

#[tokio::test]
#[ignore = "requires dbus-daemon; launches an isolated test bus"]
async fn session_shutdown_closes_retained_owner_client_clones() {
    use crate::desktop_session::SessionState;
    let (_daemon, address) = private_bus();
    let name = "org.ekubo.Wallet.Owner.SessionTest";
    let (started, mut entered) = tokio::sync::watch::channel(false);
    let calls = Arc::new(AtomicUsize::new(0));
    let service = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .name(name)
        .unwrap()
        .serve_at(
            OBJECT_PATH,
            SessionEndpoint {
                started,
                calls: calls.clone(),
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
    let sender = desktop.unique_name().unwrap().clone();
    let client = OwnerClient::on_bus(desktop, name, rustix::process::geteuid().as_raw())
        .await
        .unwrap();
    assert!(client.accounts().await.unwrap().is_empty());
    let retained = client.clone();
    let session = client.start_desktop_session();
    let state = session.state();
    tokio::time::timeout(Duration::from_secs(5), entered.changed())
        .await
        .unwrap()
        .unwrap();
    session.close().await.unwrap();
    assert_eq!(*state.borrow(), SessionState::Closed);
    assert!(retained.accounts().await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let registry = DBusProxy::new(&service).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while registry
            .name_has_owner(sender.clone().into())
            .await
            .unwrap()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    service.close().await.unwrap();
}
