use super::*;
use std::{
    fs,
    io::{BufRead as _, BufReader},
    process::{Command, Stdio},
};

fn activation_bus(
    name: &str,
    service: impl FnOnce(&str) -> String,
) -> (Bus, tempfile::TempDir, String) {
    // A fixed parent keeps both the D-Bus address and fixture XML free of
    // caller-controlled quoting. Nothing is installed on the real system bus.
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let root = directory.path().to_str().unwrap();
    let address = format!("unix:path={root}/bus");
    fs::write(
        directory.path().join(format!("{name}.service")),
        service(&address),
    )
    .unwrap();
    fs::write(directory.path().join("bus.conf"), format!(
        "<busconfig><type>session</type><listen>{address}</listen><servicedir>{root}</servicedir>\
         <policy context=\"default\"><allow own=\"*\"/><allow send_destination=\"*\"/>\
         <allow receive_sender=\"*\"/></policy></busconfig>"
    )).unwrap();
    let mut daemon = Bus(Command::new("dbus-daemon")
        .arg(format!("--config-file={root}/bus.conf"))
        .args(["--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap());
    let mut published = String::new();
    BufReader::new(daemon.0.stdout.take().unwrap())
        .read_line(&mut published)
        .unwrap();
    assert!(!published.trim().is_empty());
    (daemon, directory, published)
}

#[tokio::test]
#[ignore = "requires dbus-daemon and dbus-test-tool; launches an isolated activation fixture"]
async fn activation_starts_then_authenticates_the_actual_bus_owner() {
    let name = "org.ekubo.Wallet.Owner.ActivationTest";
    let (_daemon, _directory, address) = activation_bus(name, |address| {
        format!(
            "[D-BUS Service]\nName={name}\nExec=/usr/bin/env DBUS_SESSION_BUS_ADDRESS={address} /usr/bin/dbus-test-tool echo --name={name}\n"
        )
    });
    let bus = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let registry = DBusProxy::new(&bus).await.unwrap();
    assert!(
        !registry
            .name_has_owner(name.try_into().unwrap())
            .await
            .unwrap()
    );
    let uid = rustix::process::geteuid().as_raw();
    let transport = tokio::time::timeout(
        Duration::from_secs(5),
        LinuxOwnerTransport::activate(bus.clone(), name, uid),
    )
    .await
    .unwrap()
    .unwrap();
    assert_ne!(transport.process, std::process::id());
    assert_ne!(transport.process, 0);
    transport.proxy.call_method("Ping", &()).await.unwrap();
    let second = LinuxOwnerTransport::activate(bus.clone(), name, uid)
        .await
        .unwrap();
    assert_eq!(second.service, transport.service);
    assert!(
        LinuxOwnerTransport::activate(bus, name, uid.wrapping_add(1))
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires dbus-daemon; launches an isolated activation fixture"]
async fn activation_errors_are_not_treated_as_an_authenticated_connection() {
    let name = "org.ekubo.Wallet.Owner.u1001";
    // Exercise the actual registration asset: with systemd activation disabled,
    // its fallback must fail instead of launching custody outside the unit.
    let (_daemon, _directory, address) = activation_bus(name, |_| {
        include_str!("../../../contrib/linux-service/org.ekubo.Wallet.Owner.service.in")
            .replace("@OWNER_UID@", "1001")
    });
    let bus = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let uid = rustix::process::geteuid().as_raw();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(5),
            LinuxOwnerTransport::activate(bus.clone(), name, uid)
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(
        LinuxOwnerTransport::activate(bus.clone(), "org.ekubo.Wallet.Owner.NotInstalled", uid)
            .await
            .is_err()
    );
    assert!(
        !DBusProxy::new(&bus)
            .await
            .unwrap()
            .name_has_owner(name.try_into().unwrap())
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires dbus-daemon; launches an isolated test bus"]
async fn running_endpoint_needs_no_activation_file_and_still_requires_matching_uid() {
    let (_daemon, address) = private_bus();
    let name = "org.ekubo.Wallet.Owner.RunningActivationTest";
    let calls = Arc::new(AtomicUsize::new(0));
    let original = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .name(name)
        .unwrap()
        .serve_at(
            OBJECT_PATH,
            Endpoint {
                calls: calls.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let bus = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let uid = rustix::process::geteuid().as_raw();
    assert!(
        LinuxOwnerTransport::activate(bus.clone(), name, uid.wrapping_add(1))
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let client = OwnerConnection::from_transport(
        LinuxOwnerTransport::activate(bus, name, uid).await.unwrap(),
    );
    assert!(client.accounts().await.unwrap().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    original.close().await.unwrap();
}
