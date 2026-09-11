use super::*;

#[test]
fn malformed_delivery_never_reaches_credential_storage() {
    let profile = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();
    for (profile, nonce, bytes) in [
        (profile.clone(), nonce.clone(), vec![0; 32]),
        (Uuid::nil().to_string(), nonce.clone(), vec![0; 256]),
        (profile.clone(), Uuid::nil().to_string(), vec![0; 256]),
        ("x".repeat(4097), nonce, vec![]),
    ] {
        assert!(parse_delivery(&profile, &nonce, &bytes).is_err());
    }
}

struct PolicyEndpoint(&'static str);

#[zbus::interface(name = "org.ekubo.Wallet.InstallerRelay1")]
impl PolicyEndpoint {
    fn persist(&self) -> &'static str {
        self.0
    }
}

#[tokio::test]
#[ignore = "requires dbus-daemon; tests production rules on an isolated bus"]
async fn installer_policy_admits_only_the_exact_relay_method() {
    use std::io::{BufRead as _, BufReader};
    use std::process::{Command, Stdio};
    struct Bus(std::process::Child);
    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let temporary = tempfile::tempdir().unwrap();
    let uid = rustix::process::geteuid().as_raw().to_string();
    // Map only policy principals to this test's UID. No system bus, root
    // process, service installation or real credential store is involved.
    let production = include_str!("../../../contrib/linux-service/org.ekubo.Wallet.Provision.conf")
        .replace("user=\"root\"", &format!("user=\"{uid}\""))
        .replace("user=\"ekubo-wallet\"", &format!("user=\"{uid}\""));
    let rules = production
        .split_once("<busconfig>")
        .unwrap()
        .1
        .split_once("</busconfig>")
        .unwrap()
        .0;
    let config = temporary.path().join("bus.conf");
    std::fs::write(
        &config,
        format!(
            r#"<busconfig>
      <type>session</type><listen>unix:tmpdir=/tmp</listen><auth>EXTERNAL</auth>
      <policy context="default">
        <allow user="*"/><allow own="*"/><allow receive_sender="*"/>
        <deny send_type="method_call"/>
        <allow send_destination="org.freedesktop.DBus"/>
        <allow send_type="method_return"/><allow send_type="error"/>
      </policy>{rules}</busconfig>"#
        ),
    )
    .unwrap();
    let mut daemon = Bus(Command::new("dbus-daemon")
        .arg("--config-file")
        .arg(config)
        .args(["--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap());
    let mut address = String::new();
    BufReader::new(daemon.0.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    let server = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .serve_at(PATH, PolicyEndpoint("policy admitted the call"))
        .unwrap()
        .build()
        .await
        .unwrap();
    let client = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let destination = server.unique_name().unwrap().as_str();
    let reply = client
        .call_method(Some(destination), PATH, Some(INTERFACE), "Persist", &())
        .await
        .unwrap();
    assert_eq!(
        reply.body().deserialize::<String>().unwrap(),
        "policy admitted the call"
    );
    for (path, interface, member) in [
        ("/org/ekubo/Wallet/Other", INTERFACE, "Persist"),
        (PATH, INTERFACE, "Other"),
        (PATH, "org.ekubo.Wallet.Other", "Persist"),
    ] {
        let error = client
            .call_method(Some(destination), path, Some(interface), member, &())
            .await
            .unwrap_err();
        assert!(matches!(error, zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied"));
    }
}
