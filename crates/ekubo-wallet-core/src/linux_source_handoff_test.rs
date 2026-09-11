use super::*;

#[tokio::test]
#[ignore = "requires dbus-daemon and an ordinary UID; isolated admission test"]
async fn ordinary_process_cannot_start_collection_even_with_its_own_connected_socket() {
    use std::io::{BufRead as _, BufReader, Read as _};
    use std::process::{Command, Stdio};
    struct Bus(std::process::Child);
    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    assert_ne!(rustix::process::geteuid().as_raw(), 0);
    let mut daemon = Bus(Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap());
    let mut address = String::new();
    BufReader::new(daemon.0.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    let slots = Arc::new(Semaphore::new(1));
    let owner = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .serve_at(
            PATH,
            SourceInterface {
                slots: slots.clone(),
            },
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let client = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let (socket, mut observer) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd: std::os::fd::OwnedFd = socket.into();
    let fd = zbus::zvariant::OwnedFd::from(fd);
    let error = client
        .call_method(
            Some(owner.unique_name().unwrap().as_str()),
            PATH,
            Some(INTERFACE),
            "Start",
            &(fd,),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, zbus::Error::MethodError(name, _, _)
        if name.as_str() == "org.freedesktop.DBus.Error.AccessDenied"));
    assert_eq!(slots.available_permits(), 1);
    observer
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    // The rejected FD is closed without a worker or a single source byte.
    assert_eq!(observer.read(&mut [0; 1]).unwrap(), 0);
}
