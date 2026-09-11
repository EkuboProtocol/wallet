use super::*;

#[test]
fn peer_validation_uses_kernel_identity_and_rejects_other_object_types() {
    let (stream, _peer) = UnixStream::pair().unwrap();
    let fd: OwnedFd = stream.into();
    let uid = rustix::process::geteuid().as_raw();
    let pid = std::process::id();
    validate_peer(&fd, uid, pid).unwrap();
    assert!(validate_peer(&fd, uid.wrapping_add(1), pid).is_err());
    assert!(validate_peer(&fd, uid, pid.wrapping_add(1)).is_err());
    let (datagram, _) = std::os::unix::net::UnixDatagram::pair().unwrap();
    assert!(validate_peer(&datagram.into(), uid, pid).is_err());
    assert!(validate_peer(&tempfile::tempfile().unwrap().into(), uid, pid).is_err());
    if uid != 0 {
        assert!(InstallerStream::new(fd, pid, Duration::from_secs(1)).is_err());
    }
}

#[test]
fn cancellation_wakes_a_blocking_read_without_waiting_for_deadline() {
    let (stream, _peer) = UnixStream::pair().unwrap();
    let (mut stream, cancel) =
        InstallerStream::with_deadline(stream, Duration::from_secs(60)).unwrap();
    let (started, ready) = std::sync::mpsc::channel();
    let (finished, completion) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        started.send(()).unwrap();
        finished.send(stream.read_exact(&mut [0; 1])).unwrap();
    });
    ready.recv().unwrap();
    drop(cancel);
    assert!(
        completion
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_err()
    );
    worker.join().unwrap();
}

#[test]
fn deadline_is_absolute_and_stalled_native_reads_time_out() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let (mut stream, _cancel) =
        InstallerStream::with_deadline(stream, Duration::from_secs(1)).unwrap();
    peer.write_all(b"a").unwrap();
    stream.read_exact(&mut [0; 1]).unwrap();
    stream.deadline = Instant::now();
    assert_eq!(
        stream.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        stream.write(b"b").unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(stream.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);

    let (stream, _peer) = UnixStream::pair().unwrap();
    let (mut stream, _cancel) =
        InstallerStream::with_deadline(stream, Duration::from_millis(20)).unwrap();
    let error = stream.read(&mut [0; 1]).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ));
}
