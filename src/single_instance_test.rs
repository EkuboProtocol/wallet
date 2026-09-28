use super::*;

/// How long to wait for the activation to arrive before calling it lost.
///
/// The primary's listener polls a non-blocking socket on a 75 ms cycle, so the
/// notification is normally along in well under a tenth of a second. This bound
/// is not a latency assertion — it is how long a genuine failure takes to be
/// reported, and buying that report cheaply is worth nothing next to a suite
/// that fails on a busy machine.
///
/// It was two seconds, and it went red in full-suite runs while passing every
/// time it was run alone. Two hundred and seventy-odd tests, several of them
/// standing up GPUI windows and parking real threads, is exactly the load under
/// which a freshly spawned thread does not get scheduled promptly. That is the
/// machine being busy, not the wallet being broken, and a test that cannot tell
/// the difference teaches people to re-run it.
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(30);

#[test]
fn a_second_instance_activates_the_first() {
    let directory = tempfile::tempdir().unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let first = SingleInstance::acquire(directory.path(), sender.clone()).unwrap();
    assert!(matches!(first, InstanceOutcome::Primary(_)));
    let second = SingleInstance::acquire(directory.path(), sender).unwrap();
    assert!(matches!(second, InstanceOutcome::ActivatedExisting));
    wait_for_activation(&mut receiver);
    // Dropped explicitly, before the temporary directory goes: the primary owns
    // a listener thread and a lock file inside it, and tearing the directory
    // out from under them first is its own source of noise.
    drop(first);
    drop(second);
}

/// The channel is a cancellable future, so the bounded wait is a `timeout` on
/// a runtime the test owns rather than `recv_timeout`.
fn wait_for_activation(receiver: &mut tokio::sync::mpsc::UnboundedReceiver<()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a Tokio runtime")
        .block_on(async {
            tokio::time::timeout(ACTIVATION_TIMEOUT, receiver.recv())
                .await
                .expect("the primary instance must be told a second one tried to start")
        })
        .expect("the activation channel must stay open while the primary holds the lock");
}

/// The primary accepts and hangs up without reading. A launch that meets that
/// hang-up has still activated it and must not report a failure.
///
/// This listener accepts as fast as it can, rather than on the real 75 ms
/// poll, to put the hang-up right against the connect as often as possible.
/// With the old `activate` write after connecting, that is the `EPIPE` macOS
/// CI hit on the update handoff.
#[test]
fn activation_survives_a_primary_that_hangs_up_at_once() {
    use std::os::unix::net::UnixListener;

    const LAUNCHES: usize = 500;
    let directory = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(directory.path().join("activate.sock")).unwrap();
    let primary = std::thread::spawn(move || {
        for _ in 0..LAUNCHES {
            drop(listener.accept().expect("the launch connects"));
        }
    });
    for launch in 0..LAUNCHES {
        activate_existing(directory.path())
            .unwrap_or_else(|error| panic!("launch {launch} failed to activate: {error:#}"));
    }
    primary.join().unwrap();
}

/// The update handoff and every repeated launch go through this path, so it
/// must deliver an activation every time, not just the first.
#[test]
fn every_repeated_launch_activates_the_primary() {
    let directory = tempfile::tempdir().unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let first = SingleInstance::acquire(directory.path(), sender.clone()).unwrap();
    assert!(matches!(first, InstanceOutcome::Primary(_)));
    for _ in 0..25 {
        let second = SingleInstance::acquire(directory.path(), sender.clone()).unwrap();
        assert!(matches!(second, InstanceOutcome::ActivatedExisting));
        wait_for_activation(&mut receiver);
    }
    drop(first);
}
