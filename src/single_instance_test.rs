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
    let (sender, receiver) = std::sync::mpsc::channel();
    let first = SingleInstance::acquire(directory.path(), sender.clone()).unwrap();
    assert!(matches!(first, InstanceOutcome::Primary(_)));
    let second = SingleInstance::acquire(directory.path(), sender).unwrap();
    assert!(matches!(second, InstanceOutcome::ActivatedExisting));
    receiver
        .recv_timeout(ACTIVATION_TIMEOUT)
        .expect("the primary instance must be told a second one tried to start");
    // Dropped explicitly, before the temporary directory goes: the primary owns
    // a listener thread and a lock file inside it, and tearing the directory
    // out from under them first is its own source of noise.
    drop(first);
    drop(second);
}
