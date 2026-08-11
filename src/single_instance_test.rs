use super::*;

#[test]
fn a_second_instance_activates_the_first() {
    let directory = tempfile::tempdir().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let first = SingleInstance::acquire(directory.path(), sender.clone()).unwrap();
    assert!(matches!(first, InstanceOutcome::Primary(_)));
    let second = SingleInstance::acquire(directory.path(), sender).unwrap();
    assert!(matches!(second, InstanceOutcome::ActivatedExisting));
    receiver.recv_timeout(Duration::from_secs(2)).unwrap();
}
