use super::*;

struct Directory(std::path::PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn read_only_profile_lock_excludes_other_handles_and_releases_on_drop() {
    let directory = Directory(
        std::env::temp_dir().join(format!("ekubo-profile-lock-{}", uuid::Uuid::new_v4())),
    );
    std::fs::create_dir(&directory.0).unwrap();
    let path = directory.0.join("service.lock");
    std::fs::write(&path, b"contents are not a lock claim").unwrap();
    let first = ProfileLock::acquire(File::open(&path).unwrap()).unwrap();
    assert!(ProfileLock::acquire(File::open(&path).unwrap()).is_err());
    probe_child(&path, "locked");
    drop(first);
    probe_child(&path, "available");
    let second = ProfileLock::acquire(File::open(&path).unwrap()).unwrap();
    assert!(ProfileLock::acquire(File::open(&path).unwrap()).is_err());
    drop(second);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"contents are not a lock claim"
    );
}

fn probe_child(path: &std::path::Path, expected: &str) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "service_profile_lock::tests::child_probe",
            "--ignored",
            "--nocapture",
        ])
        .env("EKUBO_TEST_SERVICE_LOCK_PATH", path)
        .env("EKUBO_TEST_SERVICE_LOCK_EXPECTED", expected)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "run by the parent process-lock test with its synthetic file"]
fn child_probe() {
    let path = std::env::var_os("EKUBO_TEST_SERVICE_LOCK_PATH").unwrap();
    let expected = std::env::var("EKUBO_TEST_SERVICE_LOCK_EXPECTED").unwrap();
    let result = ProfileLock::acquire(File::open(path).unwrap());
    match expected.as_str() {
        "locked" => assert!(result.is_err()),
        "available" => assert!(result.is_ok()),
        _ => panic!("invalid child probe expectation"),
    }
}
