use super::*;

#[test]
fn native_status_controls_exit_codes_and_progress_match_the_phase() {
    for phase in [
        Phase::Starting,
        Phase::Running,
        Phase::Stopping,
        Phase::Stopped,
    ] {
        let report = status(phase, false);
        assert_eq!(report.dwServiceType, SERVICE_WIN32_OWN_PROCESS);
        assert_eq!(report.dwWin32ExitCode, 0);
        assert_eq!(report.dwServiceSpecificExitCode, 0);
        if phase == Phase::Running {
            assert_eq!(
                report.dwControlsAccepted,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            );
        } else {
            assert_eq!(report.dwControlsAccepted, 0);
        }
        if matches!(phase, Phase::Starting | Phase::Stopping) {
            assert_eq!(report.dwCheckPoint, 1);
            assert_eq!(report.dwWaitHint, 30_000);
        } else {
            assert_eq!(report.dwCheckPoint, 0);
            assert_eq!(report.dwWaitHint, 0);
        }
    }
    let failed = status(Phase::Stopped, true);
    assert_eq!(failed.dwCurrentState, SERVICE_STOPPED);
    assert_eq!(failed.dwWin32ExitCode, ERROR_SERVICE_SPECIFIC_ERROR.0);
    assert_eq!(failed.dwServiceSpecificExitCode, 1);
}

#[test]
fn scm_name_must_match_the_complete_installed_service_name() {
    let mut name: Vec<u16> = "EkuboWallet-test".encode_utf16().chain(Some(0)).collect();
    for (expected, matches) in [
        ("EkuboWallet-test", true),
        ("EkuboWallet-tes", false),
        ("EkuboWallet-test-longer", false),
        ("OtherWallet-test", false),
    ] {
        let expected: Vec<u16> = expected.encode_utf16().chain(Some(0)).collect();
        // SAFETY: the test owns a terminated string for the entire comparison.
        assert_eq!(
            unsafe { name_matches(PWSTR(name.as_mut_ptr()), &expected) },
            matches
        );
    }
}

#[test]
fn a_console_process_cannot_enter_the_service_host() {
    fn never(_: &str, _: Running, _: watch::Receiver<bool>) -> Result<()> {
        panic!("console process entered the wallet service host");
    }
    let error = run("S-1-5-21-1-2-3-1001", never).unwrap_err();
    let native = error.downcast_ref::<windows::core::Error>().unwrap();
    assert_eq!(
        native.code(),
        windows::Win32::Foundation::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.to_hresult()
    );
}

#[test]
fn a_console_process_cannot_enter_the_pending_host() {
    const CHILD: &str = "EKUBO_TEST_PENDING_SCM_CONSOLE";
    fn never(_: &str, _: Running, _: watch::Receiver<bool>) -> Result<()> {
        panic!("console process entered pending provisioning");
    }
    if std::env::var_os(CHILD).is_none() {
        // SCM context is process-global. Isolate this case from the active-mode
        // console test, and ensure the child actually ran the selected test.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows_service_manager::native::tests::a_console_process_cannot_enter_the_pending_host", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    let error = run_pending("S-1-5-21-1-2-3-1001", never).unwrap_err();
    assert_eq!(
        error.downcast_ref::<windows::core::Error>().unwrap().code(),
        windows::Win32::Foundation::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.to_hresult()
    );
}
