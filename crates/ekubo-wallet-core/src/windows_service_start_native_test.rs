use super::*;

#[test]
fn nonexistent_profile_service_is_not_created_or_started() {
    let name = format!("EkuboWallet-{}", uuid::Uuid::new_v4().simple());
    let error = Service::open(&name)
        .err()
        .expect("random service must not exist");
    let error = error.downcast_ref::<windows::core::Error>().unwrap();
    assert_eq!(
        error.code(),
        HRESULT::from_win32(windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST.0)
    );
}

#[test]
fn cancellation_guard_signals_worker_on_drop() {
    let flag = Arc::new(AtomicBool::new(false));
    let guard = Cancel(flag.clone());
    assert!(!flag.load(Ordering::Acquire));
    drop(guard);
    assert!(flag.load(Ordering::Acquire));
}
