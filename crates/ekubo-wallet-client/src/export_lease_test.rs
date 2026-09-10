use super::*;

#[test]
fn export_lease_counts_down_to_zero_and_stays_there() {
    let lease = ExportLease::new_for_duration(
        zeroize::Zeroizing::new("secret".to_owned()),
        Duration::from_millis(200),
    );
    let remaining = lease.remaining();
    assert!(remaining > Duration::ZERO && remaining <= Duration::from_millis(200));
    let deadline = Instant::now() + Duration::from_secs(2);
    while !lease.concealed() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    // A concealed lease reports no time left rather than a duration the
    // countdown would render as a key that is still on screen.
    assert!(lease.concealed());
    assert_eq!(lease.remaining(), Duration::ZERO);
}

#[test]
fn wire_round_trip_keeps_the_remaining_reveal_interval() {
    let scalar = format!("{:064x}", 1);
    let lease = ExportLease::new_for_duration(
        zeroize::Zeroizing::new(scalar.clone()),
        Duration::from_secs(1),
    );
    let wire = zeroize::Zeroizing::new(serde_json::to_string(&lease).unwrap());
    let received: ExportLease = serde_json::from_str(&wire).unwrap();
    assert_eq!(received.visible_value().unwrap().as_str(), scalar);
    assert!(received.remaining() > Duration::ZERO);
    assert!(received.remaining() <= Duration::from_secs(1));
}

#[test]
fn expired_exports_serialize_no_key_and_cannot_be_revealed_again() {
    let scalar = format!("{:064x}", 1);
    let lease =
        ExportLease::new_for_duration(zeroize::Zeroizing::new(scalar.clone()), Duration::ZERO);
    let wire = serde_json::to_string(&lease).unwrap();
    assert!(!wire.contains(&scalar));
    assert!(lease.value.lock().unwrap().is_empty());
    let received: ExportLease = serde_json::from_str(&wire).unwrap();
    assert!(received.visible_value().is_none());
    assert_eq!(received.remaining(), Duration::ZERO);
    assert!(received.concealed());
}

#[test]
fn invalid_export_replies_cannot_extend_or_forge_the_reveal_window() {
    let scalar = format!("{:064x}", 1);
    for value in [
        serde_json::json!({"value": scalar, "remaining_ms": 30_001}),
        serde_json::json!({"value": scalar, "remaining_ms": 0}),
        serde_json::json!({"value": "", "remaining_ms": 30_000}),
        serde_json::json!({"value": scalar, "remaining_ms": 30_000, "authorization": true}),
        serde_json::json!({"value": "not a valid secret", "remaining_ms": 30_000}),
    ] {
        assert!(serde_json::from_value::<ExportLease>(value).is_err());
    }
}
