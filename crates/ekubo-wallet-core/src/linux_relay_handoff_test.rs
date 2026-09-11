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
