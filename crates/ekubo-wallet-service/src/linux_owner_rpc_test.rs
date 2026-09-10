use super::*;

#[test]
fn zeroizing_owner_reply_keeps_the_existing_dbus_string_signature() {
    use zbus::zvariant::{LE, Type, serialized::Context, to_bytes};
    let text = "{\"accounts\":[]}";
    let response = OwnerResponse(zeroize::Zeroizing::new(text.into()));
    assert_eq!(OwnerResponse::SIGNATURE, String::SIGNATURE);
    let encoded = to_bytes(Context::new_dbus(LE, 0), &response).unwrap();
    let (decoded, _): (String, _) = encoded.deserialize().unwrap();
    assert_eq!(decoded, text);
}
