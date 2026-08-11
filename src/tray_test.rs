use super::*;

#[test]
fn tray_icon_has_valid_dimensions() {
    assert!(wallet_icon(false).is_ok());
    assert!(wallet_icon(true).is_ok());
}
