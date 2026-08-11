use super::*;

#[test]
fn tray_icon_has_valid_dimensions() {
    assert!(wallet_icon(false).is_ok());
    assert!(wallet_icon(true).is_ok());
}

#[test]
fn native_menu_ids_map_to_the_expected_commands() {
    assert_eq!(command_for_id(OPEN_ID), Some(TrayCommand::OpenWallet));
    assert_eq!(
        command_for_id(REVIEWS_ID),
        Some(TrayCommand::OpenRoute(Route::Reviews))
    );
    assert_eq!(command_for_id(QUIT_ID), Some(TrayCommand::Quit));
    assert_eq!(command_for_id("unknown"), None);
}
