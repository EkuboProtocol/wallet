use super::*;

#[test]
fn tray_icon_has_valid_dimensions() {
    assert!(wallet_icon(false).is_ok());
    assert!(wallet_icon(true).is_ok());
}

#[cfg(target_os = "macos")]
#[test]
fn macos_tray_artwork_is_inset_without_changing_its_canvas() {
    let source = image::load_from_memory_with_format(
        include_bytes!("../assets/tray/light_mode_tray_icon.png"),
        image::ImageFormat::Png,
    )
    .unwrap()
    .into_rgba8();
    let source_dimensions = source.dimensions();
    let inset = scaled_tray_artwork(source);

    assert_eq!(inset.dimensions(), source_dimensions);
    assert!(inset.get_pixel(0, 0).0[3] == 0);
    assert!(
        inset
            .get_pixel(source_dimensions.0 - 1, source_dimensions.1 - 1)
            .0[3]
            == 0
    );
}

#[cfg(target_os = "macos")]
#[test]
fn dark_menu_bar_uses_white_artwork_and_light_menu_bar_uses_dark_artwork() {
    fn mean_luminance(encoded: &[u8]) -> f32 {
        let image = image::load_from_memory_with_format(encoded, image::ImageFormat::Png)
            .unwrap()
            .into_rgba8();
        let (total, count) = image.pixels().filter(|pixel| pixel.0[3] > 0).fold(
            (0_u64, 0_u64),
            |(total, count), pixel| {
                let [red, green, blue, _] = pixel.0;
                (
                    total + u64::from(red) + u64::from(green) + u64::from(blue),
                    count + 3,
                )
            },
        );
        total as f32 / count as f32
    }

    assert!(mean_luminance(macos_tray_artwork(true)) > 220.0);
    assert!(mean_luminance(macos_tray_artwork(false)) < 40.0);
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
