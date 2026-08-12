use super::*;

#[test]
fn tray_icon_has_valid_dimensions() {
    assert!(wallet_icon(false).is_ok());
    assert!(wallet_icon(true).is_ok());
}

#[test]
fn application_badge_is_hidden_at_zero_and_exact_above_zero() {
    assert_eq!(application_badge_label(0), None);
    assert_eq!(application_badge_label(1).as_deref(), Some("1"));
    assert_eq!(application_badge_label(137).as_deref(), Some("137"));
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
    let inset = scaled_tray_artwork(&source);

    assert_eq!(inset.dimensions(), source_dimensions);
    assert_eq!(inset.get_pixel(0, 0).0[3], 0);
    assert_eq!(
        inset
            .get_pixel(source_dimensions.0 - 1, source_dimensions.1 - 1)
            .0[3],
        0
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_uses_one_high_contrast_template_source_for_every_appearance() {
    #[allow(clippy::cast_precision_loss)]
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

    assert!(mean_luminance(macos_tray_artwork()) > 220.0);
    assert!(wallet_icon(false).is_ok());
    assert!(wallet_icon(true).is_ok());
}

#[test]
fn native_menu_ids_map_to_the_expected_commands() {
    assert_eq!(command_for_id(OPEN_ID), Some(TrayCommand::OpenWallet));
    assert_eq!(
        command_for_id(REVIEWS_ID),
        Some(TrayCommand::OpenRoute(Route::Activity))
    );
    assert_eq!(command_for_id(QUIT_ID), Some(TrayCommand::Quit));
    assert_eq!(command_for_id("unknown"), None);
}
