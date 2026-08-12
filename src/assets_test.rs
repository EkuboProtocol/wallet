use super::*;

#[test]
fn wallet_assets_include_editing_icons_and_component_icons() {
    let assets = WalletAssets::default();
    assert!(assets.load(PENCIL_ICON).unwrap().is_some());
    assert!(assets.load(TRASH_ICON).unwrap().is_some());
    assert!(assets.load("icons/inbox.svg").unwrap().is_some());
}

#[test]
fn package_icon_uses_the_approved_symbol_and_brand_palette() {
    let svg = include_str!("../assets/app-icon.svg");
    assert!(svg.contains("Exact normalized Ekubo symbol"));
    assert!(svg.contains("#9D5AF2"));
    assert!(svg.contains("#661CC4"));
    assert!(svg.contains("#261B34"));

    let png = image::load_from_memory(include_bytes!("../assets/app-icon-512.png"))
        .expect("checked app icon must be a valid PNG")
        .into_rgba8();
    assert_eq!(png.dimensions(), (512, 512));
    assert_eq!(png.get_pixel(0, 0).0[3], 0);

    let white_mark = png.get_pixel(256, 180).0;
    assert!(white_mark[0] > 245 && white_mark[1] > 245 && white_mark[2] > 245);
}
