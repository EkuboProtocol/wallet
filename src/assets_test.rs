use super::*;

#[test]
fn wallet_assets_include_editing_icons_and_component_icons() {
    let assets = WalletAssets::default();
    assert!(assets.load(PENCIL_ICON).unwrap().is_some());
    assert!(assets.load(TRASH_ICON).unwrap().is_some());
    assert!(assets.load("icons/inbox.svg").unwrap().is_some());
}
