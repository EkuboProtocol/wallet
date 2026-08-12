use gpui::{AssetSource, SharedString};
use std::borrow::Cow;

pub const PENCIL_ICON: &str = "icons/wallet-pencil.svg";
pub const TRASH_ICON: &str = "icons/wallet-trash.svg";

/// Application assets layered over gpui-component's bundled icon set.
pub struct WalletAssets(gpui_component_assets::Assets);

impl Default for WalletAssets {
    fn default() -> Self {
        Self(gpui_component_assets::Assets)
    }
}

impl AssetSource for WalletAssets {
    fn load(&self, path: &str) -> gpui::Result<Option<Cow<'static, [u8]>>> {
        match path {
            PENCIL_ICON => Ok(Some(Cow::Borrowed(include_bytes!(
                "../assets/icons/wallet-pencil.svg"
            )))),
            TRASH_ICON => Ok(Some(Cow::Borrowed(include_bytes!(
                "../assets/icons/wallet-trash.svg"
            )))),
            _ => self.0.load(path),
        }
    }

    fn list(&self, path: &str) -> gpui::Result<Vec<SharedString>> {
        let mut assets = self.0.list(path)?;
        assets.extend(
            [PENCIL_ICON, TRASH_ICON]
                .into_iter()
                .filter(|asset| asset.starts_with(path))
                .map(SharedString::from),
        );
        Ok(assets)
    }
}

#[cfg(test)]
#[path = "assets_test.rs"]
mod tests;
