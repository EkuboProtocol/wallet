//! Retain the entire no-follow machine path until the fixed collector launches.

use anyhow::Result;
use std::fs::File;

pub(crate) struct InstalledCollector {
    // Drive root, every intermediate directory, installation directory, image.
    // All handles exclude write/delete sharing and refer to checked disk objects.
    _handles: Vec<File>,
}

pub(crate) fn installed_collector() -> Result<InstalledCollector> {
    let path = ekubo_wallet_windows_owner_auth::installed_helper_path()?;
    Ok(InstalledCollector {
        _handles: crate::windows_service_storage::pin_machine_image(&path)?,
    })
}
