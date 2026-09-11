//! Shared Windows ACL representation; each object type supplies its own policy.

#[cfg(target_os = "windows")]
#[path = "windows_security_native.rs"]
mod native;
#[cfg(target_os = "windows")]
pub(crate) use native::read_descriptor;

pub(crate) enum AccessEntry {
    Allow {
        sid: String,
        mask: u32,
        inherit_only: bool,
        object_inherit: bool,
    },
    Deny,
    Unsupported,
}
