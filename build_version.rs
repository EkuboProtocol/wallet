//! Shared exact source-build identity for the wallet and its stdio bridge.

use std::process::Command;

pub fn build_version(version: &str) -> String {
    let release_tag = format!("v{version}");
    if git(&["tag", "--points-at", "HEAD"])
        .is_some_and(|tags| tags.lines().any(|tag| tag == release_tag))
    {
        return version.to_owned();
    }
    let Some(commit) = git(&["rev-parse", "--short=7", "HEAD"]) else {
        return version.to_owned();
    };
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .is_some_and(|status| !status.is_empty());
    if dirty {
        format!("{version}+{commit}.dirty")
    } else {
        format!("{version}+{commit}")
    }
}

pub fn git(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}
