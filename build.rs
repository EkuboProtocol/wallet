//! Stamps development builds.

use std::{env, path::PathBuf, process::Command};

fn main() {
    embed_windows_resources();
    embed_updater_public_key();
    let version = env::var("CARGO_PKG_VERSION").expect("cargo sets the package version");
    println!(
        "cargo:rustc-env=EKUBO_WALLET_BUILD_VERSION={}",
        build_version(&version)
    );
    println!("cargo:rerun-if-changed=build.rs");
    for path in ["HEAD", "index"] {
        if let Some(resolved) = git(&["rev-parse", "--git-path", path])
            && PathBuf::from(&resolved).exists()
        {
            println!("cargo:rerun-if-changed={resolved}");
        }
    }
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=crates");
}

fn embed_windows_resources() {
    println!("cargo:rerun-if-changed=assets/windows/app-icon.ico");
    println!("cargo:rerun-if-changed=assets/windows/app.rc");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let macros = [
        format!("VERSION_MAJOR={}", env!("CARGO_PKG_VERSION_MAJOR")),
        format!("VERSION_MINOR={}", env!("CARGO_PKG_VERSION_MINOR")),
        format!("VERSION_PATCH={}", env!("CARGO_PKG_VERSION_PATCH")),
        format!(r#"VERSION_STRING=\"{}\""#, env!("CARGO_PKG_VERSION")),
    ];
    embed_resource::compile_for("assets/windows/app.rc", ["ekubo-wallet"], &macros)
        .manifest_required()
        .expect("failed to embed the Windows application identity");
}

fn embed_updater_public_key() {
    println!("cargo:rerun-if-env-changed=EKUBO_UPDATER_PUBLIC_KEY");
    let key = env::var("EKUBO_UPDATER_PUBLIC_KEY").unwrap_or_default();
    assert!(
        !(env::var("PROFILE").is_ok_and(|profile| profile == "release") && key.trim().is_empty()),
        "release builds require EKUBO_UPDATER_PUBLIC_KEY"
    );
    if !key.is_empty()
        && (!key.len().is_multiple_of(4)
            || key
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))))
    {
        panic!("EKUBO_UPDATER_PUBLIC_KEY must be canonical single-line base64");
    }
    println!("cargo:rustc-env=EKUBO_COMPILED_UPDATER_PUBLIC_KEY={key}");
}

fn build_version(version: &str) -> String {
    if git(&["describe", "--exact-match", "--tags", "HEAD"]).is_some() {
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

fn git(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}
