//! Stamps development builds.

use std::{env, path::PathBuf, process::Command};

fn main() {
    embed_updater_public_key();
    let version = env::var("CARGO_PKG_VERSION").expect("cargo sets the package version");
    println!(
        "cargo:rustc-env=EKUBO_WALLET_BUILD_VERSION={}",
        build_version(&version)
    );
    println!(
        "cargo:rustc-env=EKUBO_WALLET_BUILD_COMMIT={}",
        exact_build_commit().unwrap_or_default()
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

fn embed_updater_public_key() {
    println!("cargo:rerun-if-env-changed=EKUBO_UPDATER_PUBLIC_KEY");
    let key = env::var("EKUBO_UPDATER_PUBLIC_KEY").unwrap_or_default();
    if env::var("PROFILE").is_ok_and(|profile| profile == "release") && key.trim().is_empty() {
        panic!("release builds require EKUBO_UPDATER_PUBLIC_KEY");
    }
    if !key.is_empty()
        && (key.len() % 4 != 0
            || key
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))))
    {
        panic!("EKUBO_UPDATER_PUBLIC_KEY must be canonical single-line base64");
    }
    println!("cargo:rustc-env=EKUBO_COMPILED_UPDATER_PUBLIC_KEY={key}");
}

fn exact_build_commit() -> Option<String> {
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .is_some_and(|status| !status.is_empty());
    (!dirty).then(|| git(&["rev-parse", "HEAD"])).flatten()
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
