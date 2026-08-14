//! Stamps development builds.

use std::{env, path::PathBuf, process::Command};

fn main() {
    embed_windows_resources();
    embed_bridge_digest();
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

fn embed_bridge_digest() {
    println!("cargo:rerun-if-env-changed=EKUBO_MCP_BRIDGE_SHA256");
    let digest = env::var("EKUBO_MCP_BRIDGE_SHA256").unwrap_or_default();
    let release = env::var("PROFILE").as_deref() == Ok("release");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    assert!(
        !(release && target_os != "macos" && digest.is_empty()),
        "release builds require EKUBO_MCP_BRIDGE_SHA256"
    );
    assert!(
        digest.is_empty()
            || (digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))),
        "EKUBO_MCP_BRIDGE_SHA256 must be 64 lowercase hexadecimal characters"
    );
    println!("cargo:rustc-env=EKUBO_COMPILED_MCP_BRIDGE_SHA256={digest}");
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
        format!(r#"VERSION_STRING="{}""#, env!("CARGO_PKG_VERSION")),
    ];
    embed_resource::compile_for("assets/windows/app.rc", ["ekubo-wallet"], &macros)
        .manifest_required()
        .expect("failed to embed the Windows application identity");
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
