//! Stamps development builds.

use std::{env, path::PathBuf};

mod build_version;

fn main() {
    embed_windows_resources();
    let version = env::var("CARGO_PKG_VERSION").expect("cargo sets the package version");
    println!(
        "cargo:rustc-env=EKUBO_WALLET_BUILD_VERSION={}",
        build_version::build_version(&version)
    );
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_version.rs");
    for path in ["HEAD", "index"] {
        if let Some(resolved) = build_version::git(&["rev-parse", "--git-path", path])
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
        format!(r#"VERSION_STRING="{}""#, env!("CARGO_PKG_VERSION")),
    ];
    embed_resource::compile_for("assets/windows/app.rc", ["ekubo-wallet"], &macros)
        .manifest_required()
        .expect("failed to embed the Windows application identity");
}
