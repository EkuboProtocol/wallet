//! Stamp the bridge with the same exact source build identity as the wallet.

use std::{env, path::PathBuf};

#[path = "../../build_version.rs"]
mod build_version;

fn main() {
    let version = env::var("CARGO_PKG_VERSION").expect("cargo sets the package version");
    println!(
        "cargo:rustc-env=EKUBO_WALLET_BUILD_VERSION={}",
        build_version::build_version(&version)
    );
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../build_version.rs");
    for path in ["HEAD", "index"] {
        if let Some(resolved) = build_version::git(&["rev-parse", "--git-path", path])
            && PathBuf::from(&resolved).exists()
        {
            println!("cargo:rerun-if-changed={resolved}");
        }
    }
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=../../src");
    println!("cargo:rerun-if-changed=../../crates");
}
