//! Stamps development builds and creates the deterministic package icon.

use image::{Rgba, RgbaImage};
use std::{env, fs, path::PathBuf, process::Command};

fn main() {
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
    create_package_icon();
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

fn create_package_icon() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let output = root.join("target/packager-assets/icon-512.png");
    fs::create_dir_all(output.parent().expect("icon output parent"))
        .expect("create packager asset directory");

    let mut icon = RgbaImage::new(512, 512);
    for y in 0_u32..512 {
        for x in 0_u32..512 {
            let dx = if x < 144 {
                144 - x
            } else {
                x.saturating_sub(367)
            };
            let dy = if y < 144 {
                144 - y
            } else {
                y.saturating_sub(367)
            };
            let corner_distance_squared = dx * dx + dy * dy;
            let alpha = if corner_distance_squared <= 94 * 94 {
                255
            } else if corner_distance_squared < 97 * 97 {
                u8::try_from(((97 * 97 - corner_distance_squared) * 255) / (97 * 97 - 94 * 94))
                    .expect("corner alpha is bounded to one byte")
            } else {
                0
            };
            let blend = u16::try_from(y).expect("icon coordinate fits in u16");
            let red = 11 + u8::try_from(blend * 6 / 511).expect("red gradient fits in u8");
            let green = 20 + u8::try_from(blend * 14 / 511).expect("green gradient fits in u8");
            let blue = 38 + u8::try_from(blend * 20 / 511).expect("blue gradient fits in u8");
            icon.put_pixel(x, y, Rgba([red, green, blue, alpha]));
        }
    }

    // A compact wallet-shaped E that remains crisp when platform bundles
    // derive their smaller icon sizes.
    fill(&mut icon, 142, 132, 86, 248, [64, 226, 196, 255]);
    fill(&mut icon, 206, 132, 178, 62, [64, 226, 196, 255]);
    fill(&mut icon, 206, 225, 138, 62, [64, 226, 196, 255]);
    fill(&mut icon, 206, 318, 178, 62, [64, 226, 196, 255]);
    icon.save(output).expect("write package icon");
}

fn fill(image: &mut RgbaImage, left: u32, top: u32, width: u32, height: u32, color: [u8; 4]) {
    for y in top..top + height {
        for x in left..left + width {
            image.put_pixel(x, y, Rgba(color));
        }
    }
}
