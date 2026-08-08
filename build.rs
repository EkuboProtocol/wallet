//! Stamps the build with the commit it came from.
//!
//! A released binary is built from a `v<version>` tag, and its version alone
//! identifies it exactly. Every other build — a local `cargo install --path .`,
//! a CI run on a branch, a bisect — shares that same version string with every
//! other build of the same crate version, which is useless precisely when it
//! matters: someone reporting that a fix did not work, when what they are
//! running may predate it.
//!
//! So an untagged build carries the commit as `SemVer` build metadata:
//! `1.0.0-rc.0+8133a00`, and `+8133a00.dirty` when the tree had uncommitted
//! changes. A tagged build carries nothing extra, because there is nothing to
//! add.
//!
//! Nothing here may fail the build. A source tarball, a `cargo install` from
//! crates.io, or a checkout with no `git` on the PATH all produce the bare
//! version, which is the honest answer when there is no commit to name.

use std::{path::PathBuf, process::Command};

fn main() {
    let version = std::env::var("CARGO_PKG_VERSION").expect("cargo sets the package version");
    println!(
        "cargo:rustc-env=EKUBO_WALLET_BUILD_VERSION={}",
        build_version(&version)
    );

    println!("cargo:rerun-if-changed=build.rs");
    // Moving HEAD, committing, or checking out has to restamp the binary.
    // `--git-path` rather than a literal `.git/HEAD` because this repository is
    // often built from a worktree, where `.git` is a file and the real HEAD
    // lives elsewhere.
    for path in ["HEAD", "index"] {
        if let Some(resolved) = git(&["rev-parse", "--git-path", path])
            && PathBuf::from(&resolved).exists()
        {
            println!("cargo:rerun-if-changed={resolved}");
        }
    }
    // And so does editing a tracked file, or the `dirty` marker goes stale and
    // starts lying in the more dangerous direction — claiming a clean build.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=crates");
}

fn build_version(version: &str) -> String {
    // An exact tag means this commit *is* the release, so the version already
    // says everything the hash would.
    if git(&["describe", "--exact-match", "--tags", "HEAD"]).is_some() {
        return version.to_owned();
    }
    let Some(commit) = git(&["rev-parse", "--short=7", "HEAD"]) else {
        return version.to_owned();
    };
    // Untracked files are excluded: a stray editor swap file or a scratch
    // script says nothing about what was compiled, and marking every such
    // build dirty would make the marker mean nothing.
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .is_some_and(|status| !status.is_empty());
    if dirty {
        format!("{version}+{commit}.dirty")
    } else {
        format!("{version}+{commit}")
    }
}

/// One `git` invocation, or `None` for anything that is not a clean success —
/// no repository, no `git`, a detached or empty history.
fn git(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(arguments).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}
