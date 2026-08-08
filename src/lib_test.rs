//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::{BUILD_VERSION, VERSION};

/// Whatever the build stamped, it has to *start* with the crate version.
///
/// Everything that reads a version out of this binary — `--version`, the
/// status JSON, the MCP `serverInfo` — reads [`BUILD_VERSION`], so the
/// released string and the local one differ only in what comes after the
/// version, never in the version itself.
#[test]
fn the_build_version_extends_the_crate_version_rather_than_replacing_it() {
    assert!(
        BUILD_VERSION.starts_with(VERSION),
        "{BUILD_VERSION} does not start with {VERSION}"
    );
    let extra = &BUILD_VERSION[VERSION.len()..];
    // SemVer build metadata, so the whole string stays a version a tool can
    // parse rather than a sentence about a version.
    assert!(
        extra.is_empty() || extra.starts_with('+'),
        "build metadata `{extra}` is not SemVer build metadata"
    );
    assert!(
        !extra.contains(char::is_whitespace),
        "a version with a space in it is not one thing: {BUILD_VERSION}"
    );
}

/// A tagged build says only the version; an untagged one names its commit.
///
/// This runs in whichever of those two states the checkout is in and asserts
/// the one that applies — there is no third shape.
#[test]
fn an_untagged_build_names_the_commit_it_came_from() {
    let extra = &BUILD_VERSION[VERSION.len()..];
    let Some(metadata) = extra.strip_prefix('+') else {
        // A tagged build, or one with no git at all. Nothing to add is the
        // right answer for both.
        assert!(extra.is_empty(), "{BUILD_VERSION}");
        return;
    };
    let commit = metadata.strip_suffix(".dirty").unwrap_or(metadata);
    assert!(
        commit.len() >= 7
            && commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "`{commit}` is not an abbreviated commit hash"
    );
}

/// Guards the `RUST_MIN_STACK` plumbing in `.cargo/config.toml` and CI.
///
/// Test threads are spawned by the harness without an explicit stack size,
/// so `std` sizes them from `RUST_MIN_STACK`. Debug frames for this crate's
/// deeply generic dependency chains have overflowed default-sized test
/// threads on Windows MSVC. This test recurses through ~24 MiB of stack —
/// three times the common 8 MiB default — so it fails on exactly the
/// configurations where the raised floor is not actually in effect, instead
/// of an arbitrary business test failing there first.
#[test]
fn raised_test_thread_stack_floor_is_in_effect() {
    use std::hint::black_box;

    // ~4 KiB per frame, resistant to being collapsed at low opt levels.
    #[inline(never)]
    fn recurse(depth: u64) -> u64 {
        let pad = black_box([depth; 512]);
        if depth == 0 {
            pad[0]
        } else {
            black_box(recurse(depth - 1)) + pad[511]
        }
    }

    assert_eq!(recurse(6_000), 18_003_000);
}
