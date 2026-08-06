//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

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
