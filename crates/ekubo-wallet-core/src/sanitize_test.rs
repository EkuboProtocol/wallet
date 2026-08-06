//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

#[test]
fn control_and_bidirectional_characters_never_survive() {
    // An ANSI escape cannot start a sequence, and a right-to-left
    // override cannot reorder what the reviewer reads.
    assert_eq!(terminal_safe_line("a\u{1b}[31mb"), "a [31mb");
    assert_eq!(terminal_safe_line("pay \u{202e}000 1"), "pay  000 1");
    assert_eq!(terminal_safe_line("x\u{2066}y\u{2069}z"), "x y z");
    assert_eq!(terminal_safe_multiline("a\u{202e}b\nc"), "a b\nc");
    assert_eq!(stripped_capped("E\u{202e}TH\u{7f}", 8), "ETH");
    // The Arabic letter mark is a bidi control like the rest.
    assert_eq!(terminal_safe_line("a\u{061c}b"), "a b");
}

#[test]
fn zero_width_characters_never_survive() {
    // Two symbols a person cannot tell apart must not be two different
    // stored values: the one they are reading would not be the one that
    // was checked.
    assert_eq!(stripped_capped("USD\u{200b}C", 16), "USDC");
    assert_eq!(stripped_capped("US\u{00ad}DC", 16), "USDC");
    assert_eq!(stripped_capped("USD\u{feff}C", 16), "USDC");
    assert_eq!(stripped_capped("USD\u{2060}C", 16), "USDC");
    assert_eq!(stripped_capped("USD\u{200d}C", 16), "USDC");
    // Tag characters encode whole ASCII strings invisibly.
    assert_eq!(stripped_capped("USDC\u{e0041}\u{e0042}", 16), "USDC");
    assert_eq!(terminal_safe_line("a\u{200b}b"), "a b");
}

#[test]
fn strips_terminal_control_sequences() {
    assert_eq!(terminal_safe_line("safe\u{1b}[31m\ntext"), "safe [31m text");
}

#[test]
fn caps_count_characters_not_bytes() {
    assert_eq!(stripped_capped("éééé", 2), "éé");
}
