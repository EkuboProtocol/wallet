//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use chrono::TimeDelta;

#[test]
fn a_picker_label_carries_no_invisible_direction() {
    // Zero-width by definition, which is how they survived a clamp that
    // counts display columns: the label got shorter by no columns at all.
    let label = interactive_list_label("mainnet\u{202e}drowssap\u{200b}\u{feff}");
    assert!(
        !label
            .chars()
            .any(ekubo_wallet_core::sanitize::is_disallowed),
        "label still carries a disallowed character: {label:?}"
    );
    assert!(label.starts_with("mainnet"));
    assert_eq!(interactive_list_label("plain"), "plain");
}

#[test]
fn relative_times_read_naturally_in_both_directions() {
    let now = Utc::now();
    assert_eq!(relative_time(now), "just now");
    assert_eq!(
        relative_time(now - TimeDelta::seconds(30)),
        "30 seconds ago"
    );
    assert_eq!(relative_time(now - TimeDelta::minutes(5)), "5 minutes ago");
    assert_eq!(relative_time(now - TimeDelta::hours(3)), "3 hours ago");
    assert_eq!(relative_time(now - TimeDelta::days(2)), "2 days ago");
    assert_eq!(relative_time(now + TimeDelta::minutes(9)), "in 9 minutes");
}

#[test]
fn explorer_links_join_cleanly() {
    let network = crate::config::default_networks().remove(0);
    assert_eq!(
        explorer_transaction_url(&network, "0xabc").as_deref(),
        Some("https://etherscan.io/tx/0xabc")
    );
    let mut bare = network;
    bare.block_explorer_url = None;
    assert_eq!(explorer_transaction_url(&bare, "0xabc"), None);
}

#[test]
fn interactive_lists_never_shrink_below_a_scrollable_page() {
    // Chrome can never eat the list: a tiny or unreadable terminal still
    // leaves enough rows for the page to scroll through.
    assert_eq!(interactive_list_rows(usize::MAX), MINIMUM_LIST_ROWS);
    assert!(interactive_list_rows(6) >= MINIMUM_LIST_ROWS);
    // Reserving more rows never yields a taller list.
    assert!(interactive_list_rows(10) <= interactive_list_rows(4));
}

#[test]
fn list_labels_never_exceed_one_row_at_any_width() {
    // A wrapped label would make the prompt draw more rows than it sized
    // its page for, which is what turns a cursor key into a full-screen
    // scroll. Every width, including degenerate ones, stays within budget.
    let label = "3 minutes ago · broadcast, awaiting receipt · primary · chain 1 · 4 call(s)";
    for columns in 0..=label.len() + 5 {
        let clamped = clamp_to_columns(label, columns);
        assert!(
            display_width(&clamped) <= columns,
            "{clamped:?} fits in {columns} columns"
        );
    }
    assert_eq!(clamp_to_columns("abcdef", 4), "abc…");
    assert_eq!(clamp_to_columns("abcdef", 6), "abcdef");
}

#[test]
fn list_labels_measure_wide_glyphs_by_the_columns_they_occupy() {
    // Counting characters would let a CJK name wrap anyway: each of these
    // is one character but two columns.
    assert_eq!(display_width("東京"), 4);
    assert_eq!(display_width("ab"), 2);
    assert!(display_width(&clamp_to_columns("東京証券取引所", 5)) <= 5);
}

#[test]
fn list_labels_collapse_newlines_into_one_row() {
    assert_eq!(interactive_list_label("first\nsecond"), "first second");
}

#[test]
fn human_output_strips_control_sequences_but_keeps_lines() {
    assert_eq!(terminal_safe_multiline("a\u{1b}[31mb\nc"), "a [31mb\nc");
}
