//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::{CALLDATA_BYTES_PER_ROW, MAX_DISPLAYED_CALLDATA_BYTES, calldata_rows};

#[test]
fn the_calldata_a_reviewer_signs_is_on_the_screen() {
    let calldata: Vec<u8> = (0..70_u8).collect();
    let rows = calldata_rows(&calldata);
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(rows.concat(), hex::encode(&calldata));
    assert_eq!(rows[0].len(), CALLDATA_BYTES_PER_ROW * 2);
}

#[test]
fn oversized_calldata_says_what_it_is_not_showing() {
    let calldata = vec![0xab_u8; MAX_DISPLAYED_CALLDATA_BYTES + 100];
    let rows = calldata_rows(&calldata);
    let note = rows.last().unwrap();
    assert!(note.contains("100 of 612 bytes not shown"), "{note}");
    // The digest covers the whole thing, so the part that was elided is
    // still identifiable rather than merely absent.
    assert!(
        note.contains(&format!("{:x}", alloy::primitives::keccak256(&calldata))),
        "{note}"
    );
}

#[test]
fn empty_calldata_adds_no_rows() {
    assert!(calldata_rows(&[]).is_empty());
}
