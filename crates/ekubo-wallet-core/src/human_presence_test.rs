//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

#[test]
fn reasons_read_as_one_sentence_and_carry_no_digest() {
    let reason = PresenceRequest::SignTransaction {
        wallet: "primary".into(),
    }
    .reason();
    assert_eq!(reason, "sign a transaction from wallet primary");
    assert!(!reason.contains("0x"));
    assert_eq!(
        PresenceRequest::RemoveWallet {
            wallet: "primary".into()
        }
        .reason(),
        "delete wallet primary and its private key"
    );
    assert_eq!(
        PresenceRequest::ReplacePolicy {
            wallet: "primary".into()
        }
        .reason(),
        "replace the signing policy for wallet primary"
    );
    assert_eq!(
        PresenceRequest::SaveAddressBookEntry {
            alias: "alice".into()
        }
        .reason(),
        "save the address book alias alice"
    );
    assert_eq!(
        PresenceRequest::RemoveAddressBookEntry {
            alias: "alice".into()
        }
        .reason(),
        "remove the address book alias alice"
    );
}

#[test]
fn a_hostile_name_cannot_repaint_the_platform_dialog() {
    let reason = PresenceRequest::SignMessage {
        wallet: format!("evil\n\u{1b}[31m{}", "long".repeat(40)),
    }
    .reason();
    assert!(!reason.contains('\n') && !reason.contains('\u{1b}'));
    assert!(reason.len() < 100);
}

#[test]
fn an_empty_name_still_names_something() {
    assert_eq!(
        PresenceRequest::SignMessage {
            wallet: "   ".into()
        }
        .reason(),
        "sign a message with wallet (unnamed)"
    );
}
