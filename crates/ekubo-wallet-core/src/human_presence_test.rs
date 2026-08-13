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
fn oauth_prompt_names_and_sanitizes_the_client_and_callback_host() {
    let reason = PresenceRequest::AuthorizeAgent {
        client_name: "Codex\nforged".into(),
        redirect_host: "127.0.0.1\u{202e}".into(),
    }
    .reason();
    assert_eq!(
        reason,
        "allow Codex forged to access the wallet via 127.0.0.1"
    );
    assert!(!reason.contains('\n') && !reason.contains('\u{202e}'));
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

#[test]
fn owner_authorization_is_scope_bound() {
    let authorization = OwnerAuthorization::for_test(OwnerAuthorizationScope::NotificationPrivacy);
    authorization
        .require(OwnerAuthorizationScope::NotificationPrivacy)
        .unwrap();
    assert!(
        authorization
            .require(OwnerAuthorizationScope::AgentAccess)
            .is_err()
    );
}

#[test]
fn dapp_authorization_is_exact_and_single_use() {
    let authorization = futures::executor::block_on(authorize_dapp_access("review-a", "primary"))
        .expect("test owner authorization");
    authorization.verify("review-a", "primary").unwrap();

    let stale = futures::executor::block_on(authorize_dapp_access("review-a", "primary"))
        .expect("test owner authorization");
    assert!(stale.verify("review-b", "primary").is_err());

    let changed_account = futures::executor::block_on(authorize_dapp_access("review-a", "primary"))
        .expect("test owner authorization");
    assert!(changed_account.verify("review-a", "secondary").is_err());
}

#[test]
fn protected_setting_prompts_name_the_security_boundary() {
    assert_eq!(
        PresenceRequest::ChangeProtectedSettings {
            scope: OwnerAuthorizationScope::AgentAccess,
        }
        .reason(),
        "change which local agents can access the wallet"
    );
    assert_eq!(
        PresenceRequest::ChangeProtectedSettings {
            scope: OwnerAuthorizationScope::DappAccess,
        }
        .reason(),
        "approve the dapp connection shown in Ekubo Wallet"
    );
    assert_eq!(
        PresenceRequest::ChangeProtectedSettings {
            scope: OwnerAuthorizationScope::TokenMetadata,
        }
        .reason(),
        "change trusted token names and amount scaling"
    );
}

#[test]
fn dedicated_thread_bridge_does_not_require_a_tokio_runtime() {
    let result =
        futures::executor::block_on(run_on_dedicated_thread("owner-auth-test", || 42_u8)).unwrap();
    assert_eq!(result, 42);
}
