use super::*;
use crate::legacy_move::{MoveBinding, ReceiptPhase, selection_digest};
use uuid::Uuid;

fn receipt(profile: Uuid, nonce: Uuid, phase: ReceiptPhase) -> Receipt {
    Receipt {
        profile,
        nonce,
        phase,
        digest: [1; 32],
        accounts: vec![],
        wallets: vec![],
        binding: None,
        selection_digest: None,
    }
}

#[test]
fn source_authorization_rejects_other_selection_profile_nonce_and_phase() {
    let profile = Uuid::new_v4();
    let nonce = Uuid::new_v4();
    let source = std::env::temp_dir().join("legacy-source");
    let command = ServiceCommand::AuthorizeSource {
        nonce,
        source: source.clone(),
        preserved_profiles: vec![],
    };
    let mut proof = receipt(profile, nonce, ReceiptPhase::SourceAuthorized);
    proof.selection_digest = Some(selection_digest(profile, &source, &[]).unwrap());
    validate_receipt(&command, &proof, profile).unwrap();
    assert!(validate_receipt(&command, &proof, Uuid::new_v4()).is_err());
    proof.nonce = Uuid::new_v4();
    assert!(validate_receipt(&command, &proof, profile).is_err());
    proof.nonce = nonce;
    proof.phase = ReceiptPhase::Inspected;
    assert!(validate_receipt(&command, &proof, profile).is_err());
    proof.phase = ReceiptPhase::SourceAuthorized;
    proof.selection_digest = Some(
        selection_digest(profile, &source, &[std::env::temp_dir().join("preserved")]).unwrap(),
    );
    assert!(validate_receipt(&command, &proof, profile).is_err());
}

#[test]
fn source_receipt_cannot_authorize_cleanup_or_complete_it() {
    let profile = Uuid::new_v4();
    let nonce = Uuid::new_v4();
    let binding = MoveBinding {
        profile,
        source: std::env::temp_dir().join("source"),
        preserved_profiles: vec![],
        retained_shared_accounts: vec![],
        retirement: None,
    };
    let verify = ServiceCommand::Verify {
        digest: [1; 32],
        nonce,
        binding: binding.clone(),
    };
    let complete = ServiceCommand::Complete {
        digest: [1; 32],
        nonce,
        binding: binding.clone(),
    };
    let mut proof = receipt(profile, nonce, ReceiptPhase::SourceAuthorized);
    proof.binding = Some(binding.clone());
    assert!(validate_receipt(&verify, &proof, profile).is_err());
    proof.phase = ReceiptPhase::Verified;
    validate_receipt(&verify, &proof, profile).unwrap();
    assert!(validate_receipt(&complete, &proof, profile).is_err());
    proof.phase = ReceiptPhase::Complete;
    validate_receipt(&complete, &proof, profile).unwrap();
    proof.binding.as_mut().unwrap().source = std::env::temp_dir().join("another-source");
    assert!(validate_receipt(&complete, &proof, profile).is_err());
    proof.binding = Some(binding);
    proof.digest = [2; 32];
    assert!(validate_receipt(&complete, &proof, profile).is_err());
}

#[test]
fn recovery_authorization_and_attested_completion_validate_their_receipts() {
    use crate::legacy_move::RecoveryAbsence;
    let profile = Uuid::new_v4();
    let nonce = Uuid::new_v4();
    let binding = MoveBinding {
        profile,
        source: std::env::temp_dir().join("source"),
        preserved_profiles: vec![],
        retained_shared_accounts: vec![],
        retirement: None,
    };
    // The entry step authorizes only its own phase with a bound receipt.
    let authorize = ServiceCommand::AuthorizeRecovery { nonce };
    let mut proof = receipt(profile, nonce, ReceiptPhase::RecoveryAuthorized);
    assert!(validate_receipt(&authorize, &proof, profile).is_err());
    proof.binding = Some(binding.clone());
    validate_receipt(&authorize, &proof, profile).unwrap();
    proof.phase = ReceiptPhase::Verified;
    assert!(validate_receipt(&authorize, &proof, profile).is_err());
    // Completion requires the receipt-bound attestation to match.
    let absence = RecoveryAbsence {
        digest: [1; 32],
        source: binding.source.clone(),
    };
    let complete = ServiceCommand::CompleteWithoutSource {
        nonce,
        absence: Some(absence),
    };
    proof.phase = ReceiptPhase::Complete;
    validate_receipt(&complete, &proof, profile).unwrap();
    proof.digest = [2; 32];
    assert!(validate_receipt(&complete, &proof, profile).is_err());
    proof.digest = [1; 32];
    proof.binding.as_mut().unwrap().source = std::env::temp_dir().join("another-source");
    assert!(validate_receipt(&complete, &proof, profile).is_err());
    // An unattested completion never validates.
    let unattested = ServiceCommand::CompleteWithoutSource {
        nonce,
        absence: None,
    };
    proof.binding = Some(binding);
    assert!(validate_receipt(&unattested, &proof, profile).is_err());
}
