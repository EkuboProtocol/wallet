use super::*;

#[test]
fn raw_unlimited_approval_is_not_dependent_on_a_descriptor_label() {
    let evidence = CallEvidence {
        calldata: format!(
            "0x095ea7b3{}{}{}",
            "0".repeat(24),
            "1".repeat(40),
            "f".repeat(64)
        ),
        ..CallEvidence::default()
    };
    assert_eq!(
        approval_spender(&evidence),
        Some(format!("0x{}", "1".repeat(40)))
    );
    assert!(unlimited_approval(&evidence));
    let mut malformed = evidence;
    malformed.calldata.push_str("00");
    assert!(!unlimited_approval(&malformed));
}

#[test]
fn signature_hints_keep_their_source_and_raw_evidence_is_not_discarded() {
    let call = CallSummary {
        evidence: Some(CallEvidence {
            calldata: "0x12345678".into(),
            abi: vec![crate::slots::AbiCandidate {
                signature: "swapExactInput(uint256)".into(),
                contract_match: false,
                arguments: vec![("amountIn".into(), "Uint(250, 256)".into())],
            }],
            ..CallEvidence::default()
        }),
        ..CallSummary::default()
    };
    let projection = project(&call);
    assert_eq!(
        projection.description.as_deref(),
        Some("Unverified selector candidate: swap exact input")
    );
    assert_eq!(call.evidence.as_ref().unwrap().calldata, "0x12345678");
    assert!(projection.evidence.is_none());
}

#[test]
fn address_identity_survives_display_labels_and_checksum_case() {
    assert!(same_address_or_label(
        "USDC (0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)",
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
    assert!(!same_address_or_label("", ""));
}
