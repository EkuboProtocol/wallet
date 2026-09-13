use super::*;

#[test]
fn probe_failure_preserves_stage_and_nested_windows_hresult() {
    for stage in 0..16 {
        let error = anyhow::Error::new(windows::core::Error::from_hresult(HRESULT(
            0x8007_0006u32.cast_signed(),
        )))
        .context(ProbeStage(stage));
        let code = probe_failure_exit(&error);
        assert_eq!((code >> 24) & 15, stage);
        assert_eq!(crate::decode_probe_failure(code).unwrap().1, 0x8007_0006);
        assert_ne!(code, crate::VERIFIED_EXIT);
    }
    let error = anyhow::Error::new(windows::core::Error::from_hresult(HRESULT(
        0xd000_0005u32.cast_signed(),
    )))
    .context(ProbeStage(4));
    assert_eq!(probe_failure_exit(&error), 0xd000_0005);
    assert!(crate::decode_probe_failure(probe_failure_exit(&error)).is_none());
}

#[test]
fn ordinary_process_completes_read_only_availability_query() {
    // Comparison against the protected SYSTEM-launched child. This calls the
    // same initialization and API, without changing token/process protection.
    // Never RequestVerification, enrollment, or any biometric interaction.
    let challenge = Challenge {
        nonce: "a".repeat(64),
        operation_digest: "b".repeat(64),
        reason: "read-only availability control".into(),
    };
    let code = probe_availability(&challenge).unwrap_or_else(|error| {
        let exit = probe_failure_exit(&error);
        panic!(
            "ordinary availability query failed: exit {exit:#010x}, diagnostic {:?}, {error:#}",
            crate::decode_probe_failure(exit)
        );
    });
    assert!((crate::AVAILABILITY_EXIT_BASE..=crate::AVAILABILITY_EXIT_BASE + 4).contains(&code));
    assert_ne!(code, crate::VERIFIED_EXIT);
}

#[test]
fn system_consent_factory_exposes_hwnd_interop_without_requesting_consent() {
    // Activation/interface discovery only: never requests a PIN, biometric,
    // credential, HWND, or consent operation on a developer's Windows host.
    unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.unwrap();
    let _apartment = Apartment;
    let (_library, _factory) = system_factory().unwrap();
}
