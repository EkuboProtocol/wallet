use super::*;

#[test]
fn system_consent_factory_exposes_hwnd_interop_without_requesting_consent() {
    // Activation/interface discovery only: never requests a PIN, biometric,
    // credential, HWND, or consent operation on a developer's Windows host.
    unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.unwrap();
    let _apartment = Apartment;
    let (_library, _factory) = system_factory().unwrap();
}
