use super::*;

#[test]
fn update_configuration_requires_a_key_and_pins_the_manifest_endpoint() {
    assert!(updater_config("   ").is_err());
    let config = updater_config("RWQtest-public-key").unwrap();
    assert_eq!(config.pubkey, "RWQtest-public-key");
    assert_eq!(config.endpoints.len(), 1);
    assert_eq!(config.endpoints[0].as_str(), UPDATE_ENDPOINT);
}

#[test]
fn signed_metadata_is_bound_byte_for_byte_to_the_embedded_key() {
    let key = STANDARD.encode(
        "untrusted comment: minisign public key E7620F1842B4E81F\n\
         RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
    );
    let signature = b"untrusted comment: signature from minisign secret key\n\
RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\n\
trusted comment: timestamp:1555779966\tfile:test\n\
QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==";
    verify_metadata_signature(b"test", signature, &key).unwrap();
    assert!(verify_metadata_signature(b"Test", signature, &key).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn relaunch_uses_the_outer_macos_application_bundle() {
    let executable =
        std::path::Path::new("/Applications/Ekubo Wallet.app/Contents/MacOS/ekubo-wallet");
    assert_eq!(
        macos_bundle_path(executable).unwrap(),
        std::path::Path::new("/Applications/Ekubo Wallet.app")
    );
    assert!(macos_bundle_path(std::path::Path::new("/tmp/ekubo-wallet")).is_none());
}
