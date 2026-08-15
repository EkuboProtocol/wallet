use super::*;

#[test]
fn only_the_exact_bridge_build_is_accepted() {
    assert_eq!(
        bridge_handshake_status(Some(crate::BUILD_VERSION)),
        BridgeHandshakeStatus::Accepted
    );
    assert_eq!(
        bridge_handshake_status(Some("older-build")),
        BridgeHandshakeStatus::VersionMismatch
    );
    assert_eq!(
        bridge_handshake_status(None),
        BridgeHandshakeStatus::VersionMismatch
    );
}

#[test]
fn rejection_identifies_the_wallet_and_requires_a_new_agent_session() {
    let response = bridge_handshake_response(BridgeHandshakeStatus::VersionMismatch);
    assert_eq!(
        response["ekubo_wallet_bridge"]["status"],
        "version_mismatch"
    );
    assert_eq!(
        response["ekubo_wallet_bridge"]["wallet_version"],
        crate::BUILD_VERSION
    );
    assert!(
        response["ekubo_wallet_bridge"]["instruction"]
            .as_str()
            .unwrap()
            .contains("Start a new agent session")
    );
}
