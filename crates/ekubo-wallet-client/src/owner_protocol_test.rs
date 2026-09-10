use super::*;

#[test]
fn protocol_rejects_authority_claims_and_unimplemented_operations() {
    for request in [
        r#"{"method":"relink_automation","params":{"automation_id":"00000000-0000-0000-0000-000000000001","policy_revision":999}}"#,
        r#"{"method":"dry_run_automation","params":{"automation_id":"00000000-0000-0000-0000-000000000001","approved":true}}"#,
        r#"{"method":"accept_token_proposals","params":{"proposals":[],"approved":true}}"#,
        r#"{"method":"tokens","params":{"chain_id":null,"limit":10,"offset":0,"data_dir":"/tmp/other"}}"#,
        r#"{"method":"accounts","owner_uid":1000}"#,
        r#"{"method":"account","params":{"wallet_id":"primary","approved":true}}"#,
        r#"{"method":"account","params":{"wallet_id":"primary","data_dir":"/tmp/other"}}"#,
        r#"{"method":"sign","params":{"digest":"00"}}"#,
        r#"{"method":"get_private_key","params":{"wallet_id":"primary"}}"#,
        r#"{"method":"execute_sql","params":{"sql":"delete from policies"}}"#,
        r#"{"method":"approve_dapp_review","params":{"session_id":"00000000-0000-0000-0000-000000000001","index":0,"reviewed_identity":"review","authorization":true}}"#,
        r#"{"method":"approve_dapp_review","params":{"session_id":"00000000-0000-0000-0000-000000000001","index":0,"reviewed_identity":"review","scope":{"methods":["eth_sign"]}}}"#,
    ] {
        assert!(
            serde_json::from_str::<Request>(request).is_err(),
            "accepted {request}"
        );
    }
}
