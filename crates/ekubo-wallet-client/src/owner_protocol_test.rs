use super::*;

#[test]
fn protocol_rejects_authority_claims_and_unimplemented_operations() {
    for request in [
        r#"{"method":"sign_message","params":{"request_id":"00000000-0000-0000-0000-000000000001","reviewed_digest":"0x00","approved":true}}"#,
        r#"{"method":"sign_typed_data","params":{"request_id":"00000000-0000-0000-0000-000000000001","reviewed_digest":"0x00","private_key":"0x00"}}"#,
        r#"{"method":"sign_message","params":{"request_id":"00000000-0000-0000-0000-000000000001","reviewed_digest":"0x00","message":"replacement"}}"#,
        r#"{"method":"transaction_headlines","params":{"request_ids":[],"transactions":[{"approval_required":false}]}}"#,
        r#"{"method":"activity","params":{"wallet_id":null,"limit":10,"include_private_keys":true}}"#,
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

#[test]
fn transaction_actions_accept_only_stored_request_ids() {
    for method in [
        "rebroadcast_transaction",
        "attempt_transaction_cancellation",
    ] {
        let mut request = serde_json::json!({"method": method, "params": {"request_id": "00000000-0000-0000-0000-000000000001"}});
        assert!(serde_json::from_value::<Request>(request.clone()).is_ok());
        for field in [
            "signed_bytes",
            "nonce",
            "max_fee_per_gas",
            "to",
            "value",
            "approved",
            "wallet_id",
        ] {
            request["params"][field] = serde_json::json!(true);
            assert!(serde_json::from_value::<Request>(request.clone()).is_err());
            request["params"].as_object_mut().unwrap().remove(field);
        }
    }
}

#[test]
fn portfolio_read_cannot_replace_authoritative_inputs() {
    for field in [
        "networks",
        "rpc_urls",
        "known_tokens",
        "address",
        "data_dir",
        "testnet_mode",
    ] {
        let mut request =
            serde_json::json!({"method": "portfolio", "params": {"wallet_id": "primary"}});
        request["params"][field] = serde_json::json!("replacement");
        assert!(serde_json::from_value::<Request>(request).is_err());
    }
}

#[test]
fn history_clear_has_no_caller_selected_deletion_scope() {
    assert!(
        serde_json::from_value::<Request>(serde_json::json!({"method":"clear_activity_history"}))
            .is_ok()
    );
    for field in [
        "include_pending",
        "include_unsettled",
        "delete_transactions",
        "request_ids",
        "data_dir",
    ] {
        let mut request = serde_json::json!({"method":"clear_activity_history", "params":{}});
        request["params"][field] = true.into();
        assert!(serde_json::from_value::<Request>(request).is_err());
    }
}

#[test]
fn preview_generation_cannot_accept_caller_authored_evidence() {
    for field in [
        "plans",
        "transactions",
        "metadata",
        "summary",
        "simulation",
        "model_path",
    ] {
        let mut request =
            serde_json::json!({"method":"transaction_previews", "params":{"request_ids":[]}});
        request["params"][field] = serde_json::json!("replacement");
        assert!(serde_json::from_value::<Request>(request).is_err());
    }
}
