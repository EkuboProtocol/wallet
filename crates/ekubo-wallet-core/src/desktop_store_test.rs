use super::*;

const REDIRECT: &str = "http://127.0.0.1:43119/callback";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abc";

fn agent_authorization() -> OwnerAuthorization {
    OwnerAuthorization::for_test(OwnerAuthorizationScope::AgentAccess)
}

fn client_management_authorization(
    store: &DesktopStore,
    client_id: Uuid,
    operation: AgentManagementOperation,
) -> OAuthClientManagementAuthorization {
    let review = store
        .client_management_review(client_id, operation)
        .unwrap();
    futures::executor::block_on(authorize_oauth_client_management(review)).unwrap()
}

fn store(key: u8) -> DesktopStore {
    let directory = tempfile::tempdir().unwrap();
    DesktopStore::open(
        &directory.keep().join("wallet.db"),
        &DatabaseKey::new([key; 32]),
    )
    .unwrap()
}

fn register(store: &mut DesktopStore) -> McpClient {
    store
        .register_oauth_client("Codex", AgentKind::Codex, &[REDIRECT.to_owned()], None)
        .unwrap()
}

fn authorize_and_exchange(store: &mut DesktopStore, client: &McpClient) -> OAuthTokenPair {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let code = store
        .issue_authorization_code_with_session(
            client.id,
            REDIRECT,
            &challenge,
            MCP_SCOPE,
            MCP_RESOURCE,
            OAuthSessionPreset::OneDayOneWeek,
            client,
            &agent_authorization(),
        )
        .unwrap();
    store
        .exchange_authorization_code(
            &code.code.expose_base64url(),
            client.id,
            REDIRECT,
            VERIFIER,
            MCP_RESOURCE,
        )
        .unwrap()
}

#[test]
fn registration_creates_no_credential_until_owner_authorizes_login() {
    let mut store = store(31);
    let client = register(&mut store);
    assert!(store.clients().unwrap().is_empty());

    let pair = authorize_and_exchange(&mut store, &client);
    assert_eq!(pair.expires_in, 24 * 60 * 60);
    assert_eq!(store.clients().unwrap()[0].id, client.id);
    assert_eq!(
        store
            .authenticate_access_token(&pair.access_token.expose_base64url(), MCP_RESOURCE)
            .unwrap()
            .unwrap()
            .id,
        client.id
    );
}

/// Agent harnesses persist the `client_id` dynamic registration returned and
/// never register again, so an aged-out registration is not a stale row — it
/// is an agent that can never log in again, because `/authorize` rejects the
/// only `client_id` it has. A never-authorized registration therefore has to
/// outlive an unrelated registration made long afterwards.
#[test]
fn an_abandoned_registration_survives_so_a_cached_client_id_keeps_working() {
    let mut store = store(37);
    let abandoned = register(&mut store);
    store
        .connection
        .execute(
            "UPDATE mcp_clients SET created_at = ?1 WHERE client_id = ?2",
            params![
                Millis(Utc::now() - Duration::days(9)),
                Blob(*abandoned.id.as_bytes())
            ],
        )
        .unwrap();

    let _unrelated = register(&mut store);

    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    assert!(
        store
            .validate_oauth_authorization_request(
                abandoned.id,
                REDIRECT,
                &challenge,
                MCP_SCOPE,
                MCP_RESOURCE,
            )
            .is_ok()
    );
}

/// The registration table is still bounded; pruning is what pressure buys.
#[test]
fn registration_prunes_only_under_pressure_and_stays_capped() {
    let mut store = store(38);
    for _ in 0..MAX_OAUTH_CLIENTS {
        register(&mut store);
    }
    assert!(register_result(&mut store).is_err());

    store
        .connection
        .execute(
            "UPDATE mcp_clients SET created_at = ?1",
            [Millis(
                Utc::now() - UNAUTHORIZED_CLIENT_RETENTION - Duration::days(1),
            )],
        )
        .unwrap();
    assert!(register_result(&mut store).is_ok());

    let count: i64 = store
        .connection
        .query_row("SELECT count(*) FROM mcp_clients", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

fn register_result(store: &mut DesktopStore) -> Result<McpClient> {
    store.register_oauth_client("Codex", AgentKind::Codex, &[REDIRECT.to_owned()], None)
}

#[test]
fn native_loopback_redirects_allow_ephemeral_ports_and_host_spellings() {
    let mut store = store(41);
    let client = store
        .register_oauth_client(
            "Claude Code",
            AgentKind::ClaudeCode,
            &["http://127.0.0.1:43119/callback".into()],
            None,
        )
        .unwrap();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));

    assert!(
        store
            .validate_oauth_authorization_request(
                client.id,
                "http://localhost:49502/callback",
                &challenge,
                MCP_SCOPE,
                MCP_RESOURCE,
            )
            .is_ok()
    );
    assert!(
        store
            .validate_oauth_authorization_request(
                client.id,
                "http://[::1]:49502/callback",
                &challenge,
                MCP_SCOPE,
                MCP_RESOURCE,
            )
            .is_ok()
    );
}

#[test]
fn redirect_relaxation_never_changes_path_query_or_https_matching() {
    assert!(redirect_uri_matches(
        "http://127.0.0.1:43119/callback?channel=claude",
        "http://localhost:49502/callback?channel=claude"
    ));
    assert!(!redirect_uri_matches(
        "http://127.0.0.1:43119/callback",
        "http://localhost:49502/other"
    ));
    assert!(!redirect_uri_matches(
        "http://127.0.0.1:43119/callback?one=1",
        "http://localhost:49502/callback?one=2"
    ));
    assert!(!redirect_uri_matches(
        "https://example.com:43119/callback",
        "https://example.com:49502/callback"
    ));
}

#[test]
fn oauth_refresh_families_have_a_hard_non_sliding_session_expiry() {
    let mut store = store(36);
    let client = register(&mut store);
    let pair = authorize_and_exchange(&mut store, &client);
    let refresh = pair.refresh_token.expose_base64url();
    let original_expiration = store
        .connection
        .query_row(
            "SELECT expires_at FROM oauth_refresh_tokens WHERE consumed_at IS NULL",
            [],
            |row| Ok(row.get::<_, crate::sql::Millis>(0)?.0),
        )
        .unwrap();

    store
        .refresh_access_token(&refresh, client.id, MCP_RESOURCE)
        .unwrap();
    let rotated_expiration = store
        .connection
        .query_row(
            "SELECT expires_at FROM oauth_refresh_tokens WHERE consumed_at IS NULL",
            [],
            |row| Ok(row.get::<_, crate::sql::Millis>(0)?.0),
        )
        .unwrap();
    assert_eq!(rotated_expiration, original_expiration);
}

#[test]
fn owner_selected_oauth_access_and_refresh_lifetimes_are_bound_to_the_code() {
    let mut store = store(37);
    let client = register(&mut store);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let before = chrono::Utc::now();
    let code = store
        .issue_authorization_code_with_session(
            client.id,
            REDIRECT,
            &challenge,
            MCP_SCOPE,
            MCP_RESOURCE,
            OAuthSessionPreset::OneWeekOneMonth,
            &client,
            &agent_authorization(),
        )
        .unwrap();
    let pair = store
        .exchange_authorization_code(
            &code.code.expose_base64url(),
            client.id,
            REDIRECT,
            VERIFIER,
            MCP_RESOURCE,
        )
        .unwrap();
    let expiration = store
        .connection
        .query_row(
            "SELECT expires_at FROM oauth_refresh_tokens WHERE consumed_at IS NULL",
            [],
            |row| Ok(row.get::<_, crate::sql::Millis>(0)?.0),
        )
        .unwrap();

    assert!(expiration >= before + chrono::Duration::days(30) - chrono::Duration::seconds(1));
    assert!(expiration <= chrono::Utc::now() + chrono::Duration::days(30));
    assert_eq!(
        store.clients().unwrap()[0].session_expires_at,
        Some(expiration)
    );
    assert_eq!(pair.expires_in, 7 * 24 * 60 * 60);
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT access_token_ttl_seconds FROM oauth_refresh_tokens",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        7 * 24 * 60 * 60
    );
    assert_eq!(
        OAuthSessionPreset::OneHourOneDay.as_query_value(),
        "hour-day"
    );
    assert_eq!(
        OAuthSessionPreset::OneWeekOneMonth.label(),
        "1 week / 1 month"
    );
    assert!(OAuthSessionPreset::parse_query_value("forever").is_err());
}

#[test]
fn agent_session_listing_retains_an_expired_absolute_deadline() {
    let mut store = store(40);
    let client = register(&mut store);
    let _pair = authorize_and_exchange(&mut store, &client);
    let expired_at = chrono::DateTime::from_timestamp_millis(
        (chrono::Utc::now() - chrono::Duration::minutes(1)).timestamp_millis(),
    )
    .unwrap();
    store
        .connection
        .execute(
            "UPDATE oauth_refresh_tokens SET expires_at = ?1 WHERE client_id = ?2",
            rusqlite::params![
                crate::sql::Millis(expired_at),
                crate::sql::Blob(*client.id.as_bytes())
            ],
        )
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE oauth_authorization_codes SET session_expires_at = ?1 WHERE client_id = ?2",
            rusqlite::params![
                crate::sql::Millis(expired_at),
                crate::sql::Blob(*client.id.as_bytes())
            ],
        )
        .unwrap();

    assert_eq!(
        store.clients().unwrap()[0].session_expires_at,
        Some(expired_at)
    );
}

#[test]
fn authorization_codes_are_one_time_and_pkce_bound() {
    let mut store = store(32);
    let client = register(&mut store);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let code = store
        .issue_authorization_code_with_session(
            client.id,
            REDIRECT,
            &challenge,
            MCP_SCOPE,
            MCP_RESOURCE,
            OAuthSessionPreset::OneDayOneWeek,
            &client,
            &agent_authorization(),
        )
        .unwrap();
    let encoded = code.code.expose_base64url();
    assert!(
        store
            .exchange_authorization_code(
                &encoded,
                client.id,
                REDIRECT,
                &"Z".repeat(43),
                MCP_RESOURCE,
            )
            .is_err()
    );
    assert!(
        store
            .exchange_authorization_code(&encoded, client.id, REDIRECT, VERIFIER, MCP_RESOURCE,)
            .is_ok()
    );
    assert!(
        store
            .exchange_authorization_code(&encoded, client.id, REDIRECT, VERIFIER, MCP_RESOURCE,)
            .is_err()
    );
}

#[test]
fn authorization_code_issuance_rejects_client_state_changed_during_owner_presence() {
    let mut store = store(63);
    let client = register(&mut store);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    store
        .connection
        .execute(
            "UPDATE mcp_clients SET display_name = 'Changed' WHERE client_id = ?1",
            [Blob(*client.id.as_bytes())],
        )
        .unwrap();

    assert!(
        store
            .issue_authorization_code_with_session(
                client.id,
                REDIRECT,
                &challenge,
                MCP_SCOPE,
                MCP_RESOURCE,
                OAuthSessionPreset::OneDayOneWeek,
                &client,
                &agent_authorization(),
            )
            .is_err()
    );
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM oauth_authorization_codes",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .unwrap(),
        0
    );
    assert!(store.clients().unwrap().is_empty());
}

#[test]
fn refresh_token_rotates_and_reuse_revokes_the_family() {
    let mut store = store(33);
    let client = register(&mut store);
    let first = authorize_and_exchange(&mut store, &client);
    let first_refresh = first.refresh_token.expose_base64url();
    let second = store
        .refresh_access_token(&first_refresh, client.id, MCP_RESOURCE)
        .unwrap();
    let second_refresh = second.refresh_token.expose_base64url();
    assert_ne!(second_refresh, first_refresh);
    let replay = store.refresh_access_token(&first_refresh, client.id, MCP_RESOURCE);
    assert!(replay.is_err_and(|error| error.to_string().contains("reuse detected")));
    assert!(
        store
            .authenticate_access_token(&second.access_token.expose_base64url(), MCP_RESOURCE)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .refresh_access_token(&second_refresh, client.id, MCP_RESOURCE)
            .is_err()
    );
}

#[test]
fn concurrent_refresh_exchanges_cannot_both_succeed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("wallet.db");
    let mut store = DesktopStore::open(&path, &DatabaseKey::new([44; 32])).unwrap();
    let client = register(&mut store);
    let refresh = authorize_and_exchange(&mut store, &client)
        .refresh_token
        .expose_base64url();
    drop(store);

    let barrier = std::sync::Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let run = || {
            barrier.wait();
            DesktopStore::open(&path, &DatabaseKey::new([44; 32]))
                .unwrap()
                .refresh_access_token(&refresh, client.id, MCP_RESOURCE)
                .is_ok()
        };
        let first = scope.spawn(run);
        let second = scope.spawn(run);
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(
        outcomes.into_iter().filter(|succeeded| *succeeded).count(),
        1
    );
}

#[test]
fn revocation_invalidates_access_without_removing_harness_registration() {
    let mut store = store(34);
    let client = register(&mut store);
    let pair = authorize_and_exchange(&mut store, &client);
    let authorization =
        client_management_authorization(&store, client.id, AgentManagementOperation::Revoke);
    store.apply_client_management(authorization).unwrap();
    assert!(
        store
            .authenticate_access_token(&pair.access_token.expose_base64url(), MCP_RESOURCE)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .refresh_access_token(
                &pair.refresh_token.expose_base64url(),
                client.id,
                MCP_RESOURCE,
            )
            .is_err()
    );
    assert_eq!(
        store
            .connection
            .query_row("SELECT COUNT(*) FROM oauth_access_tokens", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .connection
            .query_row("SELECT COUNT(*) FROM oauth_refresh_tokens", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
    assert!(
        store
            .oauth_client_for_authorization(client.id, REDIRECT)
            .is_ok()
    );
}

#[test]
fn authorized_removal_deletes_every_oauth_credential() {
    let mut store = store(39);
    let client = register(&mut store);
    let pair = authorize_and_exchange(&mut store, &client);
    let authorization =
        client_management_authorization(&store, client.id, AgentManagementOperation::Remove);
    store.apply_client_management(authorization).unwrap();
    assert!(store.clients().unwrap().is_empty());
    assert!(
        store
            .authenticate_access_token(&pair.access_token.expose_base64url(), MCP_RESOURCE)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .refresh_access_token(
                &pair.refresh_token.expose_base64url(),
                client.id,
                MCP_RESOURCE,
            )
            .is_err()
    );
    assert!(
        store
            .oauth_client_for_authorization(client.id, REDIRECT)
            .is_err()
    );
}

#[test]
fn client_management_rejects_wrong_scope_expiration_and_stale_registration_identity() {
    let mut store = store(61);
    let client = register(&mut store);
    authorize_and_exchange(&mut store, &client);
    let review = store
        .client_management_review(client.id, AgentManagementOperation::Remove)
        .unwrap();
    let wrong = OAuthClientManagementAuthorization {
        owner: OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings),
        expected: review.expected,
        grant_identity: review.grant_identity,
        operation: review.operation,
    };
    assert!(store.apply_client_management(wrong).is_err());

    let review = store
        .client_management_review(client.id, AgentManagementOperation::Remove)
        .unwrap();
    let expired = OAuthClientManagementAuthorization {
        owner: OwnerAuthorization::expired_for_test(OwnerAuthorizationScope::AgentAccess),
        expected: review.expected,
        grant_identity: review.grant_identity,
        operation: review.operation,
    };
    assert!(store.apply_client_management(expired).is_err());

    let review = store
        .client_management_review(client.id, AgentManagementOperation::Remove)
        .unwrap();
    let authorization =
        futures::executor::block_on(authorize_oauth_client_management(review)).unwrap();

    store
        .connection
        .execute(
            "UPDATE mcp_clients SET redirect_uris_json = ?1 WHERE client_id = ?2",
            rusqlite::params![
                "[\"http://127.0.0.1:43120/callback\"]",
                crate::sql::Blob(*client.id.as_bytes())
            ],
        )
        .unwrap();
    assert!(store.apply_client_management(authorization).is_err());
    assert!(
        store
            .client_management_review(client.id, AgentManagementOperation::Remove)
            .is_ok()
    );
}

#[test]
fn an_already_revoked_client_cannot_be_revoked_again() {
    let mut store = store(62);
    let client = register(&mut store);
    authorize_and_exchange(&mut store, &client);
    let authorization =
        client_management_authorization(&store, client.id, AgentManagementOperation::Revoke);
    store.apply_client_management(authorization).unwrap();

    assert!(
        store
            .client_management_review(client.id, AgentManagementOperation::Revoke)
            .is_err()
    );
    assert!(
        store
            .client_management_review(client.id, AgentManagementOperation::Remove)
            .is_err()
    );
    let source = include_str!("desktop_store.rs");
    assert!(!source.contains("pub fn revoke_client("));
    assert!(!source.contains("pub fn remove_client("));
}

#[test]
fn client_management_rejects_credentials_rotated_during_owner_presence() {
    let mut store = store(64);
    let client = register(&mut store);
    let pair = authorize_and_exchange(&mut store, &client);
    let review = store
        .client_management_review(client.id, AgentManagementOperation::Revoke)
        .unwrap();
    let authorization =
        futures::executor::block_on(authorize_oauth_client_management(review)).unwrap();

    store
        .refresh_access_token(
            &pair.refresh_token.expose_base64url(),
            client.id,
            MCP_RESOURCE,
        )
        .unwrap();
    assert!(store.apply_client_management(authorization).is_err());
    assert_eq!(store.clients().unwrap()[0].id, client.id);
}

#[test]
fn protected_desktop_settings_reject_the_wrong_authorization_scope() {
    let mut store = store(35);
    let client = register(&mut store);
    let wrong_scope = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    assert!(
        store
            .set_detailed_notification_previews(true, &wrong_scope)
            .is_err()
    );
    assert!(
        store
            .issue_authorization_code_with_session(
                client.id,
                REDIRECT,
                &challenge,
                MCP_SCOPE,
                MCP_RESOURCE,
                OAuthSessionPreset::OneDayOneWeek,
                &client,
                &wrong_scope,
            )
            .is_err()
    );
    assert!(store.clients().unwrap().is_empty());
}

#[test]
fn appearance_defaults_to_system_and_persists_in_the_encrypted_store() {
    let mut store = store(36);
    assert_eq!(
        store.appearance_preference().unwrap(),
        AppearancePreference::System
    );

    store
        .set_appearance_preference(AppearancePreference::Dark)
        .unwrap();
    assert_eq!(
        store.appearance_preference().unwrap(),
        AppearancePreference::Dark
    );

    store
        .set_appearance_preference(AppearancePreference::Light)
        .unwrap();
    assert_eq!(
        store.appearance_preference().unwrap(),
        AppearancePreference::Light
    );
}

#[test]
fn testnet_mode_defaults_off_and_persists_in_the_encrypted_store() {
    let mut store = store(37);
    assert!(!store.testnet_mode().unwrap());

    store.set_testnet_mode(true).unwrap();
    assert!(store.testnet_mode().unwrap());

    store.set_testnet_mode(false).unwrap();
    assert!(!store.testnet_mode().unwrap());
}

#[test]
fn attribution_names_the_asker_even_when_its_registration_no_longer_counts() {
    // "Who asked for this record" is a different question from "which agents
    // are connected": the client that asked may never have finished
    // authorizing, or may have been revoked since. Both are absent from
    // `clients`, and the history list must still be able to name them.
    let mut store = store(38);
    let client = register(&mut store);
    assert!(
        store.clients().unwrap().is_empty(),
        "an unauthorized client is not a connection"
    );

    let attributed = Uuid::new_v4();
    let anonymous = Uuid::new_v4();
    let wallet_instance_id = Uuid::new_v4();
    store
        .connection
        .execute(
            "INSERT INTO wallet_instances(instance_id, wallet_id, wallet_address, created_at)
         VALUES (?1, 'primary', '0x0000000000000000000000000000000000000000', ?2)",
            params![wallet_instance_id.to_string(), Millis(Utc::now())],
        )
        .unwrap();
    // Distinct plan digests: two awaiting rows for one wallet and chain may
    // not name the same plan.
    for (digest, request_id) in [(6_u8, attributed), (7, anonymous)] {
        store
            .connection
            .execute(
                "INSERT INTO pending_transactions(
                     request_id, wallet_instance_id, wallet_id, wallet_address, network_name, chain_id, plan_json,
                     plan_digest, policy_revision, status, created_at, updated_at
                 ) VALUES (?1, ?2, 'primary', '0x0000000000000000000000000000000000000000',
                           'ethereum', 1, '{}', ?3, 1, 'awaiting_approval', ?4, ?4)",
                params![
                    Blob(*request_id.as_bytes()),
                    wallet_instance_id.to_string(),
                    Blob([digest; 32]),
                    Millis(Utc::now()),
                ],
            )
            .unwrap();
    }
    let signature_request = Uuid::new_v4();
    store
        .connection
        .execute(
            "INSERT INTO pending_typed_data(
                 request_id, wallet_instance_id, wallet_id, wallet_address, chain_id, typed_data_json, digest, status,
                 created_at, updated_at
             ) VALUES (?1, ?2, 'primary', '0x0000000000000000000000000000000000000000',
                       1, '{}', ?3, 'awaiting_approval', ?4, ?4)",
            params![
                Blob(*signature_request.as_bytes()),
                wallet_instance_id.to_string(),
                Blob([8_u8; 32]),
                Millis(Utc::now()),
            ],
        )
        .unwrap();

    store.attribute_transaction(attributed, client.id).unwrap();
    store
        .attribute_typed_data(signature_request, client.id)
        .unwrap();

    let attributions = store.request_attributions().unwrap();
    assert_eq!(
        attributions.get(&attributed).map(String::as_str),
        Some("Codex")
    );
    assert_eq!(
        attributions.get(&signature_request).map(String::as_str),
        Some("Codex")
    );
    assert!(
        !attributions.contains_key(&anonymous),
        "a record nobody was attributed to names nobody"
    );
}
