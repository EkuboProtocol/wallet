//! Desktop settings and the OAuth authority for the loopback MCP resource.
//!
//! Agent configuration files contain only the stable resource URL. OAuth
//! credentials are issued after owner presence and stored by the client; this
//! encrypted store retains only one-way hashes needed to validate and revoke
//! them.

use crate::{
    human_presence::{
        AgentManagementOperation, HumanPresenceError, OwnerAuthorization, OwnerAuthorizationScope,
        authorize_agent_management,
    },
    policy_store::{DatabaseKey, PolicyStore},
    sql::{Blob, Millis},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use rand::TryRng as _;
use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Stable private-range port used by every managed agent configuration.
/// Binding can still fail if another local process already owns it; the app
/// never falls back because silently changing it would invalidate OAuth
/// resource identifiers and every installed URL.
pub const MCP_PORT: u16 = 61_744;
pub const MCP_RESOURCE: &str = "http://127.0.0.1:61744/mcp";
pub const MCP_SCOPE: &str = "wallet:use";

const AUTHORIZATION_CODE_TTL: Duration = Duration::minutes(5);
const MAX_OAUTH_CLIENTS: i64 = 128;
/// How long a registered but never-authorized client survives before it
/// becomes eligible for pruning. It only bounds the registration table; a
/// client is never dropped while there is room for it.
const UNAUTHORIZED_CLIENT_RETENTION: Duration = Duration::days(30);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppearancePreference {
    #[default]
    System,
    Light,
    Dark,
}

/// An owner-selected pair of access-token and absolute refresh-token
/// lifetimes. Keeping the combinations finite and curated avoids nonsensical
/// configurations such as an access token that outlives its refresh session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuthSessionPreset {
    OneHourOneDay,
    OneDayOneWeek,
    OneWeekOneMonth,
}

impl OAuthSessionPreset {
    #[must_use]
    pub const fn as_query_value(self) -> &'static str {
        match self {
            Self::OneHourOneDay => "hour-day",
            Self::OneDayOneWeek => "day-week",
            Self::OneWeekOneMonth => "week-month",
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OneHourOneDay => "1 hour / 1 day",
            Self::OneDayOneWeek => "1 day / 1 week",
            Self::OneWeekOneMonth => "1 week / 1 month",
        }
    }

    pub fn parse_query_value(value: &str) -> Result<Self> {
        match value {
            "hour-day" => Ok(Self::OneHourOneDay),
            "day-week" => Ok(Self::OneDayOneWeek),
            "week-month" => Ok(Self::OneWeekOneMonth),
            _ => anyhow::bail!("unsupported OAuth session preset"),
        }
    }

    const fn access_duration(self) -> Duration {
        match self {
            Self::OneHourOneDay => Duration::hours(1),
            Self::OneDayOneWeek => Duration::days(1),
            Self::OneWeekOneMonth => Duration::weeks(1),
        }
    }

    const fn refresh_duration(self) -> Duration {
        match self {
            Self::OneHourOneDay => Duration::days(1),
            Self::OneDayOneWeek => Duration::weeks(1),
            Self::OneWeekOneMonth => Duration::days(30),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Codex,
    ClaudeCode,
    ClaudeDesktop,
    GeminiCli,
    Cursor,
    Opencode,
    Other,
}

impl AgentKind {
    /// The harness's own name for itself, spelled the way its own
    /// documentation does rather than as a Rust variant.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::ClaudeCode => "Claude Code",
            Self::ClaudeDesktop => "Claude Desktop",
            Self::GeminiCli => "Gemini CLI",
            Self::Cursor => "Cursor",
            Self::Opencode => "opencode",
            Self::Other => "an unrecognized harness",
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude_code",
            Self::ClaudeDesktop => "claude_desktop",
            Self::GeminiCli => "gemini_cli",
            Self::Cursor => "cursor",
            Self::Opencode => "opencode",
            Self::Other => "other",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "codex" => Ok(Self::Codex),
            "claude_code" => Ok(Self::ClaudeCode),
            "claude_desktop" => Ok(Self::ClaudeDesktop),
            "gemini_cli" => Ok(Self::GeminiCli),
            "cursor" => Ok(Self::Cursor),
            "opencode" => Ok(Self::Opencode),
            "other" => Ok(Self::Other),
            _ => anyhow::bail!("invalid MCP agent kind in encrypted database"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpClient {
    pub id: Uuid,
    pub display_name: String,
    pub agent_kind: AgentKind,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    pub registration: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub authorized_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub session_expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Exact encrypted registration and operation captured before owner presence.
/// Fields are private so callers cannot substitute a different client or turn
/// a revoke prompt into removal.
pub struct OAuthClientManagementReview {
    expected: McpClient,
    grant_identity: [u8; 32],
    operation: AgentManagementOperation,
}

/// Single-use proof for one exact registered client and one exact operation.
pub struct OAuthClientManagementAuthorization {
    owner: OwnerAuthorization,
    expected: McpClient,
    grant_identity: [u8; 32],
    operation: AgentManagementOperation,
}

impl OAuthClientManagementAuthorization {
    /// Verify that this exact client-management proof authorized the expected
    /// operation before another core-owned setting mutation shares it.
    pub(crate) fn require_operation(
        &self,
        operation: AgentManagementOperation,
    ) -> Result<(), HumanPresenceError> {
        self.owner.require(OwnerAuthorizationScope::AgentAccess)?;
        if self.operation != operation {
            return Err(HumanPresenceError::Denied(
                "owner authorization was granted for a different client operation".into(),
            ));
        }
        Ok(())
    }
}

/// Authenticate the client and operation captured by core immediately before
/// the OS prompt. Applying the result consumes it and re-reads the same state.
pub async fn authorize_oauth_client_management(
    review: OAuthClientManagementReview,
) -> std::result::Result<OAuthClientManagementAuthorization, HumanPresenceError> {
    let owner = authorize_agent_management(&review.expected.display_name, review.operation).await?;
    Ok(OAuthClientManagementAuthorization {
        owner,
        expected: review.expected,
        grant_identity: review.grant_identity,
        operation: review.operation,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedClient {
    pub id: Uuid,
    pub display_name: String,
    pub agent_kind: AgentKind,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OAuthSecret([u8; 32]);

impl OAuthSecret {
    fn generate() -> Result<Self> {
        let mut bytes = [0_u8; 32];
        rand::rng()
            .try_fill_bytes(&mut bytes)
            .context("operating-system randomness is unavailable")?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn expose_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

pub struct OAuthAuthorizationCode {
    pub code: OAuthSecret,
    pub redirect_uri: String,
}

pub struct OAuthTokenPair {
    pub access_token: OAuthSecret,
    pub refresh_token: OAuthSecret,
    pub expires_in: u64,
    pub scope: String,
}

/// A dedicated connection to the one desktop `SQLCipher` database.
pub struct DesktopStore {
    connection: rusqlite::Connection,
}

impl DesktopStore {
    pub fn production(data_dir: &Path) -> Result<Self> {
        let store = PolicyStore::production(data_dir)?;
        Ok(Self {
            connection: store.connection,
        })
    }

    /// Open a desktop store with an explicit key. Intended for tests and
    /// offline inspection; production obtains the key from the v2 keychain
    /// identity through [`Self::production`].
    pub fn open(path: &Path, key: &DatabaseKey) -> Result<Self> {
        let store = PolicyStore::open(path, key)?;
        Ok(Self {
            connection: store.connection,
        })
    }

    pub fn setting<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let value: Option<String> = self
            .connection
            .query_row(
                "SELECT value_json FROM application_settings WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| serde_json::from_str(&value).context("invalid encrypted app setting"))
            .transpose()
    }

    pub(crate) fn set_setting<T: Serialize>(&mut self, key: &str, value: &T) -> Result<()> {
        ensure!(!key.is_empty() && key.len() <= 128, "invalid setting key");
        let value = serde_json::to_string(value)?;
        ensure!(value.len() <= 1_048_576, "application setting is too large");
        self.connection.execute(
            "INSERT INTO application_settings(key, value_json, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET
                 value_json = excluded.value_json,
                 updated_at = excluded.updated_at",
            params![key, value, Millis(Utc::now())],
        )?;
        Ok(())
    }

    pub fn detailed_notification_previews(&self) -> Result<bool> {
        // Detailed lifecycle notifications are the wallet's single supported
        // presentation. Keep the decision in core because notification
        // privacy is wallet-owned security state, even though there is no
        // longer a mutable UI preference for it.
        Ok(true)
    }

    pub fn set_detailed_notification_previews(
        &mut self,
        enabled: bool,
        authorization: &OwnerAuthorization,
    ) -> Result<()> {
        authorization.require(OwnerAuthorizationScope::NotificationPrivacy)?;
        self.set_setting("notification_detailed_previews", &enabled)
    }

    pub fn appearance_preference(&self) -> Result<AppearancePreference> {
        Ok(self.setting("appearance_preference")?.unwrap_or_default())
    }

    pub fn set_appearance_preference(&mut self, preference: AppearancePreference) -> Result<()> {
        self.set_setting("appearance_preference", &preference)
    }

    /// Whether owner-facing surfaces include networks explicitly classified
    /// as testnets and records linked to those networks.
    pub fn testnet_mode(&self) -> Result<bool> {
        Ok(self.setting("testnet_mode")?.unwrap_or(false))
    }

    pub fn set_testnet_mode(&mut self, enabled: bool) -> Result<()> {
        self.set_setting("testnet_mode", &enabled)
    }

    /// Record public OAuth client metadata. This does not authorize the client
    /// and creates no credential, so it deliberately requires no owner proof.
    pub fn register_oauth_client(
        &mut self,
        display_name: &str,
        agent_kind: AgentKind,
        redirect_uris: &[String],
        registration: Option<&serde_json::Value>,
    ) -> Result<McpClient> {
        let name = display_name.trim();
        ensure!(
            !name.is_empty() && name.chars().count() <= 100,
            "invalid client name"
        );
        ensure!(
            crate::sanitize::terminal_safe_line(name) == name,
            "OAuth client name contains invisible or control characters"
        );
        ensure!(
            !redirect_uris.is_empty() && redirect_uris.len() <= 16,
            "OAuth client must register between one and 16 redirect URIs"
        );
        for redirect_uri in redirect_uris {
            validate_redirect_uri(redirect_uri)?;
        }
        let redirect_uris_json = serde_json::to_string(redirect_uris)?;
        let registration = registration.map(serde_json::to_string).transpose()?;
        if let Some(value) = &registration {
            ensure!(value.len() <= 262_144, "managed registration is too large");
        }
        // Abandoned registrations are pruned only under count pressure, and
        // only once they are long stale. Agent harnesses cache the `client_id`
        // that dynamic registration returned and reuse it for every later
        // login without re-registering, so deleting a row on a timer the
        // client cannot observe locks that agent out permanently: its
        // `/authorize` calls fail against a `client_id` this wallet no longer
        // knows, and nothing in the protocol tells it to register again.
        let mut count: i64 =
            self.connection
                .query_row("SELECT count(*) FROM mcp_clients", [], |row| row.get(0))?;
        if count >= MAX_OAUTH_CLIENTS {
            self.connection.execute(
                "DELETE FROM mcp_clients
                 WHERE authorized_at IS NULL AND created_at < ?1",
                [Millis(Utc::now() - UNAUTHORIZED_CLIENT_RETENTION)],
            )?;
            count = self
                .connection
                .query_row("SELECT count(*) FROM mcp_clients", [], |row| row.get(0))?;
        }
        ensure!(
            count < MAX_OAUTH_CLIENTS,
            "OAuth client registration limit reached"
        );
        let client = McpClient {
            id: Uuid::new_v4(),
            display_name: name.to_owned(),
            agent_kind,
            redirect_uris: redirect_uris.to_vec(),
            registration: registration
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?,
            created_at: Utc::now(),
            authorized_at: None,
            last_used_at: None,
            session_expires_at: None,
            revoked_at: None,
        };
        self.connection.execute(
            "INSERT INTO mcp_clients(
                 client_id, display_name, agent_kind, redirect_uris_json,
                 registration_json, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                Blob(*client.id.as_bytes()),
                client.display_name,
                agent_kind.as_str(),
                redirect_uris_json,
                registration,
                Millis(client.created_at),
            ],
        )?;
        // Return the canonical persisted representation. SQLite stores these
        // timestamps at millisecond precision, so returning the pre-insert
        // value could make an immediate exact-identity comparison fail even
        // though no client state changed.
        Self::read_client(&self.connection, client.id, "new OAuth client disappeared")
    }

    pub fn oauth_client_for_authorization(
        &self,
        client_id: Uuid,
        redirect_uri: &str,
    ) -> Result<McpClient> {
        Self::oauth_client_for_authorization_on(&self.connection, client_id, redirect_uri)
    }

    fn read_client(
        connection: &rusqlite::Connection,
        client_id: Uuid,
        unknown: &str,
    ) -> Result<McpClient> {
        let (
            display_name,
            kind,
            redirects,
            registration,
            created_at,
            authorized_at,
            last_used_at,
            revoked_at,
        ) = connection
            .query_row(
                "SELECT display_name, agent_kind, redirect_uris_json,
                        registration_json, created_at, authorized_at,
                        last_used_at, revoked_at
                 FROM mcp_clients WHERE client_id = ?1",
                [Blob(*client_id.as_bytes())],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Millis>(4)?.0,
                        row.get::<_, Option<Millis>>(5)?.map(|value| value.0),
                        row.get::<_, Option<Millis>>(6)?.map(|value| value.0),
                        row.get::<_, Option<Millis>>(7)?.map(|value| value.0),
                    ))
                },
            )
            .optional()?
            .with_context(|| unknown.to_owned())?;
        Ok(McpClient {
            id: client_id,
            display_name,
            agent_kind: AgentKind::parse(&kind)?,
            redirect_uris: serde_json::from_str(&redirects)?,
            registration: registration
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?,
            created_at,
            authorized_at,
            last_used_at,
            session_expires_at: None,
            revoked_at,
        })
    }

    fn oauth_client_for_authorization_on(
        connection: &rusqlite::Connection,
        client_id: Uuid,
        redirect_uri: &str,
    ) -> Result<McpClient> {
        let client = Self::read_client(connection, client_id, "unknown OAuth client")?;
        ensure!(
            client
                .redirect_uris
                .iter()
                .any(|registered| redirect_uri_matches(registered, redirect_uri)),
            "OAuth redirect URI is not registered for this client"
        );
        Ok(client)
    }

    pub fn validate_oauth_authorization_request(
        &self,
        client_id: Uuid,
        redirect_uri: &str,
        code_challenge: &str,
        scope: &str,
        resource: &str,
    ) -> Result<McpClient> {
        let client = self.oauth_client_for_authorization(client_id, redirect_uri)?;
        validate_code_challenge(code_challenge)?;
        ensure!(scope == MCP_SCOPE, "unsupported OAuth scope");
        ensure!(
            resource == MCP_RESOURCE,
            "OAuth resource does not match MCP endpoint"
        );
        Ok(client)
    }

    pub fn issue_authorization_code_with_session(
        &mut self,
        client_id: Uuid,
        redirect_uri: &str,
        code_challenge: &str,
        scope: &str,
        resource: &str,
        session_preset: OAuthSessionPreset,
        expected: &McpClient,
        authorization: &OwnerAuthorization,
    ) -> Result<OAuthAuthorizationCode> {
        authorization.require(OwnerAuthorizationScope::AgentAccess)?;
        validate_code_challenge(code_challenge)?;
        ensure!(scope == MCP_SCOPE, "unsupported OAuth scope");
        ensure!(
            resource == MCP_RESOURCE,
            "OAuth resource does not match MCP endpoint"
        );
        let code = OAuthSecret::generate()?;
        let now = Utc::now();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current =
            Self::oauth_client_for_authorization_on(&transaction, client_id, redirect_uri)?;
        ensure!(
            Self::security_identity_matches(&current, expected),
            "OAuth client registration or grant changed after owner authentication"
        );
        let had_active_client = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM mcp_clients
                 WHERE authorized_at IS NOT NULL AND revoked_at IS NULL
             )",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        transaction.execute(
            "DELETE FROM oauth_authorization_codes WHERE expires_at <= ?1",
            [Millis(now)],
        )?;
        transaction.execute(
            "INSERT INTO oauth_authorization_codes(
                 code_hash, client_id, redirect_uri, code_challenge, scope,
                 resource, expires_at, session_expires_at, access_token_ttl_seconds
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                secret_hash(&code.0).as_slice(),
                Blob(*client_id.as_bytes()),
                redirect_uri,
                code_challenge,
                scope,
                resource,
                Millis(now + AUTHORIZATION_CODE_TTL),
                Millis(now + session_preset.refresh_duration()),
                session_preset.access_duration().num_seconds(),
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE mcp_clients SET authorized_at = ?1, revoked_at = NULL
             WHERE client_id = ?2",
            params![Millis(now), Blob(*client_id.as_bytes())],
        )?;
        ensure!(
            changed == 1,
            "OAuth client disappeared before authorization"
        );
        crate::launch_at_login::enable(authorization).context(
            "launch-at-login setup failed before any OAuth authorization code was issued",
        )?;
        if let Err(issue_error) = transaction.commit() {
            if !had_active_client {
                crate::launch_at_login::rollback_enable(authorization).with_context(|| {
                    format!(
                        "OAuth grant commit failed ({issue_error}) and the unused launch-at-login registration could not be removed"
                    )
                })?;
            }
            return Err(issue_error.into());
        }
        Ok(OAuthAuthorizationCode {
            code,
            redirect_uri: redirect_uri.to_owned(),
        })
    }

    fn security_identity_matches(current: &McpClient, expected: &McpClient) -> bool {
        current.id == expected.id
            && current.display_name == expected.display_name
            && current.agent_kind == expected.agent_kind
            && current.redirect_uris == expected.redirect_uris
            && current.registration == expected.registration
            && current.created_at == expected.created_at
            && current.authorized_at == expected.authorized_at
            && current.revoked_at == expected.revoked_at
    }

    /// Capture the exact client and grant state which one owner prompt will
    /// authorize. This is read-only; applying the proof re-reads it under the
    /// same transaction that performs the mutation.
    pub fn client_management_review(
        &self,
        client_id: Uuid,
        operation: AgentManagementOperation,
    ) -> Result<OAuthClientManagementReview> {
        let expected = Self::read_client(&self.connection, client_id, "unknown MCP client")?;
        Self::validate_client_management_state(&expected, operation)?;
        Ok(OAuthClientManagementReview {
            expected,
            grant_identity: Self::grant_identity_on(&self.connection, client_id)?,
            operation,
        })
    }

    fn validate_client_management_state(
        client: &McpClient,
        _operation: AgentManagementOperation,
    ) -> Result<()> {
        ensure!(
            client.authorized_at.is_some() && client.revoked_at.is_none(),
            "unknown, unauthorized, or already revoked MCP client"
        );
        Ok(())
    }

    /// Consume one exact client-management proof, re-read its registration and
    /// grant state after authentication, and mutate within that same immediate
    /// `SQLCipher` transaction.
    pub fn apply_client_management(
        &mut self,
        authorization: OAuthClientManagementAuthorization,
    ) -> Result<()> {
        let OAuthClientManagementAuthorization {
            owner,
            expected,
            grant_identity: expected_grant_identity,
            operation,
        } = authorization;
        owner.require(OwnerAuthorizationScope::AgentAccess)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = Self::read_client(&transaction, expected.id, "unknown MCP client")?;
        ensure!(
            Self::security_identity_matches(&current, &expected),
            "OAuth client registration or grant changed after owner authentication"
        );
        ensure!(
            Self::grant_identity_on(&transaction, expected.id)? == expected_grant_identity,
            "OAuth credentials changed after owner authentication"
        );
        Self::validate_client_management_state(&current, operation)?;

        match operation {
            AgentManagementOperation::Revoke => {
                let changed = transaction.execute(
                    "UPDATE mcp_clients SET revoked_at = ?1
                     WHERE client_id = ?2 AND authorized_at IS NOT NULL AND revoked_at IS NULL",
                    params![Millis(Utc::now()), Blob(*expected.id.as_bytes())],
                )?;
                ensure!(changed == 1, "unknown or already revoked MCP client");
                transaction.execute(
                    "DELETE FROM oauth_authorization_codes WHERE client_id = ?1",
                    [Blob(*expected.id.as_bytes())],
                )?;
                transaction.execute(
                    "DELETE FROM oauth_access_tokens WHERE client_id = ?1",
                    [Blob(*expected.id.as_bytes())],
                )?;
                transaction.execute(
                    "DELETE FROM oauth_refresh_tokens WHERE client_id = ?1",
                    [Blob(*expected.id.as_bytes())],
                )?;
            }
            AgentManagementOperation::Remove => {
                let changed = transaction.execute(
                    "DELETE FROM mcp_clients WHERE client_id = ?1",
                    [Blob(*expected.id.as_bytes())],
                )?;
                ensure!(changed == 1, "unknown MCP client");
            }
        }
        let any_active = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM mcp_clients
                 WHERE authorized_at IS NOT NULL AND revoked_at IS NULL
             )",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        let disabled_launch = if any_active {
            None
        } else {
            let authorization = OAuthClientManagementAuthorization {
                owner,
                expected,
                grant_identity: expected_grant_identity,
                operation,
            };
            crate::launch_at_login::disable_for_client_management(&authorization, operation)
                .context(
                    "launch-at-login persistence could not be removed before changing agent access",
                )?;
            Some(authorization)
        };
        if let Err(change_error) = transaction.commit() {
            if let Some(authorization) = disabled_launch.as_ref() {
                crate::launch_at_login::rollback_disable(authorization, operation).with_context(
                    || {
                        format!(
                            "agent access commit failed ({change_error}) and launch-at-login persistence could not be restored"
                        )
                    },
                )?;
            }
            return Err(change_error.into());
        }
        Ok(())
    }

    fn grant_identity_on(connection: &rusqlite::Connection, client_id: Uuid) -> Result<[u8; 32]> {
        fn field(digest: &mut Sha256, bytes: &[u8]) {
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        }
        fn integer(digest: &mut Sha256, value: i64) {
            field(digest, &value.to_be_bytes());
        }
        fn optional_integer(digest: &mut Sha256, value: Option<i64>) {
            match value {
                Some(value) => {
                    field(digest, &[1]);
                    integer(digest, value);
                }
                None => field(digest, &[0]),
            }
        }

        let client = Blob(*client_id.as_bytes());
        let mut digest = Sha256::new();
        digest.update(b"ekubo-oauth-grant-state-v1");

        let mut codes = connection.prepare(
            "SELECT code_hash, redirect_uri, code_challenge, scope, resource,
                    expires_at, session_expires_at, access_token_ttl_seconds, used_at
             FROM oauth_authorization_codes
             WHERE client_id = ?1
             ORDER BY code_hash",
        )?;
        let rows = codes.query_map([client], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<i64>>(8)?,
            ))
        })?;
        for row in rows {
            let (hash, redirect, challenge, scope, resource, expiry, session, ttl, used) = row?;
            field(&mut digest, b"code");
            for value in [
                hash.as_slice(),
                redirect.as_bytes(),
                challenge.as_bytes(),
                scope.as_bytes(),
                resource.as_bytes(),
            ] {
                field(&mut digest, value);
            }
            for value in [expiry, session, ttl] {
                integer(&mut digest, value);
            }
            optional_integer(&mut digest, used);
        }
        drop(codes);

        let mut access = connection.prepare(
            "SELECT token_hash, scope, resource, created_at, expires_at
             FROM oauth_access_tokens
             WHERE client_id = ?1
             ORDER BY token_hash",
        )?;
        let rows = access.query_map([client], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        for row in rows {
            let (hash, scope, resource, created, expiry) = row?;
            field(&mut digest, b"access");
            for value in [hash.as_slice(), scope.as_bytes(), resource.as_bytes()] {
                field(&mut digest, value);
            }
            integer(&mut digest, created);
            integer(&mut digest, expiry);
        }
        drop(access);

        let mut refresh = connection.prepare(
            "SELECT token_hash, family_id, scope, resource, created_at, expires_at,
                    access_token_ttl_seconds, consumed_at
             FROM oauth_refresh_tokens
             WHERE client_id = ?1
             ORDER BY token_hash",
        )?;
        let rows = refresh.query_map([client], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<i64>>(7)?,
            ))
        })?;
        for row in rows {
            let (hash, family, scope, resource, created, expiry, ttl, consumed) = row?;
            field(&mut digest, b"refresh");
            for value in [
                hash.as_slice(),
                family.as_slice(),
                scope.as_bytes(),
                resource.as_bytes(),
            ] {
                field(&mut digest, value);
            }
            for value in [created, expiry, ttl] {
                integer(&mut digest, value);
            }
            optional_integer(&mut digest, consumed);
        }

        Ok(digest.finalize().into())
    }

    pub fn exchange_authorization_code(
        &mut self,
        encoded_code: &str,
        client_id: Uuid,
        redirect_uri: &str,
        code_verifier: &str,
        resource: &str,
    ) -> Result<OAuthTokenPair> {
        ensure!(
            resource == MCP_RESOURCE,
            "OAuth resource does not match MCP endpoint"
        );
        let code_hash = decode_and_hash_secret(encoded_code)?;
        validate_code_verifier(code_verifier)?;
        let now = Utc::now();
        let stored = self
            .connection
            .query_row(
                "SELECT a.redirect_uri, a.code_challenge, a.scope, a.resource,
                        a.expires_at, a.session_expires_at,
                        a.access_token_ttl_seconds, a.used_at
                 FROM oauth_authorization_codes a
                 JOIN mcp_clients c ON c.client_id = a.client_id
                 WHERE a.code_hash = ?1 AND a.client_id = ?2
                   AND c.revoked_at IS NULL",
                params![code_hash.as_slice(), Blob(*client_id.as_bytes())],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Millis>(4)?.0,
                        row.get::<_, Millis>(5)?.0,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<Millis>>(7)?.map(|value| value.0),
                    ))
                },
            )
            .optional()?
            .context("invalid OAuth authorization code")?;
        ensure!(
            stored.0 == redirect_uri,
            "OAuth redirect URI changed during token exchange"
        );
        ensure!(
            stored.3 == resource,
            "OAuth authorization code has the wrong audience"
        );
        ensure!(
            stored.4 > now && stored.5 > now && stored.7.is_none(),
            "OAuth authorization code expired or was already used"
        );
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        ensure!(
            bool::from(challenge.as_bytes().ct_eq(stored.1.as_bytes())),
            "OAuth PKCE verification failed"
        );
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM oauth_access_tokens WHERE expires_at <= ?1",
            [Millis(now)],
        )?;
        transaction.execute(
            "DELETE FROM oauth_refresh_tokens WHERE expires_at <= ?1",
            [Millis(now)],
        )?;
        let changed = transaction.execute(
            "UPDATE oauth_authorization_codes SET used_at = ?1
             WHERE code_hash = ?2 AND used_at IS NULL",
            params![Millis(now), code_hash.as_slice()],
        )?;
        ensure!(changed == 1, "OAuth authorization code was already used");
        let pair = insert_token_pair(
            &transaction,
            client_id,
            &stored.2,
            resource,
            Uuid::new_v4(),
            now,
            stored.5,
            Duration::seconds(stored.6),
        )?;
        transaction.commit()?;
        Ok(pair)
    }

    pub fn refresh_access_token(
        &mut self,
        encoded_refresh_token: &str,
        client_id: Uuid,
        resource: &str,
    ) -> Result<OAuthTokenPair> {
        ensure!(
            resource == MCP_RESOURCE,
            "OAuth resource does not match MCP endpoint"
        );
        let token_hash = decode_and_hash_secret(encoded_refresh_token)?;
        let now = Utc::now();
        // Serialize observation, consumption, and successor minting. With a
        // deferred transaction two processes can both read an unused token
        // before either becomes the writer.
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = transaction
            .query_row(
                "SELECT t.scope, t.resource, t.expires_at, t.access_token_ttl_seconds,
                        t.consumed_at, t.family_id
                 FROM oauth_refresh_tokens t
                 JOIN mcp_clients c ON c.client_id = t.client_id
                 WHERE t.token_hash = ?1 AND t.client_id = ?2
                   AND c.revoked_at IS NULL",
                params![token_hash.as_slice(), Blob(*client_id.as_bytes())],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Millis>(2)?.0,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<Millis>>(4)?.map(|value| value.0),
                        Uuid::from_bytes(row.get::<_, Blob<[u8; 16]>>(5)?.0),
                    ))
                },
            )
            .optional()?
            .context("invalid OAuth refresh token")?;
        if stored.4.is_some() {
            // Schema v1 access tokens are not family-attributed. Revoke all
            // access tokens for this client as the conservative response,
            // then remove the compromised refresh family. Registration stays
            // intact so the owner can explicitly authorize it again.
            transaction.execute(
                "DELETE FROM oauth_access_tokens WHERE client_id = ?1",
                [Blob(*client_id.as_bytes())],
            )?;
            transaction.execute(
                "DELETE FROM oauth_refresh_tokens WHERE family_id = ?1",
                [Blob(*stored.5.as_bytes())],
            )?;
            transaction.commit()?;
            anyhow::bail!("OAuth refresh token reuse detected; its token family was revoked");
        }
        ensure!(
            stored.1 == resource && stored.2 > now,
            "OAuth session expired or has the wrong audience"
        );
        transaction.execute(
            "DELETE FROM oauth_access_tokens WHERE expires_at <= ?1",
            [Millis(now)],
        )?;
        transaction.execute(
            "DELETE FROM oauth_refresh_tokens WHERE expires_at <= ?1",
            [Millis(now)],
        )?;
        let changed = transaction.execute(
            "UPDATE oauth_refresh_tokens SET consumed_at = ?1
             WHERE token_hash = ?2 AND consumed_at IS NULL",
            params![Millis(now), token_hash.as_slice()],
        )?;
        ensure!(changed == 1, "OAuth refresh token was already consumed");
        let pair = insert_token_pair(
            &transaction,
            client_id,
            &stored.0,
            resource,
            stored.5,
            now,
            stored.2,
            Duration::seconds(stored.3),
        )?;
        transaction.commit()?;
        Ok(pair)
    }

    pub fn authenticate_access_token(
        &mut self,
        encoded: &str,
        resource: &str,
    ) -> Result<Option<AuthenticatedClient>> {
        let candidate = decode_and_hash_secret(encoded).unwrap_or([0_u8; 32]);
        let canonical = decode_and_hash_secret(encoded).is_ok();
        let now = Utc::now();
        let mut statement = self.connection.prepare(
            "SELECT c.client_id, c.display_name, c.agent_kind, t.token_hash
             FROM oauth_access_tokens t
             JOIN mcp_clients c ON c.client_id = t.client_id
             WHERE c.revoked_at IS NULL AND t.expires_at > ?1 AND t.resource = ?2
             ORDER BY c.client_id, t.token_hash",
        )?;
        let rows = statement.query_map(params![Millis(now), resource], |row| {
            Ok((
                Uuid::from_bytes(row.get::<_, Blob<[u8; 16]>>(0)?.0),
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;

        let mut found = None;
        for row in rows {
            let (id, display_name, kind, stored) = row?;
            if stored.len() == 32
                && bool::from(candidate.as_slice().ct_eq(stored.as_slice()))
                && canonical
            {
                found = Some(AuthenticatedClient {
                    id,
                    display_name,
                    agent_kind: AgentKind::parse(&kind)?,
                });
            }
        }
        drop(statement);
        if let Some(client) = &found {
            self.connection.execute(
                "UPDATE mcp_clients SET last_used_at = ?1 WHERE client_id = ?2",
                params![Millis(Utc::now()), Blob(*client.id.as_bytes())],
            )?;
        }
        Ok(found)
    }

    pub fn clients(&self) -> Result<Vec<McpClient>> {
        let mut statement = self.connection.prepare(
            "SELECT c.client_id, c.display_name, c.agent_kind, c.redirect_uris_json,
                    c.registration_json, c.created_at, c.authorized_at, c.last_used_at, c.revoked_at,
                    NULLIF(MAX(
                        COALESCE(
                            (SELECT MAX(t.expires_at)
                             FROM oauth_refresh_tokens t
                             WHERE t.client_id = c.client_id),
                            0
                        ),
                        COALESCE(
                            (SELECT MAX(a.session_expires_at)
                             FROM oauth_authorization_codes a
                             WHERE a.client_id = c.client_id),
                            0
                        )
                    ), 0) AS session_expires_at
             FROM mcp_clients c
             WHERE authorized_at IS NOT NULL AND revoked_at IS NULL
             ORDER BY c.created_at, c.client_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                Uuid::from_bytes(row.get::<_, Blob<[u8; 16]>>(0)?.0),
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Millis>(5)?.0,
                row.get::<_, Option<Millis>>(6)?.map(|value| value.0),
                row.get::<_, Option<Millis>>(7)?.map(|value| value.0),
                row.get::<_, Option<Millis>>(8)?.map(|value| value.0),
                row.get::<_, Option<Millis>>(9)?.map(|value| value.0),
            ))
        })?;
        rows.map(|row| {
            let (
                id,
                display_name,
                kind,
                redirects,
                registration,
                created_at,
                authorized_at,
                last_used_at,
                revoked_at,
                session_expires_at,
            ) = row?;
            Ok(McpClient {
                id,
                display_name,
                agent_kind: AgentKind::parse(&kind)?,
                redirect_uris: serde_json::from_str(&redirects)?,
                registration: registration
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()?,
                created_at,
                authorized_at,
                last_used_at,
                session_expires_at,
                revoked_at,
            })
        })
        .collect()
    }

    /// Which agent asked for each request, by request ID.
    ///
    /// Attribution is recorded when a client's call creates the row, and no
    /// agent-facing API reads it back: one client learning which other client
    /// asked for something is not part of what an agent is told. The owner is
    /// the one reader entitled to the answer, and their activity list is where
    /// the question gets asked.
    ///
    /// Revoked and never-authorized clients are named too, unlike
    /// [`Self::clients`]. This answers "who asked, at the time", and a record
    /// whose asker has since been revoked is exactly the one an owner most
    /// wants attributed.
    pub fn request_attributions(&self) -> Result<std::collections::BTreeMap<Uuid, String>> {
        let mut statement = self.connection.prepare(
            "SELECT request_id, requesting_harness_kind
             FROM (
                 SELECT request_id, requesting_harness_kind FROM pending_transactions
                 UNION ALL
                 SELECT request_id, requesting_harness_kind FROM pending_messages
                 UNION ALL
                 SELECT request_id, requesting_harness_kind FROM pending_typed_data
             ) WHERE requesting_harness_kind IS NOT NULL",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                Uuid::from_bytes(row.get::<_, Blob<[u8; 16]>>(0)?.0),
                row.get::<_, String>(1)?,
            ))
        })?;
        rows.map(|row| {
            let (request_id, harness) = row?;
            Ok((request_id, AgentKind::parse(&harness)?.label().to_owned()))
        })
        .collect()
    }

    pub fn attribute_transaction(&mut self, request_id: Uuid, harness: AgentKind) -> Result<()> {
        self.attribute_uuid("pending_transactions", request_id, harness)
    }

    pub fn attribute_typed_data(&mut self, request_id: Uuid, harness: AgentKind) -> Result<()> {
        self.attribute_uuid("pending_typed_data", request_id, harness)
    }

    pub fn attribute_message(&mut self, request_id: Uuid, harness: AgentKind) -> Result<()> {
        self.attribute_uuid("pending_messages", request_id, harness)
    }

    fn attribute_uuid(&mut self, table: &str, request_id: Uuid, harness: AgentKind) -> Result<()> {
        let sql = match table {
            "pending_transactions" => {
                "UPDATE pending_transactions SET requesting_harness_kind = ?1 WHERE request_id = ?2"
            }
            "pending_typed_data" => {
                "UPDATE pending_typed_data SET requesting_harness_kind = ?1 WHERE request_id = ?2"
            }
            "pending_messages" => {
                "UPDATE pending_messages SET requesting_harness_kind = ?1 WHERE request_id = ?2"
            }
            _ => anyhow::bail!("invalid attribution table"),
        };
        let changed = self
            .connection
            .execute(sql, params![harness.as_str(), Blob(*request_id.as_bytes())])?;
        ensure!(changed == 1, "request disappeared before attribution");
        Ok(())
    }

    pub fn attribute_policy_proposal(&mut self, wallet_id: &str, harness: AgentKind) -> Result<()> {
        let changed = self.connection.execute(
            "UPDATE policy_proposals SET requesting_harness_kind = ?1 WHERE wallet_id = ?2",
            params![harness.as_str(), wallet_id],
        )?;
        ensure!(
            changed == 1,
            "policy proposal disappeared before attribution"
        );
        Ok(())
    }

    pub fn attribute_network_proposal(&mut self, chain_id: u64, harness: AgentKind) -> Result<()> {
        let changed = self.connection.execute(
            "UPDATE network_proposals SET requesting_harness_kind = ?1 WHERE chain_id = ?2",
            params![
                harness.as_str(),
                i64::try_from(chain_id).context("chain ID out of range")?
            ],
        )?;
        ensure!(
            changed == 1,
            "network proposal disappeared before attribution"
        );
        Ok(())
    }

    pub fn attribute_token_proposals(
        &mut self,
        tokens: &[(u64, [u8; 20])],
        harness: AgentKind,
    ) -> Result<()> {
        let transaction = self.connection.transaction()?;
        for (chain_id, address) in tokens {
            transaction.execute(
                "UPDATE token_proposals SET requesting_harness_kind = ?1
                 WHERE chain_id = ?2 AND address = ?3",
                params![
                    harness.as_str(),
                    i64::try_from(*chain_id).context("chain ID out of range")?,
                    Blob(*address)
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}

fn validate_redirect_uri(value: &str) -> Result<()> {
    ensure!(value.len() <= 2_048, "OAuth redirect URI is too long");
    let parsed = url::Url::parse(value).context("OAuth redirect URI is invalid")?;
    ensure!(
        parsed.fragment().is_none() && parsed.username().is_empty() && parsed.password().is_none(),
        "OAuth redirect URI must not contain credentials or a fragment"
    );
    let local_http = parsed.scheme() == "http"
        && matches!(
            parsed.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
        );
    ensure!(
        (parsed.scheme() == "https" && parsed.host_str().is_some()) || local_http,
        "OAuth redirect URI must use HTTPS or an exact loopback HTTP host"
    );
    Ok(())
}

/// Native applications bind an ephemeral loopback port for every login. RFC
/// 8252 requires authorization servers to accept any port for an otherwise
/// matching loopback redirect; Claude Code can also resolve the loopback host
/// as either `localhost` or a numeric address between registration and use.
/// PKCE protects this relaxed port match, and the actual redirect remains
/// bound byte-for-byte to the issued authorization code and token exchange.
fn redirect_uri_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    let (Ok(mut registered), Ok(mut requested)) =
        (url::Url::parse(registered), url::Url::parse(requested))
    else {
        return false;
    };
    let is_loopback = |host: url::Host<&str>| match host {
        url::Host::Ipv4(address) => address.is_loopback(),
        url::Host::Ipv6(address) => address.is_loopback(),
        url::Host::Domain(host) => host.eq_ignore_ascii_case("localhost"),
    };
    if registered.scheme() != "http"
        || requested.scheme() != "http"
        || !registered.host().is_some_and(is_loopback)
        || !requested.host().is_some_and(is_loopback)
    {
        return false;
    }
    let _ = registered.set_host(Some("localhost"));
    let _ = requested.set_host(Some("localhost"));
    let _ = registered.set_port(None);
    let _ = requested.set_port(None);
    registered == requested
}

fn validate_code_challenge(value: &str) -> Result<()> {
    ensure!(
        value.len() == 43 && value.bytes().all(is_base64url),
        "OAuth PKCE S256 challenge must be canonical base64url"
    );
    Ok(())
}

fn validate_code_verifier(value: &str) -> Result<()> {
    ensure!(
        (43..=128).contains(&value.len())
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            }),
        "OAuth PKCE verifier is invalid"
    );
    Ok(())
}

const fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

fn secret_hash(secret: &[u8]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

fn decode_and_hash_secret(encoded: &str) -> Result<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .context("OAuth credential is not canonical base64url")?;
    ensure!(
        decoded.len() == 32 && URL_SAFE_NO_PAD.encode(&decoded) == encoded,
        "OAuth credential has an invalid encoding or length"
    );
    Ok(secret_hash(&decoded))
}

fn insert_token_pair(
    transaction: &rusqlite::Transaction<'_>,
    client_id: Uuid,
    scope: &str,
    resource: &str,
    family_id: Uuid,
    now: DateTime<Utc>,
    session_expires_at: DateTime<Utc>,
    access_token_ttl: Duration,
) -> Result<OAuthTokenPair> {
    ensure!(session_expires_at > now, "OAuth session already expired");
    let (access_token, expires_in) = insert_access_token(
        transaction,
        client_id,
        scope,
        resource,
        now,
        session_expires_at,
        access_token_ttl,
    )?;
    let refresh_token = OAuthSecret::generate()?;
    transaction.execute(
        "INSERT INTO oauth_refresh_tokens(
             token_hash, family_id, client_id, scope, resource, created_at,
             expires_at, access_token_ttl_seconds
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            secret_hash(&refresh_token.0).as_slice(),
            Blob(*family_id.as_bytes()),
            Blob(*client_id.as_bytes()),
            scope,
            resource,
            Millis(now),
            Millis(session_expires_at),
            access_token_ttl.num_seconds(),
        ],
    )?;
    Ok(OAuthTokenPair {
        access_token,
        refresh_token,
        expires_in,
        scope: scope.to_owned(),
    })
}

fn insert_access_token(
    transaction: &rusqlite::Transaction<'_>,
    client_id: Uuid,
    scope: &str,
    resource: &str,
    now: DateTime<Utc>,
    session_expires_at: DateTime<Utc>,
    access_token_ttl: Duration,
) -> Result<(OAuthSecret, u64)> {
    ensure!(session_expires_at > now, "OAuth session already expired");
    ensure!(
        access_token_ttl > Duration::zero(),
        "invalid access-token lifetime"
    );
    let access_token = OAuthSecret::generate()?;
    let access_expires_at = std::cmp::min(now + access_token_ttl, session_expires_at);
    transaction.execute(
        "INSERT INTO oauth_access_tokens(
             token_hash, client_id, scope, resource, created_at, expires_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            secret_hash(&access_token.0).as_slice(),
            Blob(*client_id.as_bytes()),
            scope,
            resource,
            Millis(now),
            Millis(access_expires_at),
        ],
    )?;
    Ok((
        access_token,
        u64::try_from((access_expires_at - now).num_seconds()).expect("positive token TTL"),
    ))
}

#[cfg(test)]
#[path = "desktop_store_test.rs"]
mod tests;
