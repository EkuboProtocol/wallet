//! Desktop-only application settings and authenticated MCP client registry.
//!
//! Raw bearer tokens live in the `SQLCipher` database so an owner-approved
//! repair can rewrite a managed agent configuration. They are returned only
//! at registration or rotation and are never part of a client's metadata.

use crate::{
    policy_store::{DatabaseKey, PolicyStore},
    sql::{Blob, Millis},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::TryRng as _;
use rusqlite::{OptionalExtension as _, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::path::Path;
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DEFAULT_MCP_PORT_MIN: u16 = 49_152;
pub const DEFAULT_MCP_PORT_MAX: u16 = 65_535;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Codex,
    ClaudeCode,
    GeminiCli,
    Cursor,
    Opencode,
    Other,
}

impl AgentKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude_code",
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
    pub registration: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedClient {
    pub id: Uuid,
    pub display_name: String,
    pub agent_kind: AgentKind,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientToken([u8; 32]);

impl ClientToken {
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

pub struct RegisteredClient {
    pub client: McpClient,
    pub token: ClientToken,
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

    pub fn set_setting<T: Serialize>(&mut self, key: &str, value: &T) -> Result<()> {
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

    pub fn register_client(
        &mut self,
        display_name: &str,
        agent_kind: AgentKind,
        registration: Option<&serde_json::Value>,
    ) -> Result<RegisteredClient> {
        let name = display_name.trim();
        ensure!(
            !name.is_empty() && name.chars().count() <= 100,
            "invalid client name"
        );
        let registration = registration.map(serde_json::to_string).transpose()?;
        if let Some(value) = &registration {
            ensure!(value.len() <= 262_144, "managed registration is too large");
        }
        let token = ClientToken::generate()?;
        let client = McpClient {
            id: Uuid::new_v4(),
            display_name: name.to_owned(),
            agent_kind,
            registration: registration
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?,
            created_at: Utc::now(),
            last_used_at: None,
            revoked_at: None,
        };
        self.connection.execute(
            "INSERT INTO mcp_clients(
                 client_id, display_name, agent_kind, token, registration_json, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                Blob(*client.id.as_bytes()),
                client.display_name,
                agent_kind.as_str(),
                token.0.as_slice(),
                registration,
                Millis(client.created_at),
            ],
        )?;
        Ok(RegisteredClient { client, token })
    }

    pub fn rotate_client_token(&mut self, client_id: Uuid) -> Result<ClientToken> {
        let token = ClientToken::generate()?;
        let changed = self.connection.execute(
            "UPDATE mcp_clients SET token = ?1 WHERE client_id = ?2 AND revoked_at IS NULL",
            params![token.0.as_slice(), Blob(*client_id.as_bytes())],
        )?;
        ensure!(changed == 1, "unknown or revoked MCP client");
        Ok(token)
    }

    /// Recover an active managed client's token for an owner-approved repair.
    ///
    /// Callers must keep the returned value inside the configuration repair
    /// flow; it must never be displayed, logged, or included in diagnostics.
    pub fn repair_client_token(&self, client_id: Uuid) -> Result<ClientToken> {
        let stored: Vec<u8> = self
            .connection
            .query_row(
                "SELECT token FROM mcp_clients
                 WHERE client_id = ?1 AND revoked_at IS NULL",
                [Blob(*client_id.as_bytes())],
                |row| row.get(0),
            )
            .optional()?
            .context("unknown or revoked MCP client")?;
        let bytes: [u8; 32] = stored
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored MCP token has invalid length"))?;
        Ok(ClientToken(bytes))
    }

    pub fn revoke_client(&mut self, client_id: Uuid) -> Result<()> {
        let changed = self.connection.execute(
            "UPDATE mcp_clients SET revoked_at = ?1
             WHERE client_id = ?2 AND revoked_at IS NULL",
            params![Millis(Utc::now()), Blob(*client_id.as_bytes())],
        )?;
        ensure!(changed == 1, "unknown or already revoked MCP client");
        Ok(())
    }

    pub fn remove_client(&mut self, client_id: Uuid) -> Result<()> {
        let changed = self.connection.execute(
            "DELETE FROM mcp_clients WHERE client_id = ?1",
            params![Blob(*client_id.as_bytes())],
        )?;
        ensure!(changed == 1, "unknown MCP client");
        Ok(())
    }

    pub fn authenticate(&mut self, encoded: &str) -> Result<Option<AuthenticatedClient>> {
        // Decode into a fixed-sized candidate. Malformed inputs still execute
        // the same comparisons against every active row.
        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).ok();
        let canonical = decoded
            .as_deref()
            .is_some_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == encoded);
        let mut candidate = [0_u8; 32];
        if let Some(bytes) = decoded.as_deref().filter(|bytes| bytes.len() == 32) {
            candidate.copy_from_slice(bytes);
        }

        let mut statement = self.connection.prepare(
            "SELECT client_id, display_name, agent_kind, token
             FROM mcp_clients WHERE revoked_at IS NULL ORDER BY client_id",
        )?;
        let rows = statement.query_map([], |row| {
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
        candidate.zeroize();

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
            "SELECT client_id, display_name, agent_kind, registration_json,
                    created_at, last_used_at, revoked_at
             FROM mcp_clients ORDER BY created_at, client_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                Uuid::from_bytes(row.get::<_, Blob<[u8; 16]>>(0)?.0),
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Millis>(4)?.0,
                row.get::<_, Option<Millis>>(5)?.map(|value| value.0),
                row.get::<_, Option<Millis>>(6)?.map(|value| value.0),
            ))
        })?;
        rows.map(|row| {
            let (id, display_name, kind, registration, created_at, last_used_at, revoked_at) = row?;
            Ok(McpClient {
                id,
                display_name,
                agent_kind: AgentKind::parse(&kind)?,
                registration: registration
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()?,
                created_at,
                last_used_at,
                revoked_at,
            })
        })
        .collect()
    }

    pub fn attribute_transaction(&mut self, request_id: Uuid, client_id: Uuid) -> Result<()> {
        self.attribute_uuid("pending_transactions", request_id, client_id)
    }

    pub fn attribute_typed_data(&mut self, request_id: Uuid, client_id: Uuid) -> Result<()> {
        self.attribute_uuid("pending_typed_data", request_id, client_id)
    }

    pub fn attribute_message(&mut self, request_id: Uuid, client_id: Uuid) -> Result<()> {
        self.attribute_uuid("pending_messages", request_id, client_id)
    }

    fn attribute_uuid(&mut self, table: &str, request_id: Uuid, client_id: Uuid) -> Result<()> {
        let sql = match table {
            "pending_transactions" => {
                "UPDATE pending_transactions SET requesting_client_id = ?1 WHERE request_id = ?2"
            }
            "pending_typed_data" => {
                "UPDATE pending_typed_data SET requesting_client_id = ?1 WHERE request_id = ?2"
            }
            "pending_messages" => {
                "UPDATE pending_messages SET requesting_client_id = ?1 WHERE request_id = ?2"
            }
            _ => anyhow::bail!("invalid attribution table"),
        };
        let changed = self.connection.execute(
            sql,
            params![Blob(*client_id.as_bytes()), Blob(*request_id.as_bytes())],
        )?;
        ensure!(changed == 1, "request disappeared before attribution");
        Ok(())
    }

    pub fn attribute_policy_proposal(&mut self, wallet_id: &str, client_id: Uuid) -> Result<()> {
        let changed = self.connection.execute(
            "UPDATE policy_proposals SET requesting_client_id = ?1 WHERE wallet_id = ?2",
            params![Blob(*client_id.as_bytes()), wallet_id],
        )?;
        ensure!(
            changed == 1,
            "policy proposal disappeared before attribution"
        );
        Ok(())
    }

    pub fn attribute_network_proposal(&mut self, chain_id: u64, client_id: Uuid) -> Result<()> {
        let changed = self.connection.execute(
            "UPDATE network_proposals SET requesting_client_id = ?1 WHERE chain_id = ?2",
            params![
                Blob(*client_id.as_bytes()),
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
        client_id: Uuid,
    ) -> Result<()> {
        let transaction = self.connection.transaction()?;
        for (chain_id, address) in tokens {
            transaction.execute(
                "UPDATE token_proposals SET requesting_client_id = ?1
                 WHERE chain_id = ?2 AND address = ?3",
                params![
                    Blob(*client_id.as_bytes()),
                    i64::try_from(*chain_id).context("chain ID out of range")?,
                    Blob(*address)
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "desktop_store_test.rs"]
mod tests;
