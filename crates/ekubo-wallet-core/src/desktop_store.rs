//! Encrypted desktop settings and informational MCP harness attribution.

use crate::{
    human_presence::{OwnerAuthorization, OwnerAuthorizationScope},
    policy_store::{DatabaseKey, PolicyStore},
    sql::{Blob, Millis},
};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use rusqlite::{OptionalExtension as _, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::path::Path;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppearancePreference {
    #[default]
    System,
    Light,
    Dark,
}

/// What the guided setup remembers between runs.
///
/// Only two things need storing. Everything else about the checklist is
/// derived from the wallet's own state each time the window draws, so a box
/// can never disagree with the thing it claims to describe.
///
/// Completion latches, which is why it is stored at all rather than derived
/// afresh every time. A `WalletConnect` session ends when the dapp closes its
/// tab, and a signature history can be cleared; neither undoes the fact that
/// the owner has now done that thing once. A box that unticks itself reads as
/// a bug rather than as news.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuidedSetupState {
    /// Task identifiers seen finished, as the presenting layer names them.
    /// Unknown names are kept rather than dropped, so a downgrade does not
    /// silently reopen a task a later build had already closed.
    #[serde(default)]
    pub completed: std::collections::BTreeSet<String>,
    /// Set when the owner sends the card away. It never comes back.
    #[serde(default)]
    pub dismissed: bool,
}

/// Untrusted harness attribution supplied by the stdio bridge.
///
/// This value is never consulted for authorization. It exists only so the
/// owner-facing activity list can say, for example, "via Claude Desktop."
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Codex,
    ClaudeCode,
    ClaudeDesktop,
    GeminiCli,
    Cursor,
    Opencode,
    GrokBuild,
    Other,
}

impl AgentKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::ClaudeCode => "Claude Code",
            Self::ClaudeDesktop => "Claude Desktop",
            Self::GeminiCli => "Gemini CLI",
            Self::Cursor => "Cursor",
            Self::Opencode => "opencode",
            Self::GrokBuild => "Grok Build",
            Self::Other => "an unrecognized harness",
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude_code",
            Self::ClaudeDesktop => "claude_desktop",
            Self::GeminiCli => "gemini_cli",
            Self::Cursor => "cursor",
            Self::Opencode => "opencode",
            Self::GrokBuild => "grok_build",
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
            "grok_build" => Ok(Self::GrokBuild),
            "other" => Ok(Self::Other),
            _ => anyhow::bail!("invalid MCP harness kind in encrypted database"),
        }
    }
}

pub struct DesktopStore {
    pub(crate) connection: rusqlite::Connection,
}

impl DesktopStore {
    pub fn production(data_dir: &Path) -> Result<Self> {
        let store = PolicyStore::production(data_dir)?;
        Ok(Self {
            connection: store.connection,
        })
    }

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
        Ok(self
            .setting("notification_detailed_previews")?
            .unwrap_or(true))
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

    pub fn guided_setup(&self) -> Result<GuidedSetupState> {
        Ok(self.setting("guided_setup")?.unwrap_or_default())
    }

    pub fn set_guided_setup(&mut self, state: &GuidedSetupState) -> Result<()> {
        self.set_setting("guided_setup", state)
    }

    pub fn testnet_mode(&self) -> Result<bool> {
        Ok(self.setting("testnet_mode")?.unwrap_or(false))
    }

    pub fn set_testnet_mode(&mut self, enabled: bool) -> Result<()> {
        self.set_setting("testnet_mode", &enabled)
    }

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

#[cfg(test)]
#[path = "desktop_store_test.rs"]
mod tests;
