//! Typed, transactional configuration adapters for supported agent hosts.

use anyhow::{Context, Result, ensure};
use directories::BaseDirs;
use ekubo_wallet_core::desktop_store::{AgentKind, MCP_RESOURCE};
use serde_json::{Map, Value, json};
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use toml_edit::{DocumentMut, Item, Table, value};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The key this wallet registers itself under in every agent's MCP config.
///
/// Underscores, not hyphens, because the key is not private to the config
/// file: harnesses derive the tool names the model sees from it. Codex
/// rewrites `-` to `_` when it builds those names, so a hyphenated key
/// reaches the model only as `ekubo_wallet__wallet_send_execution_plan`
/// while `resources/list` still expects the unsanitized key — a name the
/// model has then never been shown. That mismatch made the wallet's own
/// skill and security-model resources unreachable by name. An underscore
/// key survives the rewrite unchanged, so both spellings agree.
pub const LOCAL_SERVER_NAME: &str = "ekubo_wallet";
pub const COMPANION_SERVER_NAME: &str = "ekubo";
pub const COMPANION_SERVER_URL: &str = "https://mcp.ekubo.org/mcp";

pub struct AgentAdapter {
    pub kind: AgentKind,
    pub display_name: &'static str,
    pub config_path: PathBuf,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ConfigPreview {
    #[zeroize(skip)]
    pub path: PathBuf,
    before: String,
    after: String,
    diff: String,
    #[zeroize(skip)]
    validation: ConfigValidation,
}

struct InstalledConfig {
    path: PathBuf,
    existed: bool,
    before: zeroize::Zeroizing<String>,
}

/// A set of managed configuration writes that either all remain installed or
/// all return to their exact prior bytes. Prior contents live only in
/// zeroizing memory for the duration of the batch; agent configuration files
/// can contain credentials for unrelated services and must never be copied to
/// a persistent rollback file.
pub struct ConfigBatchInstall {
    installed: Vec<InstalledConfig>,
    committed: bool,
}

impl ConfigBatchInstall {
    pub fn install(previews: Vec<ConfigPreview>) -> Result<Self> {
        let mut batch = Self {
            installed: Vec::new(),
            committed: false,
        };
        for preview in previews {
            if !preview.has_changes() {
                preview.validate_current()?;
                continue;
            }
            let path = preview.path.clone();
            let existed = path.is_file();
            match preview.install() {
                Ok(before) => batch.installed.push(InstalledConfig {
                    path,
                    existed,
                    before,
                }),
                Err(error) => {
                    batch.rollback_best_effort();
                    batch.committed = true;
                    return Err(error).context(
                        "managed agent configuration batch failed; earlier files were restored",
                    );
                }
            }
        }
        Ok(batch)
    }

    pub fn commit(mut self) {
        self.committed = true;
    }

    fn rollback_best_effort(&self) {
        for installed in self.installed.iter().rev() {
            if installed.existed {
                let _ = write_atomic(&installed.path, installed.before.as_bytes());
            } else if installed.path.is_file() {
                let _ = fs::remove_file(&installed.path);
            }
        }
    }
}

impl Drop for ConfigBatchInstall {
    fn drop(&mut self) {
        if !self.committed {
            self.rollback_best_effort();
        }
    }
}

#[derive(Clone, Copy)]
enum ConfigValidation {
    Installed { kind: AgentKind, companion: bool },
}

impl ConfigPreview {
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.before != self.after
    }

    /// Verify that an unchanged file still contains the credential-free OAuth
    /// Streamable HTTP server shape.
    pub fn validate_current(&self) -> Result<()> {
        let installed = fs::read_to_string(&self.path)
            .context("failed to read installed agent configuration")?;
        ensure!(
            installed == self.after,
            "installed agent configuration changed before validation"
        );
        validate_document(&self.path, &installed)?;
        validate_server_shape(&installed, self.validation)
    }

    pub fn install(mut self) -> Result<zeroize::Zeroizing<String>> {
        let parent = self.path.parent().context("agent config has no parent")?;
        fs::create_dir_all(parent)?;
        let existed = self.path.is_file();

        write_atomic(&self.path, self.after.as_bytes())?;
        let validation = fs::read_to_string(&self.path)
            .context("failed to re-read installed agent configuration")
            .and_then(|installed| {
                ensure!(
                    installed == self.after,
                    "installed agent configuration changed during validation"
                );
                validate_document(&self.path, &installed)?;
                validate_server_shape(&installed, self.validation)
            });
        if let Err(error) = validation {
            if existed {
                write_atomic(&self.path, self.before.as_bytes())?;
            } else if self.path.is_file() {
                fs::remove_file(&self.path)?;
            }
            return Err(error)
                .context("agent configuration validation failed; prior bytes restored");
        }
        let before = zeroize::Zeroizing::new(std::mem::take(&mut self.before));
        self.after.zeroize();
        self.diff.zeroize();
        Ok(before)
    }
}

impl AgentAdapter {
    pub fn supported() -> Result<Vec<Self>> {
        let base = BaseDirs::new().context("could not determine the user home directory")?;
        let home = base.home_dir();
        Ok(vec![
            Self {
                kind: AgentKind::Codex,
                display_name: "Codex",
                config_path: home.join(".codex/config.toml"),
            },
            Self {
                kind: AgentKind::ClaudeCode,
                display_name: "Claude Code",
                config_path: home.join(".claude.json"),
            },
            Self {
                kind: AgentKind::GeminiCli,
                display_name: "Gemini CLI",
                config_path: home.join(".gemini/settings.json"),
            },
            Self {
                kind: AgentKind::Cursor,
                display_name: "Cursor",
                config_path: home.join(".cursor/mcp.json"),
            },
            Self {
                kind: AgentKind::Opencode,
                display_name: "opencode",
                config_path: base.config_dir().join("opencode/opencode.json"),
            },
        ])
    }

    #[must_use]
    pub fn detected(&self) -> bool {
        self.config_path.exists()
            || match self.kind {
                AgentKind::Codex => binary_on_path("codex"),
                AgentKind::ClaudeCode => binary_on_path("claude"),
                AgentKind::GeminiCli => binary_on_path("gemini"),
                AgentKind::Cursor => self
                    .config_path
                    .parent()
                    .is_some_and(std::path::Path::exists),
                AgentKind::Opencode => binary_on_path("opencode"),
                AgentKind::Other => false,
            }
    }

    pub fn preview_install(&self, install_companion: bool) -> Result<ConfigPreview> {
        let before = match fs::read_to_string(&self.config_path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        let url = MCP_RESOURCE;
        let after = match self.kind {
            AgentKind::Codex => merge_codex(&before, url, install_companion)?,
            AgentKind::ClaudeCode | AgentKind::Cursor => merge_json(
                &before,
                "mcpServers",
                JsonShape::Url,
                url,
                install_companion,
            )?,
            AgentKind::GeminiCli => merge_json(
                &before,
                "mcpServers",
                JsonShape::HttpUrl,
                url,
                install_companion,
            )?,
            AgentKind::Opencode => {
                merge_json(&before, "mcp", JsonShape::Remote, url, install_companion)?
            }
            AgentKind::Other => anyhow::bail!("unsupported agent configuration"),
        };
        let diff = managed_config_diff(self.kind, &before, &after)?;
        Ok(ConfigPreview {
            path: self.config_path.clone(),
            before,
            after,
            diff,
            validation: ConfigValidation::Installed {
                kind: self.kind,
                companion: install_companion,
            },
        })
    }
}

fn binary_on_path(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|directory| directory.join(name).is_file())
    })
}

fn merge_codex(before: &str, url: &str, companion: bool) -> Result<String> {
    let mut document = if before.trim().is_empty() {
        DocumentMut::new()
    } else {
        before
            .parse::<DocumentMut>()
            .context("Codex config is not valid TOML")?
    };
    // This wallet's OAuth credentials authorize signing requests. Never let
    // Codex's `auto` mode fall back to its file credential store.
    document["mcp_oauth_credentials_store"] = value("keyring");
    let servers = document
        .as_table_mut()
        .entry("mcp_servers")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .context("Codex mcp_servers configuration must be a table")?;
    let local = servers
        .entry(LOCAL_SERVER_NAME)
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .context("Codex MCP server configuration must be a table")?;
    // Nothing but the loopback URL and OAuth mode may survive in this entry.
    // A stdio field would contradict the transport we just wrote, and a
    // header or token field is a static credential this wallet never accepts
    // — whether it arrived by hand, by another tool, or by an attacker.
    for conflicting_key in [
        "command",
        "args",
        "env",
        "env_vars",
        "cwd",
        "experimental_environment",
        "bearer_token_env_var",
        "http_headers",
        "env_http_headers",
    ] {
        local.remove(conflicting_key);
    }
    local["url"] = value(url);
    local["auth"] = value("oauth");
    if companion {
        let remote = servers
            .entry(COMPANION_SERVER_NAME)
            .or_insert_with(|| Item::Table(Table::new()))
            .as_table_mut()
            .context("Codex companion MCP configuration must be a table")?;
        remote["url"] = value(COMPANION_SERVER_URL);
    }
    Ok(document.to_string())
}

#[derive(Clone, Copy)]
enum JsonShape {
    Url,
    HttpUrl,
    Remote,
}

fn merge_json(
    before: &str,
    root: &str,
    shape: JsonShape,
    url: &str,
    companion: bool,
) -> Result<String> {
    let mut document: Value = if before.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(before).context("agent config is not valid JSON")?
    };
    let top = document
        .as_object_mut()
        .context("agent config must be a JSON object")?;
    let servers = top
        .entry(root)
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .context("agent MCP configuration must be an object")?;
    let local = match shape {
        JsonShape::Url => json!({"type": "http", "url": url}),
        JsonShape::HttpUrl => json!({"httpUrl": url}),
        JsonShape::Remote => json!({"type": "remote", "url": url}),
    };
    servers.insert(LOCAL_SERVER_NAME.into(), local);
    if companion {
        let remote = match shape {
            JsonShape::Url => json!({"type": "http", "url": COMPANION_SERVER_URL}),
            JsonShape::HttpUrl => json!({"httpUrl": COMPANION_SERVER_URL}),
            JsonShape::Remote => json!({"type": "remote", "url": COMPANION_SERVER_URL}),
        };
        servers.insert(COMPANION_SERVER_NAME.into(), remote);
    }
    Ok(format!("{}\n", serde_json::to_string_pretty(&document)?))
}

fn managed_config_diff(kind: AgentKind, before: &str, after: &str) -> Result<String> {
    let mut changes = Vec::new();
    match kind {
        AgentKind::Codex => {
            let before = parse_codex_document(before)?;
            let after = parse_codex_document(after)?;
            push_managed_change(
                &mut changes,
                "mcp_oauth_credentials_store",
                codex_value(&before, None, "mcp_oauth_credentials_store"),
                codex_value(&after, None, "mcp_oauth_credentials_store"),
            );
            for server in [LOCAL_SERVER_NAME, COMPANION_SERVER_NAME] {
                push_managed_change(
                    &mut changes,
                    &format!("mcp_servers.{server}"),
                    codex_value(&before, Some("mcp_servers"), server),
                    codex_value(&after, Some("mcp_servers"), server),
                );
            }
        }
        AgentKind::ClaudeCode | AgentKind::GeminiCli | AgentKind::Cursor | AgentKind::Opencode => {
            let root = if kind == AgentKind::Opencode {
                "mcp"
            } else {
                "mcpServers"
            };
            let before = parse_json_document(before)?;
            let after = parse_json_document(after)?;
            for server in [LOCAL_SERVER_NAME, COMPANION_SERVER_NAME] {
                push_managed_change(
                    &mut changes,
                    &format!("{root}.{server}"),
                    json_value(&before, root, server),
                    json_value(&after, root, server),
                );
            }
        }
        AgentKind::Other => anyhow::bail!("unsupported agent configuration"),
    }
    if changes.is_empty() {
        return Ok("No wallet-managed fields will change.".into());
    }
    Ok(format!(
        "Only wallet-managed fields are shown; unrelated settings remain unchanged.\n\n{}",
        changes.join("\n\n")
    ))
}

fn parse_codex_document(contents: &str) -> Result<DocumentMut> {
    if contents.trim().is_empty() {
        Ok(DocumentMut::new())
    } else {
        contents
            .parse::<DocumentMut>()
            .context("Codex config is not valid TOML")
    }
}

fn codex_value(document: &DocumentMut, table: Option<&str>, key: &str) -> Option<String> {
    let item = match table {
        Some(table) => document
            .get(table)
            .and_then(Item::as_table)
            .and_then(|table| table.get(key)),
        None => document.get(key),
    }?;
    Some(redact_toml_credentials(&item.to_string()))
}

fn redact_toml_credentials(contents: &str) -> String {
    contents
        .lines()
        .map(|line| {
            let key = line.split('=').next().unwrap_or_default();
            if sensitive_config_key(key) {
                format!(
                    "{}<credential field redacted>",
                    " ".repeat(line.len() - line.trim_start().len())
                )
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_json_document(contents: &str) -> Result<Value> {
    if contents.trim().is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_str(contents).context("agent config is not valid JSON")
    }
}

fn json_value(document: &Value, root: &str, server: &str) -> Option<String> {
    let mut value = document.get(root)?.get(server)?.clone();
    redact_json_credentials(&mut value);
    serde_json::to_string_pretty(&value).ok()
}

fn redact_json_credentials(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if sensitive_config_key(key) {
                    *value = Value::String("<credential field redacted>".into());
                } else {
                    redact_json_credentials(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_json_credentials(value);
            }
        }
        _ => {}
    }
}

fn sensitive_config_key(key: &str) -> bool {
    let key = key.trim().trim_matches(['"', '\'']).to_ascii_lowercase();
    [
        "authorization",
        "bearer",
        "credential",
        "env",
        "header",
        "password",
        "secret",
        "token",
    ]
    .iter()
    .any(|marker| key.contains(marker))
}

fn push_managed_change(
    changes: &mut Vec<String>,
    path: &str,
    before: Option<String>,
    after: Option<String>,
) {
    if before == after {
        return;
    }
    let before = before.unwrap_or_else(|| "<not configured>".into());
    let after = after.unwrap_or_else(|| "<not configured>".into());
    changes.push(format!("{path}\n- {before}\n+ {after}"));
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("agent config has no parent")?;
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

fn validate_document(path: &Path, contents: &str) -> Result<()> {
    if path.extension().and_then(|value| value.to_str()) == Some("toml") {
        contents.parse::<DocumentMut>()?;
    } else {
        serde_json::from_str::<Value>(contents)?;
    }
    Ok(())
}

fn validate_server_shape(contents: &str, validation: ConfigValidation) -> Result<()> {
    let ConfigValidation::Installed { kind, companion } = validation;
    match kind {
        AgentKind::Codex => validate_codex_shape(contents, companion),
        AgentKind::ClaudeCode | AgentKind::GeminiCli | AgentKind::Cursor | AgentKind::Opencode => {
            validate_json_shape(contents, kind, companion)
        }
        AgentKind::Other => anyhow::bail!("unsupported agent configuration"),
    }
}

fn validate_codex_shape(contents: &str, companion: bool) -> Result<()> {
    let document = contents
        .parse::<DocumentMut>()
        .context("Codex config is not valid TOML")?;
    ensure!(
        document
            .get("mcp_oauth_credentials_store")
            .and_then(Item::as_str)
            == Some("keyring"),
        "Codex must store wallet OAuth credentials in the OS keyring"
    );
    let servers = document.get("mcp_servers").and_then(Item::as_table);
    let local = servers.and_then(|servers| servers.get(LOCAL_SERVER_NAME));
    let local = local.context("local MCP server is missing")?;
    ensure!(
        local.get("command").is_none(),
        "local MCP server still uses stdio"
    );
    let url = local
        .get("url")
        .and_then(Item::as_str)
        .context("local MCP server has no HTTP URL")?;
    validate_loopback_url(url)?;
    ensure!(
        local.get("auth").and_then(Item::as_str) == Some("oauth"),
        "Codex MCP server is not configured for OAuth"
    );
    ensure!(
        local.get("http_headers").is_none()
            && local.get("env_http_headers").is_none()
            && local.get("bearer_token_env_var").is_none(),
        "Codex MCP server configuration contains a credential source"
    );
    if companion {
        ensure!(
            document["mcp_servers"][COMPANION_SERVER_NAME]["url"].as_str()
                == Some(COMPANION_SERVER_URL),
            "companion MCP server URL is missing"
        );
    }
    Ok(())
}

fn validate_json_shape(contents: &str, kind: AgentKind, companion: bool) -> Result<()> {
    let document: Value =
        serde_json::from_str(contents).context("agent config is not valid JSON")?;
    let root = if kind == AgentKind::Opencode {
        "mcp"
    } else {
        "mcpServers"
    };
    let servers = document.get(root).and_then(Value::as_object);
    let local = servers.and_then(|servers| servers.get(LOCAL_SERVER_NAME));
    let local = local.context("local MCP server is missing")?;
    ensure!(
        local.get("command").is_none(),
        "local MCP server still uses stdio"
    );
    let url_key = if kind == AgentKind::GeminiCli {
        "httpUrl"
    } else {
        "url"
    };
    let url = local
        .get(url_key)
        .and_then(Value::as_str)
        .context("local MCP server has no HTTP URL")?;
    validate_loopback_url(url)?;
    ensure!(
        local.get("headers").is_none()
            && local.get("env").is_none()
            && local.get("bearerToken").is_none(),
        "local MCP server configuration contains credentials"
    );
    if companion {
        ensure!(
            document[root][COMPANION_SERVER_NAME][url_key].as_str() == Some(COMPANION_SERVER_URL),
            "companion MCP server URL is missing"
        );
    }
    Ok(())
}

fn validate_loopback_url(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url).context("local MCP server URL is invalid")?;
    ensure!(
        parsed.scheme() == "http"
            && parsed.host_str() == Some("127.0.0.1")
            && parsed.port().is_some()
            && parsed.path() == "/mcp"
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "local MCP server URL is not the expected loopback endpoint"
    );
    Ok(())
}

#[cfg(test)]
#[path = "agent_config_test.rs"]
mod tests;
