//! Typed, transactional configuration adapters for supported agent hosts.

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use directories::BaseDirs;
use ekubo_wallet_core::desktop_store::AgentKind;
use serde_json::{Map, Value, json};
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use toml_edit::{DocumentMut, InlineTable, Item, Table, Value as TomlValue, value};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const LOCAL_SERVER_NAME: &str = "ekubo-wallet";
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

#[derive(Clone, Copy)]
enum ConfigValidation {
    Installed { kind: AgentKind, companion: bool },
    Removed { kind: AgentKind, companion: bool },
}

impl ConfigPreview {
    #[must_use]
    pub fn exact_diff(&self) -> &str {
        &self.diff
    }

    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.before != self.after
    }

    /// Verify that an unchanged file still contains the complete authenticated
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

    /// Conceal a bearer token in the human-facing diff while retaining it in
    /// the in-memory document that will be atomically installed.
    pub fn redact_diff_secret(&mut self, secret: &str) {
        self.diff = self.diff.replace(secret, "<redacted-token>");
    }

    pub fn install(mut self) -> Result<PathBuf> {
        let parent = self.path.parent().context("agent config has no parent")?;
        fs::create_dir_all(parent)?;
        let backup = if self.path.is_file() {
            let stamp = Utc::now().format("%Y%m%dT%H%M%S%.9fZ");
            let name = self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .context("agent config filename is not UTF-8")?;
            let backup = self.path.with_file_name(format!("{name}.backup-{stamp}"));
            fs::copy(&self.path, &backup).with_context(|| {
                format!("failed to back up agent config as {}", backup.display())
            })?;
            Some(backup)
        } else {
            None
        };

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
            if let Some(backup) = &backup {
                let prior = fs::read(backup)?;
                write_atomic(&self.path, &prior)?;
            } else if self.path.is_file() {
                fs::remove_file(&self.path)?;
            }
            return Err(error).context("agent configuration validation failed; backup restored");
        }
        self.before.zeroize();
        self.after.zeroize();
        self.diff.zeroize();
        Ok(backup.unwrap_or_default())
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

    pub fn preview_install(
        &self,
        port: u16,
        token: &str,
        install_companion: bool,
    ) -> Result<ConfigPreview> {
        ensure!(
            token.len() == 43 && token.bytes().all(is_base64url),
            "MCP token is not an unpadded base64url 256-bit value"
        );
        let before = match fs::read_to_string(&self.config_path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        let url = format!("http://127.0.0.1:{port}/mcp");
        let after = match self.kind {
            AgentKind::Codex => merge_codex(&before, &url, token, install_companion)?,
            AgentKind::ClaudeCode | AgentKind::Cursor => merge_json(
                &before,
                "mcpServers",
                JsonShape::Url,
                &url,
                token,
                install_companion,
            )?,
            AgentKind::GeminiCli => merge_json(
                &before,
                "mcpServers",
                JsonShape::HttpUrl,
                &url,
                token,
                install_companion,
            )?,
            AgentKind::Opencode => merge_json(
                &before,
                "mcp",
                JsonShape::Remote,
                &url,
                token,
                install_companion,
            )?,
            AgentKind::Other => anyhow::bail!("unsupported agent configuration"),
        };
        let diff = exact_diff(&before, &after);
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

    pub fn preview_remove(&self, remove_companion: bool) -> Result<ConfigPreview> {
        let before = fs::read_to_string(&self.config_path)?;
        let after = match self.kind {
            AgentKind::Codex => remove_codex(&before, remove_companion)?,
            AgentKind::ClaudeCode | AgentKind::GeminiCli | AgentKind::Cursor => {
                remove_json(&before, "mcpServers", remove_companion)?
            }
            AgentKind::Opencode => remove_json(&before, "mcp", remove_companion)?,
            AgentKind::Other => anyhow::bail!("unsupported agent configuration"),
        };
        let diff = exact_diff(&before, &after);
        Ok(ConfigPreview {
            path: self.config_path.clone(),
            before,
            after,
            diff,
            validation: ConfigValidation::Removed {
                kind: self.kind,
                companion: remove_companion,
            },
        })
    }
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

fn binary_on_path(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|directory| directory.join(name).is_file())
    })
}

fn merge_codex(before: &str, url: &str, token: &str, companion: bool) -> Result<String> {
    let mut document = if before.trim().is_empty() {
        DocumentMut::new()
    } else {
        before
            .parse::<DocumentMut>()
            .context("Codex config is not valid TOML")?
    };
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
    for legacy_key in [
        "command",
        "args",
        "env",
        "env_vars",
        "cwd",
        "experimental_environment",
        "bearer_token_env_var",
        "env_http_headers",
    ] {
        local.remove(legacy_key);
    }
    local["url"] = value(url);
    let mut headers = InlineTable::new();
    headers.insert("Authorization", TomlValue::from(format!("Bearer {token}")));
    local["http_headers"] = Item::Value(TomlValue::InlineTable(headers));
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

fn remove_codex(before: &str, companion: bool) -> Result<String> {
    let mut document = before
        .parse::<DocumentMut>()
        .context("Codex config is not valid TOML")?;
    if let Some(servers) = document.get_mut("mcp_servers").and_then(Item::as_table_mut) {
        servers.remove(LOCAL_SERVER_NAME);
        if companion {
            servers.remove(COMPANION_SERVER_NAME);
        }
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
    token: &str,
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
    let authorization = format!("Bearer {token}");
    let local = match shape {
        JsonShape::Url => {
            json!({"type": "http", "url": url, "headers": {"Authorization": authorization}})
        }
        JsonShape::HttpUrl => json!({"httpUrl": url, "headers": {"Authorization": authorization}}),
        JsonShape::Remote => {
            json!({"type": "remote", "url": url, "headers": {"Authorization": authorization}})
        }
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

fn remove_json(before: &str, root: &str, companion: bool) -> Result<String> {
    let mut document: Value =
        serde_json::from_str(before).context("agent config is not valid JSON")?;
    if let Some(servers) = document.get_mut(root).and_then(Value::as_object_mut) {
        servers.remove(LOCAL_SERVER_NAME);
        if companion {
            servers.remove(COMPANION_SERVER_NAME);
        }
    }
    Ok(format!("{}\n", serde_json::to_string_pretty(&document)?))
}

fn exact_diff(before: &str, after: &str) -> String {
    format!("--- current\n+++ proposed\n@@ exact files @@\n-{before}\n+{after}")
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
    let (kind, companion, installed) = match validation {
        ConfigValidation::Installed { kind, companion } => (kind, companion, true),
        ConfigValidation::Removed { kind, companion } => (kind, companion, false),
    };
    match kind {
        AgentKind::Codex => validate_codex_shape(contents, installed, companion),
        AgentKind::ClaudeCode | AgentKind::GeminiCli | AgentKind::Cursor | AgentKind::Opencode => {
            validate_json_shape(contents, kind, installed, companion)
        }
        AgentKind::Other => anyhow::bail!("unsupported agent configuration"),
    }
}

fn validate_codex_shape(contents: &str, installed: bool, companion: bool) -> Result<()> {
    let document = contents
        .parse::<DocumentMut>()
        .context("Codex config is not valid TOML")?;
    let servers = document.get("mcp_servers").and_then(Item::as_table);
    let local = servers.and_then(|servers| servers.get(LOCAL_SERVER_NAME));
    if !installed {
        ensure!(local.is_none(), "local MCP server was not removed");
        if companion {
            ensure!(
                servers
                    .and_then(|servers| servers.get(COMPANION_SERVER_NAME))
                    .is_none(),
                "companion MCP server was not removed"
            );
        }
        return Ok(());
    }

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
    let authorization = local
        .get("http_headers")
        .and_then(Item::as_inline_table)
        .and_then(|headers| headers.get("Authorization"))
        .and_then(TomlValue::as_str)
        .context("local MCP server has no static Authorization header")?;
    validate_authorization(authorization)?;
    if companion {
        ensure!(
            document["mcp_servers"][COMPANION_SERVER_NAME]["url"].as_str()
                == Some(COMPANION_SERVER_URL),
            "companion MCP server URL is missing"
        );
    }
    Ok(())
}

fn validate_json_shape(
    contents: &str,
    kind: AgentKind,
    installed: bool,
    companion: bool,
) -> Result<()> {
    let document: Value =
        serde_json::from_str(contents).context("agent config is not valid JSON")?;
    let root = if kind == AgentKind::Opencode {
        "mcp"
    } else {
        "mcpServers"
    };
    let servers = document.get(root).and_then(Value::as_object);
    let local = servers.and_then(|servers| servers.get(LOCAL_SERVER_NAME));
    if !installed {
        ensure!(local.is_none(), "local MCP server was not removed");
        if companion {
            ensure!(
                servers
                    .and_then(|servers| servers.get(COMPANION_SERVER_NAME))
                    .is_none(),
                "companion MCP server was not removed"
            );
        }
        return Ok(());
    }

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
    let authorization = local
        .get("headers")
        .and_then(Value::as_object)
        .and_then(|headers| headers.get("Authorization"))
        .and_then(Value::as_str)
        .context("local MCP server has no static Authorization header")?;
    validate_authorization(authorization)?;
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

fn validate_authorization(value: &str) -> Result<()> {
    let token = value
        .strip_prefix("Bearer ")
        .context("local MCP Authorization header is not a bearer token")?;
    ensure!(
        token.len() == 43 && token.bytes().all(is_base64url),
        "local MCP Authorization header does not contain a 256-bit token"
    );
    Ok(())
}

#[cfg(test)]
#[path = "agent_config_test.rs"]
mod tests;
