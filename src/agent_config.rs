//! Typed, transactional configuration adapters for supported agent hosts.

use anyhow::{Context, Result, ensure};
use directories::BaseDirs;
use ekubo_wallet_core::desktop_store::AgentKind;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command;
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
/// The credential-free hosted companion installed beside the wallet server.
pub const COMPANION_SERVER_NAME: &str = "ekubo";
pub const COMPANION_SERVER_URL: &str = "https://mcp.ekubo.org/mcp";
#[cfg(not(target_os = "macos"))]
const BRIDGE_SHA256: &str = env!("EKUBO_COMPILED_MCP_BRIDGE_SHA256");

fn installed_bridge_path() -> Result<PathBuf> {
    let data_dir = ekubo_wallet_core::config::default_data_dir()?;
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    Ok(data_dir.join("helpers").join(format!(
        "ekubo-wallet-mcp-bridge-{}{}",
        env!("CARGO_PKG_VERSION"),
        suffix
    )))
}

/// Verify the packaged bridge bytes and atomically install the versioned helper
/// in the wallet's private per-user directory. Release builds only accept the
/// helper shipped beside the wallet executable; debug builds may use the
/// workspace build-tree binary.
pub fn install_bridge_helper() -> Result<PathBuf> {
    let installed = installed_bridge_path()?;
    let executable = std::env::current_exe().context("could not locate the wallet executable")?;
    let filename = if cfg!(windows) {
        "ekubo-wallet-mcp-bridge.exe"
    } else {
        "ekubo-wallet-mcp-bridge"
    };
    let packaged = executable.with_file_name(filename);
    #[cfg(debug_assertions)]
    let source = if packaged.is_file() {
        packaged.clone()
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/debug")
            .join(filename)
    };
    #[cfg(not(debug_assertions))]
    let source = packaged;
    ensure!(source.is_file(), "the packaged MCP bridge is missing");
    let bytes = fs::read(&source).context("failed to read the packaged MCP bridge")?;
    ensure!(!bytes.is_empty(), "the packaged MCP bridge is empty");
    let digest = hex::encode(Sha256::digest(&bytes));
    #[cfg(all(debug_assertions, target_os = "macos"))]
    let unsigned_build_tree = source != packaged;
    #[cfg(all(debug_assertions, not(target_os = "macos")))]
    let unsigned_build_tree = source != packaged && BRIDGE_SHA256.is_empty();
    #[cfg(not(debug_assertions))]
    let unsigned_build_tree = false;
    verify_packaged_bridge(&source, &digest, unsigned_build_tree)?;
    if installed.is_file() && fs::read(&installed)? == bytes {
        return Ok(installed);
    }
    let parent = installed.parent().context("helper path has no parent")?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    temporary.persist(&installed).map_err(|error| error.error)?;
    ensure!(
        fs::read(&installed)? == bytes,
        "installed MCP bridge failed verification"
    );
    Ok(installed)
}

fn verify_packaged_bridge(source: &Path, digest: &str, unsigned_build_tree: bool) -> Result<()> {
    if unsigned_build_tree {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let _ = digest;
        let status = Command::new("/usr/bin/codesign")
            .args([
                "--verify",
                "--strict",
                "--test-requirement",
                "=anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists",
            ])
            .arg(source)
            .status()
            .context("could not verify the packaged MCP bridge signature")?;
        ensure!(
            status.success(),
            "the packaged MCP bridge is not signed with Developer ID"
        );
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(not(target_os = "windows"))]
        let _ = source;
        #[cfg(target_os = "windows")]
        {
            let script = "$s=Get-AuthenticodeSignature -LiteralPath $env:EKUBO_BRIDGE_TO_VERIFY; if($s.Status -ne 'Valid'){exit 1}";
            let status = Command::new("powershell.exe")
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    script,
                ])
                .env("EKUBO_BRIDGE_TO_VERIFY", source)
                .status()
                .context("could not verify the packaged MCP bridge signature")?;
            ensure!(
                status.success(),
                "the packaged MCP bridge has invalid Authenticode"
            );
        }
        ensure!(
            digest == BRIDGE_SHA256,
            "the packaged MCP bridge failed its embedded digest verification"
        );
        Ok(())
    }
}

fn harness_argument(kind: AgentKind) -> Result<&'static str> {
    match kind {
        AgentKind::Codex => Ok("codex"),
        AgentKind::ClaudeCode => Ok("claude-code"),
        AgentKind::ClaudeDesktop => Ok("claude-desktop"),
        AgentKind::GeminiCli => Ok("gemini-cli"),
        AgentKind::Cursor => Ok("cursor"),
        AgentKind::Opencode => Ok("opencode"),
        AgentKind::Other => anyhow::bail!("unsupported agent configuration"),
    }
}

fn claude_desktop_config(home: &Path, base: &BaseDirs) -> PathBuf {
    #[cfg(target_os = "macos")]
    let _ = base;
    #[cfg(target_os = "macos")]
    return home.join("Library/Application Support/Claude/claude_desktop_config.json");
    #[cfg(target_os = "windows")]
    return base.config_dir().join("Claude/claude_desktop_config.json");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    base.config_dir().join("Claude/claude_desktop_config.json")
}

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
    Installed { kind: AgentKind },
    Removed { kind: AgentKind },
}

impl ConfigPreview {
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.before != self.after
    }

    /// Verify that an unchanged file still contains the exact credential-free
    /// bridge command and hosted companion shape.
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
                kind: AgentKind::ClaudeDesktop,
                display_name: "Claude Desktop",
                config_path: claude_desktop_config(home, &base),
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
                AgentKind::ClaudeDesktop => self.config_path.parent().is_some_and(Path::exists),
                AgentKind::GeminiCli => binary_on_path("gemini"),
                AgentKind::Cursor => self
                    .config_path
                    .parent()
                    .is_some_and(std::path::Path::exists),
                AgentKind::Opencode => binary_on_path("opencode"),
                AgentKind::Other => false,
            }
    }

    pub fn preview_install(&self) -> Result<ConfigPreview> {
        let before = match fs::read_to_string(&self.config_path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        let command = installed_bridge_path()?;
        let command = command.to_string_lossy();
        let client = harness_argument(self.kind)?;
        let after = match self.kind {
            AgentKind::Codex => merge_codex(&before, &command, client)?,
            AgentKind::ClaudeCode | AgentKind::ClaudeDesktop | AgentKind::Cursor => {
                merge_json(&before, "mcpServers", JsonShape::Stdio, &command, client)?
            }
            AgentKind::GeminiCli => {
                merge_json(&before, "mcpServers", JsonShape::Gemini, &command, client)?
            }
            AgentKind::Opencode => merge_json(&before, "mcp", JsonShape::Local, &command, client)?,
            AgentKind::Other => anyhow::bail!("unsupported agent configuration"),
        };
        let diff = managed_config_diff(self.kind, &before, &after)?;
        Ok(ConfigPreview {
            path: self.config_path.clone(),
            before,
            after,
            diff,
            validation: ConfigValidation::Installed { kind: self.kind },
        })
    }

    pub fn preview_remove(&self) -> Result<ConfigPreview> {
        let before = match fs::read_to_string(&self.config_path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        let after = match self.kind {
            AgentKind::Codex => remove_codex(&before)?,
            AgentKind::ClaudeCode
            | AgentKind::ClaudeDesktop
            | AgentKind::GeminiCli
            | AgentKind::Cursor => remove_json(&before, "mcpServers")?,
            AgentKind::Opencode => remove_json(&before, "mcp")?,
            AgentKind::Other => anyhow::bail!("unsupported agent configuration"),
        };
        let diff = managed_config_diff(self.kind, &before, &after)?;
        Ok(ConfigPreview {
            path: self.config_path.clone(),
            before,
            after,
            diff,
            validation: ConfigValidation::Removed { kind: self.kind },
        })
    }
}

fn binary_on_path(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|directory| directory.join(name).is_file())
    })
}

fn merge_codex(before: &str, command: &str, client: &str) -> Result<String> {
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
    // Replace both wallet-managed entries with their exact credential-free
    // shapes instead of trying to enumerate fields which must not survive;
    // future harness credential fields are thereby removed without granting
    // the wallet authority over any sibling or global key.
    let mut local = Table::new();
    local["command"] = value(command);
    let mut args = toml_edit::Array::new();
    args.push("--client");
    args.push(client);
    local["args"] = toml_edit::value(args);
    servers.insert(LOCAL_SERVER_NAME, Item::Table(local));
    let mut companion = Table::new();
    companion["url"] = value(COMPANION_SERVER_URL);
    servers.insert(COMPANION_SERVER_NAME, Item::Table(companion));
    Ok(document.to_string())
}

fn remove_codex(before: &str) -> Result<String> {
    let mut document = parse_codex_document(before)?;
    if let Some(servers) = document.get_mut("mcp_servers").and_then(Item::as_table_mut) {
        servers.remove(LOCAL_SERVER_NAME);
        servers.remove(COMPANION_SERVER_NAME);
    }
    Ok(document.to_string())
}

#[derive(Clone, Copy)]
enum JsonShape {
    Stdio,
    Gemini,
    Local,
}

fn merge_json(
    before: &str,
    root: &str,
    shape: JsonShape,
    command: &str,
    client: &str,
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
    servers.insert(
        LOCAL_SERVER_NAME.into(),
        json_server(shape, command, client),
    );
    servers.insert(
        COMPANION_SERVER_NAME.into(),
        remote_json_server(shape, COMPANION_SERVER_URL),
    );
    Ok(format!("{}\n", serde_json::to_string_pretty(&document)?))
}

fn remove_json(before: &str, root: &str) -> Result<String> {
    let mut document = parse_json_document(before)?;
    if let Some(servers) = document.get_mut(root).and_then(Value::as_object_mut) {
        servers.remove(LOCAL_SERVER_NAME);
        servers.remove(COMPANION_SERVER_NAME);
    }
    Ok(format!("{}\n", serde_json::to_string_pretty(&document)?))
}

fn json_server(shape: JsonShape, command: &str, client: &str) -> Value {
    match shape {
        JsonShape::Stdio | JsonShape::Gemini => {
            json!({"command": command, "args": ["--client", client]})
        }
        JsonShape::Local => json!({"type": "local", "command": [command, "--client", client]}),
    }
}

fn remote_json_server(shape: JsonShape, url: &str) -> Value {
    match shape {
        JsonShape::Stdio => json!({"type": "http", "url": url}),
        JsonShape::Gemini => json!({"httpUrl": url}),
        JsonShape::Local => json!({"type": "remote", "url": url}),
    }
}

fn managed_config_diff(kind: AgentKind, before: &str, after: &str) -> Result<String> {
    let mut changes = Vec::new();
    match kind {
        AgentKind::Codex => {
            let before = parse_codex_document(before)?;
            let after = parse_codex_document(after)?;
            for server in [LOCAL_SERVER_NAME, COMPANION_SERVER_NAME] {
                push_managed_change(
                    &mut changes,
                    &format!("mcp_servers.{server}"),
                    codex_value(&before, Some("mcp_servers"), server),
                    codex_value(&after, Some("mcp_servers"), server),
                );
            }
        }
        AgentKind::ClaudeCode
        | AgentKind::ClaudeDesktop
        | AgentKind::GeminiCli
        | AgentKind::Cursor
        | AgentKind::Opencode => {
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
    match validation {
        ConfigValidation::Installed { kind } => match kind {
            AgentKind::Codex => validate_codex_shape(contents),
            AgentKind::ClaudeCode
            | AgentKind::ClaudeDesktop
            | AgentKind::GeminiCli
            | AgentKind::Cursor
            | AgentKind::Opencode => validate_json_shape(contents, kind),
            AgentKind::Other => anyhow::bail!("unsupported agent configuration"),
        },
        ConfigValidation::Removed { kind } => validate_removed_shape(contents, kind),
    }
}

fn validate_removed_shape(contents: &str, kind: AgentKind) -> Result<()> {
    match kind {
        AgentKind::Codex => {
            let document = parse_codex_document(contents)?;
            let servers = document.get("mcp_servers").and_then(Item::as_table);
            ensure!(
                servers.is_none_or(|servers| {
                    !servers.contains_key(LOCAL_SERVER_NAME)
                        && !servers.contains_key(COMPANION_SERVER_NAME)
                }),
                "wallet-managed MCP servers remain in Codex configuration"
            );
        }
        AgentKind::ClaudeCode
        | AgentKind::ClaudeDesktop
        | AgentKind::GeminiCli
        | AgentKind::Cursor
        | AgentKind::Opencode => {
            let document = parse_json_document(contents)?;
            let root = if kind == AgentKind::Opencode {
                "mcp"
            } else {
                "mcpServers"
            };
            let servers = document.get(root).and_then(Value::as_object);
            ensure!(
                servers.is_none_or(|servers| {
                    !servers.contains_key(LOCAL_SERVER_NAME)
                        && !servers.contains_key(COMPANION_SERVER_NAME)
                }),
                "wallet-managed MCP servers remain in agent configuration"
            );
        }
        AgentKind::Other => anyhow::bail!("unsupported agent configuration"),
    }
    Ok(())
}

fn validate_codex_shape(contents: &str) -> Result<()> {
    let document = contents
        .parse::<DocumentMut>()
        .context("Codex config is not valid TOML")?;
    let servers = document.get("mcp_servers").and_then(Item::as_table);
    let local = servers.and_then(|servers| servers.get(LOCAL_SERVER_NAME));
    let local = local.context("local MCP server is missing")?;
    let command = local
        .get("command")
        .and_then(Item::as_str)
        .context("local MCP server has no helper command")?;
    ensure!(
        Path::new(command) == installed_bridge_path()?,
        "local MCP helper path is not fixed"
    );
    let args = local
        .get("args")
        .and_then(Item::as_array)
        .context("local MCP server has no arguments")?;
    ensure!(
        args.len() == 2
            && args.get(0).and_then(toml_edit::Value::as_str) == Some("--client")
            && args.get(1).and_then(toml_edit::Value::as_str) == Some("codex"),
        "local MCP helper arguments are incorrect"
    );
    ensure!(
        local.as_table().is_some_and(|table| table.len() == 2),
        "Codex MCP server contains unmanaged fields"
    );
    let companion = servers
        .and_then(|servers| servers.get(COMPANION_SERVER_NAME))
        .context("companion MCP server is missing")?;
    ensure!(
        companion.get("url").and_then(Item::as_str) == Some(COMPANION_SERVER_URL),
        "companion MCP server URL is incorrect"
    );
    ensure!(
        companion.as_table().is_some_and(|table| table.len() == 1),
        "companion MCP server contains unmanaged fields"
    );
    Ok(())
}

fn validate_json_shape(contents: &str, kind: AgentKind) -> Result<()> {
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
    let shape = match kind {
        AgentKind::ClaudeCode | AgentKind::ClaudeDesktop | AgentKind::Cursor => JsonShape::Stdio,
        AgentKind::GeminiCli => JsonShape::Gemini,
        AgentKind::Opencode => JsonShape::Local,
        AgentKind::Codex | AgentKind::Other => unreachable!("validated above"),
    };
    let command = installed_bridge_path()?;
    let client = harness_argument(kind)?;
    ensure!(
        local == &json_server(shape, &command.to_string_lossy(), client),
        "local MCP server contains unmanaged fields"
    );
    let companion = servers
        .and_then(|servers| servers.get(COMPANION_SERVER_NAME))
        .context("companion MCP server is missing")?;
    ensure!(
        companion == &remote_json_server(shape, COMPANION_SERVER_URL),
        "companion MCP server has an incorrect or credential-bearing shape"
    );
    Ok(())
}

#[cfg(test)]
#[path = "agent_config_test.rs"]
mod tests;
