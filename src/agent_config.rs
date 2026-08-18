//! Typed, transactional configuration adapters for supported agent hosts.

use anyhow::{Context, Result, ensure};
use directories::BaseDirs;
use ekubo_wallet_core::desktop_store::AgentKind;
use fs2::FileExt as _;
use serde_json::{Map, Value, json};
use std::{
    fs,
    fs::{File, OpenOptions},
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

/// Every helper image this wallet has ever installed starts with this, so a
/// single prefix identifies both the file to keep and the debris to collect.
const BRIDGE_NAME_PREFIX: &str = "ekubo-wallet-mcp-bridge";
/// The one filename a harness is ever configured to execute.
///
/// It carries no version. An agent config written once therefore keeps
/// working across every wallet update: the next launch replaces the bytes at
/// this path and the harness runs the new bridge the next time it starts one.
/// Earlier releases installed `…-<version>` instead, which invalidated every
/// managed config on each update and made the user re-enable each agent.
#[cfg(windows)]
const BRIDGE_FILE_NAME: &str = "ekubo-wallet-mcp-bridge.exe";
#[cfg(not(windows))]
const BRIDGE_FILE_NAME: &str = "ekubo-wallet-mcp-bridge";

fn helpers_dir() -> Result<PathBuf> {
    Ok(ekubo_wallet_core::config::default_data_dir()?.join("helpers"))
}

fn installed_bridge_path() -> Result<PathBuf> {
    Ok(helpers_dir()?.join(BRIDGE_FILE_NAME))
}

/// The helper image this build would install. Release builds use the one
/// shipped beside the wallet executable; debug builds may use the workspace
/// build-tree binary.
fn packaged_bridge_bytes() -> Result<Vec<u8>> {
    let executable = std::env::current_exe().context("could not locate the wallet executable")?;
    let packaged = executable.with_file_name(BRIDGE_FILE_NAME);
    #[cfg(debug_assertions)]
    let source = if packaged.is_file() {
        packaged
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/debug")
            .join(BRIDGE_FILE_NAME)
    };
    #[cfg(not(debug_assertions))]
    let source = packaged;
    ensure!(source.is_file(), "the packaged MCP bridge is missing");
    let bytes = fs::read(&source).context("failed to read the packaged MCP bridge")?;
    ensure!(!bytes.is_empty(), "the packaged MCP bridge is empty");
    Ok(bytes)
}

/// Whether the helper a harness would execute is the one this build ships.
///
/// Every managed config names one fixed path, which is what lets a config
/// written once survive an update — and also what makes an agent look
/// installed no matter which build's bytes are sitting at that path. Only a
/// comparison of the bytes distinguishes an agent that reaches this wallet
/// from one that will be told its bridge is the wrong version.
///
/// A symlink into the application bundle would make the question moot, but
/// it would also put the bundle's own binary behind every long-lived bridge
/// process, which is exactly what [`install_bridge_helper`] copies to avoid
/// while the updater swaps that bundle underneath.
pub fn bridge_helper_is_current() -> Result<bool> {
    installed_image_matches(&installed_bridge_path()?, &packaged_bridge_bytes()?)
}

fn installed_image_matches(installed: &Path, packaged: &[u8]) -> Result<bool> {
    let Ok(metadata) = fs::metadata(installed) else {
        return Ok(false);
    };
    // Different lengths settle it without reading a megabyte twice.
    if metadata.len() != packaged.len() as u64 {
        return Ok(false);
    }
    Ok(fs::read(installed)? == packaged)
}

/// Atomically install the helper at its fixed path in the wallet's private
/// per-user directory.
///
/// Harnesses execute this copy, never the binary inside the installed
/// application. A long-lived bridge therefore holds no executable or file
/// handle in the app bundle while the updater swaps that bundle.
///
/// The path is fixed rather than versioned, so the managed agent configs
/// survive an update untouched. Replacing it is still a rename, so a bridge
/// already running out of the old bytes keeps its own image and no harness
/// ever sees a half-written helper. Two wallet versions sharing a data
/// directory therefore share one helper — whichever launched last owns it,
/// which is the same bridge the running wallet answers.
pub fn install_bridge_helper() -> Result<PathBuf> {
    let parent = helpers_dir()?;
    let installed = parent.join(BRIDGE_FILE_NAME);
    let bytes = packaged_bridge_bytes()?;
    fs::create_dir_all(&parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))?;
    }
    remove_superseded_helpers(&parent);
    if installed.is_file() && fs::read(&installed)? == bytes {
        return Ok(installed);
    }
    let mut temporary = NamedTempFile::new_in(&parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    replace_installed_helper(temporary, &installed)?;
    ensure!(
        fs::read(&installed)? == bytes,
        "installed MCP bridge failed verification"
    );
    Ok(installed)
}

/// Rename the freshly written helper over the installed one.
///
/// Unix replaces a running binary's directory entry without complaint. Windows
/// refuses to replace the image of a running process but does allow that image
/// to be renamed, so a failed replacement moves the old helper aside and
/// retries. Nothing executes the moved-aside copy: it loses the `.exe`
/// extension and no config names it.
fn replace_installed_helper(temporary: NamedTempFile, installed: &Path) -> Result<()> {
    let temporary = match temporary.persist(installed) {
        Ok(_) => return Ok(()),
        Err(error) if cfg!(windows) && installed.is_file() => error.file,
        Err(error) => return Err(error.error.into()),
    };
    let aside = superseded_helper_path(installed)?;
    fs::rename(installed, &aside).with_context(|| {
        format!(
            "failed to move the running MCP bridge aside to {}",
            aside.display()
        )
    })?;
    if let Err(error) = temporary.persist(installed) {
        // Leaving no helper at all would break every configured harness, so
        // put the superseded one back before reporting the failure.
        let _ = fs::rename(&aside, installed);
        return Err(error.error.into());
    }
    let _ = fs::remove_file(&aside);
    Ok(())
}

/// Pick an unused `…​.old-N` sibling for a helper that cannot be replaced in
/// place. A counter rather than a timestamp keeps the name predictable and the
/// directory bounded when several superseded images are still held open.
fn superseded_helper_path(installed: &Path) -> Result<PathBuf> {
    let name = installed
        .file_name()
        .and_then(|name| name.to_str())
        .context("installed MCP bridge path is not valid UTF-8")?;
    (0..64)
        .map(|index| installed.with_file_name(format!("{name}.old-{index}")))
        .find(|candidate| !candidate.exists())
        .context("too many superseded MCP bridge images are still in use")
}

/// Delete every helper image this wallet no longer installs: the versioned
/// copies earlier releases wrote, and the `.old-N` files a Windows replacement
/// leaves behind.
///
/// Best effort. A bridge still running out of a superseded image keeps it
/// locked on Windows, and the next launch collects it.
fn remove_superseded_helpers(parent: &Path) {
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name != BRIDGE_FILE_NAME && name.starts_with(BRIDGE_NAME_PREFIX) {
            let _ = fs::remove_file(entry.path());
        }
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
        AgentKind::GrokBuild => Ok("grok-build"),
        AgentKind::Other => anyhow::bail!("unsupported agent configuration"),
    }
}

fn claude_desktop_config(home: &Path, base: &BaseDirs) -> PathBuf {
    #[cfg(target_os = "macos")]
    let _ = base;
    #[cfg(not(target_os = "macos"))]
    let _ = home;
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
    installed: zeroize::Zeroizing<String>,
    _lock: File,
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
    pub fn install(mut previews: Vec<ConfigPreview>) -> Result<Self> {
        // A stable global order prevents two wallet processes installing the
        // same batch in a different UI order from deadlocking on sidecars.
        previews.sort_by(|left, right| left.path.cmp(&right.path));
        let mut batch = Self {
            installed: Vec::new(),
            committed: false,
        };
        for preview in previews {
            match preview.install() {
                Ok(Some(installed)) => batch.installed.push(installed),
                Ok(None) => {}
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
            let Ok(current) = fs::read_to_string(&installed.path) else {
                continue;
            };
            // A non-cooperating editor can ignore the sidecar. Never erase
            // bytes written after ours unless they are still exactly ours.
            if current != installed.installed.as_str() {
                continue;
            }
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
    /// bridge command and, where supported, hosted companion shape.
    fn validate_current(&self) -> Result<()> {
        let installed = fs::read_to_string(&self.path)
            .context("failed to read installed agent configuration")?;
        ensure!(
            installed == self.after,
            "installed agent configuration changed before validation"
        );
        validate_document(&self.path, &installed)?;
        validate_server_shape(&installed, self.validation)
    }

    fn install(mut self) -> Result<Option<InstalledConfig>> {
        let parent = self.path.parent().context("agent config has no parent")?;
        fs::create_dir_all(parent)?;
        let lock_path = config_lock_path(&self.path)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("failed to open {}", lock_path.display()))?;
        lock.lock_exclusive()
            .with_context(|| format!("failed to lock {}", lock_path.display()))?;
        let current = match fs::read_to_string(&self.path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        ensure!(
            current == self.before,
            "agent configuration changed after review; generate a fresh preview"
        );
        if !self.has_changes() {
            self.validate_current()?;
            return Ok(None);
        }
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
        let installed = zeroize::Zeroizing::new(std::mem::take(&mut self.after));
        self.diff.zeroize();
        Ok(Some(InstalledConfig {
            path: self.path.clone(),
            existed,
            before,
            installed,
            _lock: lock,
        }))
    }
}

fn config_lock_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("agent config filename is not valid UTF-8")?;
    Ok(path.with_file_name(format!(".{name}.ekubo-wallet.lock")))
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
            Self {
                kind: AgentKind::GrokBuild,
                display_name: "Grok Build",
                config_path: home.join(".grok/config.toml"),
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
                AgentKind::GrokBuild => binary_on_path("grok"),
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
            AgentKind::Codex | AgentKind::GrokBuild => merge_codex(&before, &command, client)?,
            AgentKind::ClaudeCode | AgentKind::Cursor => merge_json(
                &before,
                "mcpServers",
                JsonShape::Stdio,
                &command,
                client,
                true,
            )?,
            AgentKind::ClaudeDesktop => merge_json(
                &before,
                "mcpServers",
                JsonShape::Stdio,
                &command,
                client,
                false,
            )?,
            AgentKind::GeminiCli => merge_json(
                &before,
                "mcpServers",
                JsonShape::Gemini,
                &command,
                client,
                true,
            )?,
            AgentKind::Opencode => {
                merge_json(&before, "mcp", JsonShape::Local, &command, client, true)?
            }
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
            AgentKind::Codex | AgentKind::GrokBuild => remove_codex(&before)?,
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
    include_companion: bool,
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
    if include_companion {
        servers.insert(
            COMPANION_SERVER_NAME.into(),
            remote_json_server(shape, COMPANION_SERVER_URL),
        );
    } else {
        // Claude Desktop reserves this file for local stdio servers. Its
        // remote MCP services are account-level custom connectors managed in
        // Claude's UI, so repair also removes our obsolete remote JSON entry.
        servers.remove(COMPANION_SERVER_NAME);
    }
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
        AgentKind::Codex | AgentKind::GrokBuild => {
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
            AgentKind::Codex | AgentKind::GrokBuild => validate_toml_shape(contents, kind),
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
        AgentKind::Codex | AgentKind::GrokBuild => {
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

fn validate_toml_shape(contents: &str, kind: AgentKind) -> Result<()> {
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
            && args.get(1).and_then(toml_edit::Value::as_str) == Some(harness_argument(kind)?),
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
        AgentKind::Codex | AgentKind::GrokBuild | AgentKind::Other => {
            unreachable!("validated above")
        }
    };
    let command = installed_bridge_path()?;
    let client = harness_argument(kind)?;
    ensure!(
        local == &json_server(shape, &command.to_string_lossy(), client),
        "local MCP server contains unmanaged fields"
    );
    if kind == AgentKind::ClaudeDesktop {
        ensure!(
            servers.is_some_and(|servers| !servers.contains_key(COMPANION_SERVER_NAME)),
            "Claude Desktop remote companion must be an account connector, not an mcpServer"
        );
    } else {
        let companion = servers
            .and_then(|servers| servers.get(COMPANION_SERVER_NAME))
            .context("companion MCP server is missing")?;
        ensure!(
            companion == &remote_json_server(shape, COMPANION_SERVER_URL),
            "companion MCP server has an incorrect or credential-bearing shape"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "agent_config_test.rs"]
mod tests;
