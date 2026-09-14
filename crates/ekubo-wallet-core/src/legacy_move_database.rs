//! Logical, lossless transfer of the supported compiled schema. Never executes
//! source DDL, upgrades the source, or silently omits an unknown table/column.
use super::{
    DatabaseKey, PolicyStore, SCHEMA_VERSION, create_current_schema, schema_version,
    verify_integrity,
};
use anyhow::{Context as _, Result, ensure};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _,
    types::{Value, ValueRef},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, path::Path};

const MOVE_STATE: &str = "legacy_move_state";
pub(crate) const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) enum Cell {
    Null,
    Integer(i64),
    Real(u64),
    Text(String),
    Blob(Vec<u8>),
}
impl Cell {
    fn read(value: ValueRef<'_>) -> Result<Self> {
        Ok(match value {
            ValueRef::Null => Self::Null,
            ValueRef::Integer(value) => Self::Integer(value),
            ValueRef::Real(value) => Self::Real(value.to_bits()),
            ValueRef::Text(value) => Self::Text(std::str::from_utf8(value)?.to_owned()),
            ValueRef::Blob(value) => Self::Blob(value.to_vec()),
        })
    }
    fn value(&self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Integer(value) => Value::Integer(*value),
            Self::Real(value) => Value::Real(f64::from_bits(*value)),
            Self::Text(value) => Value::Text(value.clone()),
            Self::Blob(value) => Value::Blob(value.clone()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Table {
    pub name: String,
    columns: Vec<String>,
    pub rows: Vec<Vec<Cell>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub tables: Vec<Table>,
}

fn identifier(name: &str) -> Result<String> {
    ensure!(
        !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'),
        "unsupported SQL identifier"
    );
    Ok(format!("\"{name}\""))
}

fn layout(connection: &Connection, destination: bool) -> Result<BTreeMap<String, Vec<String>>> {
    let mut result = BTreeMap::new();
    let mut statement =
        connection.prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")?;
    for name in statement.query_map([], |row| row.get::<_, String>(0))? {
        let name = name?;
        if destination && name == MOVE_STATE {
            continue;
        }
        let mut columns =
            connection.prepare(&format!("PRAGMA table_xinfo({})", identifier(&name)?))?;
        let columns: Vec<String> = columns
            .query_map([], |row| {
                let hidden: i64 = row.get(6)?;
                if hidden != 0 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                row.get(1)
            })?
            .collect::<rusqlite::Result<_>>()?;
        result.insert(name, columns);
    }
    Ok(result)
}

fn compiled_layout() -> Result<BTreeMap<String, Vec<String>>> {
    let connection = Connection::open_in_memory()?;
    create_current_schema(&connection)?;
    layout(&connection, false)
}

pub(crate) fn capture(connection: &Connection, destination: bool) -> Result<Snapshot> {
    capture_with_limit(connection, destination, MAX_BYTES)
}

/// Fail-closed schema gate for the first-run-only move contract: the source
/// must be exactly `SCHEMA_VERSION`. Anything else refuses the move and
/// leaves the source unchanged; there is no upgrade or partial path.
fn capture_with_limit(
    connection: &Connection,
    destination: bool,
    limit: usize,
) -> Result<Snapshot> {
    ensure!(
        schema_version(connection)? == Some(SCHEMA_VERSION),
        "legacy move requires the exact supported schema; source was left unchanged"
    );
    let actual = layout(connection, destination)?;
    ensure!(
        actual == compiled_layout()?,
        "unsupported legacy tables or columns; no state was omitted"
    );
    let executable: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type IN ('view','trigger')",
        [],
        |r| r.get(0),
    )?;
    ensure!(executable == 0, "legacy schema contains executable objects");
    let mut tables = Vec::new();
    let mut bytes = 0usize;
    for (name, columns) in actual {
        let names = columns
            .iter()
            .map(|name| identifier(name))
            .collect::<Result<Vec<_>>>()?
            .join(",");
        let mut statement = connection.prepare(&format!(
            "SELECT {names} FROM {} ORDER BY {names}",
            identifier(&name)?
        ))?;
        let mut rows = statement.query([])?;
        let mut values = Vec::new();
        while let Some(row) = rows.next()? {
            let row = (0..columns.len())
                .map(|index| Cell::read(row.get_ref(index)?))
                .collect::<Result<Vec<_>>>()?;
            let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&row)?);
            bytes = bytes
                .checked_add(encoded.len())
                .context("legacy snapshot size overflow")?;
            ensure!(
                bytes <= limit,
                "legacy state exceeds the bounded move size; nothing was omitted or deleted"
            );
            values.push(row);
        }
        tables.push(Table {
            name,
            columns,
            rows: values,
        });
    }
    Ok(Snapshot { tables })
}

impl Snapshot {
    pub(crate) fn digest(&self) -> Result<[u8; 32]> {
        self.digest_with_limit(MAX_BYTES)
    }

    fn digest_with_limit(&self, limit: usize) -> Result<[u8; 32]> {
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(self)?);
        ensure!(
            bytes.len() <= limit,
            "legacy snapshot exceeds the move limit"
        );
        Ok(Sha256::digest(bytes.as_slice()).into())
    }
    fn validate(&self) -> Result<()> {
        let layout: BTreeMap<_, _> = self
            .tables
            .iter()
            .map(|table| (table.name.clone(), table.columns.clone()))
            .collect();
        ensure!(
            layout.len() == self.tables.len() && layout == compiled_layout()?,
            "move bundle schema mismatch"
        );
        self.digest()?;
        Ok(())
    }
}

pub(crate) fn open_source(path: &Path, key: &DatabaseKey) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.pragma_update(None, "cipher_log_level", "NONE")?;
    key.with_sqlcipher_literal(|key| connection.pragma_update(None, "key", key))?;
    connection.pragma_update(None, "cipher_memory_security", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.execute_batch("BEGIN")?;
    let journal: String = connection.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    ensure!(
        journal == "delete",
        "legacy move requires the released rollback-journal format"
    );
    verify_integrity(&connection)?;
    Ok(connection)
}

pub(crate) fn wallets(connection: &Connection) -> Result<Vec<crate::config::WalletMetadata>> {
    let encoded: Option<String> = connection
        .query_row(
            "SELECT value_json FROM application_settings WHERE key=?1",
            [crate::config::WALLET_CONFIGURATION_SETTING],
            |r| r.get(0),
        )
        .optional()?;
    let config: crate::config::WalletConfig =
        serde_json::from_str(&encoded.context("legacy wallet configuration is missing")?)?;
    crate::config::validate_config(&config)?;
    ensure!(
        config.wallets.len() <= 512,
        "legacy move supports at most 512 accounts; no credentials were changed"
    );
    let active: i64 = connection.query_row(
        "SELECT count(*) FROM wallet_instances WHERE retired_at IS NULL",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        usize::try_from(active)? == config.wallets.len(),
        "legacy active account inventory mismatch"
    );
    for wallet in &config.wallets {
        let matches:i64=connection.query_row("SELECT count(*) FROM wallet_instances WHERE instance_id=?1 AND wallet_id=?2 AND wallet_address=?3 AND created_at=?4 AND retired_at IS NULL",
            rusqlite::params![wallet.instance_id.to_string(),wallet.id,format!("{:#x}",wallet.address),wallet.created_at.timestamp_millis()],|r|r.get(0))?;
        ensure!(
            matches == 1,
            "legacy signing identity disagrees with wallet configuration"
        );
    }
    Ok(config.wallets)
}

pub(crate) fn require_quiescent(connection: &Connection) -> Result<()> {
    let live: i64 = connection.query_row("SELECT count(*) FROM pending_transactions WHERE status IN ('signed','submitting','broadcast','cancelling')",[],|r|r.get(0))?;
    let enabled: i64 = connection.query_row(
        "SELECT count(*) FROM automations WHERE state='enabled'",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        live == 0 && enabled == 0,
        "settle in-flight transactions and disable automations before moving; all their records will be preserved"
    );
    Ok(())
}

pub(crate) fn initialize_baseline(data_dir: &Path) -> Result<()> {
    let mut store = PolicyStore::production(data_dir)?;
    let tx = store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS legacy_move_state(slot TEXT PRIMARY KEY CHECK(slot IN ('baseline','receipt')),digest BLOB NOT NULL CHECK(length(digest)=32))")?;
    ensure_cleanup_columns(&tx)?;
    if state(&tx, "baseline")?.is_none() {
        let count: i64 = tx.query_row("SELECT count(*) FROM wallet_instances", [], |r| r.get(0))?;
        ensure!(count == 0, "initial move baseline requires zero accounts");
        // Materialize the normal lazy default before fingerprinting: the first
        // read-only UI snapshot must not itself invalidate move eligibility.
        let config = crate::config::WalletConfig {
            version: 3,
            wallets: Vec::new(),
            networks: crate::config::default_networks(),
        };
        tx.execute("INSERT OR IGNORE INTO application_settings(key,value_json,updated_at) VALUES(?1,?2,?3)",
            rusqlite::params![crate::config::WALLET_CONFIGURATION_SETTING,serde_json::to_string(&config)?,chrono::Utc::now().timestamp_millis()])?;
        // Fresh startup must not inherit the optional transfer's size limit.
        let digest = capture_with_limit(&tx, true, usize::MAX)?.digest_with_limit(usize::MAX)?;
        tx.execute(
            "INSERT INTO legacy_move_state(slot,digest) VALUES('baseline',?1)",
            [digest.as_slice()],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn state(connection: &Connection, slot: &str) -> Result<Option<Vec<u8>>> {
    Ok(connection
        .query_row(
            "SELECT digest FROM legacy_move_state WHERE slot=?1",
            [slot],
            |r| r.get(0),
        )
        .optional()?)
}

#[cfg(test)]
pub(crate) fn import(
    data_dir: &Path,
    snapshot: &Snapshot,
    prepare_keys: impl FnOnce(&[crate::config::WalletMetadata]) -> Result<()>,
) -> Result<[u8; 32]> {
    import_bound(data_dir, snapshot, "test-only-unbound-source", prepare_keys)
}

pub(crate) fn import_bound(
    data_dir: &Path,
    snapshot: &Snapshot,
    binding: &str,
    prepare_keys: impl FnOnce(&[crate::config::WalletMetadata]) -> Result<()>,
) -> Result<[u8; 32]> {
    ensure!(
        binding.len() <= 256 * 1024,
        "move identity metadata is oversized"
    );
    snapshot.validate()?;
    let expected = snapshot.digest()?;
    let mut store = PolicyStore::production(data_dir)?;
    let tx = store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    ensure_cleanup_columns(&tx)?;
    if let Some(previous) = state(&tx, "receipt")? {
        require_binding(&tx, binding)?;
        ensure!(
            !cleanup_complete(&tx)?,
            "legacy move cleanup is already complete"
        );
        ensure!(
            previous == expected,
            "this v2 profile already imported another source"
        );
        ensure!(
            capture(&tx, true)?.digest()? == expected,
            "imported state changed; source cleanup is not verified"
        );
        prepare_keys(&wallets(&tx)?)?;
        return Ok(expected);
    }
    // First-run-only contract: the destination must still match its empty
    // first-run baseline. Any pre-move v2 write (legal acceptance, settings,
    // schema bump) permanently refuses the move for this profile; the check
    // fails closed with no overwrite path. Recovery is a fresh install or
    // reset of the v2 profile.
    let baseline = state(&tx, "baseline")?.context("v2 has no fresh first-run move baseline")?;
    ensure!(
        capture_with_limit(&tx, true, usize::MAX)?
            .digest_with_limit(usize::MAX)?
            .as_slice()
            == baseline.as_slice(),
        "v2 is no longer empty and unchanged; refusing to overwrite its state"
    );
    tx.execute_batch("PRAGMA defer_foreign_keys=ON")?;
    for table in &snapshot.tables {
        tx.execute(&format!("DELETE FROM {}", identifier(&table.name)?), [])?;
    }
    for table in &snapshot.tables {
        let columns = table
            .columns
            .iter()
            .map(|name| identifier(name))
            .collect::<Result<Vec<_>>>()?
            .join(",");
        let placeholders = vec!["?"; table.columns.len()].join(",");
        let mut insert = tx.prepare(&format!(
            "INSERT INTO {}({columns}) VALUES({placeholders})",
            identifier(&table.name)?
        ))?;
        for row in &table.rows {
            ensure!(
                row.len() == table.columns.len(),
                "legacy row arity mismatch"
            );
            insert.execute(rusqlite::params_from_iter(row.iter().map(Cell::value)))?;
        }
    }
    require_quiescent(&tx)?;
    let mut foreign = tx.prepare("PRAGMA foreign_key_check")?;
    ensure!(
        foreign.query([])?.next()?.is_none(),
        "legacy rows violate compiled references"
    );
    drop(foreign);
    let inventory = wallets(&tx)?;
    prepare_keys(&inventory)?;
    ensure!(
        capture(&tx, true)?.digest()? == expected,
        "destination state readback mismatch"
    );
    tx.execute(
        "INSERT INTO legacy_move_state(slot,digest,binding) VALUES('receipt',?1,?2)",
        rusqlite::params![expected.as_slice(), binding],
    )?;
    tx.commit()?;
    Ok(expected)
}

fn ensure_cleanup_columns(connection: &Connection) -> Result<()> {
    let columns = connection
        .prepare("PRAGMA table_info(legacy_move_state)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|name| name == "binding") {
        connection.execute_batch("ALTER TABLE legacy_move_state ADD COLUMN binding TEXT; ALTER TABLE legacy_move_state ADD COLUMN cleanup_complete INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_complete IN (0,1))")?;
    }
    Ok(())
}

fn cleanup_complete(connection: &Connection) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT cleanup_complete FROM legacy_move_state WHERE slot='receipt'",
        [],
        |row| row.get(0),
    )?)
}

fn require_binding(connection: &Connection, binding: &str) -> Result<()> {
    let stored: Option<String> = connection.query_row(
        "SELECT binding FROM legacy_move_state WHERE slot='receipt'",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        stored.as_deref() == Some(binding),
        "move source, preserved inventory, or destination identity changed"
    );
    Ok(())
}

pub(crate) struct MoveState {
    pub baseline: bool,
    pub receipt: Option<[u8; 32]>,
    pub binding: Option<String>,
    pub complete: bool,
}

/// Read-only, including on profiles predating completion metadata.
pub(crate) fn move_state(data_dir: &Path) -> Result<MoveState> {
    let store = PolicyStore::production(data_dir)?;
    store.connection.execute_batch("BEGIN")?;
    let exists: bool = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='legacy_move_state')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(MoveState {
            baseline: false,
            receipt: None,
            binding: None,
            complete: false,
        });
    }
    let receipt: Option<[u8; 32]> = state(&store.connection, "receipt")?
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid move receipt"))
        })
        .transpose()?;
    let columns = store
        .connection
        .prepare("PRAGMA table_info(legacy_move_state)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let (binding, complete) = if receipt.is_some() && columns.iter().any(|name| name == "binding") {
        store.connection.query_row(
            "SELECT binding,cleanup_complete FROM legacy_move_state WHERE slot='receipt'",
            [],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, bool>(1)?)),
        )?
    } else {
        (None, false)
    };
    Ok(MoveState {
        baseline: state(&store.connection, "baseline")?.is_some(),
        receipt,
        binding,
        complete,
    })
}

pub(crate) fn verify_binding(data_dir: &Path, binding: &str) -> Result<()> {
    let store = PolicyStore::production(data_dir)?;
    require_binding(&store.connection, binding)
}

pub(crate) fn finish_cleanup(data_dir: &Path, expected: [u8; 32], binding: &str) -> Result<()> {
    let mut store = PolicyStore::production(data_dir)?;
    let tx = store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    require_binding(&tx, binding)?;
    ensure!(
        state(&tx, "receipt")?.as_deref() == Some(expected.as_slice())
            && capture(&tx, true)?.digest()? == expected,
        "destination changed before cleanup completion"
    );
    tx.execute(
        "UPDATE legacy_move_state SET cleanup_complete=1 WHERE slot='receipt'",
        [],
    )?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn verify(
    data_dir: &Path,
    expected: [u8; 32],
) -> Result<Vec<crate::config::WalletMetadata>> {
    let store = PolicyStore::production(data_dir)?;
    store.connection.execute_batch("BEGIN")?;
    ensure!(
        state(&store.connection, "receipt")?.as_deref() == Some(expected.as_slice()),
        "no matching durable destination receipt"
    );
    ensure!(
        capture(&store.connection, true)?.digest()? == expected,
        "destination state no longer matches the source"
    );
    verify_integrity(&store.connection)?;
    wallets(&store.connection)
}

#[cfg(test)]
#[path = "legacy_move_database_test.rs"]
mod tests;
