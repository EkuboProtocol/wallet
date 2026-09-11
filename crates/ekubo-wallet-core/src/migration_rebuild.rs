//! Rebuild wallet data under compiled schema. Never execute source-provided DDL.
use super::migration_database::{open_checked_source, open_existing, verify_inventory};
use super::{DatabaseKey, create_current_schema, verify_integrity};
use crate::config::WalletMetadata;
use anyhow::{Context as _, Result, ensure};
use rusqlite::{Connection, TransactionBehavior, types::Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use uuid::Uuid;

pub(crate) fn rebuild(
    source: &Path,
    destination: &Path,
    key: &DatabaseKey,
    expected: &BTreeMap<Uuid, WalletMetadata>,
) -> Result<()> {
    let source = open_checked_source(source, key)?;
    verify_inventory(&source, expected)?;
    let mut target = open_existing(destination, key)?;
    let objects: i64 =
        target.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
    ensure!(objects == 0, "canonical build destination is not empty");
    target.pragma_update(None, "journal_mode", "DELETE")?;
    target.pragma_update(None, "synchronous", "FULL")?;
    target.pragma_update(None, "foreign_keys", "ON")?;
    create_current_schema(&target)?;
    let tables = table_names(&target)?;
    ensure!(
        table_names(&source)? == tables,
        "source database table inventory differs from compiled schema"
    );
    ensure!(
        source.query_row("SELECT count(*) FROM schema_metadata", [], |row| row
            .get::<_, i64>(0))?
            == 1,
        "source schema metadata is not a singleton"
    );
    let transaction = target.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.pragma_update(None, "defer_foreign_keys", "ON")?;
    for table in tables {
        let columns = column_names(&transaction, &table)?;
        ensure!(
            column_names(&source, &table)?
                .into_iter()
                .collect::<BTreeSet<_>>()
                == columns.iter().cloned().collect(),
            "source database columns differ from compiled schema"
        );
        if table != "schema_metadata" {
            copy_table(&source, &transaction, &table, &columns)?;
        }
    }
    for pragma in ["user_version", "application_id"] {
        let value: i64 = source.pragma_query_value(None, pragma, |row| row.get(0))?;
        transaction.pragma_update(None, pragma, value)?;
    }
    transaction.commit()?;
    verify_integrity(&target)?;
    verify_inventory(&target, expected)?;
    Ok(())
}

pub(super) fn table_names(connection: &Connection) -> Result<BTreeSet<String>> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*'",
    )?;
    Ok(statement
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?)
}

pub(super) fn column_names(connection: &Connection, table: &str) -> Result<Vec<String>> {
    let mut statement =
        connection.prepare("SELECT name,hidden FROM pragma_table_xinfo(?1) ORDER BY cid")?;
    let mut rows = statement.query([table])?;
    let mut columns = Vec::new();
    while let Some(row) = rows.next()? {
        ensure!(
            row.get::<_, i64>(1)? == 0,
            "generated or hidden columns are not supported in wallet migration"
        );
        columns.push(row.get(0)?);
    }
    ensure!(!columns.is_empty(), "source table has no columns");
    Ok(columns)
}

pub(super) fn identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn copy_table(
    source: &Connection,
    target: &Connection,
    table: &str,
    columns: &[String],
) -> Result<()> {
    // Names originate in the freshly compiled schema, never source SQL. Preserve
    // rowid as well so tied display order and existing implicit identities survive.
    let fields = std::iter::once("rowid".to_owned())
        .chain(columns.iter().map(|name| identifier(name)))
        .collect::<Vec<_>>()
        .join(",");
    let parameters = vec!["?"; columns.len() + 1].join(",");
    let mut input = source.prepare(&format!("SELECT {fields} FROM {}", identifier(table)))?;
    let mut output = target.prepare(&format!(
        "INSERT INTO {}({fields}) VALUES({parameters})",
        identifier(table)
    ))?;
    let mut rows = input.query([])?;
    while let Some(row) = rows.next()? {
        let values = (0..=columns.len())
            .map(|index| row.get::<_, Value>(index))
            .collect::<rusqlite::Result<Vec<_>>>()?;
        output
            .execute(rusqlite::params_from_iter(values))
            .with_context(|| format!("source rows violate compiled constraints for {table}"))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "migration_rebuild_test.rs"]
mod tests;
