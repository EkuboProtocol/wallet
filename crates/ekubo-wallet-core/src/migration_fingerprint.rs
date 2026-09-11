//! Stable logical identity across independently salted encrypted exports.
use super::{
    create_current_schema,
    migration_rebuild::{column_names, identifier, table_names},
};
use anyhow::{Result, ensure};
use rusqlite::{Connection, types::ValueRef};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) fn describe(source: &Connection) -> Result<[u8; 32]> {
    let trusted = Connection::open_in_memory()?;
    create_current_schema(&trusted)?;
    let tables = table_names(&trusted)?;
    ensure!(
        table_names(source)? == tables,
        "fingerprint source table inventory differs from compiled schema"
    );
    // Reject executable and internal tables before reading any source rows.
    // The current compiled schema has no sequences or WITHOUT ROWID tables.
    let unsupported: i64 = source.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type NOT IN ('table','index') OR (type='table' AND (name GLOB 'sqlite_*' OR upper(sql) LIKE '%VIRTUAL%'))",
        [], |row| row.get(0),
    )?;
    ensure!(unsupported == 0, "unsupported fingerprint source schema");
    let mut digest = Sha256::new();
    digest.update(b"ekubo-wallet/migration-source/v1\0");
    hash_query(
        source,
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type COLLATE BINARY,name COLLATE BINARY",
        &mut digest,
    )?;
    for pragma in ["user_version", "application_id"] {
        let value: i64 = source.pragma_query_value(None, pragma, |row| row.get(0))?;
        digest.update(value.to_be_bytes());
    }
    for table in tables {
        let columns = column_names(&trusted, &table)?;
        ensure!(
            column_names(source, &table)?
                .into_iter()
                .collect::<BTreeSet<_>>()
                == columns.iter().cloned().collect(),
            "fingerprint source columns differ from compiled schema"
        );
        frame(&mut digest, table.as_bytes());
        let fields = std::iter::once("rowid".to_owned())
            .chain(columns.iter().map(|name| identifier(name)))
            .collect::<Vec<_>>()
            .join(",");
        hash_query(
            source,
            &format!("SELECT {fields} FROM {} ORDER BY rowid", identifier(&table)),
            &mut digest,
        )?;
    }
    Ok(digest.finalize().into())
}

fn frame(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn hash_query(source: &Connection, sql: &str, digest: &mut Sha256) -> Result<()> {
    let mut statement = source.prepare(sql)?;
    let columns = statement.column_count();
    digest.update((columns as u64).to_be_bytes());
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        digest.update([1]);
        for index in 0..columns {
            match row.get_ref(index)? {
                ValueRef::Null => digest.update([0]),
                ValueRef::Integer(value) => {
                    digest.update([1]);
                    digest.update(value.to_be_bytes());
                }
                ValueRef::Real(value) => {
                    digest.update([2]);
                    digest.update(value.to_bits().to_be_bytes());
                }
                ValueRef::Text(value) => {
                    digest.update([3]);
                    frame(digest, value);
                }
                ValueRef::Blob(value) => {
                    digest.update([4]);
                    frame(digest, value);
                }
            }
        }
    }
    digest.update([0]);
    Ok(())
}

#[cfg(test)]
#[path = "migration_fingerprint_test.rs"]
mod tests;
